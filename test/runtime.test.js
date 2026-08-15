"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  GRANT_SCHEMA,
  cleanupWorkspace,
  cloneCustomer,
  executeZephyr,
  isSafeArchivePath,
  readDeploymentProtectionBypass,
  redeemRuntime,
  requireArchiveUrl,
  stageEncryptedGrant,
  validateRuntimeResponse,
} = require("../src/runtime");

function runtimePayload() {
  return {
    repository: "customer/repository",
    oidc_audience: "cresting-clouds-runtime",
    redeem_url: "https://nimbus.example.invalid/api/pulsecheck",
  };
}

function runtimeResponse() {
  return {
    ok: true,
    async json() {
      return {
        schema: "cresting-clouds-runtime/v1",
        repository: "customer/repository",
        heartbeat_id: "heartbeat-123",
        customer_token: "temporary-customer-token-value",
        archive_url: "https://codeload.github.com/org/repo/tar.gz/abc",
        zephyr_sha: "a".repeat(40),
      };
    },
  };
}

test("cleans workspace contents and recreates the directory for post actions", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "steam-cleanup-test-"));
  const workspace = path.join(root, "customer", "repository");
  await fs.mkdir(path.join(workspace, "nested"), { recursive: true });
  await fs.writeFile(path.join(workspace, "runtime.txt"), "runtime\n");
  await fs.writeFile(path.join(workspace, "nested", "customer.txt"), "customer\n");

  try {
    await cleanupWorkspace(workspace);
    assert.deepEqual(await fs.readdir(workspace), []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("clones from the surviving workspace parent after deleting the checkout", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "steam-clone-test-"));
  const workspace = path.join(root, "customer", "repository");
  await fs.mkdir(workspace, { recursive: true });
  await fs.writeFile(path.join(workspace, "stale.txt"), "stale\n");

  try {
    await cloneCustomer({
      repository: "customer/repository",
      customerToken: "temporary-customer-token-value",
    }, workspace, async (command, args, options) => {
      assert.equal(command, "git");
      assert.deepEqual(args, [
        "clone",
        "--no-tags",
        "https://github.com/customer/repository.git",
        workspace,
      ]);
      assert.equal(options.cwd, path.dirname(workspace));
      await fs.access(options.cwd);
      await assert.rejects(fs.access(workspace), { code: "ENOENT" });
    });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("accepts only GitHub HTTPS archive URLs", () => {
  assert.equal(requireArchiveUrl("https://codeload.github.com/org/repo/tar.gz/abc"), "https://codeload.github.com/org/repo/tar.gz/abc");
  assert.throws(() => requireArchiveUrl("https://attacker.invalid/runtime.tar.gz"), /invalid_runtime_archive_url/);
  assert.throws(() => requireArchiveUrl("http://codeload.github.com/runtime.tar.gz"), /invalid_runtime_archive_url/);
});

test("rejects traversal archive paths", () => {
  assert.equal(isSafeArchivePath("owner-repo/run.js"), true);
  assert.equal(isSafeArchivePath("../outside"), false);
  assert.equal(isSafeArchivePath("/absolute"), false);
  assert.equal(isSafeArchivePath("owner\\outside"), false);
});

test("validates a repository-bound runtime response", () => {
  const runtime = validateRuntimeResponse({
    schema: "cresting-clouds-runtime/v1",
    repository: "customer/repository",
    heartbeat_id: "heartbeat-123",
    customer_token: "temporary-customer-token-value",
    archive_url: "https://codeload.github.com/org/repo/tar.gz/abc",
    zephyr_sha: "a".repeat(40),
  }, "customer/repository");
  assert.equal(runtime.heartbeatId, "heartbeat-123");
  assert.throws(() => validateRuntimeResponse({
    schema: "cresting-clouds-runtime/v1",
    repository: "other/repository",
  }, "customer/repository"), /runtime_repository_mismatch/);
});

test("omits the deployment protection header when the customer secret is absent", async () => {
  const masked = [];
  let request;
  await redeemRuntime({
    reference: "signed.runtime.reference",
    payload: runtimePayload(),
    core: {
      getIDToken: async () => "github-oidc-token",
      setSecret: value => masked.push(value),
    },
    secretsJson: JSON.stringify({ OTHER_SECRET: "ignored" }),
    fetchImpl: async (url, options) => {
      request = { url, options };
      return runtimeResponse();
    },
  });

  assert.equal(request.url.toString(), "https://nimbus.example.invalid/api/pulsecheck");
  assert.equal(request.options.headers.authorization, "Bearer github-oidc-token");
  assert.equal(request.options.headers["x-vercel-protection-bypass"], undefined);
  assert.deepEqual(masked, ["github-oidc-token"]);
});

test("masks and forwards the customer deployment protection bypass", async () => {
  const masked = [];
  let request;
  await redeemRuntime({
    reference: "signed.runtime.reference",
    payload: runtimePayload(),
    core: {
      getIDToken: async () => "github-oidc-token",
      setSecret: value => masked.push(value),
    },
    secretsJson: JSON.stringify({ NIMBUS_VERCEL_BYPASS: "customer-bypass-secret" }),
    fetchImpl: async (url, options) => {
      request = { url, options };
      return runtimeResponse();
    },
  });

  assert.equal(
    request.url.toString(),
    "https://nimbus.example.invalid/api/pulsecheck?x-vercel-protection-bypass=customer-bypass-secret",
  );
  assert.equal(request.options.headers["x-vercel-protection-bypass"], "customer-bypass-secret");
  assert.deepEqual(masked, ["customer-bypass-secret", "github-oidc-token"]);
});

test("normalizes the established query-fragment bypass secret", async () => {
  const masked = [];
  let request;
  const runtime = await redeemRuntime({
    reference: "signed.runtime.reference",
    payload: runtimePayload(),
    core: {
      getIDToken: async () => "github-oidc-token",
      setSecret: value => masked.push(value),
    },
    secretsJson: JSON.stringify({
      NIMBUS_VERCEL_BYPASS: "?x-vercel-protection-bypass=customer%2Fbypass%2Bsecret",
    }),
    fetchImpl: async (url, options) => {
      request = { url, options };
      return runtimeResponse();
    },
  });

  assert.equal(
    request.url.toString(),
    "https://nimbus.example.invalid/api/pulsecheck?x-vercel-protection-bypass=customer%2Fbypass%2Bsecret",
  );
  assert.equal(request.options.headers["x-vercel-protection-bypass"], "customer/bypass+secret");
  assert.deepEqual(masked, ["customer/bypass+secret", "github-oidc-token"]);
  assert.equal(runtime.callbackHost, "https://nimbus.example.invalid");
  assert.equal(runtime.callbackSecret, "customer/bypass+secret");
});

test("passes only the signed callback context into the Zephyr process", async () => {
  const commands = [];
  await executeZephyr({
    runtime: {
      heartbeatId: "heartbeat-123",
      callbackHost: "https://nimbus.example.invalid",
      callbackSecret: "customer-bypass-secret",
    },
    workspace: "/tmp/customer-workspace",
    zephyrDir: "/tmp/zephyr-runtime",
    runCommand: async (command, args, options) => commands.push({ command, args, options }),
  });

  assert.equal(commands.length, 2);
  assert.deepEqual(commands[1].args, ["/tmp/zephyr-runtime/run.js"]);
  assert.equal(commands[1].options.cwd, "/tmp/customer-workspace");
  assert.equal(
    commands[1].options.env.CRESTING_CLOUDS_RUNTIME_HOST,
    "https://nimbus.example.invalid",
  );
  assert.equal(
    commands[1].options.env.CRESTING_CLOUDS_RUNTIME_SECRET,
    "customer-bypass-secret",
  );
  assert.equal(commands[1].options.env.HEARTBEAT_ID, "heartbeat-123");
});

test("fails closed when the inherited secret bundle is malformed", () => {
  assert.throws(() => readDeploymentProtectionBypass("{"), /invalid_all_secrets_json/);
  assert.throws(
    () => readDeploymentProtectionBypass(JSON.stringify({ NIMBUS_VERCEL_BYPASS: 123 })),
    /invalid_deployment_protection_bypass/,
  );
  assert.throws(
    () => readDeploymentProtectionBypass(JSON.stringify({
      NIMBUS_VERCEL_BYPASS: "x-vercel-protection-bypass=one&unexpected=two",
    })),
    /invalid_deployment_protection_bypass/,
  );
  assert.throws(
    () => readDeploymentProtectionBypass(JSON.stringify({
      NIMBUS_VERCEL_BYPASS: "line-one\nline-two",
    })),
    /invalid_deployment_protection_bypass/,
  );
});

test("stages only the signed encrypted reference for the workflow uploader", async () => {
  const runnerTemp = await fs.mkdtemp(path.join(os.tmpdir(), "steam-test-"));
  try {
    const staged = await stageEncryptedGrant({
      reference: "signed.encrypted.reference",
      payload: {
        artifact_name: "cresting-clouds-vscode-auth-nonce123",
        encrypted_grant: { ciphertext: "not-written-separately" },
      },
      runnerTemp,
    });
    const document = JSON.parse(await fs.readFile(staged.file, "utf8"));
    assert.equal(staged.artifactName, "cresting-clouds-vscode-auth-nonce123");
    assert.equal(path.dirname(staged.file), staged.root);
    assert.equal(path.dirname(staged.root), runnerTemp);
    assert.match(path.basename(staged.root), /^cresting-clouds-grant-/);
    assert.equal(document.schema, GRANT_SCHEMA);
    assert.deepEqual(Object.keys(document).sort(), ["reference", "schema"]);
  } finally {
    await fs.rm(runnerTemp, { recursive: true, force: true });
  }
});

test("delegates grant upload to GitHub's pinned action and always cleans the staged file", async () => {
  const action = await fs.readFile(path.join(__dirname, "..", "action.yml"), "utf8");
  const source = await fs.readFile(path.join(__dirname, "..", "src", "index.js"), "utf8");
  const packageJson = JSON.parse(await fs.readFile(path.join(__dirname, "..", "package.json"), "utf8"));

  assert.match(action, /id: steam/);
  assert.match(action, /if: \$\{\{ steps\.steam\.outputs\.purpose == 'vscode-auth' \}\}/);
  assert.match(action, /actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/);
  assert.match(action, /retention-days: 1/);
  assert.match(action, /if-no-files-found: error/);
  assert.match(action, /if: \$\{\{ always\(\) && steps\.steam\.outputs\.grant-root != '' \}\}/);
  assert.match(action, /"\$RUNNER_TEMP_ROOT"\/cresting-clouds-grant-\*/);
  assert.doesNotMatch(source, /DefaultArtifactClient|@actions\/artifact/);
  assert.equal(packageJson.dependencies["@actions/artifact"], undefined);
});
