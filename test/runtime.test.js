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
  reportBootstrapIfUnstarted,
  reportRuntimeBootstrapFailure,
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

test("passes the redeemed customer credential and signed callback context into Zephyr", async () => {
  const commands = [];
  const previousGithubToken = process.env.GITHUB_TOKEN;
  const previousGhToken = process.env.GH_TOKEN;
  process.env.GITHUB_TOKEN = "restricted-actions-token";
  process.env.GH_TOKEN = "restricted-actions-token";
  try {
    await executeZephyr({
      runtime: {
        heartbeatId: "heartbeat-123",
        customerToken: "temporary-customer-token-value",
        callbackHost: "https://nimbus.example.invalid",
        callbackSecret: "customer-bypass-secret",
      },
      workspace: "/tmp/customer-workspace",
      zephyrDir: "/tmp/zephyr-runtime",
      startedFile: "/tmp/zephyr-started",
      runCommand: async (command, args, options) => commands.push({ command, args, options }),
    });
  } finally {
    if (previousGithubToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = previousGithubToken;
    if (previousGhToken === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = previousGhToken;
  }

  assert.equal(commands.length, 2);
  assert.equal(commands[0].options.env.GITHUB_TOKEN, "restricted-actions-token");
  assert.equal(commands[0].options.env.GH_TOKEN, "restricted-actions-token");
  assert.deepEqual(commands[1].args, ["/tmp/zephyr-runtime/run.js"]);
  assert.equal(commands[1].options.cwd, "/tmp/customer-workspace");
  assert.equal(commands[1].options.env.GITHUB_TOKEN, "temporary-customer-token-value");
  assert.equal(commands[1].options.env.GH_TOKEN, "temporary-customer-token-value");
  assert.equal(
    commands[1].options.env.CRESTING_CLOUDS_RUNTIME_HOST,
    "https://nimbus.example.invalid",
  );
  assert.equal(
    commands[1].options.env.CRESTING_CLOUDS_RUNTIME_SECRET,
    "customer-bypass-secret",
  );
  assert.equal(
    commands[1].options.env.CRESTING_CLOUDS_RUNTIME_STARTED_FILE,
    "/tmp/zephyr-started",
  );
  assert.equal(commands[1].options.env.HEARTBEAT_ID, "heartbeat-123");
});

test("reports a sanitized Zephyr issue when the runtime fails before its boundary starts", async () => {
  const previousRunId = process.env.GITHUB_RUN_ID;
  const previousRunAttempt = process.env.GITHUB_RUN_ATTEMPT;
  const previousRepository = process.env.GITHUB_REPOSITORY;
  const previousServerUrl = process.env.GITHUB_SERVER_URL;
  process.env.GITHUB_RUN_ID = "12345";
  process.env.GITHUB_RUN_ATTEMPT = "2";
  process.env.GITHUB_REPOSITORY = "customer/repository";
  process.env.GITHUB_SERVER_URL = "https://github.com";
  let request;
  try {
    const result = await reportRuntimeBootstrapFailure({
      repository: "customer/repository",
      heartbeatId: "heartbeat-123",
      callbackHost: "https://nimbus.example.invalid",
      callbackSecret: "customer-bypass-secret",
      zephyrSha: "a".repeat(40),
    }, new Error("bun failed at https://signed.example.invalid/archive?secret=1 with github_pat_private"), async (url, options) => {
      request = { url, options };
      return {
        ok: true,
        async json() {
          return { reported: true, issue_url: "https://github.com/Cresting-Clouds/zephyr/issues/123" };
        },
      };
    });

    assert.equal(result.sent, true);
    assert.equal(
      request.url.toString(),
      "https://nimbus.example.invalid/api/product-issues/report?x-vercel-protection-bypass=customer-bypass-secret",
    );
    assert.equal(request.options.headers["x-vercel-protection-bypass"], "customer-bypass-secret");
    const payload = JSON.parse(request.options.body);
    assert.equal(payload.event_id, "steam:12345:2:heartbeat-123");
    assert.equal(payload.source, "zephyr");
    assert.equal(payload.suggested_owner_repo, "Cresting-Clouds/zephyr");
    assert.equal(payload.expected, false);
    assert.deepEqual(payload.customer, {
      org: "customer",
      repo: "repository",
      full_name: "customer/repository",
    });
    assert.equal(payload.context.heartbeat_id, "heartbeat-123");
    assert.equal(payload.context.workflow_run_id, "12345");
    assert.equal(payload.context.zephyr_sha, "a".repeat(40));
    assert.doesNotMatch(payload.message, /signed\.example\.invalid|github_pat_private/);
  } finally {
    if (previousRunId === undefined) delete process.env.GITHUB_RUN_ID;
    else process.env.GITHUB_RUN_ID = previousRunId;
    if (previousRunAttempt === undefined) delete process.env.GITHUB_RUN_ATTEMPT;
    else process.env.GITHUB_RUN_ATTEMPT = previousRunAttempt;
    if (previousRepository === undefined) delete process.env.GITHUB_REPOSITORY;
    else process.env.GITHUB_REPOSITORY = previousRepository;
    if (previousServerUrl === undefined) delete process.env.GITHUB_SERVER_URL;
    else process.env.GITHUB_SERVER_URL = previousServerUrl;
  }
});

test("does not double-report after Zephyr has started its own failure boundary", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "steam-started-marker-test-"));
  const startedFile = path.join(root, "zephyr-started");
  await fs.writeFile(startedFile, "started\n");
  let requests = 0;
  const logs = [];
  try {
    const result = await reportBootstrapIfUnstarted({
      runtime: {
        repository: "customer/repository",
        heartbeatId: "heartbeat-123",
        callbackHost: "https://nimbus.example.invalid",
      },
      startedFile,
      error: new Error("handled Zephyr failure"),
      core: {
        info: value => logs.push(value),
        warning: value => logs.push(value),
      },
      fetchImpl: async () => {
        requests += 1;
        throw new Error("must not report");
      },
    });
    assert.deepEqual(result, { sent: false, reason: "runtime_started_or_not_redeemed" });
    assert.equal(requests, 0);
    assert.deepEqual(logs, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
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
