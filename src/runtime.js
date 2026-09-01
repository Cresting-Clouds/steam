"use strict";

const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const tar = require("tar");

const RUNTIME_SCHEMA = "cresting-clouds-runtime/v1";
const GRANT_SCHEMA = "cresting-clouds-vscode-grant/v1";
const SALESFORCE_RESULT_SCHEMA = "cresting-clouds-salesforce-operation-result/v1";
const SALESFORCE_RESULT_FILE = "salesforce-operation-result-v1.json";
const SALESFORCE_RESULT_ARTIFACT = "cresting-clouds-salesforce-operation-result";
const SALESFORCE_RESULT_MAX_BYTES = 64 * 1024 * 1024;
const GITHUB_ARCHIVE_HOSTS = new Set([
  "codeload.github.com",
  "github.com",
  "objects.githubusercontent.com",
]);
const SAFE_REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SAFE_SHA = /^[a-f0-9]{40}$/;
const VERCEL_PROTECTION_BYPASS_SECRET = "NIMBUS_VERCEL_BYPASS";

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", ...options });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} failed with ${signal ? `signal ${signal}` : `exit ${code}`}`));
    });
  });
}

function requireArchiveUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("invalid_runtime_archive_url");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    !GITHUB_ARCHIVE_HOSTS.has(url.hostname.toLowerCase())
  ) {
    throw new Error("invalid_runtime_archive_url");
  }
  return url.toString();
}

function isSafeArchivePath(entryPath) {
  if (typeof entryPath !== "string" || !entryPath || entryPath.includes("\\")) return false;
  const normalized = path.posix.normalize(entryPath);
  return !path.posix.isAbsolute(normalized) && normalized !== ".." && !normalized.startsWith("../");
}

function validateRuntimeResponse(value, expectedRepository) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("invalid_runtime_response");
  }
  if (value.schema !== RUNTIME_SCHEMA) throw new Error("unsupported_runtime_response");
  if (!SAFE_REPOSITORY.test(String(value.repository || "")) || value.repository !== expectedRepository) {
    throw new Error("runtime_repository_mismatch");
  }
  if (!SAFE_SHA.test(String(value.zephyr_sha || ""))) throw new Error("invalid_runtime_sha");
  if (typeof value.heartbeat_id !== "string" || !value.heartbeat_id) {
    throw new Error("invalid_runtime_heartbeat");
  }
  if (typeof value.customer_token !== "string" || value.customer_token.length < 20) {
    throw new Error("invalid_runtime_customer_token");
  }
  return {
    schema: RUNTIME_SCHEMA,
    repository: value.repository,
    heartbeatId: value.heartbeat_id,
    customerToken: value.customer_token,
    archiveUrl: requireArchiveUrl(value.archive_url),
    zephyrSha: value.zephyr_sha,
  };
}

async function stageEncryptedGrant({ reference, payload, runnerTemp }) {
  const root = await fs.mkdtemp(path.join(runnerTemp, "cresting-clouds-grant-"));
  const file = path.join(root, "grant.json");
  const document = {
    schema: GRANT_SCHEMA,
    reference,
  };
  try {
    await fs.writeFile(file, `${JSON.stringify(document)}\n`, { encoding: "utf8", mode: 0o600 });
    return {
      artifactName: payload.artifact_name,
      file,
      root,
    };
  } catch (error) {
    await fs.rm(root, { recursive: true, force: true });
    throw error;
  }
}

function positiveRunNumber(value, errorCode) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new Error(errorCode);
  return number;
}

function salesforceResultArtifactName(runId, runAttempt) {
  positiveRunNumber(runId, "invalid_salesforce_result_run_id");
  positiveRunNumber(runAttempt, "invalid_salesforce_result_run_attempt");
  return SALESFORCE_RESULT_ARTIFACT;
}

async function stageSalesforceResultArtifact({ runnerTemp, runId, runAttempt }) {
  const numericRunId = positiveRunNumber(runId, "invalid_salesforce_result_run_id");
  const numericRunAttempt = positiveRunNumber(runAttempt, "invalid_salesforce_result_run_attempt");
  const root = await fs.mkdtemp(path.join(runnerTemp, "cresting-clouds-salesforce-result-"));
  await fs.chmod(root, 0o700);
  return {
    artifactName: salesforceResultArtifactName(numericRunId, numericRunAttempt),
    file: path.join(root, SALESFORCE_RESULT_FILE),
    root,
  };
}

function safeRepositoryRelativePath(value) {
  if (typeof value !== "string" || !value || value.includes("\\")) return false;
  const normalized = path.posix.normalize(value);
  return !path.posix.isAbsolute(normalized) && normalized !== ".." && !normalized.startsWith("../");
}

function validateSortedLines(value) {
  if (!Array.isArray(value)) return false;
  let previous = 0;
  for (const entry of value) {
    if (!Number.isSafeInteger(entry) || entry <= previous) return false;
    previous = entry;
  }
  return true;
}

function validateCoverageEntries(value) {
  if (!Array.isArray(value)) return false;
  return value.every(entry => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
    if (!new Set(["ApexClass", "ApexTrigger"]).has(entry.type)) return false;
    if (!validateSortedLines(entry.coveredLines) || !validateSortedLines(entry.uncoveredLines)) return false;
    if (typeof entry.coveredLinesAvailable !== "boolean") return false;
    if (entry.path !== undefined) {
      if (!safeRepositoryRelativePath(entry.path)) return false;
      if (typeof entry.source !== "string") {
        if (entry.source !== undefined || typeof entry.sourceOmitted !== "string" || !entry.sourceOmitted) {
          return false;
        }
      }
    } else if (entry.source !== undefined) {
      return false;
    }
    return true;
  });
}

async function validateSalesforceResultArtifact({
  staged,
  repository,
  zephyrSha,
  zephyrSourceSha,
  runId,
  runAttempt,
}) {
  let stat;
  try {
    stat = await fs.lstat(staged.file);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("invalid_salesforce_result_file");
  if (stat.size <= 0 || stat.size > SALESFORCE_RESULT_MAX_BYTES) {
    throw new Error("invalid_salesforce_result_size");
  }
  if ((stat.mode & 0o077) !== 0) throw new Error("insecure_salesforce_result_permissions");

  const numericRunId = positiveRunNumber(runId, "invalid_salesforce_result_run_id");
  const numericRunAttempt = positiveRunNumber(runAttempt, "invalid_salesforce_result_run_attempt");
  let document;
  try {
    document = JSON.parse(await fs.readFile(staged.file, "utf8"));
  } catch {
    throw new Error("invalid_salesforce_result_json");
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("invalid_salesforce_result_document");
  }
  if (document.schema !== SALESFORCE_RESULT_SCHEMA || document.schemaVersion !== 1) {
    throw new Error("unsupported_salesforce_result_schema");
  }
  if (document.artifactName !== staged.artifactName ||
      document.artifactName !== salesforceResultArtifactName(numericRunId, numericRunAttempt)) {
    throw new Error("salesforce_result_artifact_name_mismatch");
  }
  if (document.repository?.fullName !== repository ||
      document.workflow?.runId !== numericRunId ||
      document.workflow?.runAttempt !== numericRunAttempt) {
    throw new Error("salesforce_result_context_mismatch");
  }
  if (!new Set(["success", "failure"]).has(document.conclusion) ||
      !new Set(["success", "failure"]).has(document.pipeline?.conclusion) ||
      typeof document.timestamps?.completedAt !== "string" || !document.timestamps.completedAt) {
    throw new Error("nonterminal_salesforce_result");
  }
  if (!SAFE_SHA.test(String(zephyrSha || "")) || document.producer?.runtimeSha !== zephyrSha) {
    throw new Error("salesforce_result_producer_mismatch");
  }
  const sourceSha = String(zephyrSourceSha || zephyrSha || "");
  if (!SAFE_SHA.test(sourceSha) ||
      document.producer?.sha !== sourceSha ||
      document.producer?.sourceSha !== sourceSha) {
    throw new Error("salesforce_result_source_provenance_mismatch");
  }
  const expectedRunUrl = `${process.env.GITHUB_SERVER_URL || "https://github.com"}/${repository}/actions/runs/${numericRunId}` +
    (numericRunAttempt > 1 ? `/attempts/${numericRunAttempt}` : "");
  if (document.workflow?.runUrl !== expectedRunUrl) throw new Error("salesforce_result_run_url_mismatch");
  const snapshot = document.tested_snapshot;
  if (snapshot?.strategy !== "base_plus_head_merge_worktree" ||
      !SAFE_SHA.test(String(snapshot?.base_sha || "")) ||
      !SAFE_SHA.test(String(snapshot?.head_sha || "")) ||
      !SAFE_SHA.test(String(snapshot?.tree_sha || ""))) {
    throw new Error("invalid_salesforce_result_tested_snapshot");
  }
  if (document.source?.sha !== snapshot.head_sha || document.target?.sha !== snapshot.base_sha) {
    throw new Error("salesforce_result_revision_mismatch");
  }
  if (!validateCoverageEntries(document.normalized?.codeCoverage)) {
    throw new Error("invalid_salesforce_result_coverage");
  }
  return true;
}

async function resolveZephyrSourceSha({ zephyrDir, runtimeSha }) {
  if (!SAFE_SHA.test(String(runtimeSha || ""))) throw new Error("invalid_runtime_sha");
  const provenanceFile = path.join(zephyrDir, "zephyr-runtime-provenance.json");
  let stat;
  try {
    stat = await fs.lstat(provenanceFile);
  } catch (error) {
    if (error?.code === "ENOENT") return runtimeSha;
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > 64 * 1024) {
    throw new Error("invalid_runtime_provenance_file");
  }
  let provenance;
  try {
    provenance = JSON.parse(await fs.readFile(provenanceFile, "utf8"));
  } catch {
    throw new Error("invalid_runtime_provenance_json");
  }
  const sourceSha = String(provenance?.source_sha || "").toLowerCase();
  if (!SAFE_SHA.test(sourceSha)) throw new Error("invalid_runtime_source_sha");
  return sourceSha;
}

function readDeploymentProtectionBypass(secretsJson) {
  if (!secretsJson) return "";

  let secrets;
  try {
    secrets = JSON.parse(secretsJson);
  } catch {
    throw new Error("invalid_all_secrets_json");
  }

  if (!secrets || typeof secrets !== "object" || Array.isArray(secrets)) {
    throw new Error("invalid_all_secrets_json");
  }

  const bypass = secrets[VERCEL_PROTECTION_BYPASS_SECRET];
  if (bypass === undefined || bypass === null || bypass === "") return "";
  if (typeof bypass !== "string" || /[\r\n]/.test(bypass)) {
    throw new Error("invalid_deployment_protection_bypass");
  }

  const query = bypass.replace(/^[?&]/, "");
  if (!query.startsWith("x-vercel-protection-bypass=")) return bypass;

  const params = new URLSearchParams(query);
  const values = params.getAll("x-vercel-protection-bypass");
  if ([...params].length !== 1 || values.length !== 1 || !values[0]) {
    throw new Error("invalid_deployment_protection_bypass");
  }
  return values[0];
}

async function redeemRuntime({
  reference,
  payload,
  core,
  fetchImpl = fetch,
  secretsJson = process.env.ALL_SECRETS_JSON,
}) {
  const protectionBypass = readDeploymentProtectionBypass(secretsJson);
  if (protectionBypass) core.setSecret(protectionBypass);

  const oidcToken = await core.getIDToken(payload.oidc_audience);
  core.setSecret(oidcToken);
  const headers = {
    authorization: `Bearer ${oidcToken}`,
    "content-type": "application/json",
  };
  const redemptionUrl = new URL(payload.redeem_url);
  const callbackHost = redemptionUrl.origin;
  if (protectionBypass) {
    headers["x-vercel-protection-bypass"] = protectionBypass;
    redemptionUrl.searchParams.set("x-vercel-protection-bypass", protectionBypass);
  }

  const response = await fetchImpl(redemptionUrl, {
    method: "POST",
    redirect: "error",
    headers,
    body: JSON.stringify({ reference }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    throw new Error(`runtime_redemption_failed_${response.status}`);
  }
  return {
    ...validateRuntimeResponse(await response.json(), payload.repository),
    callbackHost,
    callbackSecret: protectionBypass,
  };
}

async function cloneCustomer(runtime, workspace, runCommand = run) {
  const authorization = Buffer.from(`x-access-token:${runtime.customerToken}`, "utf8").toString("base64");
  const workspaceParent = path.dirname(workspace);
  await fs.rm(workspace, { recursive: true, force: true });
  await fs.mkdir(workspaceParent, { recursive: true });
  await runCommand(
    "git",
    ["clone", "--no-tags", `https://github.com/${runtime.repository}.git`, workspace],
    {
      cwd: workspaceParent,
      env: {
        ...process.env,
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader",
        GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${authorization}`,
        GIT_TERMINAL_PROMPT: "0",
      },
    },
  );
}

async function downloadRuntime(runtime, archivePath, fetchImpl = fetch) {
  const response = await fetchImpl(runtime.archiveUrl, {
    redirect: "follow",
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) throw new Error(`runtime_archive_download_failed_${response.status}`);
  requireArchiveUrl(response.url || runtime.archiveUrl);
  await fs.writeFile(archivePath, Buffer.from(await response.arrayBuffer()), { mode: 0o600 });
}

async function extractRuntime(archivePath, destination) {
  await fs.mkdir(destination, { recursive: true });
  await tar.x({
    file: archivePath,
    cwd: destination,
    strip: 1,
    filter: (entryPath) => {
      if (!isSafeArchivePath(entryPath)) throw new Error("unsafe_runtime_archive_path");
      return true;
    },
  });
  await fs.access(path.join(destination, "run.js"));
  await fs.access(path.join(destination, "package.json"));
  await fs.access(path.join(destination, "package-lock.json"));
}

async function executeZephyr({
  runtime,
  workspace,
  zephyrDir,
  startedFile,
  salesforceResultFile,
  zephyrSourceSha,
  runCommand = run,
}) {
  await runCommand("bun", ["install", "--frozen-lockfile", "--production"], {
    cwd: zephyrDir,
    env: { ...process.env, CI: "true" },
  });
  await runCommand("bun", [path.join(zephyrDir, "run.js")], {
    cwd: workspace,
    env: {
      ...process.env,
      // The workflow GITHUB_TOKEN can be configured to forbid pull-request
      // creation even when the job requests pull-requests: write. Nimbus has
      // already authenticated and returned a short-lived customer installation
      // token, so keep every Zephyr GitHub mutation on that same credential.
      GITHUB_TOKEN: runtime.customerToken,
      GH_TOKEN: runtime.customerToken,
      CRESTING_CLOUDS_RUNTIME_HOST: runtime.callbackHost,
      CRESTING_CLOUDS_RUNTIME_SECRET: runtime.callbackSecret || "",
      CRESTING_CLOUDS_RUNTIME_STARTED_FILE: startedFile || "",
      CRESTING_CLOUDS_SALESFORCE_RESULT_FILE: salesforceResultFile || "",
      CRESTING_CLOUDS_ZEPHYR_SHA: runtime.zephyrSha,
      CRESTING_CLOUDS_ZEPHYR_SOURCE_SHA: zephyrSourceSha || runtime.zephyrSha,
      HEARTBEAT_ID: runtime.heartbeatId,
    },
  });
}

function publicFailureMessage(error) {
  const name = error && typeof error.name === "string" ? error.name : "Error";
  const message = error && typeof error.message === "string" ? error.message : String(error || "unknown failure");
  return `${name}: ${message}`
    .replace(/https?:\/\/\S+/gi, "<url>")
    .replace(/(?:gh[opsu]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)/g, "<token>")
    .replace(/\s+/g, " ")
    .slice(0, 1000);
}

async function reportRuntimeBootstrapFailure(runtime, error, fetchImpl = fetch) {
  const [org, repo] = runtime.repository.split("/");
  const endpoint = new URL("/api/product-issues/report", runtime.callbackHost);
  const headers = { "content-type": "application/json" };
  if (runtime.callbackSecret) {
    headers["x-vercel-protection-bypass"] = runtime.callbackSecret;
    endpoint.searchParams.set("x-vercel-protection-bypass", runtime.callbackSecret);
  }
  const runId = String(process.env.GITHUB_RUN_ID || "unknown");
  const runAttempt = String(process.env.GITHUB_RUN_ATTEMPT || "1");
  const message = publicFailureMessage(error);
  const payload = {
    event_id: `steam:${runId}:${runAttempt}:${runtime.heartbeatId}`,
    source: "zephyr",
    suggested_owner_repo: "Cresting-Clouds/zephyr",
    classification: "runtime_bootstrap_failure",
    criticality: "sev2",
    title: "Zephyr runtime failed before its failure boundary started",
    message,
    phase: "runtime.bootstrap",
    task: "runtime-bootstrap",
    expected: false,
    customer: { org, repo, full_name: runtime.repository },
    context: {
      heartbeat_id: runtime.heartbeatId,
      org,
      repo,
      workflow_run_id: runId,
      workflow_run_attempt: runAttempt,
      run_url: process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
        ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
        : undefined,
      zephyr_sha: runtime.zephyrSha,
    },
  };

  try {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) return { sent: false, reason: `report_failed_${response.status}` };
    const result = await response.json().catch(() => undefined);
    return result?.reported === true
      ? { sent: true, result }
      : { sent: false, reason: result?.reason || "not_reported" };
  } catch (reportError) {
    return { sent: false, reason: publicFailureMessage(reportError) };
  }
}

async function fileExists(file) {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

async function reportBootstrapIfUnstarted({ runtime, startedFile, error, core, fetchImpl = fetch }) {
  if (!runtime || await fileExists(startedFile)) {
    return { sent: false, reason: "runtime_started_or_not_redeemed" };
  }

  const report = await reportRuntimeBootstrapFailure(runtime, error, fetchImpl);
  if (report.sent) core.info("Zephyr bootstrap product issue reported.");
  else core.warning(`Zephyr bootstrap product issue was not reported: ${report.reason}`);
  return report;
}

async function cleanupWorkspace(workspace) {
  await fs.rm(workspace, { recursive: true, force: true });
  await fs.mkdir(workspace, { recursive: true });
}

async function cleanupRuntime({ workspace, tempRoot }) {
  try {
    process.chdir(process.env.RUNNER_TEMP || os.tmpdir());
  } catch {
    // The process can still remove absolute paths if the runner temp vanished.
  }
  const home = os.homedir();
  const paths = [
    tempRoot,
    path.join(home, ".sf"),
    path.join(home, ".sfdx"),
    path.join(home, ".config", "sf"),
    path.join(home, ".cache", "sf"),
  ];
  await Promise.allSettled(paths.map((target) => fs.rm(target, { recursive: true, force: true })));
  await cleanupWorkspace(workspace);
}

async function runRuntime({
  reference,
  payload,
  core,
  salesforceResultFile,
  onRuntimeRedeemed,
  fetchImpl = fetch,
  runCommand = run,
}) {
  const runnerTemp = process.env.RUNNER_TEMP || os.tmpdir();
  const workspace = process.env.GITHUB_WORKSPACE;
  if (!workspace || !path.isAbsolute(workspace)) throw new Error("missing_github_workspace");
  const tempRoot = await fs.mkdtemp(path.join(runnerTemp, "cresting-clouds-runtime-"));
  const archivePath = path.join(tempRoot, "runtime.tar.gz");
  const zephyrDir = path.join(tempRoot, "runtime");
  const startedFile = path.join(tempRoot, "zephyr-started");
  let runtime;
  try {
    runtime = await redeemRuntime({ reference, payload, core, fetchImpl });
    core.setSecret(runtime.customerToken);
    core.setSecret(runtime.archiveUrl);
    await cloneCustomer(runtime, workspace, runCommand);
    await downloadRuntime(runtime, archivePath, fetchImpl);
    await extractRuntime(archivePath, zephyrDir);
    const zephyrSourceSha = await resolveZephyrSourceSha({
      zephyrDir,
      runtimeSha: runtime.zephyrSha,
    });
    onRuntimeRedeemed?.({
      repository: runtime.repository,
      zephyrSha: runtime.zephyrSha,
      zephyrSourceSha,
    });
    await executeZephyr({
      runtime,
      workspace,
      zephyrDir,
      startedFile,
      salesforceResultFile,
      zephyrSourceSha,
      runCommand,
    });
  } catch (error) {
    await reportBootstrapIfUnstarted({ runtime, startedFile, error, core, fetchImpl });
    throw error;
  } finally {
    await cleanupRuntime({ workspace, tempRoot });
  }
}

module.exports = {
  GRANT_SCHEMA,
  RUNTIME_SCHEMA,
  SALESFORCE_RESULT_FILE,
  SALESFORCE_RESULT_ARTIFACT,
  SALESFORCE_RESULT_MAX_BYTES,
  SALESFORCE_RESULT_SCHEMA,
  cleanupRuntime,
  cleanupWorkspace,
  cloneCustomer,
  executeZephyr,
  isSafeArchivePath,
  readDeploymentProtectionBypass,
  reportBootstrapIfUnstarted,
  reportRuntimeBootstrapFailure,
  resolveZephyrSourceSha,
  redeemRuntime,
  requireArchiveUrl,
  runRuntime,
  salesforceResultArtifactName,
  stageEncryptedGrant,
  stageSalesforceResultArtifact,
  validateSalesforceResultArtifact,
  validateRuntimeResponse,
};
