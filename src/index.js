import os from "node:os";
import * as core from "@actions/core";
import referenceModule from "./reference.js";
import runtimeModule from "./runtime.js";

const { verifyReference } = referenceModule;
const {
  runRuntime,
  stageEncryptedGrant,
  stageSalesforceResultArtifact,
  validateSalesforceResultArtifact,
} = runtimeModule;

async function main() {
  const reference = core.getInput("ref", { required: true });
  const { payload } = verifyReference(reference);
  core.setOutput("purpose", payload.purpose);

  if (payload.purpose === "vscode-auth") {
    const stagedGrant = await stageEncryptedGrant({
      reference,
      payload,
      runnerTemp: process.env.RUNNER_TEMP || os.tmpdir(),
    });
    core.setOutput("artifact-name", stagedGrant.artifactName);
    core.setOutput("artifact-path", stagedGrant.file);
    core.setOutput("grant-root", stagedGrant.root);
    return;
  }

  const runId = process.env.GITHUB_RUN_ID;
  const runAttempt = process.env.GITHUB_RUN_ATTEMPT || "1";
  const stagedResult = await stageSalesforceResultArtifact({
    runnerTemp: process.env.RUNNER_TEMP || os.tmpdir(),
    runId,
    runAttempt,
  });
  core.setOutput("salesforce-result-name", stagedResult.artifactName);
  core.setOutput("salesforce-result-path", stagedResult.file);
  core.setOutput("salesforce-result-root", stagedResult.root);
  core.setOutput("salesforce-result-ready", "false");

  let runtimeError;
  let runtimeIdentity;
  try {
    await runRuntime({
      reference,
      payload,
      core,
      salesforceResultFile: stagedResult.file,
      onRuntimeRedeemed: identity => {
        runtimeIdentity = identity;
      },
    });
  } catch (error) {
    runtimeError = error;
  }

  let artifactError;
  try {
    const ready = await validateSalesforceResultArtifact({
      staged: stagedResult,
      repository: payload.repository,
      zephyrSha: runtimeIdentity?.zephyrSha,
      zephyrSourceSha: runtimeIdentity?.zephyrSourceSha,
      runId,
      runAttempt,
    });
    core.setOutput("salesforce-result-ready", String(ready));
  } catch (error) {
    artifactError = error;
  }

  if (runtimeError && artifactError) {
    throw new AggregateError([runtimeError, artifactError],
      "Zephyr failed and its Salesforce evidence artifact was invalid");
  }
  if (runtimeError) throw runtimeError;
  if (artifactError) throw artifactError;
}

main().catch((error) => {
  core.setFailed(error instanceof Error ? error.message : String(error));
});
