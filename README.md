# Cresting Clouds Steam

Public GitHub Action used by the Cresting Clouds customer workflow.

The action accepts one Nimbus-signed reference and fails closed unless its
signature, key identifier, audience, lifetime, and purpose are valid. Depending
on that signed purpose it either publishes an encrypted, short-lived
authorization grant or redeems a GitHub OIDC identity for a temporary runtime
package.

Authorization grants are staged as one temporary `grant.json` file, uploaded by
GitHub's pinned official artifact action with one-day retention, and removed in
an unconditional cleanup step. The Steam process never receives or exports
GitHub's internal artifact-service credential.

The action contains only public verification keys and generic transport code.
It does not contain a Nimbus hostname, a Zephyr repository coordinate, a
private signing key, entitlement logic, or a customer credential.

## Usage

Use the protected `main` branch as the stable customer reference:

```yaml
- uses: Cresting-Clouds/steam@main
  with:
    ref: ${{ inputs.ref }}
  env:
    ALL_SECRETS_JSON: ${{ toJSON(secrets) }}
```

Customer workflows intentionally consume reviewed Steam changes without a
workflow-file update. `main` is therefore a live customer execution boundary.
Before this reference is enabled, the branch must be protected; every change
must require review and passing tests; and force-pushes must be disabled.
Alternate branches, tags, and commit references are not part of the supported
customer contract.

Runtime workflows must grant `id-token: write`. Customer workflow installation
and trust registration are managed by Cresting Clouds.

When Nimbus development or preview deployments use Vercel deployment
protection, the customer repository can retain the existing
`NIMBUS_VERCEL_BYPASS` secret. Steam reads only that field from
`ALL_SECRETS_JSON`, accepts either the raw value or the established
`x-vercel-protection-bypass=...` query-fragment form, masks it before use, and
forwards it only on the Nimbus-signed runtime redemption request. The value is
never written to disk or included in action outputs.

After redemption, Steam passes the signed callback origin and masked bypass
to the downloaded runtime process. This keeps environment routing out of the
customer workflow while ensuring every Zephyr callback returns to the Nimbus
deployment that issued the one-time reference.

Steam also establishes the outer unexpected-failure boundary for the downloaded
runtime. Zephyr writes a private marker as soon as all of its modules have loaded.
If cloning, archive download/extraction, dependency installation, or module load
fails before that marker exists, Steam sends a sanitized, heartbeat-authenticated
incident to Nimbus for the Zephyr issue repository. After the marker exists,
Zephyr owns reporting, preventing duplicate issues for expected or handled
pipeline failures.

For Salesforce validations and deployments, Steam also stages one private
`salesforce-operation-result-v1.json` destination outside its disposable
runtime directory. Zephyr writes the sanitized result there; Steam validates
the repository, run identity, tested merge-tree provenance, and coverage
shape, then uploads it with seven-day retention through the pinned official
artifact action. The deterministic, run-scoped artifact name is
`cresting-clouds-salesforce-operation-result`; a later run attempt replaces
the prior attempt's artifact after its new payload passes validation. The upload and
exact-prefix cleanup steps use `always()`, so structured Salesforce failures
retain evidence without widening the canonical one-step customer workflow.

## Development

```shell
npm ci
npm test
npm run build
git diff --exit-code -- dist/index.js
```

`dist/index.js` is committed because GitHub Actions executes the bundled file.
