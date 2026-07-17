# Product Material Release Installation and Quickstart

## Scope

This guide explains how to prepare the release-flow plugins and how to perform a safe first validation. It stops short of claiming production deployment.

## External Prerequisites

| Area | Required before installation |
| --- | --- |
| Mail | A mailbox that can read and send the required workflow subjects. |
| Feishu | A writable audit location and a readable cloud document path. |
| GitLab | A project, protected variables, and an available runner. |
| Identity | A local private identity on each host and approved operator access. |
| Scheduler | A host that can run unattended jobs or a headless CLI. |

If these do not exist, installation can still be documented, but the quickstart cannot complete end-to-end.

## What Gets Installed

Install the plugins in the accepted architecture, not as one combined tool:

- `test-submission`
- `submission-gate`
- `pre-release`
- `release-gate`
- `release-approval`
- `release-approval-verifier`
- `product-release-gate`
- `rd-flywheel`

Dependency helpers such as mail, Feishu, GitLab, and SSH connectors are separate capabilities. They are prerequisites, not substitutes for the workflow plugins.

## Identity And Auth

Installers should auto-init an optional identity on first run. That identity stays local to the host.

For cross-host production, use this model:

- local private identity on each host.
- Feishu public-key subscription and approval for public verification.
- no shared secret sent by email.
- no shared secret stored in Feishu.

ProductMaterialWorkflow/v1 auth and HMAC are optional. Missing auth is unverified and may continue through normal review. A verified auth claim shows the compliant-plugin badge. A claimed auth that cannot be verified blocks the path.

## Installation Order

1. Install the dependency helpers required by the target role.
2. Install the role plugin that matches the operator’s responsibility.
3. Create one config source for that plugin.
4. Run the plugin’s preflight checks.
5. Run the plugin’s headless validation or first run.
6. Confirm that the expected mail subject, audit record, or handoff event was produced.

Do not merge multiple role configurations into one shared state file. The architecture depends on role separation.

## Quickstart Paths

### Submission Path

Use this path when starting from a new product material change:

1. Open `test-submission`.
2. Capture the material set and submission metadata.
3. Emit `【提测】`.
4. Wait for `submission-gate` to return a pass or block result.

### Pre-Release Path

Use this path after testing is complete:

1. Open `pre-release`.
2. Load the approved test conclusion.
3. Generate Manifest-R only from the approved material set.
4. Emit `【发布门禁检查】`.

### Release Path

Use this path when the release gate has passed:

1. Open `release-gate`.
2. Validate the frozen release material.
3. Emit `【发布申请】`.
4. Hand the result to `release-approval` and `release-approval-verifier`.
5. Pass the verified handoff to `product-release-gate` for downstream stage execution.

### Governance Path

Use this path when a capability is missing or a repeated failure needs recovery planning:

1. Open `rd-flywheel`.
2. Preserve the frozen checkpoint.
3. Record the missing capability.
4. Build or restore the capability through the approved process.
5. Re-run from the original checkpoint.

## Quick Validation Checklist

You have a valid setup only when all of the following are true:

- The plugin reads one config source only.
- The mail identity is the intended role identity.
- The identity was auto-initialized locally when needed and was not exported as a shared secret.
- The configured folder or mailbox matches the workflow.
- Feishu writeback and readback both work.
- GitLab evidence can be produced and read back.
- The same `event_id` and `round_id` survive a replay.
- The scheduler does not overlap runs.
- The plugin does not claim success when evidence is missing.
- Verified auth shows the compliant-plugin badge, while missing auth remains unverified instead of failing closed.

## What This Quickstart Does Not Prove

This quickstart does not prove:

- production deployment.
- production authorization.
- external administrator approval.
- final rollback readiness for the production environment.

Those are separate production prerequisites and must be validated separately.
