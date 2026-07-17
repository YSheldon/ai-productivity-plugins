# Product Material Release Architecture

## Status Boundary

This document captures the accepted architecture for the product-material release flow. It does not claim a production rollout or a completed production deployment.

What is already defined in the source design and staged plugin contracts:

- The first four role plugins: `test-submission`, `submission-gate`, `pre-release`, and `release-gate`. Each embeds `release_workflow_core`.
- `product-release-gate` as the downstream authorization and deploy control plane.
- The unified multi-role release approval flow: `release-approval` and `release-approval-verifier`.
- `rd-flywheel` as the governance and capability-gap loop.
- The four equivalent surfaces: MCP, Skill, CLI, and unattended scheduler.
- The required mail subjects: `【提测】`, `【发布门禁检查】`, and `【发布申请】`.
- ProductMaterialWorkflow/v1 auth and HMAC are optional. Missing auth is ordinary and unverified, and may continue. A valid verified auth claim earns the visible compliant-plugin badge. An invalid claimed auth blocks.
- Each plugin may auto-init an optional local identity on install. Cross-host production uses a local private identity plus Feishu public-key subscription and approval. Shared secrets are never distributed through email or Feishu.
- Legacy subject parsing still counts the standard module words in the subject line, but the subject alone is never proof.
- The four-stage downstream deployment and rollback chain: preproduction, canary, full production, and readback.

External production prerequisites are separate and are not satisfied by this documentation alone:

- Real mailbox accounts and mail routing.
- Real Feishu workspace access and document permissions.
- Real GitLab project access, protected variables, and runners.
- Administrator-provisioned credentials and approvals.

## Architecture Map

| Component | Responsibility | Boundary |
| --- | --- | --- |
| `release_workflow_core` | Shared workflow core embedded by the first four role plugins. | Does not own downstream authorization or deployment authority. |
| `test-submission` | Collects submission data, builds Manifest-S, runs local or remote preflight, and sends `【提测】` requests. | Does not approve itself or bypass gate results. |
| `submission-gate` | Reads submission mail, performs authoritative submission gate checks, and emits pass or block reports. | Does not treat mail delivery or a successful job exit as proof. |
| `pre-release` | Aggregates test conclusions, builds Manifest-R, and sends `【发布门禁检查】` requests. | Does not widen the approved artifact set. |
| `release-gate` | Reads pre-release mail, performs release gate checks, and emits `【发布申请】` notifications. | Does not authorize production deployment. |
| `product-release-gate` | Owns the authorization state, policy state, evidence chain, and downstream deployment orchestration. | Keeps release readiness, authorization, deployment, and readback separate. |
| `release-approval` | Captures per-role approval decisions from a local page or direct reply. | Does not produce final approval by itself. |
| `release-approval-verifier` | Normalizes and verifies all role decisions and produces the single handoff event. | Fails closed on missing headers, mismatched digests, or identity mismatch. |
| `rd-flywheel` | Handles capability gaps, recovery checkpoints, and governance loops. | Does not self-grant missing privileges or convert a blocked event into success. |

## Control Flow

The accepted flow is evidence-driven and ordered:

1. `test-submission` freezes submission intent and emits `【提测】`.
2. `submission-gate` validates the submission and returns a pass or block result.
3. `pre-release` records testing outcome and emits `【发布门禁检查】`.
4. `release-gate` validates the release material and emits `【发布申请】`.
5. `release-approval` collects role decisions for the same `event_id` and `round_id`.
6. `release-approval-verifier` verifies identity, thread evidence, and frozen digests.
7. `product-release-gate` consumes the verified handoff and drives the four-stage downstream deployment chain.

`RELEASE_READY` and `RELEASE_READY_NOTIFIED` are intermediate states. They are not production authorization and they are not proof of deployment.

## Submission Input Contract

SVN sender inputs are accepted when they include the task, module, version, locator or path, fixed revision, and retrieval instructions.

The following are not mandatory for acceptance:

- file list.
- hash.
- signature.
- cloud mirror.

Minimum trusted retrieval is a nonempty provenance trail plus an audit record. Optional checks are marked `NOT_APPLICABLE` when they are absent rather than forced into the contract.

## Four Surfaces

Every workflow plugin in this architecture is expected to expose the same operational core through four surfaces:

- MCP for tool-based orchestration.
- Skill for Codex-native workflow entry.
- CLI for direct operator use and automation.
- Unattended scheduler for headless run-once execution.

All four surfaces must share one controller, one config model, and one state store. The scheduler is a thin adapter only. It must not implement alternate policy, alternate state transitions, or catch-up execution for missed intervals.

## Evidence Model

The flow is only authoritative when the following evidence is preserved and cross-linked:

- `event_id` and `round_id`.
- Manifest-S and Manifest-R digests.
- Mail `Message-ID`, `In-Reply-To`, and `References`.
- IMAP UID and UIDVALIDITY for message identity.
- Feishu document writeback and cloud readback.
- GitLab pipeline, job, and artifact references.
- Stage deployment, rollback, and readback references.

Real Feishu, mail, and GitLab evidence are required for production acceptance. A subject line alone is never enough, even when the legacy subject parser can count the standard module words.

## Four-Stage Deployment and Rollback

The downstream deployment chain is fixed:

1. Preproduction.
2. Canary.
3. Full production.
4. Production readback.

Each stage has its own rollback path. A failure at any stage blocks advancement, records evidence, and preserves the frozen checkpoint for recovery or replay. A readback mismatch is treated as a production truth failure, not as a harmless notification issue.
