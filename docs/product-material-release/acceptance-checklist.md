# Product Material Release Acceptance Checklist

## Scope

Use this checklist to confirm the accepted architecture is in place and that the production boundary is not being overstated.

This checklist does not claim a production deployment.

## Architecture Acceptance

- [ ] The four role plugins exist as separate responsibilities: `test-submission`, `submission-gate`, `pre-release`, and `release-gate`.
- [ ] The first four role plugins embed `release_workflow_core`.
- [ ] `product-release-gate` is the downstream authorization and deploy control plane, not a duplicate policy engine.
- [ ] `release-approval` and `release-approval-verifier` implement the unified multi-role approval flow.
- [ ] `rd-flywheel` owns capability-gap governance and checkpoint recovery.
- [ ] Every workflow plugin exposes MCP, Skill, CLI, and unattended scheduler surfaces.
- [ ] The scheduler runs headless `run-once` behavior only and does not backfill missed intervals.
- [ ] The required subjects are fixed: `【提测】`, `【发布门禁检查】`, and `【发布申请】`.
- [ ] Legacy subject parsing still counts the standard module words, but subject text alone is never proof.

## Evidence Acceptance

- [ ] `event_id` and `round_id` are preserved across the full chain.
- [ ] Manifest-S and Manifest-R digests are bound to the same event.
- [ ] Mail identity evidence includes thread headers, UID, and UIDVALIDITY.
- [ ] ProductMaterialWorkflow/v1 auth and HMAC are optional.
- [ ] Missing auth is treated as unverified rather than an automatic block.
- [ ] A valid verified auth claim produces the visible compliant-plugin badge.
- [ ] An invalid claimed auth blocks the path.
- [ ] Feishu writeback and cloud readback are both captured.
- [ ] GitLab pipeline, job, and artifact references are captured.
- [ ] A subject line alone is not treated as proof.
- [ ] `RELEASE_READY` is treated as intermediate state only.
- [ ] `RELEASE_READY_NOTIFIED` is not treated as deployment success.

## Approval Acceptance

- [ ] `release-approval` can capture a decision from a local page or direct reply.
- [ ] `release-approval-verifier` rejects missing, expired, or mismatched evidence.
- [ ] A single verified handoff event is produced for a valid approval set.
- [ ] A missing role, bad digest, or bad thread causes fail-closed behavior.
- [ ] The approval flow does not mint deployment authority by itself.
- [ ] Each host auto-inits an optional local identity on install.
- [ ] Cross-host production uses local private identity plus Feishu public-key subscription and approval.
- [ ] No shared secret is distributed through email or Feishu.

## Input Acceptance

- [ ] SVN sender input includes task, module, version, locator or path, fixed revision, and retrieval instructions.
- [ ] File list, hash, signature, and cloud mirror are not mandatory fields.
- [ ] Optional checks are marked `NOT_APPLICABLE` when absent.
- [ ] Minimum trusted retrieval is a nonempty provenance trail plus an audit record.

## Deployment and Rollback Acceptance

- [ ] The downstream chain has four stages: preproduction, canary, full production, and readback.
- [ ] Each stage has a rollback path.
- [ ] Stage failure blocks the next stage.
- [ ] A readback mismatch is treated as a production truth failure.
- [ ] Rollback evidence is captured separately from deployment evidence.

## External Production Prerequisites

- [ ] A real mailbox is provisioned and accessible.
- [ ] Feishu permissions are provisioned and verified.
- [ ] GitLab protected variables and runner access are provisioned.
- [ ] Any administrator approval required by the environment is complete.
- [ ] Credentials are managed outside the docs and outside the workflow artifacts.

## Blocked-State Readiness

- [ ] CA trust can be read back from the local trust store.
- [ ] The SVN protected credential is bound and auditable without exposing the secret.
- [ ] The GitLab runner is protected and matches the release policy.
- [ ] Repository provenance can be reconstructed from the frozen task, module, version, locator or path, fixed revision, and retrieval instructions.
- [ ] CI pipeline, job, and artifact evidence can be produced and read back.

## Not Accepted

Reject the release if any of the following are true:

- The flow depends on a subject line without thread evidence.
- The flow depends on a successful job exit without readback evidence.
- The flow depends on a green local page without mail verification.
- The flow depends on a single combined role plugin instead of separated roles.
- The flow depends on a deployment claim that is not backed by evidence.
- The flow treats missing auth as an automatic failure when no invalid claim exists.
- The flow requires file lists, hashes, signatures, or cloud mirrors as mandatory SVN sender inputs.
- The flow distributes a shared secret by email or Feishu.
