# Product Material Release Acceptance Checklist

## Scope

Use this checklist to confirm the accepted architecture is in place and that the production boundary is not being overstated.

This checklist does not claim a production deployment.

## Verified Evidence (2026-07-18)

- Plugin hardening commits: `64e0a68`, `99d1715`, `cdbb363`, and `4c39493`; the product CI Windows trust-anchor hardening commit is `abaaf9595273da6f7e8948fb0e38af2f4b414034`.
- Default-branch publication was independently read back: GitHub plugin marketplace `main` at `bb9cfc644a8c09bc43976454ab1ed93c65753e83`; GitLab product CI `main` at `abaaf9595273da6f7e8948fb0e38af2f4b414034`, published with `ci.skip`.
- Offline suite: `807` JUnit cases with zero failures, errors, or skips; final JUnit SHA-256: `A846B0FC47AB528CD10D2ABC06D91D761C05855C31B9281FA87D67F7DF4E195C`.
- Workflow plugin versions under test: `product-release-gate` `0.3.4`, `pre-release` `0.1.4`, and `release-gate` `0.1.4`.
- Installed GitLab plugin: `gitlab@ai-productivity-plugins` `0.1.5`; runtime source/cache files match `9/9`, MCP initialization and read-only GitLab connection passed, and token, runner-registration, and GitLab CI-variable value redaction were verified.
- Security boundary: GitLab client blocks absolute URLs and redirects, redacts structured sensitive fields, and resolves system PowerShell with Win32 `GetSystemDirectoryW` before using the Schannel fallback; the helper receives credentials only on stdin and fails closed.
- Base evidence summary: `C:\Work\AI\AutoEMail\artifacts\product-release-gate\production-readiness-verification-2026-07-17.json` (SHA-256 `64FBA5D76322D9CFD6CA43AE2016274BF02539DBFE2BE55CCF84032BF592D039`).
- Final JUnit evidence: `C:\Work\AI\AutoEMail\artifacts\product-release-gate\plugin-offline-tests-2026-07-18-release-workflow-final.xml` (SHA-256 `A846B0FC47AB528CD10D2ABC06D91D761C05855C31B9281FA87D67F7DF4E195C`).

## Explicitly Deferred

- Real `/api/v1/scans` validation is not executed because that endpoint is not implemented.
- GitLab `live_gate`, protected production deployment targets, and runner-registration credential rotation remain outside the completed evidence boundary.
- The enterprise mailbox passed IMAP and SMTP login checks; its persisted credential uses Windows CurrentUser DPAPI with no plaintext password field or unexpected non-owner write ACL.
- GitLab project 59 currently has zero CI variables, so protected scan/deployment variables are not provisioned and the corresponding production prerequisite remains unchecked.
- One configured runner matches the exact `live_gate` tag and is active, unpaused, and `ref_protected`; its last verified state was offline, and no pipeline or job was triggered during verification.

## Architecture Acceptance

- [x] The four role plugins exist as separate responsibilities: `test-submission`, `submission-gate`, `pre-release`, and `release-gate`.
- [x] The first four role plugins embed `release_workflow_core`.
- [x] `product-release-gate` is the downstream authorization and deploy control plane, not a duplicate policy engine.
- [x] `release-approval` and `release-approval-verifier` implement the unified multi-role approval flow.
- [x] `rd-flywheel` owns capability-gap governance and checkpoint recovery.
- [x] Every workflow plugin exposes MCP, Skill, CLI, and unattended scheduler surfaces.
- [x] The scheduler runs headless `run-once` behavior only and does not backfill missed intervals.
- [x] The required subjects are fixed: `【提测】`, `【发布门禁检查】`, and `【发布申请】`.
- [x] Legacy subject parsing still counts the standard module words, but subject text alone is never proof.

## Evidence Acceptance

- [x] `event_id` and `round_id` are preserved across the full chain.
- [x] Manifest-S and Manifest-R digests are bound to the same event.
- [x] Mail identity evidence includes thread headers, UID, and UIDVALIDITY.
- [x] ProductMaterialWorkflow/v1 auth and HMAC are optional.
- [x] Missing auth is treated as unverified rather than an automatic block.
- [x] A valid verified auth claim produces the visible compliant-plugin badge.
- [x] An invalid claimed auth blocks the path.
- [x] Feishu writeback and cloud readback are both captured.
- [x] GitLab pipeline, job, and artifact references are captured.
- [x] A subject line alone is not treated as proof.
- [x] `RELEASE_READY` is treated as intermediate state only.
- [x] `RELEASE_READY_NOTIFIED` is not treated as deployment success.
- [x] Unverified fallback mail is rebound to authoritative Manifest-S/Manifest-R state before success.
- [x] Sender-supplied provenance, policy digests, and checklist claims are not propagated from unverified fallback mail.

## Approval Acceptance

- [x] `release-approval` can capture a decision from a local page or direct reply.
- [x] `release-approval-verifier` rejects missing, expired, or mismatched evidence.
- [x] A single verified handoff event is produced for a valid approval set.
- [x] A missing role, bad digest, or bad thread causes fail-closed behavior.
- [x] The approval flow does not mint deployment authority by itself.
- [x] Each host auto-inits an optional local identity on install.
- [x] Cross-host production uses local private identity plus Feishu public-key subscription and approval.
- [x] No shared secret is distributed through email or Feishu.
- [x] Multi-role direct replies are normalized before aggregate approval verification.
- [x] Overdue reminders target only missing roles and deduplicate SMTP-accepted sends until the repeat interval.

## Input Acceptance

- [x] SVN sender input includes task, module, version, locator or path, fixed revision, and retrieval instructions.
- [x] File list, hash, signature, and cloud mirror are not mandatory fields.
- [x] Optional checks are marked `NOT_APPLICABLE` when absent.
- [x] Minimum trusted retrieval is a nonempty provenance trail plus an audit record.

## Deployment and Rollback Acceptance

- [x] The downstream chain has four stages: preproduction, canary, full production, and readback.
- [x] Each stage has a rollback path.
- [x] Stage failure blocks the next stage.
- [x] A readback mismatch is treated as a production truth failure.
- [x] Rollback evidence is captured separately from deployment evidence.
- [x] A valid signed production-readback receipt repairs an interrupted state commit without rerunning the external adapter.
- [x] A tampered or release-mismatched production-readback receipt fails closed.

## External Production Prerequisites

- [x] A real mailbox is provisioned and accessible.
- [x] Feishu permissions are provisioned and verified.
- [ ] GitLab protected scan, SVN retrieval, and deployment variables are provisioned.
- [ ] The protected runner bound to the `live_gate` tag is online and able to accept release jobs.
- [ ] Any administrator approval required by the environment is complete.
- [x] Credentials are managed outside the docs and outside the workflow artifacts.

## Blocked-State Readiness

- [x] CA trust can be read back from the local trust store.
- [ ] The SVN protected credential is bound and auditable without exposing the secret.
- [x] The GitLab runner selected by the exact `live_gate` tag is protected and matches the release policy.
- [ ] The selected protected runner is online.
- [x] Repository provenance can be reconstructed from the frozen task, module, version, locator or path, fixed revision, and retrieval instructions.
- [x] CI pipeline, job, and artifact evidence can be produced and read back.

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
