# Product Material Release Acceptance Checklist

## Scope

Use this checklist to confirm the accepted architecture is in place and that the production boundary is not being overstated.

This checklist does not claim a production deployment.

## Verified Evidence (2026-08-12)

- GitHub plugin marketplace baseline `main` is `cc7300e90f69bf17dd23409698c3f65de522aaa6`. The production-audit topic worktree passed the complete configured local suite with `1050 passed` and `45 subtests passed`; this is implementation evidence, not a production deployment receipt.
- GitLab product CI protected `main` is `286009c5a86f18e70bbfe4ffaacc825085b1d26a` after the secure Runner1 provisioning bridge merge.
- The GitLab CI repository passed its current local suite with `246 tests`, `OK`, and `3 skipped`. The skips are Windows symlink-privilege cases; live-launcher, policy, bundle, trust, request-binding, and deployment tests were not skipped.
- Main pipeline `1927` passed Linux unit tests, Windows unit tests, Runner1 binary staging, and controlled fixture `CLEAN` and `BLOCKED` jobs. The protected `live_gate` remains manual and has not run.
- Pipeline `1927` job `5055` reached the restricted Runner1 credential handoff and then failed closed as `credential_wait_failed`; its artifact reports `ready=false`, `security_ready=false`, and `credential_cleanup_confirmed=false`. This is not production Runner evidence.
- Runner `20` is an online Windows/amd64 test Runner locked exclusively to project `59`, has `run_untagged=false`, `access_level=not_protected`, and carries only the non-production `windows` and `product-material-gate-ci-test` tags. Pipeline `1927` job `5049` passed on this Runner. It is valid test evidence and cannot run `live_gate`.
- Runner `2` provides Linux test and fixture evidence. It is not a production Runner.
- Runner `1` is an online protected Windows bootstrap plane but remains shared across signing and other projects. It may bootstrap the isolated Runner1 policy; it is not the final `live_gate` execution plane.
- Runner `8` is protected, locked, and project-exclusive, but it is not the operator-approved remote production host and does not carry the exact `product-material-gate-windows-runner1` identity/tag contract. It is not accepted for production evidence.
- Project `59` has the two protected OpenSSH bootstrap inputs. Production SVN retrieval, live request/handoff, deployment authority, report delivery, and dedicated Runner1 evidence are not yet provisioned or verified.
- The authoritative cloud-scan contract is the unauthenticated SVN Version Scan API at `POST /api/v1/scans` plus `GET /api/v1/scans/{scan_id}`. `PMG_CLOUD_SCAN_TOKEN` is neither required nor sent. Fixture coverage is complete; real protected-runner `CLEAN` and controlled `BLOCKED` evidence is still required.
- GitLab issues `#2` and `#3` were closed with current evidence: the ordinary production environment record is routing metadata rather than an authorization source, and Runner `20` satisfies the isolated Windows test-Runner contract. Issue `#1` remains open for real SVN/cloud-scan evidence and was corrected to forbid `PMG_CLOUD_SCAN_TOKEN`.
- The enterprise mailbox previously passed IMAP and SMTP login and exact Message-ID readback checks. Production report delivery must still be reverified under the final scheduler identity and locked dependency set.

## Explicitly Deferred

- Provision and attest the exact `product-material-gate-windows-runner1` service on the approved remote Windows host. The current retry must pair a fresh `provision_runner1` job ID with the restricted local credential feeder inside its bounded lease; no existing Runner currently satisfies the complete production identity contract.
- Install and attest the protected gate bundle built from authenticated `main`, then provision the locked live request, Runner configuration, SVN read-only retrieval boundary, TLS trust, and approval handoff.
- Execute one real protected `CLEAN` scan and one controlled protected `BLOCKED` scan against `/api/v1/scans`, preserving the scan IDs and GitLab/local receipt bindings.
- Complete release authorization, pre-production, canary, full production, final readback, production-report delivery/readback, and the four-stage rollback rehearsal. Production deployment is not complete until all of these receipts pass independent readback.
- Exercise the implemented `rd-flywheel.decision_role_source` path against the final live Feishu role document and preserve one hash-bound, multi-role Visual Companion/email governance receipt. Local contract, persistence, tamper, restart, and verifier tests are complete; the live role snapshot and decisions remain production evidence to collect.

## Architecture Acceptance

- [x] The four role plugins exist as separate responsibilities: `test-submission`, `submission-gate`, `pre-release`, and `release-gate`.
- [x] The first four role plugins embed `release_workflow_core`.
- [x] `product-release-gate` is the downstream authorization and deploy control plane, not a duplicate policy engine.
- [x] `release-approval` and `release-approval-verifier` implement the unified multi-role approval flow.
- [x] `rd-flywheel` owns capability-gap governance and checkpoint recovery.
- [x] `rd-flywheel` consumes the configured Feishu decision-role source and blocks on a verified multi-role governance-decision receipt before capability construction; live run-bound evidence is tracked separately below.
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

- [x] A real mailbox has passed baseline SMTP/IMAP access and exact Message-ID readback.
- [x] Feishu baseline document access has been verified; final role-snapshot and production audit writeback still require run-bound evidence below.
- [ ] GitLab/host SVN retrieval, deployment authority, live request/handoff, and report-delivery inputs are provisioned. No cloud-scan token is required or permitted.
- [ ] A new Windows/amd64 runner is registered exclusively to project `59`, bound to the protected `live_gate` tag, and online to accept release jobs.
- [ ] Any administrator approval required by the environment is complete.
- [x] Credentials are managed outside the docs and outside the workflow artifacts.

## Blocked-State Readiness

- [ ] The approved remote production host trusts the exact GitLab, SVN, and cloud-scan TLS chains, and the trust evidence has been read back from that host.
- [ ] The final Feishu role snapshot, required-role set, decision-page SHA-256, SMTP notifications, per-role page/email decisions, and aggregate governance receipt are bound to one `rd-flywheel` event and audit head.
- [ ] The final release-approval verifier output is independently rebound to the release request and cannot be reused as design-consent or cross-event authority.
- [ ] The SVN protected credential is bound and auditable without exposing the secret.
- [ ] GitLab readback proves the selected gate runner is Windows/amd64, protected, exclusive and locked to project `59`, unable to run untagged work, online/idle, and bound to the exact `live_gate` tag.
- [x] Repository provenance can be reconstructed from the frozen task, module, version, locator or path, fixed revision, and retrieval instructions.
- [ ] A non-skipped `live_gate` pipeline has produced job and artifact evidence and that evidence has been read back.
- [ ] Real `/api/v1/scans` `CLEAN` and controlled `BLOCKED` results are bound to their fixed SVN source/revision, scan IDs, and protected gate receipts.

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
