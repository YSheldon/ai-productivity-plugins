# Product Material Release Acceptance Checklist

## Scope

Use this checklist to confirm the accepted architecture is in place and that the production boundary is not being overstated.

This checklist does not claim a production deployment.

## Verified Evidence (2026-08-07)

- GitHub plugin marketplace `main` was refreshed at `6e8cf1cd4d7ccde19870d9ae2bd32d0225ea9cea`. The complete configured test suite passed locally with `992 passed` and `45 subtests passed`.
- GitLab product CI merge request `!24` passed its merge-request pipeline `1919` and was merged to protected `main` as `84f2161c6c7d6da9b8e14c7132a7f414e9fa1d88`.
- The GitLab CI repository passed locally with `242 passed`, `3 skipped`, and `39 subtests passed`. The three skips are Windows symlink-privilege cases; live-launcher, policy, bundle, trust, request-binding, and deployment tests were not skipped.
- Main pipeline `1921` passed Linux unit tests, Windows unit tests, Runner1 binary staging, and controlled fixture `CLEAN` and `BLOCKED` jobs. It is waiting only on the three expected manual production jobs: Runner1 OpenSSH bootstrap, Runner1 install/provisioning, and `live_gate`.
- Runner `20` is an online Windows/amd64 test Runner locked exclusively to project `59`, has `run_untagged=false`, and carries only the non-production `windows` and `product-material-gate-ci-test` tags. It is valid test evidence and cannot run `live_gate`.
- Runner `2` provides Linux test and fixture evidence. It is not a production Runner.
- Runner `1` is an online protected Windows bootstrap plane but remains shared across signing and other projects. It may bootstrap the isolated Runner1 policy; it is not the final `live_gate` execution plane.
- Runner `8` is protected, locked, and project-exclusive, but it is not the operator-approved remote production host and does not carry the exact `product-material-gate-windows-runner1` identity/tag contract. It is not accepted for production evidence.
- Project `59` has the two protected OpenSSH bootstrap inputs. Production SVN retrieval, live request/handoff, deployment authority, report delivery, and dedicated Runner1 evidence are not yet provisioned or verified.
- The authoritative cloud-scan contract is the unauthenticated SVN Version Scan API at `POST /api/v1/scans` plus `GET /api/v1/scans/{scan_id}`. `PMG_CLOUD_SCAN_TOKEN` is neither required nor sent. Fixture coverage is complete; real protected-runner `CLEAN` and controlled `BLOCKED` evidence is still required.
- The enterprise mailbox previously passed IMAP and SMTP login and exact Message-ID readback checks. Production report delivery must still be reverified under the final scheduler identity and locked dependency set.

## Explicitly Deferred

- Provision and attest the exact `product-material-gate-windows-runner1` service on the approved remote Windows host; no existing Runner currently satisfies that complete identity contract.
- Install and attest the protected gate bundle built from authenticated `main`, then provision the locked live request, Runner configuration, SVN read-only retrieval boundary, TLS trust, and approval handoff.
- Execute one real protected `CLEAN` scan and one controlled protected `BLOCKED` scan against `/api/v1/scans`, preserving the scan IDs and GitLab/local receipt bindings.
- Complete release authorization, pre-production, canary, full production, final readback, production-report delivery/readback, and the four-stage rollback rehearsal. Production deployment is not complete until all of these receipts pass independent readback.

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
- [ ] GitLab/host SVN retrieval, deployment authority, live request/handoff, and report-delivery inputs are provisioned. No cloud-scan token is required or permitted.
- [ ] A new Windows/amd64 runner is registered exclusively to project `59`, bound to the protected `live_gate` tag, and online to accept release jobs.
- [ ] Any administrator approval required by the environment is complete.
- [x] Credentials are managed outside the docs and outside the workflow artifacts.

## Blocked-State Readiness

- [ ] The approved remote production host trusts the exact GitLab, SVN, and cloud-scan TLS chains, and the trust evidence has been read back from that host.
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
