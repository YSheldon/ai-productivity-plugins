# Product Material Release Operations Runbook

## Purpose

Use this runbook to operate the accepted product-material release flow without confusing readiness, approval, deployment, or readback.

This runbook describes the control path only. It does not claim a production deployment.

## Before You Start

Confirm the external prerequisites first:

- Mailbox access is configured and can read and send the required subjects.
- Feishu writeback and cloud readback are available.
- GitLab project access, protected variables, and runners are available.
- The operator has the right role and mailbox identity.
- The relevant plugin is installed with its dependency set already resolved.

If any of those are missing, stop and treat the event as blocked or capability-limited. Do not paper over the gap with a manual email, a green job exit, or a subject match.

## Routine Operating Loop

| Role | Routine action | Success evidence | Block if |
| --- | --- | --- | --- |
| `test-submission` | Gather submission details, validate local artifacts, and send `【提测】`. | Submission manifest, event ID, and sent mail record. | Artifact missing, digest mismatch, or preflight failure. |
| `submission-gate` | Read submission mail and run authoritative gate checks. | Gate result, evidence bundle, and reply mail. | Any required check fails or evidence is incomplete. |
| `pre-release` | Aggregate test results and send `【发布门禁检查】`. | Test summary, Manifest-R draft, and mail record. | Test result is not final, or the approved artifact set drifts. |
| `release-gate` | Read pre-release mail and emit `【发布申请】`. | Release gate result and request mail. | Missing gate evidence, manifest drift, or policy violation. |
| `release-approval` | Capture per-role decisions from a page or thread reply. | Decision event and thread evidence. | Missing thread headers, role mismatch, or bad digest binding. |
| `release-approval-verifier` | Normalize, verify, and aggregate all role decisions. | Verified receipt and a single handoff event. | Any role is missing, expired, quarantined, or conflicted. |
| `product-release-gate` | Authorize and execute preproduction, canary, full production, and readback. | Authorization receipt, stage receipts, rollback receipts, and readback evidence. | Any stage failure, readback mismatch, or invalid claimed auth. |
| `rd-flywheel` | Manage capability gaps and replay from frozen checkpoints. | Capability event and recovery evidence. | The missing capability cannot be built or verified safely. |

## Daily Checks

1. Confirm the plugin is reading the intended single config source.
2. Confirm the scheduler is idle or on the expected interval.
3. Confirm mail identity and folder bindings have not changed.
4. Confirm Feishu writeback and readback both work.
5. Confirm GitLab evidence is being produced and read back.
6. Confirm `event_id` and `round_id` are stable across replays.
7. Confirm no duplicate mail, duplicate decision, or duplicate handoff has been recorded.

## Blocked-State Runbook

Use this runbook when the path is blocked before or during production readiness.

| Blocker | What to verify | Required outcome | Do not do |
| --- | --- | --- | --- |
| CA trust | Root and intermediate CA chain, local trust store, and certificate chain readback. | The host trusts the expected CA chain and the check is recorded. | Do not bypass with ad-hoc pinning or a one-off trusted-host exception. |
| SVN protected credential | Protected credential binding, sender identity, and retrieval instructions. | The sender can prove the protected credential without exposing the secret. | Do not paste the secret into mail, docs, or chat. |
| Protected GitLab runner | Runner protection, project binding, and branch or tag restrictions. | The job runs only on the protected runner that matches the release policy. | Do not fall back to an unprotected runner for release evidence. |
| Repository provenance | Task, module, version, locator or path, fixed revision, and retrieval instructions. | The request can be retrieved and audited from the frozen provenance set. | Do not require file lists, hashes, signatures, or cloud mirrors as mandatory fields. |
| CI evidence | Pipeline, job, and artifact references plus readback. | The CI trail is visible and repeatable from the recorded IDs. | Do not treat a green local run as CI evidence. |

## Failure Handling

### Missing Capability

If a required integration is absent, set the event to `CAPABILITY_BLOCKED` and preserve the original checkpoint. Do not auto-promote a blocked event to success.

### Gate Failure

If a gate result fails, stop the current path, record the failure evidence, and send the appropriate blocked mail only. Do not send the next-stage success mail.

### Identity or Thread Failure

If mail identity, thread headers, or digest binding do not match the frozen request, quarantine the message and do not count it as a valid decision.

### Duplicate Input

If the same UID, Message-ID, page submission, or decision is replayed, treat it as an idempotent repeat. Record the repeat, but do not create a second business event.

## Evidence to Preserve

Keep the following together for each event:

- `event_id` and `round_id`.
- Mail `Message-ID`, `In-Reply-To`, `References`, UID, and UIDVALIDITY.
- Manifest-S or Manifest-R digest.
- Feishu document link and readback proof.
- GitLab pipeline, job, and artifact references.
- Deployment stage receipts, rollback receipts, and readback receipts.
- Any `CAPABILITY_BLOCKED` checkpoint and the reason it was frozen.

## When to Escalate

Escalate to `rd-flywheel` when the blocker is a missing capability, missing adapter, or a repeat failure that requires recovery planning.

Escalate to the system owner when the blocker is external:

- mailbox ownership.
- Feishu permissions.
- GitLab project access.
- protected variables or runner access.
- production deployment authority.
