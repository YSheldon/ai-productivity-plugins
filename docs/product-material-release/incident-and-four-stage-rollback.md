# Incident Handling and Four-Stage Rollback

## Scope

This guide covers failures in the downstream deployment chain after `【发布申请】` has already been produced and verified.

It does not claim that the production environment is active.

## Incident Classes

Treat the following as incidents:

- missing or mismatched mail identity evidence.
- invalid claimed auth, compliant-plugin badge mismatch, or a claim that cannot be verified against the local private identity.
- missing Feishu writeback or readback.
- missing GitLab pipeline, job, or artifact evidence.
- approval mismatch or approval expiry.
- `CAPABILITY_BLOCKED` recovery requirement.
- preproduction, canary, full production, or readback failure.
- any digest mismatch across the frozen event chain.

## Immediate Response

1. Stop the current advancement path.
2. Preserve the frozen `event_id`, `round_id`, and artifact digests.
3. Record the failing stage, auth state, and the exact evidence that failed.
4. Quarantine duplicate or ambiguous mail inputs.
5. Send only the blocked or incident notice required by the workflow.
6. If the blocker is a missing capability, hand the checkpoint to `rd-flywheel`.

Do not move to the next stage until the current stage has either passed or been rolled back.

## Four-Stage Rollback Model

| Stage | Normal role | Rollback expectation | Evidence to keep |
| --- | --- | --- | --- |
| Preproduction | First production rehearsal stage. | Revert the preproduction change set and keep later stages untouched. | Deployment receipt, rollback receipt, and stage verification. |
| Canary | Partial exposure stage. | Remove the canary change and preserve the preproduction outcome. | Canary receipt, rollback receipt, and observation log. |
| Full production | Final production rollout stage. | Restore the prior production state and stop further rollout. | Full rollout receipt, rollback receipt, and operator acknowledgment. |
| Readback | Truth-check stage. | If readback fails, roll back the full production stage and treat the readback as a production truth failure. | Readback receipt, observed digest, and rollback trace. |

Rollback is stage-specific. A failure in one stage does not erase earlier successful evidence, but it does block the release from being treated as complete.

## Common Failure Responses

### Evidence Missing

If the stage cannot prove what happened, assume the stage did not pass. Keep the checkpoint and block advancement.

### Digest Mismatch

If the observed manifest digest or artifact digest does not match the frozen digest, treat the current state as invalid and roll back the current stage.

### Approval Drift

If approval evidence no longer matches the frozen role snapshot or message thread, stop the release and quarantine the new evidence.

### Capability Gap

If the failure is caused by a missing connector, adapter, or permission, do not improvise a bypass. Record the gap and let `rd-flywheel` manage the recovery path.

### Authorization or Badge Mismatch

If a claimed auth cannot be verified, or the compliant-plugin badge does not match the frozen identity, treat the claim as invalid and block advancement. Missing auth stays unverified; it is not by itself proof of compromise.

## Evidence Packet for Incidents

For every incident, preserve:

- `event_id` and `round_id`.
- the failed stage name.
- the failing digest or message reference.
- the rollback reference, if any.
- the auth state and identity evidence, if relevant.
- the Feishu and GitLab references tied to the incident.
- the blocked or quarantined mail reference, if applicable.
- the `rd-flywheel` checkpoint, if a capability gap was involved.

## Recovery Rule

After rollback, recovery must begin from the last valid checkpoint, not from a rewritten history. If the release material changed materially, create a new round and re-run the upstream gates.
