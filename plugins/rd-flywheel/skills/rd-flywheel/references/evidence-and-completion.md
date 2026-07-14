# Evidence and Completion Contract

## Authoritative States

Primary lifecycle:

`DISCOVERED -> CONTRACTED -> FIRST_PRACTICE -> BUILT -> VERIFIED -> AUTHORIZED -> DEPLOYED -> OBSERVED -> HARVESTED -> CLOSED`

Capability branch:

`CAPABILITY_BLOCKED -> CAPABILITY_CONTRACTED -> CAPABILITY_BUILT -> CAPABILITY_VERIFIED -> CAPABILITY_REGISTERED -> RESUME_CHECKPOINT`

Failures do not erase prior events. Fixes create a new input or manifest revision. Replaying an idempotency key must not repeat a side effect.

## Evidence Envelope

Every gate or deployment observation retains event, revision, stage, check, canonical input hash, policy hash, target identity, tool version, PASS/FAIL/ERROR/UNSUPPORTED result, raw evidence location and hash, observed time, expiry, idempotency key, operation identifier, attestation, and compensation reference when applicable.

AI explanations may annotate evidence but never determine PASS.

## Fail-Closed Rules

- Missing, stale, malformed, mismatched, ERROR, or UNSUPPORTED evidence blocks the transition.
- Authorization binds frozen output, policy, deployment plan, and rollback plan. Drift revokes it.
- A missing capability starts the capability branch. Approval cannot waive an absent required detector.
- Code automation may merge a verified capability; credential issuance and permission expansion require external authority.
- On restart, reconcile tool-reported reality before retrying or compensating.

## Separate Proof Surfaces

Report each independently: authoritative source sync, local artifact, test evidence, policy gate, design decision, approval, cloud document, deployed target, health observation, rollback proof, outbound notification, and mailbox/readback evidence.

## Completion Levels

- **Built:** implementation and tests exist.
- **Verified:** the real or representative case passes gates and failure scenarios.
- **Production deployed:** authorized bits are present on the designated production target and health observation passes.
- **Closed:** production evidence, rollback availability, external readbacks, risk audit, and reusable experience harvest are complete.

Never downgrade the requested completion level to match available evidence. If a production target or authority is unavailable, state that production remains unproved.
