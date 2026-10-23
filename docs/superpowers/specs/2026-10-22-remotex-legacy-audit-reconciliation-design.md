# RemoteX Legacy Audit Reconciliation Repair

Status: approved in chat on 2026-10-22 for implementation, testing and release.
Real-store owner reconciliation remains a separate native action-time decision.
Baseline: RemoteX 0.7.1. All product text remains English.

## Problem And Exit Condition

An old reader can leave a valid integrity key without a recovery envelope.
Ordinary login and upgrade must continue to reject that layout. The upgrade
adapter also loses the specific missing-state diagnostic; that diagnostic-only
repair is within the previously approved design and is implemented locally.

The recovery inspector rejects every legacy task-binding digest because it
cannot recover historical origins/accounts. It additionally treats the old
site service's `completed` result as an unresolved write. Those records prove
technical completion, not business verification. Older synthetic integration
tests also used temporary recovery stores but appended to the shared default
audit file. Test isolation is already corrected in 0.7.1; the historical audit
must not be edited, deleted, or automatically labeled synthetic.

Exit condition: a genuinely eligible, idle key-only store can reach one native
owner reconciliation decision; after successful protected recovery, normal site
authorization can proceed. Recovery is not login acceptance.

## Explicit Policy Change Requiring Approval

The previous design blocks unexplained historical scope outright. This amendment
would permit the owner to reconcile *all* technically closed legacy history for
the exact shared store, including bindings whose historical origin/account is
unrecoverable. It does not invent those identities from today's configuration.

Likewise, a fully paired old `completed` action may enter owner review, but is
never automatically relabeled `verified`. The owner must affirm that its prior
effects have been reconciled. Neither a revoked grant nor a successful click is
business-result proof. If the owner cannot make that statement, recovery remains
blocked. This is a deliberate acceptance of missing-history risk, not a claim
that the old envelope was empty or all records were tests.

## Admission And Evidence

- Retain the valid 32-byte original key, absent-envelope, local non-reparse path,
  complete audit-chain validation, exact root/key identity and live idle checks.
- Correlate each operation and attempt by full recorded identity, not counts.
  For legacy site actions, require request, dispatch and terminal result with
  consistent binding and action, and a closed or provably expired grant.
- Distinguish `verified`, `failed-before-dispatch`, `completed-read`, and
  `completed-effect-requiring-owner-reconciliation`. Do not infer success from
  `operation-finish` alone or turn fill/click into read-only actions.
- Missing/duplicate/conflicting records, unknown event semantics, unmatched
  dispatch, `outcome-unknown`, partial verification, corrupt evidence, active or
  unknown lifecycle, and any existing pending write remain non-overridable.
- A request without any grant or dispatch is not a completed write. Include it
  explicitly in the review summary; it cannot stand in for a closed grant.
- Preserve every historical binding in the private evidence inventory. Show
  counts, time ranges, action categories, unresolved counts and unknown-scope
  warnings. Show configured scopes separately, never as historical attribution.
  Do not expose keys, credentials, cookies, raw bodies or credential hashes.

## Native Review And Commit

Keep the existing `remotex_web_authorization_recovery` API and private decision
channel; no force/reset flag, arbitrary root, supplied approval, or bypass mode.
Preview remains non-mutating and cannot grant site authority.

The native form must clearly show the historical-scope uncertainty and any
technically completed effects needing owner reconciliation. One initially
unchecked statement covers the exact digest-bound inventory. The operator then
clicks Recover Legacy State. Keep the original 180-second review deadline;
chat replies and stored receipts never substitute for that decision.

Retain the original-key private backup, no-overwrite initial v2 publication,
temporary deny-only marker, durable receipt/audit and final authenticated
readback. The receipt and backup record the inventory digest, category counts
and explicit owner-reconciled basis, without changing the standard v2 envelope.
Relevant new web activity invalidates the preview; unrelated append-only SSH/VM
activity does not. Interrupted recovery still needs a fresh native decision.

This transition cannot replay a historical action, verify a business result,
release someone else's queue, read a credential, or grant site automation.

## Bounded Implementation And Delivery

1. Retain the local upgrade-diagnostic repair and its real MCP regression tests.
2. Add regression fixtures for legacy paired history, unknown scopes and site
   completion semantics. Implement only the approved inspector, evidence and
   native-summary amendment; leave login, site permissions and business code
   unchanged.
3. Test orphan/unknown attempts, forged native frames, cancelled/expired review,
   changed evidence, mixed-version writers, no-overwrite races and interrupted
   finalization. Prove old bytes are preserved and `completed` is not rewritten
   to business verification. Use isolated temporary audit/state paths only.
4. Complete the changed candidate's required full suite, real independent review,
   synthetic native acceptance and exact-head Windows CI. Reuse unchanged prior
   evidence where valid; do not rerun the old candidate merely to repeat it.
5. After successful gates and release authorization, commit to
   YSheldon/ai-productivity-plugins, merge main and install the new release. Keep
   other consumers and their sessions untouched.
6. Read-only preview the real shared store again. Only if eligible, request its
   native owner window. After successful recovery readback, recheck the shared
   queue; acquire only when free and permitted. Validate the saved account's
   login and current-page reading under a separate site grant. No business
   writes, no preemption and no credential submission before all login gates.

## Decision Needed

Approve or reject the explicit policy change above and its bounded delivery.
Design approval does not attest that real historical effects are reconciled;
that separate statement must still be made in the native action-time window.
No real recovery has been performed by preparing this document.
