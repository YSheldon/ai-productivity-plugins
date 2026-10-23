# RemoteX Legacy Audit Reconciliation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline. The user has
> approved the bounded implementation and delivery in this session.

**Goal:** Reach a legitimate native recovery preview for complete legacy history,
then restore the separately authorized login/read workflow without resetting data.

**Architecture:** A pure history reconciler classifies verified ledger records;
the existing recovery service owns live decisions and protected state publication.
The native form distinguishes recorded technical results from owner reconciliation.

**Tech Stack:** Python, pytest, Windows PowerShell/WinForms, existing Edge fixture.

**Spec:** `docs/superpowers/specs/2026-10-22-remotex-legacy-audit-reconciliation-design.md`

## Global Constraints

- Keep the original key and full audit; never replace an appearing envelope.
- No unknown outcomes, unfinished dispatch, corrupt evidence or active lifecycle.
- Keep 180-second native review, 12-hour site cap and 30-second sensitive ticket.
- No credentials, queue mutation, remote requests or site grants during recovery.
- Preserve ordinary login/upgrade fail-closed behavior and standard v2 envelope.
- All product/UI/documentation text remains English; no business-specific code.
- Commit/release only after required tests, independent review and native acceptance.

## Review Focus

- Cross-binding/session collisions must not let one result close another attempt.
- A revoked grant must not erase an unknown result or an unfinished network effect.
- Unknown scope and ungranted requests must remain visible, never inferred as tests.
- An old authenticated receipt must not acquire a new policy basis after restart.
- Wall-clock expiry cannot accept malformed timestamps, invalid TTL or future grants.

## Task 1: Diagnostic And History Reconciler

Files: `plugins/remotex/src/web_adapter.py`, new
`plugins/remotex/src/web_recovery_history.py`, `plugins/remotex/src/web_recovery.py`,
`plugins/remotex/tests/test_web_authorization_upgrade.py`,
`plugins/remotex/tests/test_web_recovery.py`, new
`plugins/remotex/tests/test_web_recovery_history.py`.

Interface: `observe(records, scope, *, now=None)` returns `(summary, inventory)`;
inventory is private evidence, never authority. `LegacyEvidence` binds it to the
existing root/key/ledger/scope snapshot. Keep public recovery arguments unchanged.

- [x] Add MCP missing-state/invalid-key/corrupt-envelope tests; observe seven REDs.
- [x] Fix the adapter diagnostic without storage mutation; targeted 123 tests pass.
- [x] Add a hand-built ledger with request/grant/requested/dispatch/result/revoke.
  Assert `completed` reads and effects are separate and scope remains unknown.
- [x] Add literal malformed cases: missing/duplicate identity, conflicting action,
  orphan finish, unknown result, active grant, invalid/future timestamp and TTL.
  Assert they cannot yield an eligible preview or create a state file.
- [x] Run RED: `python -m pytest plugins/remotex/tests/test_web_recovery_history.py -q`.
- [x] Implement the pure classifier and attach its inventory to recovery evidence.
  Record original event states, full attempt identities, time ranges and counts;
  do not infer historical origin/account or business verification.
- [x] Run history, recovery, credential and MCP tests; inspect every failure.

## Task 2: Native Summary And Durable Reconciliation Basis

Files: `plugins/remotex/src/web_recovery.py`,
`plugins/remotex/scripts/web_recovery_approval.ps1`,
`plugins/remotex/tests/test_web_recovery.py`,
`plugins/remotex/tests/test_web_approval_ui.py`,
`plugins/remotex/tests/test_web_site_integration.py`.

Interface: a new receipt kind binds the inventory digest/counts and explicit
owner-reconciled basis. Accept old receipts only under their original strict
history rules; never reuse them to authorize the amended policy.

- [x] Add RED tests for inventory binding, old receipt compatibility, restart,
  forged/expired/cancelled decision and unchanged original audit records.
- [x] Save the private inventory in backup evidence and authenticated receipt;
  recheck continuity before publication/finalization. Keep v2 state unchanged.
- [x] Show configured scopes separately, unknown-scope counts, technical read and
  effect counts, and the owner's reconciliation responsibility in the native form.
- [x] Run existing native protocol/notification/cleanup tests. Extend the isolated
  synthetic acceptance to include paired legacy history, then request one actual
  recovery decision and one separate Allow Automation decision using fake data.

## Task 3: Release And Real Acceptance

Files: RemoteX version manifests, skill/docs, generated project catalog/changelog.

- [x] Document the new eligibility and risks, update the patch version and run
  `python scripts/project_docs.py --check` plus `git diff --check`.
- [x] Run the changed candidate's complete `python -m pytest -q --tb=short
  --junitxml=artifacts/remotex-recovery/full-local-reconciliation-final-1.xml` once green.
- [x] Obtain one real independent whole-change review; fix findings with RED/GREEN
  and applicable final-suite evidence. Preserve existing artifacts and other edits.
- [ ] Complete native synthetic acceptance, commit scoped files, push the feature
  branch and open a PR. Require successful exact-head Windows CI before merge.
- [ ] Merge main and install the same verified release without interrupting other
  consumers. Verify installed source hashes, version and actual tool loading.
- [ ] Read-only preview real recovery; if eligible and idle, request its local
  owner confirmation. Verify protected readback before checking/acquiring a free
  queue and requesting a separate site grant. Validate login and page reading
  only; do not perform any real business write or preempt another requester.
