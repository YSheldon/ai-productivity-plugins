# RemoteX Legacy Key-Only Recovery Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for native execution in this chat after plan approval. Keep one real independent final review; do not create user-visible tasks or mandate subagent implementation.

**Goal:** Recover an eligible legacy key-only store through one explicit native owner review, without automatic reset or loss of uncertain-write protection.

**Architecture:** Add a local recovery coordinator beside the current authorization store. Reuse protected paths, the recovery lock, audit verification and private native IPC; use a separate recovery acknowledgment rather than granting site authority. Publish v2 with a temporary deny marker, then finalize only that marker after durable evidence.

**Tech Stack:** Existing Python 3.11+, Windows PowerShell/WinForms, Windows Job lifetime and standard-library cryptography/Win32 bindings. No new package dependency. Node.js 24+, Playwright Core 1.62.1 and jsonc-parser 3.3.1 remain unchanged.

**Spec:** `docs/superpowers/specs/2026-10-22-remotex-key-only-recovery-design.md`

## Global Constraints

- Proposed version is RemoteX 0.7.1; baseline main is adc10704c57224441b5d4b750800cd97d81c16cf.
- Implementation starts only after review of this plan, on codex/remotex-key-only-recovery from freshly verified main. Preserve unrelated/private files.
- All product/UI/documentation text is English. Do not change center business code.
- Preserve the 180-second native review, 12-hour site-grant cap and 30-second sensitive-action ticket.
- No real credential read/submission, queue claim/release or live recovery during automated testing.
- Recovery is local and grants no browser/site authority. No arbitrary paths, force flag or public approval field.
- A recovery receipt is evidence, never authority to clear or initialize state.
- Do not automatically migrate, rotate keys, reset pending records, or downgrade v2.

## Review Focus

1. Legitimate legacy key-only state versus lost/corrupt state: expose ambiguity, require owner review, and reject unsupported layouts (Task 1).
2. Old or competing writers creating state during review: recheck and publish without replacement (Task 2).
3. An extending/shared audit ledger: tolerate unrelated append-only activity, reject relevant or ambiguous changes, and never infer completion from counts (Task 1).
4. Native close/expiry, duplicate frames and process/thread failure: no synthetic grant or automatic retry; cancellation cannot undo a committed transition (Task 3).
5. Disk/ACL/readback failure around commit: retain v2/protective fence, never erase later pending writes or reinitialize from a receipt (Task 2).

## Existing Integration Points

- `plugins/remotex/src/web_authorization_store.py`: strict Journal.existing, canonical/MAC encoding, v1/v2 validation, recovery lock and conflict representations.
- `plugins/remotex/src/web_adapter.py`: state_root, read-only _upgrade_web_idle, precredential require_site_protocol, and tool registration.
- `plugins/remotex/src/web_approval.py`: private nonce/digest frames, Windows Job, native lifecycle receipts and original review deadline. Current acknowledgments are grant-oriented and must not be reused as a fake recovery grant.
- `plugins/remotex/src/audit_log.py`: _records/_verify_records verify existing evidence; _locked_file creates/adjusts files and is not a read-only preview API.
- `plugins/remotex/tests/fixtures/web_authorization_store_069.py`: frozen actual old implementation for compatibility tests.

## Task 1: Read-Only Evidence And Explicit Diagnostics

**Files**
- Create `plugins/remotex/src/web_recovery.py`.
- Create `plugins/remotex/tests/test_web_recovery.py`.
- Modify `plugins/remotex/src/web_adapter.py` only for specific missing-state diagnostics after the coordinator is available.

**Interfaces**

```python
@dataclass(frozen=True)
class LegacyEvidence:
    mode: Literal['initialize', 'finalize']
    root: Path
    key_identity: tuple[int, int, int, int]
    ledger_identity: tuple[int, int]
    ledger_size: int
    ledger_checkpoint: str
    scope_digest: str
    summary: dict[str, Any]

# All return data remains server-private until formatted by public_summary.
inspect_legacy_state(root, *, audit_path, scope, check_idle) -> LegacyEvidence
inspect_interrupted_recovery(root, recovery_id, *, audit_path, scope, check_idle) -> LegacyEvidence
recheck_legacy_evidence(evidence, *, audit_path, scope, check_idle) -> None
public_summary(evidence) -> dict[str, Any]
```

key_identity means device/file identity, size and modification time, not a hash
of key bytes. scope is the sanitized complete web-profile/history scope list.
ledger_checkpoint stays private. ScopeError uses fixed codes only.

- [ ] Write failing tests for actual old key-only initialization; preview byte/permission preservation; valid existing v1/v2; missing or invalid key; broken MAC/ledger; reparse/network paths; unmatched/unknown writes; and incomplete audit records.

```python
def test_key_only_preview_is_not_proof_of_empty_history(legacy_store, ledger):
    before = snapshot_bytes(legacy_store.root)
    evidence = inspect_legacy_state(
        legacy_store.root, audit_path=ledger, scope=WEB_SCOPE,
        check_idle=lambda: True,
    )
    public = public_summary(evidence)
    assert public['historyBasis'] == 'owner-review-required'
    assert public['classification'] == 'key-only-ambiguous'
    assert snapshot_bytes(legacy_store.root) == before
    assert not legacy_store.state_path.exists()
```

Test-local legacy_store loads the frozen fixture through importlib; ledger
contains verified synthetic records; WEB_SCOPE uses console.example/operator;
snapshot_bytes returns relative-file-name to byte-content for that owned temp
directory. Define these fixtures/helpers in the same test module, not production.

- [ ] Run `python -m pytest -q plugins/remotex/tests/test_web_recovery.py --tb=short`; observe missing-module/API failures.
- [ ] Implement read-only inspection without constructing initializing Journal or taking audit writer/queue locks. Verify a captured complete ledger prefix and pair attempts by identity, not aggregate count.
- [ ] Implement fixed errors: recovery-state-missing, recovery-key-invalid, recovery-evidence-invalid, recovery-unresolved-write, recovery-scope-unknown, recovery-busy and recovery-stale. Do not label corrupt state as legacy state.
- [ ] Add tests that unrelated SSH/VM append-only records do not change relevant evidence, while new relevant web activity, changed scope/key/root, truncated prefix or incomplete append blocks/requires new preview.
- [ ] Add an MCP-level preview test with an isolated audit file; recovery material stays unchanged even though normal invocation metadata is audited.
- [ ] Run the complete new evidence suite and existing authorization-store/upgrade tests. Commit this independently testable inspection change only after its tests pass.

## Task 2: Protected Commit, No-Replace Publish And Crash Fence

**Files**
- Modify `plugins/remotex/src/web_authorization_store.py`.
- Extend `plugins/remotex/src/web_recovery.py`.
- Extend `plugins/remotex/tests/test_web_recovery.py`.

**Interfaces**

```python
# Private backend function; no public tool maps directly to this function.
recover_key_only_v2(
    evidence, *, recovery_id, before_publish, backup_root
) -> dict[str, Any]
finalize_recovery_v2(
    evidence, *, recovery_id, before_publish
) -> dict[str, Any]

# before_publish is a trusted live-coordinator callback. It checks the original
# native decision/deadline/cancel state and fresh evidence under the store lock.
# Public arguments can never supply or replace it.
read_recovery_status(root, recovery_id) -> dict[str, Any]
```

- [ ] Add failing tests for unchanged key bytes, owner-private backup, existing destination, an old writer winning either side of the lock, deadline/cancel during preparation, and no queue/resource lock acquisition under the recovery lock.

```python
def test_crash_after_publish_leaves_existing_070_writers_fenced(recovery_case):
    recovery_case.fail_at('after_publish')
    result = recovery_case.commit_from_private_native_decision()
    assert result['state'] == 'committed-unverified'
    current = Journal(recovery_case.root)
    assert current._load()['version'] == 2
    with pytest.raises(ScopeError, match='unresolved-prior-write'):
        current.reserve_site('b' * 32, 'https://console.example')
    assert recovery_case.original_key_unchanged()
```

recovery_case is a test-only coordinator fixture with a fake private prompt and
named I/O fault injection; it is explicitly not human-approval evidence.
Its fail_at(point) installs a monkeypatch at the named internal I/O boundary;
commit_from_private_native_decision() invokes the coordinator's private callback
using its fake prompt manifest; original_key_unchanged() compares test-owned key
bytes without printing or returning them through a public tool.

- [ ] Run the new cases RED before implementing the commit helper.
- [ ] Under the existing exclusive recovery lock, recheck key-only layout, key identity, idle lifecycle and trusted before_publish callback. Never acquire queue/lease/resource-operation locks in this region.
- [ ] Create a protected local backup/receipt after native review. Preserve the original key in place. Backup key/evidence privately; record the lock's metadata without reading its held lock byte. No backup or raw record enters the repo/chat.
- [ ] Encode standard v2 state with one temporary reservation: pending[recovery_id] contains the existing HMAC of SITE_SESSION_CONFLICT. Do not invent a new envelope schema.
- [ ] Stage a private same-directory file, fsync it, recheck the decision and absent destination, then publish through MoveFileExW with flag 0x8 only. Do not set replace, copy-across-volume or reboot flags; no fallback overwrites a destination. On unsupported publication, keep the old layout and report failure.
- [ ] Add a real Windows test that creates the destination immediately before publish and proves its bytes are preserved. Validate Win32 argument/return/error handling independently from mocks.
- [ ] Authenticate readback and persist owner-reviewed audit/receipt before removing only the technical marker. Domain-separate the receipt with kind=legacy-key-only-recovery-receipt-v1; store no live native nonce. Persist the verified/finalization-intent phase before marker removal, and derive completion from receipt plus authenticated state. Keep the original deadline through finalization. Do not call public Journal.resolve recursively while holding its lock.
- [ ] Make the final marker removal the last required durable state transition; infer its result by authenticated readback. Failure after publication never restores v1. Do not claim the marker remains if readback itself is unavailable.
- [ ] Status/repeated requests must not reinitialize. An interrupted technical marker requires a fresh native review plus authenticated ownership receipt; missing receipt, another pending entry or ambiguous ownership blocks finalization.
- [ ] On a restarted MCP, allow read-only reconstruction of a finalize-mode preview from authenticated receipt/state, never from a bare caller ID. The new native nonce/deadline is independent of the original review. finalize_recovery_v2 removes only its exact technical marker and never republishes an empty envelope. An already resolved marker returns status without writes; later business reservations remain untouched.
- [ ] Test all pre/post-publication failure points, repeated IDs, missing receipt, marker corruption, later real pending entries, and actual old 0.6.9 rejection of v2. Run store, upgrade, broker and site-service regression before committing.

## Task 3: Recovery-Specific Native Review And One Public Entry Point

**Files**
- Extend `plugins/remotex/src/web_recovery.py` with RecoveryService.
- Modify `plugins/remotex/src/web_approval.py` for recovery-specific transport behavior.
- Create `plugins/remotex/scripts/web_recovery_approval.ps1`.
- Modify `plugins/remotex/src/web_adapter.py` for one new tool.
- Create `plugins/remotex/tests/test_web_recovery_approval.py`.
- Extend `plugins/remotex/tests/test_web_recovery.py` and `test_mcp_protocol.py`.

**Interfaces**

```python
RecoveryService.preview() -> dict[str, Any]
RecoveryService.open(recovery_id: str) -> dict[str, Any]
RecoveryService.status(recovery_id: str) -> dict[str, Any]
RecoveryService.cancel() -> None
RecoveryPrompt.start(manifest, *, on_decision, on_revoke, on_cancel)

# Public schema: confirm:boolean (default false), recovery_id:32-hex (optional).
# No approved/force/root/path/key/cookie/password fields.
remotex_web_authorization_recovery(confirm=False, recovery_id=None)
```

- [ ] Add RED tests for public confirmation requesting a window but never approving, unknown IDs, stale evidence, repeated open, one pending per process, forged/duplicate nonce/digest frames and cancellation.

```python
def test_confirm_argument_cannot_recover_without_native_decision(service_case):
    preview = service_case.service.preview()
    opened = service_case.service.open(preview['recovery_id'])
    assert opened['state'] == 'pending'
    assert not service_case.state_path.exists()
    assert service_case.prompt_count == 1
```

- [ ] Implement the live in-memory registry and private one-use decision binding. A disk receipt is never accepted as new authority. Repeated open/status does not reset the 180-second deadline or automatically reopen a form.
- [ ] Give recovery private frames their own strict schema: decision carries owner_reviewed=true, request_id, nonce and request_digest, not choices/ttl_seconds. These fields exist only on inherited IPC; public arguments reject owner_reviewed or other approval fields. Decode grant-oriented frames exactly as before in site/granular modes.
- [ ] Reuse ApprovalPrompt framing, protected PowerShell environment and Windows Job lifetime through a recovery-specific prompt variant. Do not return a fake grant_id, start a grant-expiry timer, or invoke rollback from on_revoke after a committed recovery.
- [ ] Add `-DescribeProtocol` returning exactly `{"legacy_recovery":1,"review_seconds":180}`; probe the actual helper before opening it.
- [ ] Implement the English native form: target/scopes/evidence/uncertainty, one unchecked owner statement, Recover Legacy State, Cancel and original countdown. No categories, JSON import or password field. A known hard block cannot be overridden by checking the box.
- [ ] Add recovery-result acknowledgment and recovery-complete lifecycle receipt only for recovery mode. Display success only after committed backend acknowledgment; close the completed form without undoing data. Preserve site/granular close/revoke behavior byte-for-byte where possible.
- [ ] Cover stdin EOF, helper launch/job failure, cleanup-thread failure, expiry during fsync, cancel/commit ordering and repeated clicks. Never add synchronous prompt-lock fallback.
- [ ] Run native shown/expiry smoke without making a decision, then the existing site/action/v3 native transport suites. Run one manual synthetic recovery only after the operator confirms readiness; no automated human decision.
- [ ] Verify after synthetic recovery that ordinary site approval remains separate, and the existing synthetic login/read/save flow works with the new standard v2 state.
- [ ] Commit only after focused Python/Node/native regressions and real independent review pass.

## Task 4: Release, Install And Controlled Operational Handoff

**Files**
- Update RemoteX Codex/Cursor manifests, server version, marketplace version entry and version assertions to 0.7.1.
- Update `plugins/remotex/docs/web-site-authorization.md`, plugin README/skill, root CHANGELOG, installation guide and generated catalog.
- Keep all examples synthetic and English. Do not include local accounts, private IPs, keys or audit data in public docs.

- [ ] Document specific missing-state diagnostics, one-time owner-review uncertainty, no automatic reset, receipt-only status, interrupted finalization and normal one-click site use afterward.
- [ ] Run `python scripts/project_docs.py --write` then `--check`; review generated changes and `git diff --check`.
- [ ] Run the entire repository suite with native checks and strict startup-budget flag, manual approval flags unset, and an isolated REMOTEX_AUDIT_FILE. Save unique logs/JUnit; no stale result or skipped failing test counts as a pass.
- [ ] Preserve the known unrelated release-approval asynchronous SHA race if encountered. Investigate and report it; do not edit an unrelated plugin or waive the suite merely to publish RemoteX.
- [ ] Obtain required independent final review. Fix within approval; retained human review applies after three failed corrective attempts.
- [ ] Verify repository/feature branch/remote refs and exact staged files. Commit and push only the feature branch; create/attach a new PR rather than editing merged PR #54.
- [ ] Await exact-candidate Windows CI, verify JUnit/zero failures and merge gates, then apply the user's selected merge/install path only when its authority remains applicable.
- [ ] Compare merged tree with the tested tree. Install through the native target command; if full marketplace clone times out, inspect the clean managed snapshot before an ff-only cache refresh. Never reset user changes or stop active consumers.
- [ ] Verify installed tracked blobs, manifest/server version, new recovery tool, actual helper descriptor and pinned dependencies via an isolated MCP probe. Distinguish disk install, loaded tools and real recovery.
- [ ] Before any real data recovery, refresh the preview and operator evidence, confirm all web sessions naturally finished, and obtain a fresh local native decision. Do not treat plan approval as that decision.
- [ ] Do not start production web probe/login until the host's supported browser read succeeds and the task owns a covering queue lease. Perform only the already authorized login/read acceptance; no business write or preemption.

## Completion Evidence

- Code/source and publication: feature commit, candidate CI, merged tree/commit.
- Installation: native result, full tracked-file comparison, loaded protocol and dependencies.
- Recovery: owner-reviewed basis, protected backup/receipt, authenticated v2 and removal of only its temporary marker.
- Authentication: separate supported-browser, queue, login and page-read evidence.
- Any unavailable stage remains explicitly pending; a successful previous stage is not evidence for it.
