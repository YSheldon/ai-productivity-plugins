# RemoteX Task Authorization Implementation Plan

> For agentic workers: use `superpowers:executing-plans` in this session. Track
> red/green evidence and delivery state in the scoped progress ledger.

**Goal:** Implement human-approved, bounded web read/write tasks, publish and
install the tested release, then validate the existing center profile through
approval/readback and stop at a concrete real-write preview for human confirmation.

**Architecture:** The original MCP supervisor owns a Python authorization broker
and private native approval helpers. The existing Edge worker retains DOM
references and typed actions, and consults the broker before network forwarding.
An independent cancellation path remains usable during blocked command/audit work.

**Tech stack:** Python 3, Node.js 24+, existing Playwright Core 1.62.1, Windows
PowerShell 5.1/WinForms, existing RemoteX protected storage, queue and audit APIs.

**Spec:** [Approved protocol revision 2](../specs/2026-10-17-remotex-task-authorization-protocol.md)

## Global Constraints

- Preserve exact origin/account/TLS/pin checks, supported host browser access,
  original session/process ownership, credential isolation and queue fairness.
- No center business-code changes, raw HTTP tools, arbitrary scripts/selectors,
  portable authority tokens, auto-approval flags or credential-value arguments.
- Batch limit 32 items/32 KiB; TTL 60-900 seconds/default 300; current session and
  covering queue lease cap every grant; requested authority cannot self-approve.
- Only the design-approved scope may be implemented. Passing local/CI/package,
  publication, installation and real-site acceptance are separate evidence.
- Real business writes remain pending until the user confirms actual target IDs
  and a concrete before/after preview; a native grant is also required.
- Keep all repository documentation English and private environment data local.
- Preserve unrelated dirty generated files and the earlier uncommitted tests.

## Review Focus

1. Same-user cooperative human approval must not be described as OS-grade isolation.
2. Request/response/audit cancellation races must not resurrect authority or output.
3. Partial approval must narrow target/request effects, not only UI selections.
4. A changed key/session/value must not bypass an unresolved dispatched write.
5. Old APIs and login/background requests must not bypass the approval gate.

## Task 1: Immutable Scope, Broker and Deny-only Recovery Store

Files: create `plugins/remotex/src/web_authorization.py` and
`plugins/remotex/tests/test_web_authorization.py`.

Interfaces: `Broker(binding, journal, check, close, clock)` owns `request`,
`accept_decision`, `status`, `reserve`, `finish`, `release_output`, `revoke` and
`execution_status`. `ScopeError.code` supplies sanitized stable failures.
`Journal` persists only keyed metadata/uncertainty fences, never executable grants.

- [ ] Write tests before code for unsigned decisions, batch dependency cycles,
  partial target approval, reduced quotas/TTL, exact idempotency, expiry/revoke,
  concurrent budget reservation, cross-binding reuse, and key/value/session changes
  blocked by an unresolved write.
- [ ] Run `py -3 -m pytest plugins/remotex/tests/test_web_authorization.py -q`;
  verify failures describe absent broker behavior.
- [ ] Implement strict canonical schemas and hash bindings; use monotonic active
  deadlines and a separate one-way emergency fence around slow durable writes.
- [ ] Exercise the real broker with a temporary journal and controlled clock:

```python
request = broker.request(items, idempotency_key="inventory-1", ttl_seconds=300)
assert request["state"] == "pending"
assert broker.status(request["request_id"])["allowed_items"] == []
```

- [ ] Run the task tests and existing Python web-control tests; record red/green
  counts and any migrated superseded test expectations before scoped commit.

## Task 2: Local Human Approval and Revocation

Files: create `plugins/remotex/src/web_approval.py`,
`plugins/remotex/scripts/web_approval.ps1`, and
`plugins/remotex/tests/test_web_approval.py`.

Interfaces: `ApprovalPrompt.start(manifest, on_decision, on_revoke)` launches a
single owned child using inherited stdin/stdout IPC. Decision frames bind the
request nonce/digest/helper and contain selected item IDs/target subsets,
lowered uses and TTL. Closing or canceling never grants authority.

- [ ] Write and run failing tests for helper launch failure, bounded framing,
  mismatched/replayed decisions, no decision fields in MCP, cancel/timeout and
  decisions arriving after session expiry.
- [ ] Implement a visible WinForms checklist, complete target/change detail,
  lowerable limits and explicit approve/reject/cancel; approved helper exposes
  revoke. Use absolute PowerShell paths and the established child module path.
- [ ] Run Python helper tests and PowerShell parser validation. Synthetic tests
  inject a decision transport only from test code; no production test flag.
- [ ] Record real human prompt verification separately during acceptance.

## Task 3: Grounded Browser Components and Typed Operations

Files: create `plugins/remotex/scripts/web_components.mjs`; modify
`scripts/web_control.mjs`; add `tests/web_authorization.test.mjs`.

Interfaces: component discovery returns bounded public references and internal
fingerprints; draft resolution grounds immutable workflow/target/field facts.
Typed execution supports approved region/table/field reads, fragment/menu
navigation, finite query inputs and approved business workflows only.

- [ ] Write and run real-Edge fixture tests that fail for menus outside the
  success region, visible table projection, exact targets/old-new values,
  changed nodes, hidden/secret fields and unknown workflow controls.
- [ ] Implement metadata-only discovery separately from content projection.
  Keep authentication marker, content regions and navigation independent.
- [ ] Implement `action_prepare` with no DOM/network mutation; allow a first-use
  proposed effect contract to be reviewed in the same task approval.
- [ ] Migrate the two earlier author-owned navigation experiments to the new
  grant-based contract, preserving their content/navigation separation evidence.
- [ ] Run Node browser suites and record actual passing/failed cases.

## Task 4: Network Permits, Async IPC and Write Recovery

Files: modify `scripts/web_login_worker.mjs`, `src/web_channel.py`;
create `scripts/web_network_authorization.mjs` and its tests.

Interfaces: bounded `authorization-check` frames on the original worker pipe
are serviced independently of serialized operation responses. A reader pump
handles permit/revocation frames while a page action is waiting. Broker checks
exact parsed request contracts; every write permit is one-use and step-bound.

- [ ] Write red tests for a post-login background write, duplicate form/JSON
  keys, unknown parameters, wrong target/change, expired permits, revocation
  during a blocked command, denied output after delayed audit, and no replay.
- [ ] Implement strict bounded JSON/form descriptors, internal authentication
  slots and default-deny phases from worker startup. Unknown login contracts
  yield reviewable setup descriptors without transmitting credentials.
- [ ] Preserve existing TLS/redirect/network canary checks on every forwarded
  request. Known reads cannot borrow armed business-write permits.
- [ ] Verify per-target dispatched/accepted/running/verified/unknown evidence,
  durable uncertainty fences, and separately approved reconciliation/compensation.
- [ ] Run Python channel/broker and real-browser network tests, then commit.

## Task 5: MCP Integration and Compatibility

Files: modify `src/web_adapter.py`, `src/remotex_mcp.py`, `src/audit_log.py`,
`tests/test_web_control.py`, `tests/test_web_credentials.py`,
`tests/test_mcp_protocol.py`; add `tests/test_web_authorization_integration.py`.

Interfaces: expose only the seven protocol tools from spec section 10.
All paths resolve the original channel and current queue acquisition binding.
Legacy content/navigation tools return `approval-required` without an explicit
valid scope. Status, component metadata and owned cleanup remain usable.

- [ ] Write red integration tests for original requester/lease/config checks,
  new tool schemas, no arbitrary input, partial approval and old API bypass.
- [ ] Add broker creation/lifecycle, approval callbacks, draft/request/status/
  execution/revoke handlers, field projections and authorization audit events.
- [ ] Keep shared profile JSON unchanged; preserve old active sessions until
  they finish. New sessions never silently downgrade to old permissions.
- [ ] Run the configured repository suite with a fresh writable basetemp and all
  Node web suites; inspect failures rather than waiving unrelated breakage.

## Task 6: Review, Release and Installation

Files: update RemoteX version/manifests, README, skill, web credentials reference,
root changelog and affected catalog/showcase entries using existing repo tools.

- [ ] Update operator guidance for batch/subset approval, exact write preview,
  revocation, uncertainty and current browser-access prerequisite.
- [ ] Run repository validation, full tests, installed-package smoke and secret/
  private-endpoint checks; keep private runtime evidence outside version control.
- [ ] Obtain a real fresh-context whole-branch review as required by
  `executing-plans`; resolve important findings with regression evidence.
- [ ] Commit only the scoped files, push the topic branch, create/attach PR,
  wait for required Windows CI and merge main under the user's explicit approval.
- [ ] Install the merged release through the supported plugin mechanism and
  verify package hashes/version. Reconnect only affected idle clients.

## Task 7: Real Center Acceptance and Human Write Checkpoint

- [ ] Verify current supported Edge access, inspect the web queue and acquire
  only when free/first in FIFO with the stable task requester.
- [ ] Use the saved profile/credential/pin; verify the native approval window,
  at least one partial decision, terminal-list navigation and current-page read.
- [ ] Inspect a suitable existing reversible business operation and render the
  exact test targets, before/after values, expected side effects, class and
  restoration preview. Wait for the user's specific confirmation before writing.
- [ ] After confirmation and local approval, execute once, verify target results,
  revoke and demonstrate refusal, then close/read back/release only this task.
- [ ] Report source/CI/merge/install/live evidence separately; any missing target,
  contract, approval or policy prerequisite remains a concrete acceptance gap.
