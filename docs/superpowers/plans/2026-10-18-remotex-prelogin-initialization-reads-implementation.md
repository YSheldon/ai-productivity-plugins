# RemoteX Pre-Login Initialization Read Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task in the current session. Steps use checkbox (`- [ ]`) syntax for tracking. Workspace AGENTS.md permits native execution without a team handoff. A real independent whole-candidate review remains required before publication.

**Goal:** Permit individually human-reviewed, exact pre-login initialization POST reads, then separately approved authentication and page reads, without widening Bootstrap, replacing credential isolation, or increasing the four-active-grant limit.

**Architecture:** Extend the existing setup protocol with a strict revision 2. The original supervisor owns native decisions, append-only prerequisites, fresh resume identities and typed one-request receipts; the private worker evaluates bounded initialization responses before fulfilling them to the page. Broker-owned atomic replacement carries only remaining revision-2 static authority into an explicitly reviewed replacement, while legacy contracts retain their original single-phase behavior.

**Tech Stack:** Python supervisor and pytest, Node.js 24+, existing pinned Playwright Core 1.62.1 with Microsoft Edge, Windows PowerShell/WinForms, existing hash-chained durable journal. Add the exact pinned `jsonc-parser` 3.3.1 package for strict response-tree validation only; do not change the request JSON/form codec.

**Spec:** `docs/superpowers/specs/2026-10-18-remotex-prelogin-initialization-reads-design.md`, SHA-256 `08A6877C24C5468E99CCB1A2DB60789CB9A4B44612D2B324E80A6F35D41C1FA9`.

**Review State:** The human approved the design, including Section 8, and this implementation plan, with native execution in the current session. Scoped test/commit/push/main-merge/install/live-read delivery is authorized after its required gates. No second release-permission menu is needed for unchanged scope.

## Baseline And Execution Scope

- Date: 2026-10-18, America/Tijuana.
- Worktree: `C:/Users/sysadm/Documents/AI/ai-productivity-plugins-remotex-auth`.
- Inspected HEAD: `5f2c13b10a6a4a6312f967c0101ddfc5b5ff80a3`, branch `codex/remotex-approval-hints`.
- Inspected local `origin/main`: `93547d95b1a952810989e262d54ec972d0e9a504`. This is a local reference, not a fresh remote-status claim.
- Both inspected trees: `45e77b6e37d630f87c98f3653b46f50b0f7824c7`.
- Expected next version: RemoteX 0.6.8, subject to a fresh main/version check before implementation. Never overwrite a newer published version.
- Reuse this linked worktree. Preserve all pre-existing dirty Cursor manifests/launchers, including `plugins/remotex/scripts/launch_cursor_mcp.cmd`, and all private `.remotex-*` evidence. Do not stage them.
- Do not edit another repository, center frontend/backend, profile configuration, saved credential, system trust store, browser settings or running unrelated process.
- Plan preparation changes only this file. Creating the implementation branch, product edits and tests of new behavior follow plan review.

## Global Constraints

- Human review: original 120 seconds, not restarted by shown or a refresh.
- Requested task TTL: default/maximum 43,200 seconds; human may reduce it.
- New browser session: default/maximum 46,800 seconds; covering lease plus 45s.
- Startup document/fragment budget: one total 45s; resume outer wait 55s.
- Issued permission check: 10s. Initialization POST uses the ordinary check path, not static JS/CSS queue waiting or static audit batching.
- Business operation 30s and high-risk one-use confirmation up to 30s unchanged.
- One pending request, four active grants, 32 items/32 KiB per proposal, existing per-item preview/descriptor bounds, 100 denied refs with 120s TTL.
- Setup uses remain 1..10; proposed Initialization Read default is 2, not unlimited. Human may reduce them. No quota refund after a consumed/cancelled permit.
- Existing component-reference 30s lifetime, output bounds, write-target quotas, uncertainty fencing and business-write previews are unchanged.
- Preserve the existing aggregate 200-use proposal limit, per-item 4096-byte preview limit, strict request codec and the original binding/business deadline.
- Initialization response: at most 64 KiB, at most 8 reviewed checks, JSON Pointer depth at most 8. No raw response, selected value, GUID, header or cookie is public output or audit content.
- No arbitrary POST, raw HTTP, arbitrary script/eval, browser attach/CDP escape, approval API, wildcard endpoint scope or inferred read-only semantics.
- Real acceptance is security login and a separately approved current-page read only. No business writes, no queue preemption, no credential resubmission after possible authentication.
- All product UI, code comments, repository docs and tests remain English. ASCII is the default for new text.

## Review Focus

1. A response arriving after a new document/resume must not satisfy that document's prerequisite; test document/resume/generation mismatches in Tasks 2 and 3.
2. An omitted or rejected initialization row must not disappear when a later proposal contains fewer rows; test append-only requirements and conflicting predicates in Tasks 1 and 3.
3. A valid twelve-hour grant must not permit idle polling outside an explicit startup resume; test stale/cancelled context and credential-armed boundaries in Tasks 2 and 3.
4. Closing a retired source window must not revoke its replacement, while revoking a source during commit must prevent new authority; test both orderings in Task 4.
5. An initialization response's Set-Cookie must not take effect before rejection, including the non-pinned TLS path; test the real transport/cookie jar in Tasks 3 and 6.

## File Responsibilities

Paths below are repository-relative; execute commands from the worktree above.

| File | Responsibility |
| --- | --- |
| `plugins/remotex/scripts/web_initialization_contracts.mjs` (new) | Pure revision-2 eligibility, readiness-check normalization and strict response validation; no I/O or authority |
| `plugins/remotex/scripts/web_startup_state.mjs` (new) | Private document/resume prerequisite receipts and seal lifecycle; exports only fixed counts/state |
| `plugins/remotex/scripts/web_task_contracts.mjs` | Preserve revision 1; normalize revision 2 and commit every new field to native scope/digests |
| `plugins/remotex/scripts/web_authorization_ipc.mjs` | Correlate and consume typed private receipts; retain static-only bounded FIFO/batches |
| `plugins/remotex/scripts/web_network_authorization.mjs` | Exact request descriptors, one-request forwarding receipt, initialization/authentication accounting |
| `plugins/remotex/scripts/web_worker_runtime.mjs` | Strict private dispatch and read-only revision/readiness metadata |
| `plugins/remotex/scripts/web_login_worker.mjs` | Original worker orchestration, readiness-before-credentials and guarded response fulfillment |
| `plugins/remotex/scripts/web_tls.mjs` | Bounded, cookie-isolated initialization response transport under existing CA or pin policy |
| `plugins/remotex/src/web_initialization.py` (new) | Independent setup validation and original-supervisor startup identity/state; no credential retrieval |
| `plugins/remotex/src/web_channel.py` | Strict original-pipe envelopes for typed receipts and fixed startup events |
| `plugins/remotex/src/web_authorization.py` | Native semantics and lock/durability/counter-safe resource-only replacement |
| `plugins/remotex/src/web_task_service.py` | Bind contracts to grants, exclude overlapping work, retire replaced/startup helpers safely |
| `plugins/remotex/src/web_approval.py` | Preserve native diagnostics; truthful server-driven replacement stop/failure reasons |
| `plugins/remotex/scripts/web_approval.ps1`, `web_approval_ui.ps1` | English Initialization Read help, pre-auth/replacement scope, explicit final decision |
| `plugins/remotex/src/web_adapter.py` | Strict tool schema/status and complete pinned runtime dependency admission |
| `plugins/remotex/scripts/web-runtime/package.json`, `package-lock.json` | Exact parser dependency and integrity-locked runtime, no floating version |
| Focused tests listed in each task | Contract, IPC, lifecycle, native UI, broker and real-Edge regression evidence |
| Release files listed in Task 7 | Version consistency and English public documentation |

## Task 0: Preserve And Establish The Implementation Candidate

**Files:** No product change. Keep the approved spec and this plan available.

**Interfaces:** Implementation starts only after plan review. Git writes use applicable tool permission; approvals for the named repository and delivery effects already exist.

- [ ] After plan review, read executing-plans, TDD and protect-cross-repo-main instructions at the applicable stage. Reuse approved scope; do not introduce a team/execution-method menu.
- [ ] Read `git status --short --branch`, `git rev-parse --git-dir --git-common-dir`, `git remote -v` and current main/version. Record unrelated dirty paths without modifying them.
- [ ] Fetch `origin/main`, confirm the named remote identity, compare refreshed main to the inspected tree, then create `codex/remotex-prelogin-init` from refreshed main in this linked worktree. If the name already exists, inspect ownership/history before reuse rather than resetting it.

```powershell
git fetch origin main
git rev-parse HEAD origin/main 'HEAD^{tree}' 'origin/main^{tree}'
git switch -c codex/remotex-prelogin-init origin/main
```

- [ ] Inspect any new overlapping main changes before applying this plan. Preserve unrelated local edits. An incompatible protocol/security change requires a bounded design update, not blind application.
- [ ] Establish `$py` for later commands and verify Node >=24 and existing Edge/runtime availability. Do not alter global Python, browser or unrelated plugin settings.

```powershell
$py = 'C:\Users\sysadm\AppData\Local\Programs\Python\Python313\python.exe'
& $py --version
node --version
```

## Task 1: Strict Revision-2 Contracts And Bounded Response Checks

**Files:**
- Create `plugins/remotex/scripts/web_initialization_contracts.mjs`.
- Modify `plugins/remotex/scripts/web_task_contracts.mjs` at `networkItem` and `setupContracts`.
- Modify the pinned runtime package/lock only for `jsonc-parser: "3.3.1"`.
- Create `plugins/remotex/tests/web_initialization_contracts.test.mjs`; extend `web_task_contracts.test.mjs`.

**Interfaces:**

```javascript
// New pure module, with parser injected from the validated pinned runtime.
normalizeResponseChecks(value); // -> deeply frozen normalized Check[]; throws fixed code
validateInitializationDescriptor(descriptor); // -> cloned exact eligible descriptor
evaluateInitializationResponse({status, headers, body}, checks, parseTree);
// -> {ready:true} or throws an allowlisted fixed error; never returns values/body

// Existing module; existing callers keep the same two-argument signature.
setupContracts(setup, network);
// rev1: unchanged {ok:true,items,contracts}
// rev2: additionally setup_revision:2, preauth_lifecycle, phase_applicability,
//       prerequisites, replace_grant_ids; lifecycle is supplied by the worker.
```

Checks use exactly these shapes: `{pointer,test:'type',expected}` where expected is `object|array|string|boolean|integer|null`; `{pointer,test:'nonempty-string'}`; `{pointer,test:'equals-boolean',expected:boolean}`; `{pointer,test:'equals-integer',expected:safeInteger}`. Reject all extra keys, empty lists, root-value predicates, more than 8 checks and paths deeper than 8. Decode only valid JSON Pointer `~0`/`~1` escapes, cap encoded pointer length at 512 characters, reject prototype keys and credential/token/session/challenge/signature path segments. Never permit string equality, regex or functions. Integer means safe integer, not boolean or rounded numeric input.

- [ ] Add a failing positive contract test with an observed synthetic POST; the public input contains no URL/body/header.

```javascript
test('revision 2 binds exact prelogin init and never widens Bootstrap', () => {
  const descriptor = {method:'POST',path:'/init',query:{},
    contentType:'application/json',body:{cmd:'database_info'},resourceType:'xhr'};
  const network = {phase:'bootstrap',preauthLifecycle:'a'.repeat(32),
    resolve:() => structuredClone(descriptor)};
  const proof = [{kind:'source-review',reference:'Synthetic handler revision 1'}];
  const result = setupContracts({revision:2,phase:'bootstrap',requests:[{
    network_ref:'b'.repeat(32),purpose:'initialization-read',max_uses:2,
    response_checks:[{pointer:'/exist',test:'equals-boolean',expected:true}],
    evidence:proof}],replace_grant_ids:[]}, network);
  const contract = result.contracts['setup.network.1'];
  assert.equal(contract.semantics, 'initialization-read');
  assert.deepEqual(contract.phase_applicability, ['bootstrap','login-once']);
  assert.equal(contract.required, true);
  assert.equal(result.items[0].parameters.review_kind, 'initialization-read');
  assert.throws(() => setupContracts({phase:'bootstrap',network_refs:['b'],
    evidence:proof}, network), /request-contract-unavailable/);
});
```

- [ ] Run `node --test plugins/remotex/tests/web_task_contracts.test.mjs plugins/remotex/tests/web_initialization_contracts.test.mjs`; capture the intended red assertion/import, not an unrelated environment failure.
- [ ] Add table-driven red cases for legacy/v2 mixed keys, unknown revision/purpose, caller phase applicability/lifecycle, duplicate refs, changed descriptors, POST static rows, GET init rows, `internalAuth` nested anywhere, secret-tainted parameters, unsupported content type, and replacement IDs >2/duplicate/non-hex.
- [ ] Implement revision-2 normalization. Require current worker pre-auth phase, 1..32 unique new refs and 1..10 uses; static purpose maps to native `bootstrap`, init maps to native `initialization-read`. Fix the phase set to the two pre-auth phases. Bind descriptor, checks, evidence, required ID, phase set and lifecycle into preview, fingerprint/effect commitments and normalized contracts. Reject over-size data before registering any prerequisite. A changed predicate for an already-declared descriptor is a conflict, not a way to discard the previous requirement.

```javascript
const initContract = {
  revision:2, purpose:'initialization-read', semantics:'initialization-read',
  phase:'bootstrap', phase_applicability:['bootstrap','login-once'],
  preauth_lifecycle:network.preauthLifecycle, parent_id:null, targets:[],
  descriptor:structuredClone(descriptor), response_checks:checks,
  required:true, prerequisite_id:prerequisiteDigest
};
// prerequisiteDigest commits to lifecycle + exact descriptor + normalized checks.
// Only the normalizer creates this shape; the public schema cannot supply it.
```

- [ ] Add response-validator red tests for duplicate/escaped-duplicate JSON keys, invalid UTF-8, comments, trailing commas, non-finite/unsafe integers, depth/size limits, missing fields, wrong types, failed booleans, error/redirect/401/407 responses, Set-Cookie and authentication negotiation headers. Test pretty-printed strict JSON succeeds; do not add canonical-request decoding fallback.

```javascript
test('readiness emits no selected value and rejects duplicate keys', () => {
  const checks = normalizeResponseChecks([
    {pointer:'/exist',test:'equals-boolean',expected:true}]);
  const response = body => ({status:200,headers:{'content-type':'application/json'},
    body:Buffer.from(body)});
  assert.deepEqual(evaluateInitializationResponse(
    response('{\n  "exist": true\n}'),checks,parseTree), {ready:true});
  assert.throws(() => evaluateInitializationResponse(
    response('{"exist":false,"exist":true}'),checks,parseTree));
  assert.throws(() => evaluateInitializationResponse(
    {...response('{"exist":true}'),headers:{'set-cookie':'not-applied=1'}},
    checks,parseTree));
});
```

- [ ] Pin the parser, use `parseTree` with `disallowComments:true`, `allowTrailingComma:false`, `allowEmptyContent:false`, reject every parse error, and reject duplicate decoded property names by walking object nodes before reading values. Decode UTF-8 with `new TextDecoder('utf-8',{fatal:true})`. Do not log parser errors/source text. The parser is not a credential or request codec. Manually edit package.json with apply_patch, then generate the lock and install its exact contents:

```powershell
npm install --package-lock-only --prefix plugins/remotex/scripts/web-runtime --ignore-scripts --no-audit --no-fund
npm ci --prefix plugins/remotex/scripts/web-runtime --ignore-scripts --no-audit --no-fund
```
- [ ] Re-run both Node test files green and existing request-codec regressions; commit only this task's exact files after reviewing the staged diff.

Parser reference: [Microsoft parser API](https://github.com/microsoft/node-jsonc-parser/blob/main/README.md), [3.3.1 release](https://github.com/microsoft/node-jsonc-parser/releases/tag/v3.3.1). The documented parser is fault tolerant, so an error-free tree and an explicit duplicate-key walk are mandatory; simply calling `parse()` is insufficient.

## Task 2: Original-Supervisor Resume State And Typed One-Request Receipts

**Files:**
- Create `plugins/remotex/src/web_initialization.py`.
- Modify `web_channel.py`, `web_task_service.py`, `web_authorization_ipc.mjs`, `web_network_authorization.mjs`, `web_worker_runtime.mjs`.
- Create `plugins/remotex/tests/test_web_initialization.py`.
- Extend `test_web_task_service.py`, `test_web_control.py`, `web_authorization_ipc.test.mjs`, `web_network_authorization.test.mjs`, `web_worker_runtime.test.mjs`.

**Interfaces:**

```text
validate_setup_context(resolved: dict, binding: dict) -> dict
StartupAuthority(binding: dict, *, clock, wall_clock)
StartupAuthority.begin(*, lifecycle: str, session_deadline_ms: int) -> dict
StartupAuthority.event(frame: dict) -> dict
StartupAuthority.issue(*, check_id: str, message: dict, contract: dict) -> dict
StartupAuthority.end(resume_id: str) -> None
StartupAuthority.status() -> dict
```

These are interface signatures; the new private module imports ScopeError/canonical/digest from web_authorization. `begin` creates a fresh private 32-hex resume ID and deadline bounded by the original session and one 45-second budget. `event` accepts only fixed original-worker state transitions described below, returns a fixed audit event, and never decreases possible-authentication accounting. `issue` returns an exact typed receipt only for an active, matching human contract before credential arming. `status` returns only required/ready/pending/blocked counts, `controls_ready` and a fixed state.

```text
WorkerAuthority.checkNetwork(request, options) -> boolean | private receipt
WorkerAuthority.consumeNetworkReceipt(receipt, expected) -> validated private receipt
NetworkPolicy.takeForwardingReceipt(request) -> {kind:'ordinary'} | private init receipt
```

`checkNetwork` is used only by the production network requestPermit callback; action `check` remains boolean. The receipt has process-private provenance in WorkerAuthority, not merely a matching JSON label. NetworkPolicy retains it in a WeakMap keyed by the actual browser Request; `takeForwardingReceipt` removes that entry and calls `consumeNetworkReceipt` to revalidate check membership, exact descriptor digest, phase/generation, document/resume identity, cancellation and expiry. An absent/stale/unknown typed receipt throws before forwarding. It never falls back to ordinary permission. Ordinary boolean permissions still require the existing successful exact authorization before their private WeakMap entry is created.

```javascript
// Exact private receipt fields; no public token or reusable permission cache.
{kind:'initialization-read', check_id, descriptor_digest, binding_digest,
 preauth_lifecycle, resume_id, document_id, generation, expires_at_ms,
 prerequisite_id, response_checks}
```

`Channel._read` adds the original authorization-check envelope ID when calling the supervisor callback. Only that pipe can return the typed reply. Keep boolean ordinary/action and static-batch replies compatible. Typed replies are accepted only for a matching outstanding ordinary network check, never for an action or a static batch. Scope and resume fields come from supervisor-owned state, not public arguments.

- [ ] Write red tests proving an active native init scope alone cannot issue a receipt when no original resume exists, and a caller `purpose` or `permit_kind` cannot suppress authentication accounting.
- [ ] Test `StartupAuthority.begin/event/issue/end` using fixed clocks: wrong lifecycle/document/resume/generation, expired 10-second check, cancelled resume, session expiry, armed credentials, and possible authentication all deny. Same binding after queue reacquisition must still deny because acquisition identity changed.
- [ ] Run `& $py -m pytest -q plugins/remotex/tests/test_web_initialization.py plugins/remotex/tests/test_web_task_service.py`; verify the new behavior is red before implementation.
- [ ] Independently validate normalized worker contexts in Python: exact keys, descriptor eligibility, fixed phases, checks and scope commitments; reject a forged `initialization-read` contract even if its display row claims Bootstrap or Read. Add the new semantic to native-decision validation only with matching expected review kind. Unknown semantics remain denied.
- [ ] Wrap only private `resume-login` dispatch with supervisor-created startup arguments; the public tool still accepts no extra fields. Introduce private fixed `startup-state` events correlated to that ID: `document-opening`, `document-committed`, `controls-ready`, `credentials-armed`, `authentication-forwarded`, `authentication-verified`, `resume-ended`. Validate the entire frame before applying any transition. The initial automatic unapproved navigation has no typed-init authority.
- [ ] Track physical phase/generation plus a fresh document ID. A Bootstrap-to-Login phase handoff may update the context generation without changing its resume ID or original deadline. A fresh resume first permits only exact configured-document GET; initialization reopens only after the old document was replaced and the original supervisor proves zero possible authentication. Reject stale events; do not let an event reset an earlier counter/fence.
- [ ] Preserve `WorkerAuthority.check` action/ordinary boolean behavior. Store validated typed network receipts privately, bind them to the actual Request object and its exact digest, and consume once in `NetworkPolicy.beginForwarding`. Check context, cancellation, expiry and object identity again immediately before dispatch. Do not accept an arbitrary object with a matching `kind` string.

```javascript
// Required accounting at the existing forwarding boundary:
const receipt = this.takeForwardingReceipt(request);
if (receipt.kind === 'initialization-read') {
  this.startupState.check(receipt);
  if (this.authenticationForwarded > 0) throw new Error('scope-mismatch');
  this.initializationForwarded++;
} else if (this.phase === 'login-once') {
  this.loginForwarded++;
  const descriptor = describeRequest(request,this.origin,this.secrets);
  const internalAuth = value => Boolean(value && typeof value === 'object' &&
    (value.internalAuth === true || Object.values(value).some(internalAuth)));
  if (!['GET','HEAD'].includes(descriptor.method) ||
      internalAuth(descriptor.body) || internalAuth(descriptor.query)) {
    this.authenticationForwarded++;
  }
}
```

Retain the existing active-attempt forwarded/inFlight branch around this startup accounting. No exemption depends on endpoint or command spelling.

- [ ] Add IPC red tests for missing/extra fields, wrong check membership, substituted descriptor, replay, late/retired reply, typed reply in a boolean batch, cancellation during fsync and reordered generation. Verify no initialization POST enters `_isStatic`, `_pump` or `consume_static_network_batch`.
- [ ] Re-run the focused Python files and `node --test plugins/remotex/tests/web_authorization_ipc.test.mjs plugins/remotex/tests/web_network_authorization.test.mjs plugins/remotex/tests/web_worker_runtime.test.mjs`. Preserve 10/45/55-second assertions and existing stale-reply behavior. Commit exact task files after a staged-diff check.

## Task 3: Readiness Before Credentials And Response-Before-Cookie Validation

**Files:**
- Create `plugins/remotex/scripts/web_startup_state.mjs`.
- Modify `web_login_worker.mjs`, `web_tls.mjs`, `web_worker_runtime.mjs`, `web_adapter.py`.
- Create `plugins/remotex/tests/web_startup_state.test.mjs`.
- Extend `web_login_worker.test.mjs`, `web_tls.test.mjs`, `test_web_credentials.py`, `test_web_control.py`.

**Interfaces:**

```javascript
class StartupState {
  constructor({lifecycle, clock, emit});
  register(contracts); // append-only requirements; exact duplicate is idempotent
  open(context); // a fresh owned document, not a permission to replay requests
  begin(permit); // returns a private unsettled receipt identity
  check(receipt); // throws if document/resume/generation/deadline/seal changed
  response(receipt, {ready}); // applies only to its original context/document
  canInsertCredentials(); // true only for all current required receipts, none pending
  armCredentials(); // irreversible for this document
  end(context); // cancels pending receipts, exports no values
  status(); // fixed state/counts only
}

// web_tls.mjs, response bytes never touch the browser before inspection.
initializationResponse(request, origin, pinOrUndefined, signal, deadline);
// -> bounded {status,headers,body}; max64KiB, no redirect/retry/cookie jar
```

- [ ] Add red tests for append-only required IDs: selected first row plus rejected second row blocks credentials; a later one-row proposal cannot delete the second; exact duplicate is idempotent; changed predicates for the same descriptor conflict; failed/unsettled/old-document responses do not satisfy requirements.
- [ ] Add a synthetic page test that records every username/password typing call and submit. Until initialization checks and controls are ready, the call trace must be empty. A button becoming visible without a passing required response is insufficient.
- [ ] Run `node --test plugins/remotex/tests/web_startup_state.test.mjs plugins/remotex/tests/web_login_worker.test.mjs`; capture intended red results.
- [ ] Register immutable prerequisites only after the complete proposal passed normalization/bounds and the supervisor accepted it for native review. Register all init rows, not merely approved ones. Use a private `register-initialization` command with exact normalized contracts; it has no public counterpart. If worker registration fails, cancel only the new request and grant no authority; requirements already registered cannot be erased by a later request.
- [ ] Wire response receipts into `guardRoute`: consume a valid typed permit, use cookie-isolated transport, validate status/headers/body/checks before `route.fulfill`, then record fixed response/ready state for that request. No summary/projectResponse is emitted for init payloads. Do not make a denied/error response visible as readiness.
- [ ] Implement the initialization transport by sharing the existing HTTPS sender, header filtering, socket cancellation and pre-first-byte trust checks. Pinned mode retains exact leaf SHA-256 and validity checks. Non-pinned mode uses `rejectUnauthorized:true` with hostname/system-CA verification under Node's existing `--use-system-ca`; never use the pin bypass without a valid configured pin. Do not use `route.fetch`/browser APIRequestContext for initialization, since it may apply cookies before validation. Keep ordinary legacy transport behavior unchanged.

```javascript
// Initialization-only pre-fulfillment order:
const response = await initializationResponse(request, origin, pin, signal, deadline);
evaluateInitializationResponse(response, receipt.response_checks, parseTree);
startup.check(receipt);
await route.fulfill(response);
startup.response(receipt, {ready:true});
// No cookie setters, response exports or authentication negotiation fallback.
```

- [ ] Enforce the 64-KiB ceiling while streaming, not only after allocation. Reject duplicate/conflicting raw Content-Type/Content-Length, Set-Cookie, WWW-/Proxy-Authenticate, upgrade/auth negotiation and redirect responses before fulfillment. Preserve the existing shorter request/resume cancellation deadline and no automatic POST retry. A timeout consumes the issued count and yields a fixed unknown/blocked result, never replays captured bytes.
- [ ] Wire the same private StartupState instance into the owned NetworkPolicy and worker orchestration; do not create a second mutable copy of the credential-armed seal. Move readiness and no-resubmit checks before any credential field interaction. Once all requirements and controls are ready, seal initialization before `submitLogin`. On the next explicit pre-auth resume, replace the document via GET and reset only document-scoped response receipts, never requirements, uses, deadlines or authentication history. If authentication might have forwarded, retain the existing no-resubmit/unknown path.
- [ ] Add a parser runtime readiness check alongside Playwright. Use a new versioned runtime directory for the candidate, never overwrite a runtime used by old sessions. Keep `_module_path()` compatibility; add a separate exact parser-module lookup and admit startup only when both pinned modules are present. The existing runtime setup preview explains the two exact packages; `confirm=true` installs the lockfile in the new directory. Pass the validated parser module path only in the private new-worker launch, not as a secret/config migration. Never silently accept a Playwright-only runtime as complete.
- [ ] Extend TLS/cookie tests with pinned and normal-CA fixtures: a rejected init Set-Cookie never appears in `context.cookies()`, bad trust sends zero request bytes, malformed/non-JSON/oversize/error responses never type credentials, and a successful JSON response can update only the owned page runtime.
- [ ] Run the two affected Python test files, the new state test, login-worker test and TLS tests green. Keep the production `viewport:null` and existing resize regressions unchanged. Commit exact task files after reviewing the staged diff.

## Task 4: Four-Slot Resource-Only Atomic Replacement

**Files:**
- Modify `web_authorization.py`, `web_task_service.py`, `web_initialization.py`, `web_approval.py`.
- Create `plugins/remotex/tests/test_web_setup_replacement.py`.
- Extend `test_web_authorization.py`, `test_web_task_service.py`, `test_web_authorization_store.py`, `test_web_ui_receipts.py`.

**Interfaces:**

```python
# Extend the existing Broker API with private optional arguments only.
Broker.request(items, *, idempotency_key, ttl_seconds=MAX_GRANT_SECONDS,
               setup_context=None, replacement_source_ids=())
# Existing accept_decision/status APIs remain unchanged.
# Request/grant private state retains validated setup_context and source snapshot.
```

`setup_context` is independently validated supervisor data, not an accepted public dictionary. The broker composes carried rows from source grant scopes/contracts itself. Source/new ID collisions use deterministic local IDs `carry.<sourceOrdinal>.<itemOrdinal>` while retaining source scope/item/digest commitments. Remove old `approved_semantics` from proposed rows; native review starts Unreviewed and must explicitly classify carried rows again. No caller descriptor is copied as a source.

- [ ] Add red source-eligibility tests: max2 distinct sources; same binding/lifecycle/fixed phases; revision2 only; every source item is Bootstrap-resource-only, unrevoked, unexpired, idle and has a positive remaining count. Mixed/init/Login/business/revision1 sources deny. An exhausted source cannot be renewed or silently omitted.
- [ ] Add this concrete broker test using the existing `prepared`, `item`, `MemoryJournal` fixture style; define `static_context` in the new test module to construct the exact Task 1 normalized resource context.

```python
def test_replacement_carries_remainder_not_original_uses(prepared):
    broker, clock, journal, *_ = prepared
    row = {**item('root'), 'capability':'web.page_step', 'max_uses':4,
           'parameters':{'network_ref':'root','review_kind':'bootstrap'},
           'output':{'rows':0,'columns':0,'bytes':0}}
    request = broker.request([row], idempotency_key='root', ttl_seconds=300,
                             setup_context=static_context(row))
    manifest = broker.approval_manifest(request['request_id'])
    choice = {'item_id':'root','max_uses':4,'targets':[],
              'semantic_classification':'bootstrap'}
    original = broker.accept_decision(request['request_id'],nonce=manifest['nonce'],
        digest=manifest['request_digest'],choices=[choice],ttl_seconds=300)
    approved_row = broker.grants[original['grant_id']]['items']['root']
    broker.consume_static_network(original['grant_id'],'root',approved_row['parameters'])
    new_row = {**row,'item_id':'new','parameters':{
        'network_ref':'new','review_kind':'bootstrap'}}
    replacement = broker.request([new_row],
        idempotency_key='replace',ttl_seconds=43200,
        setup_context=static_context(new_row),
        replacement_source_ids=[original['grant_id']])
    proposal = broker.approval_manifest(replacement['request_id'])
    carried = next(r for r in proposal['items'] if r['item_id'].startswith('carry.'))
    assert carried['max_uses'] == 3
    assert proposal['replacement']['source_grant_ids'] == [original['grant_id']]
    assert proposal['ttl_seconds'] <= 300
```

`static_context(row)` must use a bodyless document GET `/`, `revision:2`, `purpose:'bootstrap-resource'`, the fixed two-phase applicability, `semantics:'bootstrap'`, lifecycle `'a'*32` and a contract keyed to that row's item_id. It must not prefill `approved_semantics`.

- [ ] Run `& $py -m pytest -q plugins/remotex/tests/test_web_setup_replacement.py`; verify intended red behavior before broker changes.
- [ ] Stage source snapshots under the existing authority lock: immutable scopes/contracts, remaining counters, source deadlines, binding and lifecycle. Compose every source row plus new rows, then apply existing 32-item/32-KiB/4096-preview/200-use limits to the combined proposal. Over-capacity returns `setup-plan-capacity-required`, not truncation or a fifth active grant.
- [ ] Coordinate replacement admission with one service operation gate. Reject replacement if any resume/operation/permit is unsettled; do not stop it. While a replacement is pending, reject resumes, execution and new forwarding; allow passive status/cancel/revoke. Add red races in both orderings, including initial worker startup and a late ordinary check. Do not wait while holding a lock needed by that operation.
- [ ] On the native decision, require every carried row selected with counts no larger than the captured/current remainder. Permit partial new-row approval. Compute one deadline as the minimum of the human limit, every source deadline, session/lease and stronger binding deadline; new rows share that deadline. Show its cap in the native manifest and bind source snapshots/carried mappings/deadline to the request digest. Same-key readback never refreshes source TTL or review deadline.
- [ ] Under the broker lock, recheck all source snapshots/counters/fences/bindings, idle state, request lifetime and `active - sources + 1 <= 4`. Persist a bounded replacement transition using the existing full-chain-verifying journal before any new permit can be issued. Prepare private new authority ineligible for forwarding; atomically retire sources and activate only after persistence plus final cancellation checks. No executable authority is recovered from the journal on restart.

```python
effective_deadline = min(human_deadline, binding_deadline,
                         *(source['deadline'] for source in sources))
assert active_count - len(sources) + 1 <= 4
# Persist source/destination scope digests and counter commitments under lock.
# Recheck immediate fences after durability; transition has no public midpoint.
```

- [ ] Test a source revoke/cancel during durability. It must mark the pending transition ineligible even though existing revocation sets fences before taking the audit lock. Recheck those fences before activation; if persistence is uncertain, fence the owned transition/session. Never return an active destination after a failed transition.
- [ ] On success, mark old requests server-retired before stopping their helpers with `grant-replaced`; remove old forwarding contexts and install only the approved new context. A retired callback cannot revoke/resurrect the new grant. On omission/expiry/counter change/revocation/conflict, close only the new failed replacement helper with a fixed reason, return no new grant, and preserve still-valid sources. Native local button/title is never the authority readback.
- [ ] Add tests for four-active admission, zero/five-active observation, 33 items/over32KiB/over200uses, source expiry, partial new rows, omitted carried row, narrowed lifetime, source alias collision, source close before/during/after commit, own-session audit failure and unrelated grant preservation.
- [ ] Run focused replacement/broker/service/store/UI receipt tests green. Review staged files and commit this task without unrelated launchers or private ledgers.

## Task 5: Native English Review, Strict Tool Schema And Safe Status

**Files:**
- Modify `web_approval.ps1`, `web_approval_ui.ps1`, `web_approval.py`, `web_adapter.py`, `web_worker_runtime.mjs`.
- Extend `tests/Test-WebApprovalUI.ps1`, `test_web_approval_ui.py`, `test_web_approval.py`, `test_web_ui_receipts.py`, `test_web_task_tools.py`, `web_worker_runtime.test.mjs`.

**Interfaces:**
- Existing `remotex_web_authorization_request.setup` becomes a mutually exclusive legacy/revision2 schema. Revision2 accepts only the fields in spec Section 5, with bounded checks/evidence/replacement IDs. No raw request or approve tool is added.
- Native choice `semantic_classification:'initialization-read'` must match expected review kind exactly; caller input cannot supply that field.
- Read-only status adds `setup_revisions:[1,2]`, supported purpose names, fixed readiness counts and fixed replacement state/source IDs. Never export private resume/document/check IDs, response predicates' selected values or receipt contents.

- [ ] Add red schema tests for valid v2 shape, legacy compatibility and forbidden mixed/extra keys. Check backend rejection as well as JSON Schema; do not rely solely on clients honoring `oneOf`.
- [ ] Add native harness cases `apply-initialization-read`, `mixed-init-refused`, `init-hint`, `replacement-scope`, `replacement-carried-required`, `replacement-lifetime` and `replacement-failed-receipt`. All are synthetic manifests and actual WinForms controls, never real user approvals.
- [ ] Run `& $py -m pytest -q plugins/remotex/tests/test_web_task_tools.py plugins/remotex/tests/test_web_approval_ui.py` to see the new red assertions.
- [ ] Add Initialization Read to both dropdowns and compatibility mapping, with this English adjacent explanation:

```text
Initialization Read: reviewed pre-login initialization only. Exact POST;
no authentication, configuration changes or business writes.
```

- [ ] Show every row's exact path/parameters, purpose, evidence, required status and fixed pre-auth phases; replacement header identifies sources and carried items plus effective shorter lifetime. Keep details readable at existing minimum size and Windows DPI; use wrapped text and scrollable details, not a larger hard-coded window. Do not hide incompatibility by automatically classifying a mixed checked batch.
- [ ] Preserve Select All/Clear/Apply as non-authorizing actions. Partial new selection is allowed; missing carried items prevents replacement locally and in the broker. Keep separate Approve Selected, original 120-second countdown, shown/closed/error receipts, and closure-to-revoke semantics. Add only allowlisted server-driven replacement stop reasons; do not mislabel retirement as operator rejection.
- [ ] Verify fresh server status is authoritative after native click. A failed replacement helper closes, cannot display a persistent active destination and cannot close any source helper. Keep action-confirmation 30-second and parent-grant semantics intact.
- [ ] Run native/schema/receipt/runtime tests green, including existing inline hints, mixed-effect refusal, action-context hints and resize checks; commit only exact task files.

## Task 6: Full Original-Worker And Supervisor Integration

**Files:**
- Create `plugins/remotex/tests/fixtures/web_initialization_worker.mjs` for synthetic private-pipe adversarial frames only.
- Create `plugins/remotex/tests/test_web_prelogin_integration.py`.
- Extend `web_tls.test.mjs`, `web_startup_budget.test.mjs`, `test_web_authorization_integration.py`, `test_web_browser.py` only if a new fixture needs registration; do not raise existing test budgets to hide slowness.

**Interfaces:** Use the production worker/channel/service/broker plus a loopback HTTPS fixture. Test-only native decisions use fake manifests/callbacks under the existing harness; no test may automate approval of the real center or reuse a real credential.

- [ ] Add red real-Edge scenarios: initial controls hidden until three synthetic exact POST reads finish; server counts request/credential bytes; deny unreviewed POST, wrong classification, approval-without-resume and partial plans. Zero credentials may be typed before all reviewed readiness conditions hold.
- [ ] Exercise the planned four-slot flow: root v2 grant; explicit carry-root+24 resource replacement; remaining23 resource grant; independently classified static/init batch; separately observed one-use Login as the fourth active grant. Verify old scopes never forward after replacement and no instant exposes a fifth active grant. Actual fixture serialized sizes, not only item counts, must fit existing hard bounds.
- [ ] Add adversarial cases for every spec Section 13 item: exact shape changes, auth slots/taint, invalid request codecs, misleading command names, duplicate response JSON, Set-Cookie/auth negotiation, typed receipt substitution/replay/late arrival, revoked leases and original-scope expiry.
- [ ] Prove pre-auth reloads work in Bootstrap and pre-credential Login-once without migrating legacy grants; fresh-document readiness is required again. After possible authentication, initialization never reopens and an uncertain login is not resubmitted. Login success alone grants no page read or background business request.
- [ ] Verify a separately approved `web.read_region` can read the synthetic current page after authentication; without that native grant, content/DOM/result export stays blocked. Reject business writes for this acceptance scenario. Existing business-writing tests remain as regressions rather than live authority.
- [ ] Assert unchanged 45/55/10/120/30-second boundaries, 12h/13h ceilings, queue/session +45 seconds, descriptors100/120s, component30s, static64-queue/16-batch behavior and ordinary init POST path. Use deterministic clocks for expiry/ordering and a real worker fixture for transport/forwarding outcomes.
- [ ] Run all Node web suites using the repository's existing pytest browser wrapper and complete local suite with native/budget flags; save a new candidate-specific JUnit outside the committed files.

```powershell
$env:REMOTEX_TEST_NATIVE_APPROVAL = '1'
$env:REMOTEX_ASSERT_STARTUP_BUDGET = '1'
& $py -m pytest -q --tb=short --junitxml=../remotex-0.6.8-full-local.xml
& $py scripts/project_docs.py --check
```

- [ ] Record pass/fail/skip/subtest counts, exact HEAD/tree/diff and environment. Failures require diagnosis within scope; three failed corrective modifications retain the local human-review gate. Do not skip tests, merge a failed candidate or substitute static checks for the live acceptance item.
- [ ] After product/docs changes are ready, obtain a real independent whole-candidate review under the applicable review skill, with a clean bounded context and the approved spec/plan/diff/test artifacts. Do not call self-review independent. Resolve findings within approved scope and rerun affected/full gates as required. Do not restart already-passing unchanged checks merely because a skill/phase changed.

## Task 7: Version, Public Docs, Exact-Candidate CI And Install

**Files:**
- Modify `plugins/remotex/.codex-plugin/plugin.json`, `.cursor-plugin/plugin.json`, `src/remotex_mcp.py` and exact-version assertions in `test_mcp_protocol.py`, `test_plugin_contract.py`.
- Modify `plugins/remotex/README.md`, `plugins/remotex/docs/web-task-authorization.md`, `plugins/remotex/skills/remotex/SKILL.md`.
- Modify root `README.md`, `CHANGELOG.md`, `docs/installation.md`, `docs/remotex-showcase.md` only where this new workflow changes claims/instructions; regenerate `docs/plugin-catalog.md` with `scripts/project_docs.py --write`.
- Include the approved spec and reviewed plan in the scoped candidate; never stage private progress/PR/diagnostic ledgers, real payloads, credentials or current session files.

- [ ] Set the candidate's available version consistently, expected 0.6.8. Preserve unrelated fields and do not stage unrelated pre-existing Cursor changes. Update English docs with v1/v2 compatibility, Initialization Read versus Bootstrap/Login/Read/Write, fixed readiness/check limitations, exact static replacement/no-renewal behavior, four-grant batching and unsupported authentication-encoding response.
- [ ] Document normal failure states without suggesting alternate labels, manual HTTP, a global trust override or a hidden-approval bypass. Update skill examples with opaque observed refs only; explicitly require trustworthy handler/effect evidence and separate native Login/Read decisions. No production secrets or example real request bodies.
- [ ] Run docs generation/check, manifest/protocol tests, full local suite and independent review against the final content. Review `git diff --check`, complete staged file list, new-file contents and changed code for secrets. Use explicit `git add` paths only, never `git add .`.

```powershell
& $py scripts/project_docs.py --write
& $py scripts/project_docs.py --check
git diff --check
git diff --cached --stat
git diff --cached --name-only
```

- [ ] Commit the scoped candidate and push the feature branch to the approved named repository. Create/attach a PR and read back its exact head SHA. Do not push main directly or infer merge permission merely from PR creation; the current human request already explicitly authorized this scoped merge after passing gates.
- [ ] Wait for `.github/workflows/release-gate-ci.yml` on that exact candidate head. Preserve Windows Python3.12, Node24, pinned runtime install, native-host prerequisite, all existing compile/reminder/full-suite steps and JUnit upload. Download/read the final JUnit and distinguish real passes, skips and failures. Reconcile any head change; never merge a run for another SHA.
- [ ] Merge only the tested/reviewed head with a head-SHA match condition, then read back merged state, merge SHA and main tree. No history rewrite, default-branch protection change or skipped gate.
- [ ] Use the official plugin marketplace upgrade/install path. Verify installed/enabled RemoteX version, immutable merged runtime hashes, public tool schema and a fresh owned MCP initialize version. Do not kill unrelated clients or force GitLab/IMAP cache locks. Preserve profile/credential configuration; do not migrate secrets or interrupt running RemoteX sessions.
- [ ] If the current chat's connector is stale, start only a fresh owned installed-version MCP process using public stdio tools, prove its version, and keep all operations in that original supervisor. Do not adopt or restart another chat's session to obtain new capabilities.

## Task 8: Queue-Safe Real Login And Current-Page Read

**Target:** Existing `web-security-6868` profile, configured origin/account/trust, stored `security` credential. No credential input in chat, no business write, no center-code mutation. Historical sessions/leases/refs/grants are closed and are never reusable evidence.

**Exit condition:** One verified authentication in the new owned session, followed by a separately native-approved read of its current center page, with bounded evidence and no secret/response export. Publication/install success and live acceptance are reported separately.

- [ ] First prove current supported Edge browser use with a harmless owned tab and an actual supported browser read. Inventory alone is not proof. If policy is disabled/denied/unknown, stop remote browser work; no RemoteX/raw CDP/shell fallback around that policy. Close only the test tab created by this task.
- [ ] Read live queue/lease/acquisition. Keep requester `remotex-task-authorization-20261017` stable. If another owner or operation holds the resource, do not claim/preempt/close it; report the current queue state. Messaging another user chat needs its own explicit authorization.
- [ ] Claim only an available FIFO resource under the existing queue tool policy. For a new default46800-second session, obtain a lease covering at least46845 seconds, normally46900. Validate the original config/trust/account binding and installed-version worker. If the certificate changed/expired, stop for existing trust rules rather than accepting a network-read fingerprint as proof.
- [ ] Before an Initialization Read request is proposed, inspect trustworthy deployed handler/API evidence for each candidate's side effects and actual supported encoding. The earlier local frontend correlation is not deployed-handler evidence. Do not modify the center while checking. If evidence is unavailable or a handler mutates configuration/identity/business state, leave it denied and report that exact blocker.
- [ ] Start a fresh owned login session with explicit current authority. Use the revision-2 four-slot batching/replacement workflow from Task 6 and actual fresh denied refs, not the previous run's IDs. Check actual serialized size and remaining source counts/deadline before proposing replacement. If no safe layout fits, report `setup-plan-capacity-required` and stop instead of increasing limits.
- [ ] Open each real native review only when the user can act; report digest, purpose, exact counts and remaining review time from shown diagnostics. Human selects compatible Bootstrap or Initialization Read rows and independently clicks Approve Selected. Approval chat replies, visible windows or helper titles are never authority; read approved/active state from the original supervisor. Reuse unchanged valid grants, not new approval loops.
- [ ] Explicitly resume after approval. Verify fixed prerequisite readiness/counts and observed one-use Login descriptor; separately obtain native Login approval. Do not submit credentials through any other path. If actual authentication encoding is unsupported, stop with that scoped compatibility limitation; this approved change contains no legacy decoder workaround.
- [ ] After verified login, confirm startup scopes retired and request the exact current-page `web.read_region`/appropriate bounded read from fresh component refs. Obtain its native Read decision and execute once. Do not navigate business actions, submit forms, move groups or create tasks. A login screen/HTTP200/init response is not a successful current-center-page read.
- [ ] Record exact version, queue acquisition, own session identity, fixed readiness/approval/read outcomes and timestamps. Never record password, token, cookies, GUID values, raw initialization responses or private receipt contents.
- [ ] Close only the browser/session owned by this run, separately read back `closed`, then release only its queue lease. Stop its owned stdio MCP process before ending the turn. Do not terminate another session or release an unconfirmed-closed session's resource.
- [ ] Final report separates implementation, full local tests, independent review, exact WindowsCI, commit/PR/main merge, installed version and real login/page-read result. State any untested or externally blocked item without calling the whole delivery complete.

## Spec Coverage And Plan Self-Review

| Spec requirement | Owning tasks |
| --- | --- |
| Goal, no arbitrary POST, exact-site/account/queue/credential isolation | Tasks 1-3, 6, 8 |
| Evidence limits, no inference from get_* names, actual handler/codec gate | Tasks 1, 5, 8 |
| Independent purpose and fixed phases; no revision1 migration | Tasks 1-3, 5-6 |
| Append-only required plan and response/controls before credential arming | Tasks 1-3, 6 |
| Strict versioned schema, commitments and capability advertisement | Tasks 1-2, 5 |
| Response64KiB/check8/depth8, no secret oracle or response/cookie export | Tasks 1, 3, 6 |
| Human partial review, mixed refusal, English help and lifecycle receipts | Tasks 4-6 |
| Section8 four grants, bounded source-only replacement, no renewal | Tasks 4-6, 8 |
| Original typed receipts, conservative auth accounting and no resubmit | Tasks 2-3, 6 |
| Unchanged deadlines, capacity, descriptor/component bounds and quotas | Global Constraints; Tasks 1-6, 8 |
| Durable audit, cancellation/revocation and uncertain outcomes | Tasks 2-4, 6, 8 |
| Existing-session compatibility, no center/config/credential migration | Tasks 0, 3, 7-8 |
| Complete tests, independent review, exact CI, authorized publication | Tasks 6-7 |
| Fresh-queue real authentication plus separate current-page read | Task 8 |

Self-review checklist for the plan document, not executed product-test results:

- [x] Confirm each spec Section1-14 has an owner in the coverage table.
- [x] Confirm every new cross-task signature/field is defined once and used consistently.
- [x] Check parser/runtime admission includes both dependencies and existing-session isolation.
- [x] Check source replacement cannot increase remaining uses/deadlines or discard carried items.
- [x] Check no code/task step turns a caller label, event, UI title or response success into authority.
- [x] Scan for unfinished markers and validate referenced existing paths; inspect only proposed paths as new files. All 43 checked existing paths resolved; ASCII text, balanced fences and zero trailing whitespace/unfinished markers were verified.
- [x] Confirm no product implementation, runtime change, real authorization or release is claimed by preparation of this plan.

## Review Checkpoint

Please review this implementation plan before product edits, as retained by the approved spec Section13 item10 and the writing-plans Execution Handoff. Native execution in the current session is the preserved implementation method; a new team/task/method choice is not needed. The already-granted authorization for scoped testing, repository publication, passing-candidate main merge, installation and queue-safe no-write acceptance remains in force for this design.
