# RemoteX Public Initialization Literal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans for native implementation task by task in this conversation after this plan is explicitly approved. Steps use checkbox syntax. Preserve the existing native execution preference; no mandatory team/OMX handoff. One real independent whole-candidate review remains required before release.

**Goal:** Implement reviewed, exact, product-neutral initialization compatibility for public fixed literals without allowing authentication data, arbitrary POSTs or weakened credential boundaries.

**Architecture:** Add a strict initialization-only setup revision 3 alongside unchanged revision-1/2 authority. Pure JS/Python profiles and one immutable outgoing intent feed a memory-only original-supervisor authority. A bounded nonauthorizing native reference-check roundtrip precedes a separate final human decision; stable grant intent and fresh per-document permits remain distinct.

**Tech Stack:** Existing Python/pytest supervisor, Node.js 24+, pinned Playwright Core 1.62.1 and jsonc-parser 3.3.1, Windows PowerShell/WinForms, original private pipes and durable audit. No new package, browser, system trust or center dependency is planned.

**Spec:** `docs/superpowers/specs/2026-10-19-remotex-public-initialization-literals-design.md`, human-approved SHA-256 `A67ED14CACDAC44477BD729333836CD13C2E7B04C2F66B7397F0EA83B2566EA4`.

**Review State:** The human approved that design and authorized preparation of this plan ONLY. This plan is a review draft. No implementation, tests of new behavior, git write, publication, installation or remote operation is authorized by this planning turn. Stop after presenting the plan for human review. Later implementation approval does not erase retained publication, installation, credential, queue, native-decision or operation-time gates.

## Baseline And Execution Boundaries

- Planning worktree: `C:/Users/sysadm/Documents/AI/ai-productivity-plugins-remotex-auth`.
- Inspected HEAD: `f545e79a1e23b25fbb47595304cf10525a9a3876`, RemoteX 0.6.8. No claim that this is freshly fetched main.
- Preserve the original 2026-10-18 design, SHA-256 `08A6877C24C5468E99CCB1A2DB60789CB9A4B44612D2B324E80A6F35D41C1FA9`.
- Preserve unrelated dirty manifests/launchers, particularly `plugins/remotex/scripts/launch_cursor_mcp.cmd`, and private `.remotex-*` evidence. Never stage them with this feature.
- At execution, prefer a suitable isolated managed worktree after inspecting attached artifacts. Do not switch/reset the current dirty checkout merely to obtain a clean baseline. Use the returned execution root as `$repo` for commands below; all file paths are repository-relative.
- The proposed next plugin release is 0.6.9 only if a fresh main/version check still makes that valid. Never overwrite a newer release. A version change is not a protocol downgrade or a permission.
- No center frontend/backend, profile, credential entry, SSH/RDP/VM resource, browser security setting, system trust store or unrelated process is part of implementation.
- Tests use synthetic loopback origins and fake values only. Real target evidence, Login and current-page Read remain separate acceptance, never inferred from fixture results.

## Global Constraints

- Four active grants, one pending proposal, 32 setup items, 32 KiB combined contract/manifest, 4096-byte preview and 200-use combined cap.
- At most two idle same-lifecycle revision-2 static-only replacement sources; retain every carried row, only remaining uses and the earliest deadline. No revision-3 replacement sources or fifth grant.
- Denied-reference capacity 100 and TTL 120 seconds. Listing/status does not refresh them.
- Startup 45 seconds; resume wrapper 55 seconds; ordinary check/permit 10 seconds; native review 120 seconds from request creation; existing operation/action confirmation 30 seconds.
- Task grants up to 12 hours; sessions up to 13 hours with covering queue lease plus 45 seconds. Stronger source/session/lease/task deadlines prevail.
- Setup per-row uses remain 1..10. Proposed initialization defaults to 2. No automatic retry, count reset or refund after an issued permission.
- Raw body at most 16 KiB; raw query at most 8192 UTF-8 bytes; depth at most 8; at most 100 object members/array elements/form pairs; logical keys at most 128 UTF-8 bytes; safe integers only. Reject malformed encodings, controls and dangerous prototype keys.
- Reference strings at most 256 UTF-8 bytes; at most 8 review units per request and 24 per proposal. Keys, scalar values, empty containers and the structured outer carrier count as specified in the approved design.
- Initialization response at most 64 KiB, strict UTF-8 JSON, at most 8 checks and pointer depth 8; type/nonempty-string/boolean/safe-integer checks only. No raw response or secret-derived predicate.
- Known private/authentication slots, internalAuth, known-secret taint and actual authentication/session/challenge material cannot be declassified. Unknown evidence/role stays denied. A constant public authentication key is not eligible.
- Human judgments and expected public values use private native IPC only. No public approve/compare/raw-network tool, caller literals, arbitrary headers, secret files, environment payloads, raw/private hashes or equality oracle.
- Actual request bytes are never reconstructed after commitment. Named finite profiles are review interpretations, not MIME sniffing, permissive fallback, code evaluation or an endpoint/field whitelist.
- All product code/UI/docs remain English; ASCII is the default. Plan approval does not approve any business write.

## Review Focus

1. A secret can be a path segment, header name or JSON-shaped field name, not only a body value. Pin opaque projection and no unkeyed fingerprints in Tasks 1 and 4.
2. Decoded-equivalent packets can differ in wire bytes, charset, empty-value spelling or JSON string/object type. Pin representation and frozen transport identity in Tasks 1 and 2.
3. Editing a human reference or receiving a late private reply must invalidate the previous match without resetting 120 seconds. Pin compare revisions, partial coverage and post-fsync expiry in Tasks 3 and 4.
4. A cookie change or new document cannot borrow an old permit/readiness receipt. Pin cookie epochs, pre-send cancellation and fresh document receipts in Tasks 2, 4 and 5.
5. A fake Prompt fixture is not real native approval, and a fifth grant is not a capacity repair. Pin evidence categories, mixed-version denial and resource-only replacement in Tasks 4, 5 and 7.

## File Responsibilities And Dependencies

Create only these focused source modules:

- `plugins/remotex/scripts/web_request_profiles.mjs`: pure strict profiles, ordered typed views, complete public-reference coverage and review-unit counting. No I/O/authority.
- `plugins/remotex/scripts/web_outgoing_intent.mjs`: duplicate-aware private capture, fixed egress adjustments and opaque immutable intent handles. No public serializer or permission.
- `plugins/remotex/src/web_request_profiles.py`: independent pure validation of the same bounded private profiles/reference structures.
- `plugins/remotex/src/web_initialization_v3.py`: process-memory registry, private reference proof, HMAC binding and v3 permit validation. Never use persisted Journal.key for this authority.
- `plugins/remotex/scripts/web_reference_review.ps1`: native reference-panel state and nonblocking private reply handling; no direct grant operation.

Modify existing modules only at their relevant seams:

- `web_network_authorization.mjs`, `web_task_contracts.mjs`, `web_worker_runtime.mjs`: private observations, isolated v3 normalization and safe status.
- `web_authorization_ipc.mjs`, `web_channel.py`, `web_initialization.py`: typed private frames and fresh startup permits, retaining the existing state machine.
- `web_task_service.py`, `web_authorization.py`, `web_adapter.py`: original-supervisor integration, final decisions, public schema and advertised capabilities.
- `web_approval.py`, `web_approval.ps1`, `web_approval_ui.ps1`: bounded private roundtrip and final native review, preserving legacy helper behavior.
- `web_login_worker.mjs`, `web_tls.mjs`, `web_startup_state.mjs`: actual frozen dispatch and fresh response/readiness ownership.
- `web_authorization_store.py`: only allowlisted safe event metadata if new event IDs are required; no generic private-payload logging.
- Tests and English docs are listed by task. No unrelated refactor or broad launcher generator.

Dependency order is Task 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7. Task 8 is separately gated distribution/live acceptance. Do not parallelize overlapping integration ownership; read-only review/mapping may be delegated with bounded fork-none context.

## Shared Interface Contract

Freeze these names in Task 1 before dependent work. They are proposed implementation interfaces, not new public tools.

### Private Capture And Profiles

```javascript
// web_request_profiles.mjs; raw bytes are canonical padded base64 in private IPC.
parseV3Profile(capture, profileId, parseTree);
// -> PrivateView {profile_id, ordered_tree, locations, unit_count, byte_count}
validatePublicReference(capture, view, reference);
// -> private {matched, complete, unit_count}; never a public tool result
safeV3Observation(refs, publicIdentity);
// -> opaque refs, profile IDs, positions/types/counts/fixed codes only

// CaptureV3 exact keys; unknown keys fail.
// version, method, origin, resource_type, target_b64, body_b64,
// content_type_b64, original_headers, effective_headers,
// transport_policy, cookie_context, protection_refs
// Header entries: {name_b64,value_b64}; all bytes are private.
// cookie_context: original jar_ref + immutable non-auth-context epoch_ref,
// never an imported jar or public cookie value.
```

`method` is POST; `resource_type` is xhr/fetch. `target_b64` is the actual outgoing path/query representation after the fixed URL policy, not a decoded map. Capture original duplicate-preserving headers, independently derive effective headers with the existing fixed Host/Content-Length/identity Accept-Encoding policy, and compare both representations. Permit only ASCII header names/values valid for the transport; unsupported header encodings deny. Protection references are original-worker-owned handles to known private/auth markers, never caller classifications.

Profiles are exactly `json-utf8-v1`, `form-utf8-v1`, `form-json-name-view-v1`. Use the existing pinned strict JSON tree parser; never recursively parse arbitrary JSON-looking values. The structured-name profile requires successful strict base-form parsing, one pair, an empty value and a complete strict JSON object in the decoded name. It does not assert how a real server interprets that wire representation.

### Immutable Intent And Supervisor Authority

```javascript
// web_outgoing_intent.mjs
await captureInitializationIntent(request, policy); // -> opaque IntentHandle
privateIntentFrame(handle);                         // -> bounded CaptureV3
withInitializationIntent(handle, sendFrozen);       // trusted transport access
disposeInitializationIntent(handle);               // drop/clear owned buffers
```

The handle is backed by private module state; do not expose a mutable Buffer/header array or JSON serialization. `withInitializationIntent` supplies the same owned snapshot used for commitments, not another read from the browser Request. References/copies used for private validation must not mutate the dispatch snapshot.

The profile's review locations cover non-fixed data-bearing path/header components as well as query/body. Fixed configured identity and immutable transport-policy metadata are distinct from reviewed data units; a caller cannot relabel data as metadata to avoid coverage/counts. If the actual request exceeds the approved 8-unit/24-unit or byte limits, report unsupported capacity. Do not promise that the real site fits before its private wire/evidence review, or split one incomplete request across grants to evade its unit cap.

```text
web_request_profiles.py:
  validate_v3_capture(capture, profile_id) -> PrivateView
  validate_public_reference(capture, view, reference) -> PrivateComparison

web_initialization_v3.py:
  V3Authority(binding, clock, key_factory)
  register_plan(request_id, captures, evidence_locators) -> PrivatePlan
  check_reference(request_id, check_id, edit_revision, native_input) -> ReviewProof
  require_review(request_id, item_id, review_ref, edit_revision) -> ReviewedItem
  bind_grant(request_id, grant_id, approved_items) -> None
  issue(grant_id, item_id, capture, execution) -> TypedV3Receipt
  revoke(grant_id) -> None
  close() -> None
```

These signatures define behavior below, not empty implementation bodies. `register_plan` validates and accounts the whole private capture/view/evidence budget. `check_reference` accepts only original native pipe input, compares complete public wire/reference coverage and stages a nonauthorizing proof. `require_review` rejects missing/stale/wrong-item proof, incomplete data/role/effect evidence or hard private markers. `bind_grant` retains only final approved, narrowed scopes. `issue` revalidates the actual new capture and current execution context; revoke/close fence pending work and clear memory.

Use separate HMAC-SHA-256 domains `remotex/v3/grant-intent`, `remotex/v3/reference-proof` and `remotex/v3/dispatch-permit`, each followed by a NUL byte and canonical ASCII JSON. Sort object keys, preserve array order, reject non-safe numbers, and encode any non-ASCII/binary payload as canonical base64 before commitment. Python alone owns the fresh 32-byte context key. It is not Journal.key, not exported to the model/helper, and not persisted.

Stable intent binds exact outgoing representation/profile, lifecycle, binding, evidence and response contract. A separate one-use execution receipt adds current resume_id, document_id, generation, check_id, receipt_id and unchanged expiry. New documents may change only this execution binding, not wire scope or old readiness. The worker trusts only correlated original private-channel receipts; it does not mint one from a purpose label.

### Native Private Frames

Revision-3 helper manifests carry `protocol_revision:3`. All following frames include request_id, nonce and request_digest. Existing revision-1/2 helper frames remain unchanged.

- Native -> supervisor `helper-ready`: exact supported private protocol/profile versions, no authority.
- Native -> supervisor `reference-check`: check_id, item_id, edit_revision, bounded expected PUBLIC reference plus independent evidence/data/role/effect input. At most one outstanding and eight attempts per proposal, all within the same review deadline.
- Supervisor -> native `reference-result`: matching check/item/edit identifiers, private review_ref or null and fixed human-only coverage/result codes. No observed values.
- Native -> supervisor final `decision`: existing narrowed choices/TTL plus each v3 choice's review_ref and edit_revision. No new raw public-MCP fields.
- Supervisor -> native `decision-result`: committed active/rejected/cancelled state and effective limits. The v3 helper must not display Authorization Active before this acknowledgment. This does not replace original-supervisor public status readback.

Serialized writes have one owner/lock in ApprovalPrompt. A nonblocking native reader places replies into a bounded queue; the Forms timer drains it on the UI thread. Do not block the UI with Console.ReadLine or run a PowerShell event script on a foreign thread. Edits invalidate proof immediately. Compare/ready frames do not set decided, cancel/reset the timer or grant anything. A missing/old helper protocol denies; never emulate a final choice.

`native_input` has the following exact private shape; it cannot appear in the public tool schema. Native controls create it from independently reviewed PUBLIC reference text, not from captured unknown values:

```json
{
  "version": 3,
  "reference": {
    "profile_id": "json-utf8-v1",
    "target_text": "/bootstrap?mode=public",
    "content_type": "application/json",
    "body_text": "{\"mode\":\"public\"}",
    "public_headers": [{"name":"accept","value":"application/json"}]
  },
  "attestation": {
    "data_status": "public-invariant",
    "role": "non-auth",
    "effect": "initialization-read",
    "sensitive_ack_refs": [],
    "evidence": {
      "kind": "verified-record",
      "source_ref": "synthetic-public-reference",
      "revision_ref": "fixture-v1",
      "deployment_ref": "owned-loopback-fixture",
      "basis": "Reviewed fixture handler, public data and response contract",
      "independently_reviewed": true
    }
  },
  "cookie_review": {"context_ref":null,"role":"none","evidence_ref":null}
}
```

This is a synthetic schema example, not real-site evidence. The method/origin come from the immutable binding, not editable reference inputs. Cookie presence requires a matching private owned context_ref, role `non-auth-prelogin` and reviewed evidence_ref; no cookie value is entered. Actual/unknown auth state denies. Other header fields must either match the fixed transport policy or be fully covered by independently reviewed public reference/non-auth role. The complete effective outgoing intent, not only the displayed example headers, is checked.

Use snake_case for shared wire keys. Check IDs/review refs are random 32-hex IDs; nonce/digest use existing exact formats. edit_revision is a positive safe integer increasing per item. Public-reference strings/evidence text are bounded by their field limits and the aggregate 32-KiB budget. reference-result has only event/binding identifiers, edit_revision, review_ref, unit_count and fixed code `ready|reference-incomplete|reference-mismatch|ineligible|expired|stale-edit`; it stays on the private native pipe. A success proof requires complete current native attestations as well as matching data. Final choices use `review_ref` and `edit_revision`; no raw reference is repeated in the final choice.

Private compare outcomes never enter public status/audit, including error text. Final malformed/missing/stale proof decisions raise the fixed `decision-invalid`; ineligible profile/capture resolution uses `request-contract-unavailable`; aggregate/capacity overflow uses `setup-plan-capacity-required`. Do not include private input in exception messages or failing-test frame reprs.

## Task 0: Establish The Future Execution Candidate

**Files:** Approved design and this plan only until execution is authorized.

**Interfaces:** No implementation begins before human plan approval. No main write, merge, install or target access follows merely from branch setup.

- [ ] After explicit approval, read executing-plans, TDD, using-git-worktrees and applicable repository-protection instructions. Record the approved design/plan hashes separately; do not edit the approved design to change its status/hash.
- [ ] Inspect attached worktrees and repository identity/status/remotes. Reuse a suitable clean isolated worktree or create one through the normal Codex worktree tool from refreshed origin/main. Preserve this dirty source checkout and copy only the approved design/plan into the execution candidate.
- [ ] Record the returned `$repo`, fresh main/version and any design-relevant overlap; create/reuse owned `codex/remotex-init-public-literals` without reset/history rewrite. Incompatible protocol/security changes require bounded review before product edits.

```powershell
git -C $repo status --short --branch
git -C $repo remote -v
git -C $repo fetch origin main
git -C $repo rev-parse HEAD origin/main 'origin/main^{tree}'
git -C $repo switch -c codex/remotex-init-public-literals origin/main
$py = 'C:\Users\sysadm\AppData\Local\Programs\Python\Python313\python.exe'
& $py --version
node --version
```

- [ ] Verify Python/Node and existing Edge/native prerequisites; install only the existing pinned local test runtime if missing, with applicable tool permission. No global/browser/security-setting change.

```powershell
npm ci --prefix plugins/remotex/scripts/web-runtime --ignore-scripts --no-audit --no-fund
```

- [ ] Keep scoped local progress and separate RED/GREEN/full-suite artifacts. No raw native comparison input, private capture or real credential enters those logs.

## Task 1: Strict Profiles, Reference Coverage And Safe Projections

**Files:** Create the JS/Python profile modules above; create `tests/fixtures/v3_profile_vectors.json`, `tests/fixtures/v3_test_support.mjs`, `tests/remotex_v3_support.py`, `tests/web_request_profiles.test.mjs` and `tests/test_web_request_profiles.py`, all under `plugins/remotex`. Modify `scripts/web_network_authorization.mjs` only for private capture/projection seams.

**Interfaces:** Consumes CaptureV3/profile IDs; produces the pure interfaces above and synthetic-only shared vectors. No grant or transport send.

- [ ] Write failing cross-language cases using ordered synthetic captures. Include ordinary JSON/form, the explicit structured form-name view, a sensitive-looking public reference and the three-way public/non-auth/read distinction. Define test helpers completely: `sampleCapture(overrides)` builds canonical base64 wire fields for `https://fixture.example/bootstrap?mode=public`; `publicReference(case_id)` returns a clone of an independently declared, fixed synthetic source record. It must NOT accept a capture or derive expected values from it. Helpers never access profiles, queues, real sites or Credential Manager.

The Node helper loads parseTree through createRequire from the existing pinned `../../scripts/web-runtime/node_modules/jsonc-parser` path. New Python tests explicitly add plugin src/tests to sys.path before importing the uniquely named remotex_v3_support helper, consistent with repository importlib test mode. Define each fixture facade in its owning task: authority_case in Task 2 wraps only a fake clock/private authority and local count observer; native_manifest/compare_frame in Task 3 generate bounded synthetic private frames; service_case in Task 4 drives the real Service with test-only native callbacks; v3_runtime in Task 5 owns the production loopback pipeline. None is a shipped approve API.

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import {parseV3Profile, validatePublicReference} from '../scripts/web_request_profiles.mjs';
import {sampleCapture, publicReference, parseTree} from './fixtures/v3_test_support.mjs';

test('a named form view is explicit and full reference coverage is required', () => {
  const capture = sampleCapture({contentType:'application/x-www-form-urlencoded',
    bodyText:'{"public_info":{"userSession":"PUBLIC_MARKER"}}'});
  const view = parseV3Profile(capture, 'form-json-name-view-v1', parseTree);
  const reference = publicReference('public-info-form');
  assert.equal(validatePublicReference(capture, view, reference).complete, true);
  reference.body_text = '{"public_info":{"userSession":"DIFFERENT"}}';
  assert.equal(validatePublicReference(capture, view, reference).matched, false);
  assert.throws(() => parseV3Profile(sampleCapture({contentType:'text/plain',
    bodyText:'{"public_info":{}}'}), 'form-json-name-view-v1', parseTree));
});
```

- [ ] Run the exact new Node/Python focused files and capture intentional missing-module/assertion RED, not a missing runtime/host failure.

```powershell
node --test plugins/remotex/tests/web_request_profiles.test.mjs
& $py -m pytest -q plugins/remotex/tests/test_web_request_profiles.py
```

- [ ] Implement strict byte/UTF-8/percent parsing, ordered trees, duplicate rejection, nonrecursive JSON string semantics, safe numbers, prototype/control rejection and all parser caps. Require successful base form before the optional explicit JSON-name view; no raw-JSON assertion from a field summary. Match complete key sets/types/containers/pair order/scalars and all public wire spelling; key/empty-container/carrier accounting must match the approved 8/24 rule. A private V3 capture is not reconstructed from a legacy masked descriptor: retain every original protected marker/known-secret rejection, never erase internalAuth or re-observe merely to strip it. A case needing that relaxation remains unsupported and needs separate review.

```javascript
const profiles = new Set(['json-utf8-v1','form-utf8-v1','form-json-name-view-v1']);
// Normative result keys used by dependent tasks, never returned by public tools.
const viewShape = ['profile_id','ordered_tree','locations','unit_count','byte_count'];
const comparisonShape = ['matched','complete','unit_count'];
```

- [ ] Add RED -> GREEN boundary vectors at each exact ceiling and one above; malformed percent/UTF-8/charset, duplicate/escaped-duplicate keys, plus/double decoding, JSON string versus object, empty structures, >8 units, >24 aggregate units, changed whitespace/order/escaping and mixed opaque/ordinary form pairs. A logical match without complete public-wire reference fails.
- [ ] Make candidate metadata opaque across pending summaries, network-item previews, fingerprints/effect digests, results/errors/audit. Test secret-bearing path/header/key canaries and repeated low-entropy values; no raw or unkeyed digest may leak. Do not reuse the old networkItem serializer for private v3 captures. V3-only candidates cannot downgrade through legacy setup to expose their private state; safe legacy grant semantics remain unchanged.
- [ ] Run existing network/contract tests plus new profile tests; compare JS/Python vector results including canonical HMAC input bytes. Commit only the explicit Task 1 source/tests after GREEN.

## Task 2: Immutable Egress, Memory Authority And Typed Execution Binding

**Files:** Create `scripts/web_outgoing_intent.mjs`, `src/web_initialization_v3.py`, `tests/web_outgoing_intent.test.mjs`, `tests/test_web_initialization_v3.py`; extend `web_tls.mjs`, `web_authorization_ipc.mjs`, `web_channel.py`, `web_initialization.py` and their focused tests.

**Interfaces:** Consumes Task 1 profiles/capture schema. Produces IntentHandle, V3Authority, private wire/reference/permit commitments and versioned typed check replies. Public v3 capability is still disabled until integration is complete.

- [ ] Write RED tests proving capture owns the bytes/header array and dispatch does not reread them. The test fake Request implements url/method/resourceType/postDataBuffer/headersArray with call counters and mutable input arrays; return copies into the captured private record only once.

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import {captureInitializationIntent, privateIntentFrame,
  withInitializationIntent} from '../scripts/web_outgoing_intent.mjs';
import {fakeRequest, capturePolicy} from './fixtures/v3_test_support.mjs';

test('the committed snapshot is the actual frozen transport input', async () => {
  const req = fakeRequest({bodyText:'{"mode":"public"}'});
  const intent = await captureInitializationIntent(req, capturePolicy());
  req.replaceBody('{"mode":"changed"}');
  const frame = privateIntentFrame(intent);
  const sent = await withInitializationIntent(intent, frozen =>
    ({body:Buffer.from(frozen.body).toString('utf8'), headers:frozen.headers}));
  assert.equal(sent.body, '{"mode":"public"}');
  assert.equal(frame.body_b64, Buffer.from(sent.body).toString('base64'));
  assert.equal(req.calls.postDataBuffer, 1);
  assert.equal(req.calls.headersArray, 1);
});
```

- [ ] Implement complete duplicate-preserving `Request.headersArray()` capture; fail if that supported view is unavailable. Validate duplicates and header role, derive the fixed egress headers once and keep private owned body/header data inaccessible through public serialization. V3 `initializationIntentResponse(intent, origin, pin, signal, deadline, beforeSend)` in web_tls consumes the handle; preserve the old initializationResponse request signature for old contracts.
- [ ] Implement independent Python capture/profile validation, memory-only context key and the three domain-separated commitments. Never reuse persisted `Journal.key`. Preserve the distinction between stable grant intent and fresh current execution receipt; the supervisor key stays in Python, while correlated receipts traverse only the original authenticated private channel.

```python
def test_comparison_does_not_grant_and_permits_bind_fresh_context(tmp_path):
    from remotex_v3_support import authority_case
    c = authority_case(tmp_path)  # synthetic authority/binding/clock only
    before = c.active_grant_count()
    proof = c.authority.check_reference(c.request_id, '1' * 32, 1,
                                       c.independent_native_input())
    assert proof['review_ref']
    assert c.active_grant_count() == before
    assert c.network_count() == 0
    c.commit_native(proof['review_ref'], edit_revision=1)
    permit = c.authority.issue(c.grant_id, c.item_id, c.capture, c.execution())
    assert permit['kind'] == 'initialization-permit-v3'
    assert permit['document_id'] == c.document_id
    assert not c.accept_permit_in_new_document(permit)
```

- [ ] Extend exact private schemas, not optional unversioned flags: v3 check includes the captured intent handle/version/private snapshot; its reply includes kind/version, stable contract/intent identity and current check/receipt/resume/document/generation/expiry. Correlate with the actual Request object and consume once. A boolean permit, caller label, foreign ref or stale reply cannot suppress authentication accounting.
- [ ] Add RED -> GREEN tests for actual-auth/internalAuth/known-secret markers, unknown header/cookie roles, Authorization/custom authentication headers, foreign jar, cookie epoch/security-attribute changes, byte-equivalent normalization collisions, new document/resume, cancellation/expiry and TLS pin failure. Compare the frozen intent again post-certificate/pre-HTTP. No header stripping or payload reconstruction to force eligibility.
- [ ] Assert outgoing snapshot plus safe view/reference/evidence accounting fits 32 KiB, not the larger channel envelope limit. At most 100 observation records plus the bounded pending/active authority records; no unbounded side buffer. Dispose on eviction/fence/close without persisting captures/keys. Do not claim universal zeroization of arbitrary language-runtime copies.
- [ ] Run the focused new modules and existing TLS/IPC/startup tests. Commit only Task 2 files after GREEN; no public v3 flag yet.

## Task 3: Bounded Native Reference Roundtrip And Review UI

**Files:** Create `scripts/web_reference_review.ps1`, `tests/Test-WebReferenceReview.ps1`, `tests/test_web_reference_review.py`; modify `src/web_approval.py`, `scripts/web_approval.ps1`, `web_approval_ui.ps1`, `tests/test_web_approval.py`, `test_web_ui_receipts.py` and `Test-WebApprovalUI.ps1`.

**Interfaces:** Consumes Task 2 private comparison authority via an `on_reference` callback. Produces bounded native reference/decision frames and explicit proof-linked final choices, never a public approve function.

- [ ] Write RED protocol tests for helper-ready/reference-check/reference-result/decision-result schemas, duplicate/extra keys, wrong nonce/request digest, foreign item, check reuse, edit revision changes and old helper versions. Preserve existing V1/V2 no-unsolicited-decision tests unchanged; V3 ready/compare frames are explicitly nonauthorizing.

```python
def test_native_compare_is_not_a_final_decision():
    from web_approval import decode_frame
    from remotex_v3_support import native_manifest, compare_frame
    packet = native_manifest()
    value = decode_frame(compare_frame(packet, edit_revision=1), packet)
    assert value['event'] == 'reference-check'
    assert 'choices' not in value
    assert 'approved_semantics' not in value
```

- [ ] Extend ApprovalPrompt with one serialized stdin writer and a bounded reference callback. Keep stdout private authority frames and stderr fixed UI diagnostics separate. Validate before callback; fixed errors never echo payloads. Reference checks have at most one outstanding/8 attempts and at most 10 seconds each, capped by the original review remainder; they do not extend review, create grants or alter decided/timer state.
- [ ] Implement a nonblocking .NET StreamReader async input loop that enqueues typed private replies; drain a bounded queue from the existing Forms timer on the UI thread. Keep manifests first-line compatible; only V3 enables duplex replies. No background PowerShell script touching controls, no blocking Console.ReadLine in a click handler.

```powershell
# New native review-state functions, used by production UI and test harness.
New-V3ReferenceState -RequestId $requestId -ItemId $itemId
Invalidate-V3ReferenceState -State $state
Apply-V3ReferenceResult -State $state -Frame $frame
Test-V3ReferenceDecisionReady -State $state
```

- [ ] Add English controls for independently supplied PUBLIC reference, evidence basis/deployment applicability, data status, non-auth role and separate Initialization Read effect. Unknown captured values/keys/path/header text never populate controls or tooltips. Expected reference is a comparison input only; it cannot modify outgoing data. Show fixed human-only match/coverage, never the captured value.
- [ ] Every reference/evidence/profile edit increments edit_revision, clears proof and disables final approval until a current full match. Permit explicit groups only within one complete matched request/reference/evidence basis; require sensitive-key role acknowledgment. Select All/Apply Effect cannot create field judgments. Hard-private and incomplete/unknown units remain unapprovable.
- [ ] Final Approve Selected sends narrowed choices with staged review_ref/edit_revision. Show Awaiting Authority Commit until original supervisor decision-result; only then show active limits. The original 120-second timer includes comparison and commit; late result/decision cannot activate after it expires. Close/revoke semantics and truthful shown diagnostics remain unchanged.
- [ ] Run actual Forms control scenarios plus opt-in production-helper pipe tests for ready/compare/lifecycle. Use fake public inputs only and test-local pipes. Do not add a production test-mode/autoapprove flag. Commit Task 3 files only after GREEN.

```powershell
& $py -m pytest -q plugins/remotex/tests/test_web_reference_review.py plugins/remotex/tests/test_web_approval_ui.py plugins/remotex/tests/test_web_approval.py plugins/remotex/tests/test_web_ui_receipts.py
```

## Task 4: Original-Supervisor V3 Integration And Safe Public Schema

**Files:** Modify `web_task_contracts.mjs`, `web_network_authorization.mjs`, `web_worker_runtime.mjs`, `web_login_worker.mjs`, `web_startup_state.mjs`, `src/web_task_service.py`, `web_authorization.py`, `web_adapter.py`, `web_initialization.py`, `web_authorization_store.py`; extend existing contract/service/tool/protocol/startup/replacement/audit tests and create `tests/test_web_initialization_v3_service.py`.

**Interfaces:** Consumes Tasks 1-3. Produces actual strict v3 public setup, safe candidate discovery, original-supervisor proof-gated grants and exact v3 dispatch/readiness. No new public tool.

- [ ] Add RED public-schema tests using only refs/evidence/checks/uses. Reject caller values, verdicts, provenance, method/URL/body/headers/cookies, resource rows, replace_grant_ids, unknown revision and mixed keys. V1/V2 route explicitly to their old normalizers; V3-only refs cannot downgrade.

```python
def test_v3_choice_requires_current_private_native_proof(tmp_path):
    from remotex_v3_support import service_case
    c = service_case(tmp_path)
    request = c.request_v3()
    forged = c.choice(public_invariant=True, non_auth=True)
    assert c.try_native_decision(request, forged) == 'decision-invalid'
    assert c.active_grant_count() == 0
    assert c.network_count() == 0
    proof = c.compare_through_native_callback(request, edit_revision=1)
    c.edit_reference(request)
    assert c.try_native_decision(request, c.choice_with(proof)) == 'decision-invalid'
    assert c.active_grant_count() == 0
```

- [ ] Wire explicit setupContractsV3 into worker resolve-setup and independent supervisor validation. Preserve original worker/lifecycle ownership, fresh 120-second discovery refs, immutable accepted proposal lifetime and all byte/unit caps. Public evidence strings are proposed locators, not attested provenance; only current private native review can add that attestation.
- [ ] Before starting V3 review require the owned pre-auth worker idle using existing hold-setup/release-setup semantics; reject busy work rather than interrupt it. One pending review prevents overlapping resume/compare/replacement transitions. Source metadata reads never renew refs. Release hold on committed/failed/cancelled review without extending any deadline.
- [ ] Original Service owns on_reference, proof storage and final proof validation. Broker still creates one pending request and enforces four active grants. After durable audit, recheck original deadline/fences/bindings and proof revision before publication; fsync finishing after review expiry must not create authority. Append prerequisites only with the validated required contract; partial/rejected rows cannot disappear later.
- [ ] Route approved V3 requests through the frozen intent transport and typed permit. At each fresh explicit resume match stable reviewed intent, mint current one-use execution binding and require fresh response/readiness. No initializer can run after credentials arm or possible authentication; no caller/public label suppresses no-resubmit accounting.
- [ ] Preserve strict 64-KiB response evaluation and pre-fulfillment rejection of Set-Cookie/auth negotiation/redirect/error/unknown encoding. Readiness pointers require independently reviewed public meaning, not merely a non-sensitive name. Separate one-use Login and post-auth Read remain mandatory.
- [ ] Project safe metadata everywhere, including legacy readers of candidate records; no raw private hash enters existing request/fingerprint/effect/audit digests. Public status never includes per-reference match/equality replies. Use opaque IDs and allowlisted event enums/counts; do not reuse persisted Journal.key as v3 process authority.
- [ ] Add tests for both source-window orders in resource replacement, source expiry/count changes, all carried rows, 4+1 capacity, incomplete prerequisites, forged receipts, TLS revocation, current document changes and stronger cookie/session/task deadlines. No v3 grant is a static replacement source.
- [ ] Run focused JS/Python integration/service/schema/audit/replacement suites; commit only the explicit Task 4 paths after GREEN.

## Task 5: Synthetic Edge And Real Native Evidence

**Files:** Create `tests/fixtures/web_initialization_v3_worker.mjs` and `tests/test_web_initialization_v3_integration.py`; extend actual-helper tests/Forms harness where needed. No production fixture-mode or endpoint whitelist.

**Interfaces:** Consumes the complete Task 4 path. Produces separately labeled parser/service/Edge/native-pipe/whole-chain evidence, not real-target acceptance.

- [ ] First add failing loopback fixture modes `complete`, `partial`, `auth-field`, `wire-change`, `cookie-change`, `late-reference`, `new-document` and `response-cookie`. Use a synthetic HTTPS origin, synthetic protected credential and reviewed fixture source/reference/schema. Assert production Job/Channel/Service/worker and real Edge are used.
- [ ] The automated authority fixture may inject a test Prompt only for 127.0.0.1 and fake values. It must exercise production private reference validation before final callbacks; it cannot call broker.decide with an invented public verdict. Label this evidence as synthetic Prompt, not real human/native approval.

```python
def test_complete_v3_flow_keeps_compare_approval_and_send_separate(v3_runtime):
    r = v3_runtime('complete')
    r.approve_static_resources()
    proposal = r.request_initialization()
    assert r.stats()['initialization'] == 0
    r.compare_independent_public_references(proposal)
    assert r.stats()['initialization'] == 0
    r.commit_native_fixture_decision(proposal)
    assert r.stats()['initialization'] == 0
    r.resume_explicitly()
    assert r.stats()['initialization'] == 3
    assert r.stats()['logins'] == 0
    r.approve_one_login_and_resume()
    assert r.stats()['logins'] == 1
    assert r.read_current_page_with_separate_grant()['verified'] is True
    assert r.stats()['writes'] == 0
```

- [ ] Negative modes assert zero forbidden POST/auth bytes, no stale readiness, no secret in public/state/UI/audit artifacts, no automatic resend and no fifth grant. Public API-key/auth-role fixtures remain denied even if constant and even if a forged frame claims public. Complete body/query coverage cannot hide secret paths/headers/formatting.
- [ ] Run actual PowerShell control harness and production-helper pipe scenarios separately. Include missing companion module, helper old version, edit-during-check, wrong proof revision, canceled/late private reply, match-without-final-decision and decision-ack-after-expiry. Tests must leave no windows/readers/processes behind.
- [ ] Add opt-in test `test_manual_native_original_supervisor_v3` using the REAL ApprovalPrompt with no Prompt replacement. A local human supplies only the documented fake public reference and final decisions in the unchanged native window; the production private compare, final commit, Edge initialization and separate Login/Read must all be observed. This is required whole-chain native evidence before treating that gate as complete; lack of operator/host availability is missing coverage, not a pass.

Use a new synthetic 1800-second session for this manual fixture, not the old automated fixture's 180-second session; request at most that remaining lifetime for fixture grants. This is within the production 13-hour/12-hour ceilings, not an extension of any review/operation limit. Its queue/binding is isolated test-owned state, never the default web-security-6868/SSH queue. Each native review is still at most 120 seconds and each startup/resume/check retains 45/55/10 seconds. Default CI must not enter this manual session.

```powershell
# Run only when the operator is available; no real credentials or center access.
$oldManual = $env:REMOTEX_TEST_MANUAL_V3
$oldNative = $env:REMOTEX_TEST_NATIVE_APPROVAL
try {
  $env:REMOTEX_TEST_MANUAL_V3 = '1'
  $env:REMOTEX_TEST_NATIVE_APPROVAL = '1'
  & $py -m pytest -q plugins/remotex/tests/test_web_initialization_v3_integration.py -k manual_native
} finally {
  $env:REMOTEX_TEST_MANUAL_V3 = $oldManual
  $env:REMOTEX_TEST_NATIVE_APPROVAL = $oldNative
}
```

- [ ] Keep manual-only cases explicitly skipped by default CI; automated fixture/control tests remain in the full suite. Do not enlarge the existing 240-second Node-wrapper, 20-second Forms-harness or 30-minute workflow budget just to hide a regression. Investigate limits/performance within approved scope; an actual needed configuration exception requires review.
- [ ] Run new automated modes plus old original-worker/document/viewport/native lifecycle regressions. Commit only Task 5 fixture/tests after GREEN.

## Task 6: Capability Admission, Version And English Guidance

**Files:** `plugins/remotex/.codex-plugin/plugin.json`, `.cursor-plugin/plugin.json`, `src/remotex_mcp.py`, `tests/test_mcp_protocol.py`, `tests/test_plugin_contract.py`, `tests/test_web_task_tools.py`, plugin README, `docs/web-task-authorization.md`, `docs/web-credentials.md`, `skills/remotex/SKILL.md`; root README, CHANGELOG, `docs/installation.md`, `docs/remotex-showcase.md`, `docs/plugin-catalog.md` and `.cursor-plugin/marketplace.json` only for the RemoteX version mirror.

**Interfaces:** Advertise revision 3/profile versions only when parser, authority, helper protocol and frozen transport are complete. Installed files alone are not active tool capability.

- [ ] Add failing exact-version/capability/mixed-component tests before updating release metadata. Check fresh main/version first; use 0.6.9 only if still the next valid release. Do not change Playwright/jsonc-parser pins or rebuild unrelated runtimes.
- [ ] Update status/tools/list with exact v3 shape and named profile capabilities. A missing old helper/module/runtime support must fail before credentials/native grant, not merely claim local readiness. Test installed-versus-loaded version mismatch and old component rejection.
- [ ] Document public versus authentication role, complete independent public-reference evidence, private native comparison, field edits/partial approval, exact-byte mismatch, cookie restrictions, 120-second review versus 12-hour grant and the four-slot layout. Include a generic example, not real site payloads, credentials or an endpoint/sentinel whitelist. Clearly state unsupported encoding/role/evidence remains blocked.
- [ ] Update only affected English public claims; real target login remains unverified until Task 8. Do not publish the private diagnostic/protocol JSONL artifacts.

```powershell
& $py scripts/project_docs.py --write
& $py scripts/project_docs.py --check
& $py -m pytest -q plugins/remotex/tests/test_mcp_protocol.py plugins/remotex/tests/test_plugin_contract.py plugins/remotex/tests/test_web_task_tools.py
```

- [ ] Do not run sync_cursor_plugin_manifests.py over unrelated packaging/launchers. Stage only the exact owned version/docs paths, inspect staged diff and commit after focused GREEN.

## Task 7: Full Candidate Verification And Independent Review

**Files:** Candidate sources frozen; local result artifacts only. No source edit while a full run is active.

**Interfaces:** Produces local full-suite/native evidence and a candidate-bound independent review. These are not publication/install/live acceptance.

- [ ] Run complete repository pytest, not only RemoteX. Restore process-scoped flags afterwards; no manual-native wait in the unattended full suite. Preserve old and new skip reasons in JUnit.

```powershell
New-Item -ItemType Directory -Force artifacts/remotex-v3 | Out-Null
$oldNative = $env:REMOTEX_TEST_NATIVE_APPROVAL
$oldBudget = $env:REMOTEX_ASSERT_STARTUP_BUDGET
$oldManual = $env:REMOTEX_TEST_MANUAL_V3
try {
  $env:REMOTEX_TEST_NATIVE_APPROVAL = '1'
  $env:REMOTEX_ASSERT_STARTUP_BUDGET = '1'
  $env:REMOTEX_TEST_MANUAL_V3 = $null
  & $py -m pytest -q --tb=short --junitxml=artifacts/remotex-v3/full-local.xml
} finally {
  $env:REMOTEX_TEST_NATIVE_APPROVAL = $oldNative
  $env:REMOTEX_ASSERT_STARTUP_BUDGET = $oldBudget
  $env:REMOTEX_TEST_MANUAL_V3 = $oldManual
}
& $py scripts/project_docs.py --check
git diff --check
```

- [ ] Independently read JUnit totals/failures/errors/skips; confirm all new automated modes actually ran and the separate manual-native result exists. A timeout/partial log/missing XML is not a pass. Distinguish pure tests, synthetic Prompt, actual helper pipes/controls and complete native/Edge chain.
- [ ] Obtain one fresh independent whole-candidate review on the strongest available reviewer, bounded fork-none context and exact candidate tree/spec/plan/artifacts. It must examine disclosure/oracles, private frames, wire commitment/dispatch, cookies, deadlines, 4+1/replacement, mixed versions and no-resubmit. Do not relabel self-review as independent review.
- [ ] Repair validated issues only within approved design using RED -> GREEN; a candidate change invalidates affected full-suite evidence. After three failed corrective fixes, preserve investigation but request the retained human review before further modifications. Never skip a gate to publish.
- [ ] Scan the explicit candidate diff for credentials, raw captures/templates, private protocol logs and unrelated edits. Freeze the exact local commit/tree and report implementation/full tests/native evidence/independent review separately. Do not claim the real site login passed.

## Task 8: Separately Gated Distribution And Live Read Acceptance

**Files:** Only already-reviewed release/doc metadata and scoped evidence. This task is not authorized by approval of design/planning alone.

**Interfaces:** Proceed only when the human explicitly authorizes the named-repository publication/main merge/install and live target scope, or when same-target/same-effect authority is freshly established as valid. Creating a PR is not merge approval. Never reuse a consumed one-message approval or another candidate's release approval.

- [ ] If authorized, push only the owned feature branch to `YSheldon/ai-productivity-plugins`, create/attach the PR, run existing `.github/workflows/release-gate-ci.yml` and read back exact-head Windows CI/JUnit. Its default skips do not replace opt-in local native evidence. No workflow-permission or CI-timeout change is part of this plan.
- [ ] Merge only an approved exact head with successful required CI, then verify main's resulting tree and CI. No rewrite/reset of unrelated work. Keep publication, main merge and installation as distinct reported states.
- [ ] Install through the supported narrow plugin-management path without force-unlocking/restarting unrelated plugins. Preserve default config hash, saved references, trust and running sessions. Read actual runtime initialize/tools/list/status for version/revision 3/profile/helper support; installed manifest or an old schema cache is not enough.
- [ ] Before any target operation, establish current supported browser access with a harmless owned blank-page read; stop on denied/disabled/unknown policy, with no terminal/CDP/profile workaround. Check only non-secret config/runtime/credential presence. Reuse unchanged probe evidence only when inputs/freshness remain valid; never infer authentication from presence.
- [ ] Confirm the operator can act during the next 120-second native window. Recheck web-security-6868 and atomically acquire a NEW covering lease with the stable task requester. If busy, do not preempt/close another session or leave a forgotten queue item. A coordination message requires its own valid explicit sending authority.
- [ ] Start a fresh original-supervisor session and keep it through all readbacks. Use only fresh observed refs. Do not adopt ordinary browser tabs, copy cookies, reuse historical session IDs or restore old grants.
- [ ] Reuse unchanged native scopes/counts within that session. Consolidate static authority only through the existing bounded native replacement; target the feasible two-static/one-init/one-Login layout. Inspect exact combined scope/bytes/remaining uses/earliest deadline first. If it cannot fit, report capacity rather than increase four.
- [ ] For actual initialization, the human must verify the real public reference, non-auth roles, header/cookie context, deployed effect and response contract. Do not guess a /ready predicate, regard a get_* name as proof, or treat this plan's fixture values as the site's data. Unsupported inputs are a specific acceptance blocker.
- [ ] Create each exact native request only when prepared; immediately notify from the first result with actual digest, state and remainder. Starting is not shown; shown is not visibility/approval. Read committed original-supervisor active grants before explicit resume. No automatic reopens after a reported window problem.
- [ ] Verify required initialization responses/current-document readiness, then exactly one separately approved Login. Possible authentication is never resubmitted. Obtain separate native Read and verify the actual current page; do not perform grouping, task submission, service deployment or any business write.
- [ ] On completion/blocker/revocation, close only this owned session, read closed state, then release only its queue and read actual state. Stop the owned client after cleanup; leave no pending processes/windows/waiters. Report actual login/read result and any unsupported encoding/evidence/cookie/MFA/certificate condition separately from release success.

## Self-Review And Handoff Gate

- [x] Mapped spec Sections 1-3 to baseline/version/scope in Tasks 0/6; Sections 4-6 to strict profiles/reference authority in Tasks 1-3; Sections 7-9 to private/public frame integration in Tasks 2-4; Section 10 to readiness/capacity in Tasks 4-5; Sections 11-12 to audit/full evidence in Tasks 4-8; Section 13 to this pending human review.
- [x] Checked new API/frame/type names against Shared Interface Contract and commands against the repository runner. Corrected public-reference fixture independence, private native schema, helper import path and manual-native test selection.
- [x] Scanned for incomplete instructions, unowned files, omitted negative cases and accidental permission claims. The five Review Focus cases have explicit owning tests above. These are document checks, not executed feature tests.
- [ ] Human review of this plan. STOP here: do not execute Task 0, create a branch/worktree, install dependencies, edit product files, run feature tests, commit/push/merge/install or open any remote/native approval until the human confirms the plan and applicable action scope.
