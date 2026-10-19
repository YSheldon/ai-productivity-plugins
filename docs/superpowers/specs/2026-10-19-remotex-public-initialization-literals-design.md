# RemoteX Public Initialization Literal Compatibility

Status: DRAFT FOR HUMAN REVIEW. Design only; not approved for implementation.
Date: 2026-10-19, America/Tijuana.
Baseline: RemoteX 0.6.8, inspected commit
`f545e79a1e23b25fbb47595304cf10525a9a3876`.

## 1. Review Decision And Scope

The requested outcome is a product-neutral way to distinguish independently
verified public fixed literals from actual authentication material during
pre-login initialization. An unusual field name must not become either an
automatic credential verdict or an automatic exception. Only the existing
local human review can authorize an eligible, exact observed request.

Recommend an explicitly advertised setup revision 3 for this capability. Keep
revision 1/2 meanings unchanged. This proposal revises initialization eligibility
and representation binding; it does not widen Bootstrap, Login, ordinary Read or
Business Write, and does not modify any center business code.

All credential isolation, exact HTTPS origin/account/trust binding, queue
ownership, response validation, four-active/one-pending limits and the original
120-second review remain mandatory. No endpoint, command, field name or marker
value is built into an allowlist. A name such as `userSession` is an example of
a review concern, not a policy entry or permission.

This document authorizes no code, configuration change, test exception, commit,
publication, merge, installation, remote connection or real request. Approval
would permit preparation of an implementation plan, not its execution.

## 2. Evidence And Explicit Limits

The previous live run verified revision-2 discovery and three native approved
grants: the root document plus 24 and 23 exact JS/CSS scopes. Login was not
submitted and authenticated page reading did not complete. A local pure-validator
case using an observed JSON-shaped form-field name containing a session-looking
key returned `request-contract-unavailable`. That is structural evidence, not a
server call or proof that a placeholder is safe.

Current form parsing uses `URLSearchParams`; its public field summary contains
parsed key names. Therefore a JSON-looking form-field name is not evidence of an
original JSON body, a particular field value, charset or server decoder. Future
eligibility must inspect the protected original representation rather than infer
it from that summary.

Current receipts bind normalized descriptors while forwarding original payload
bytes. Local inspection found representations that normalize alike, including
percent-encoding variants and JSON strings versus recursively decoded objects.
This does not prove differing deployed effects, but a new literal exception
must not inherit that equivalence as exact-request authorization.

The runtime can attest owned observation, bytes, parser profile, known protected
slots and known-secret matches. It cannot generally reconstruct arbitrary
JavaScript dataflow, prove that every unrecognized value is public, or prove
remote read-only behavior. Independent human review against trustworthy,
deployment-applicable evidence is a required trust boundary, not an automated
proof. Missing or contradictory evidence means denial.

## 3. Alternatives

1. Retain the blanket sensitive-name rejection. It remains fail-closed but cannot
   handle verified public constants whose names resemble authentication fields.
2. Remove the name check, accept a caller flag, or whitelist a field/endpoint.
   Reject this option: constant credentials and public authentication keys exist;
   neither naming nor public availability establishes non-authentication use.
3. Recommended: explicit representation plus human-reviewed public-reference
   matching, separate authentication-role review, and exact private request
   commitments. It adds review work but keeps unknown/authentication material
   outside the initialization capability and does not bind the tool to a site.

## 4. Eligibility: Three Independent Conditions

Each request needs all three conditions; none substitutes for another:

- Data status: every data-bearing request component, not just body/query
  parameters, has a reviewed public fixed reference or an explicitly permitted
  private transport-context role for this exact scope. States are `unreviewed`,
  `public-invariant`, `private`, or `unknown`. Private transport context never
  becomes a public parameter; only the separately constrained cookie treatment
  in Section 8 may carry eligible non-auth pre-login state.
- Security role: the reviewed data is `non-auth`, not `auth` or `unknown`.
  Authentication, identity selection, session establishment/rotation, challenge
  handling or credential management are not initialization reads.
- Effect: the exact operation has independently reviewed `initialization-read`
  effects, with no configuration, identity or business mutation, plus a reviewed
  public response-readiness contract.

Sensitive-looking names trigger explicit review rather than a silent exception.
An ordinary-looking name is not a safe harbor: private data under `x` is denied.
Repetition, low entropy, equality to the field name, public script availability,
or successful parsing cannot establish these conditions.

Protected credential slots, `internalAuth`, known-secret taint, known actual
authentication/session/challenge data and credential-bearing dynamic keys remain
hard-denied. A native choice cannot turn those markers back into public literals.
A constant API key that confers authority is still authentication material.
An empty or public-looking value whose operation creates a session is also
ineligible. Unhandled encodings/derivations stay denied; do not claim complete
browser taint tracking or rely on entropy detection to prove safety.

## 5. Explicit, Finite Representation Profiles

Revision 3 selects a worker-issued, versioned representation reference. It does
not accept a caller parser name, raw body or replacement payload. The native
review explicitly confirms the representation and its evidence.

Initial profiles are deliberately narrow:

- `json-utf8-v1`: strict UTF-8 JSON object, no duplicate properties, comments,
  trailing content or implicit recursive interpretation of JSON-looking strings.
- `form-utf8-v1`: strict, unambiguous UTF-8 form pairs, one decoding step, unique
  decoded names, preserving pair order and original bytes in the private scope.
- `form-json-name-view-v1`: the same strict form parser must succeed first;
  exactly one pair is present, its value is empty, and its complete decoded
  name is a strict JSON object. Only that explicitly named review view unwraps
  the structured name. Mixed ordinary/structured pairs, duplicate keys, extra
  decoding, malformed UTF-8/percent encodings and ambiguous forms deny.

The third profile is a typed review view of a valid form request, not a claim
about how a particular server parses it. Handler/API or equivalent operator
evidence must identify the meaning of the original bytes. It never relabels the
Content-Type, rewrites the body or tries JSON after form parsing fails. There is
no content-type sniffing, compressed/base64 decoder or recursive legacy fallback.
The previous live metadata alone does not prove that this profile fits the site.

Apply the existing parser bounds consistently in JS and Python, with explicit
byte ceilings no larger than the old decoded limits: raw body at most 16 KiB,
raw query at most 8192 UTF-8 bytes, nesting depth at most 8, at most 100 object
members/array elements/form pairs, logical keys at most 128 UTF-8 bytes and safe
integers only. Reject dangerous prototype keys, controls and malformed Unicode.
The structured outer form-name carrier is bounded by the same 16-KiB body limit;
its inner logical keys retain the 128-byte bound. It is not an unbounded key
exception. Validate malformed-percent and strict UTF-8 behavior for query and
body, not only for the structured view. The stricter public-reference limits
in Section 6 still apply after parsing.

Bind the complete original Content-Type including supported charset parameters;
unsupported charsets or parameters deny. A source with a new encoding requires a
new supported profile/design, not an automatic second parser attempt.

## 6. Public References Without Exposing Unknown Values

The protected worker resolves a fresh denied network reference, inspects its
entire representation and mints opaque field/representation references. Keys
are data too. In particular, a JSON-shaped key is not exported wholesale as
innocuous `body_fields` before its contents have been classified.

Public status uses opaque references, positions/types, safe profile identifiers,
counts and fixed reason codes. It exposes neither unreviewed key text nor raw
unknown/private values, bytes, ordinary hashes, equality results or secret-source
details. This conservative projection also applies when an older status reader
encounters a structured key; it must not leak the raw key as a compatibility aid.
Apply it to every candidate-request public surface: pending-network summaries,
network-item previews, fingerprints/effect digests, authorization results, errors
and audit, not just one status endpoint. An old unkeyed hash must not disclose an
unknown value through a dictionary attack.

The same non-disclosure rule covers data-bearing path segments and non-fixed
header names/values. Native scope views show independently reviewed public
references, configured public site/account identity and fixed allowlisted
transport metadata. Otherwise they show opaque locations and remain
unapprovable. Private exact matching does not authorize displaying captured
unknown bytes. Already-public scope metadata is not proof that hidden components
are safe.

Prepare the independent public reference and operation/response evidence before
requesting native review. The current evidence kinds remain available: reviewed
source, API document, verified record, or independently operator-inspected
evidence. No specific source-code path or business integration is mandatory.
Evidence must explain deployment applicability, the data's public fixed value
and non-authentication role, operation effects and expected public response
schema. A requesting page, model-created note or evidence-kind label alone is
not independent evidence. The runtime records human attestation and its basis;
it does not claim to verify the truth of arbitrary external documents.

Inside the existing native review, the human supplies/checks the expected
PUBLIC reference literal or structured reference template from that independent
evidence. No credential may be entered. This input travels only through the
existing private native IPC; there is no public value parameter, secret file,
environment variable or command-line payload. The human may enter small public
references directly; a source path is not required.

The private authority compares that reference with the captured semantic view,
including all parameter/key locations. Unknown/private observed material is not
displayed merely to ask whether it is secret. The UI shows the independently
supplied public reference, not the captured unknown value, and a human-only
matching/coverage result. Nonmatching or incomplete coverage cannot approve.
Comparison results are not a public lookup/equality tool. Known private/auth
material is rejected before this comparison and remains unapprovable.

Logical-tree equality alone is insufficient to establish public data. The
independent public reference must also cover the complete data-bearing wire
representation: payload/query/path spelling, order, escaping and formatting.
It may be an independently reviewed exact PUBLIC wire reference, or a complete
public template plus an explicitly fixed finite profile serialization that
matches every such byte. These are native-only comparison inputs, never a raw
request to execute. If that complete coverage is unavailable, deny. A private
commitment to unknown bytes binds them but does not make them public; variation
hidden in whitespace or equivalent encodings must not become a covert payload.
This check does not reconstruct or replace the page-generated outgoing request.

Use a bounded typed reference tree with location IDs defined by representation
profile, container/pair position and semantic key path. Match exact key sets,
types, container kinds, array lengths, form pair order and scalar values. Empty
objects/arrays and all query fields are covered too; omitted fields cannot be
accepted. For the structured form view, bind the outer carrier, empty form value
and complete inner key/value tree to the same original bytes.

A review unit is each property/form-name key, scalar value or empty container;
the structured outer carrier counts once in addition to its semantic contents.
Nonempty container structure is matched in full even though it is not another
unit. Field refs cover their complete fixed key path, not only the final scalar.
For this first revision, public reference values are exact scalars, not ranges,
regexes, variable placeholders or expressions. Limit each string to 256 UTF-8
bytes, at most 8 review units per request and 24 per proposal. These are
additional narrow limits, not increases to existing item/manifest/preview quotas.
Oversized or more complex references need a separately bounded plan, not
truncation. Dynamic keys or values cannot inherit a fixed-literal declaration.

## 7. Proposed Public And Private Interfaces

Keep `remotex_web_authorization_request` and add a mutually exclusive revision-3
initialization-only shape. No raw-request, approve, cookie-export or browser-
attach tool is added. Illustrative schema shape, not a callable request:

```json
{
  "setup": {
    "revision": 3,
    "phase": "bootstrap",
    "requests": [{
      "network_ref": "<fresh owned denied reference>",
      "purpose": "initialization-read",
      "representation_ref": "<worker-issued exact representation reference>",
      "literal_review_refs": ["<worker-issued field reference>"],
      "max_uses": 2,
      "response_checks": [{"pointer": "/ready", "test": "equals-boolean", "expected": true}],
      "evidence": [{"kind": "operator-inspected", "reference": "<independent review basis>"}]
    }]
  }
}
```

The example response predicate is not a real site's contract. Preserve current
bounded count/pointer validation. The agent cannot supply public/private verdicts,
authentication roles, reference literal values, source provenance, headers,
cookies, raw method/URL/body, or approved semantics. Unknown/additional fields,
mixed setup revisions and caller-generated/foreign references deny.
The illustrated evidence input is only a proposed locator/kind to be assessed;
it is not attested source provenance. Only independent native human review can
record that attestation and its deployment applicability.

The original supervisor independently validates the complete bounded private
representation, evidence bindings and native decision. The worker cannot exempt
authentication accounting by labeling a packet public. Final private decisions
bind the reference-match commitment, coverage, field roles, effect review,
evidence, representation, requested reductions and existing nonce/request digest.
Human inputs are narrowing conditions, not a way to change the outgoing packet.

Capabilities/status explicitly advertise revision 3 and the supported profile
versions. Old clients/workers/supervisors reject the new shape before use. No
downgrade to revision 2, legacy setup, Login or ordinary Read is permitted.
Existing revision-1/2 grants do not acquire the new literal treatment.

## 8. Exact Outgoing Request And Transport Context

Use both a typed semantic contract and a private exact outgoing-request
commitment. The latter covers method, exact configured origin, outgoing path and
query representation, raw body bytes, complete supported Content-Type, resource
type, profile/view version and the effective outgoing header/cookie policy.
The reviewed grant intent also binds operation/evidence/readiness commitments,
account, trust/config snapshot, original supervisor/worker, session, requester,
queue acquisition and pre-auth lifecycle. It does not fix the grant to the
aborted observation's document/resume, since explicit same-session reloads remain
part of the existing initialization flow.

Keep a distinct execution receipt for each actual check. The supervisor mints
that receipt only after the new page-generated intent matches the still-active
reviewed grant, adding the CURRENT document, generation, resume and unchanged
check deadline. An old receipt never moves to a new page/resume; granting a scope
does not carry old readiness or create a fresh receipt by itself. The page or
caller cannot rebind either layer. No new cookie/value variability follows from
this distinction: changed exact intent still requires a new review.

This is application-request exactness, not hashing TLS/TCP octets. Compute the
commitment after the transport's existing fixed Host, Content-Length and identity
Accept-Encoding treatment, and send precisely that frozen intent. Define the
allowed header-name/order normalization explicitly; duplicate/ambiguous fields
deny. No caller-selectable exclusions or reconstruction of a cleaner body.
Construct one bounded immutable outgoing-intent object. That exact object must
supply both the commitment and the actual dispatch bytes/headers; the transport
must not call request body/header getters again or rebuild them after the check.
Capture reliable duplicate-preserving header information before map
normalization. If the supported browser interface cannot establish the required
unambiguous view, deny rather than claim duplicate detection. Private supervisor
validation, permit issuance and the post-certificate/pre-send guard all bind the
same intent version and commitment.

Use a domain-separated HMAC-SHA-256 commitment with a fresh supervisor-context
key held in protected memory, separately labeling grant intent and execution
receipts. Do not export
raw request/field hashes or a comparison oracle. Public identifiers and audit
references are opaque random IDs; public scope digests must not encode an
unkeyed low-entropy private value. Private context keys and captured bytes are
not persisted to files, arguments, environment variables or exported logs.

An approved grant does not replay the captured packet. After explicit resume,
the page must generate another request; compare its full frozen outgoing intent
with the reviewed scope at check/permit issuance and again immediately before
HTTP bytes can be sent, after certificate validation. Changed escaping, order,
charset, query, value, header or other bound representation requires new review,
even if the normalized objects compare equal. No automatic retry on mismatch.

### Headers And Cookies

Body review is not permission for hidden authentication elsewhere. Authorization,
Proxy-Authorization, custom authentication headers and actual account/auth cookies
are ineligible. Unknown security roles deny; a constant header is not necessarily
non-authenticating. No caller can add, import, export or edit these values.

Retain the existing internally managed same-origin pre-login cookie boundary;
do not turn cookies into public literals or claim same-origin proves safety.
For revision 3, any needed cookie context must be independently reviewed as
non-account, non-auth pre-login context, belong to the original owned jar/epoch,
and be bound privately in the exact outgoing intent. Its values stay hidden.
If the context cannot be enforced/established, or changes between review and
dispatch, deny this request rather than strip headers, import a jar, broaden a
cookie rule or fall back to the old behavior. No new dynamic-cookie exception or
cookie renewal mechanism is part of this revision.

The existing response-side cookie/authentication-negotiation rejection remains;
request-side cookie presence must not be confused with accepting Set-Cookie.

## 9. One Native Review, Still 120 Seconds

There is no untimed declassification/approval stage and no reusable public-field
certificate. Preparation of independent evidence grants nothing. All field and
operation decisions belong to the same original 120-second request review.

The English native window shows the exact site/account, request scope, proposed
representation, safe reference/coverage view, evidence basis, data status,
authentication role, Initialization Read effect, readiness predicates and limits.
Every classification starts Unreviewed. Known private/auth rows are locked out.

The human reviews the independently supplied public reference, confirms its
fixed/public status and non-auth role, and separately reviews Initialization Read
effects and response predicates. Select All or Apply to Checked cannot mark
unknown/private data public. A bulk effect choice cannot supply field judgments
or approve an incompatible mixed selection. The final Approve Selected remains
the sole authority-creating decision. Partial approval is supported, but omitted
or rejected required initialization rows continue to block credentials.
To keep review usable, the human may confirm a complete matched public reference
as one explicit data/role review group WITHIN one request and one independent
evidence basis; every covered unit is recorded. Sensitive-looking keys still
need an explicit role acknowledgment. Grouping cannot cross request/template
boundaries, include hard-private/unknown units, or be inferred from Select All
or an Initialization Read effect choice. The unit/coverage caps still apply.

The deadline starts when the request is created, not when shown, noticed or
activated. Evidence entry, parser review and native comparison use that same
budget. Late decisions are discarded. Keep shown/closed/error receipts and
remaining-review diagnostics; shown is not visibility, foreground or authority.
Notify immediately from the initial request result with truthful starting/shown
state, rather than delaying the first human notice for another status roundtrip.

Final commit rechecks the original immutable scope, human-added narrowing
conditions, queues/bindings/fences and quota under the existing authority rules,
with durable audit before any permit. Closing an active window revokes it;
revocation cannot undo work already accepted by a server.

## 10. Readiness, Four Grants And Unchanged Limits

Retain pre-auth-only applicability to Bootstrap and pre-credential Login-once,
explicit per-resume typed permission, and readiness for every fresh document.
All declared required reads must have received their approved responses, passed
their public predicates and settled; login controls must be visible before any
credential insertion. Requirements cannot be removed to bypass a rejection.

Keep response ceilings and checks: 64 KiB, strict UTF-8 JSON, no duplicate keys,
at most 8 checks and pointer depth 8; only type, nonempty-string, boolean equality
and safe-integer equality. No arbitrary predicate, response value export or
caller success flag. Predicates need reviewed public-state meaning, not merely
a harmless-looking pointer name. A hidden secret under /info is not eligible.
Reject redirect/error responses, unsupported encoding, Set-Cookie and
authentication negotiation before browser fulfillment or cookie application.

Preserve exactly: four active grants, one pending proposal, 32 setup items,
32 KiB combined contract/manifest, 4096-byte preview and 200-use combined cap;
existing per-row use limits; denied-ref capacity 100 and TTL 120 seconds;
startup 45 seconds, resume wrapper 55 seconds, check/permit 10 seconds,
native review 120 seconds, existing operation/action confirmation 30 seconds;
task grants up to 12 hours, sessions up to 13 hours with covering lease plus
45 seconds. All stronger source/session/lease/task deadlines still apply.

Private revision-3 snapshots, safe views and evidence commitments must fit the
existing 32-KiB combined contract ceiling, not a parallel unbounded side buffer.
No resource is claimed merely to prepare this design or collect local evidence.

Revision-2 static-only replacement is unchanged: at most two idle same-lifecycle
sources, every carried row, only remaining uses and the earliest deadline,
atomic durable retirement/activation and no fifth grant. Revision-3 initialization
grants are not replacement sources; public-field decisions never migrate through
replacement. Revision 3 does not add replace_grant_ids or a mixed resource mode.

A feasible capacity layout remains two consolidated static grants, one batch of
initialization reads, then the separate one-use Login grant. If a real plan cannot
fit existing limits, return setup-plan-capacity-required rather than auto-merge,
discard requirements or increase capacity. Retire pre-login authority after
authentication; authenticated page reading still needs separate native Read.

Possible authentication seals initialization and preserves no-resubmit fencing.
An uncertain initialization response consumes its issued count and remains
unresolved; approval never retries it automatically. A later explicit UI resume
may regenerate an exact reviewed read only within its remaining scope and
unchanged pre-credential bounds. It is not captured-packet replay.

## 11. Audit, Compatibility And Change Surface

Record observation/profile/reference IDs, evidence commitments, native field and
effect decisions, scope/limit changes, permit/forward/response/readiness outcomes,
revocation/expiry and fixed denial reasons. Preserve full-chain verification and
fsync-before-permit durability. Do not log templates, raw values/keys/headers,
cookies, payloads, credentials, private commitments or response contents. Private
IPC is versioned and bounded; stale/forged/cross-session messages fail closed.

Expected future modules are the existing network descriptor/profile parser,
initialization validators in JS and Python, contract/tool schemas, original
supervisor/private IPC/transport, native approval UI and focused tests/docs.
Do not edit unrelated launchers, SSH/RDP/VM/ESXi behavior, credential stores,
system trust/browser settings or center applications. Existing running sessions
are not adopted, restarted or silently upgraded. No automatic installation,
release or migration follows from approval of this draft.

## 12. Acceptance Required After Separate Implementation Approval

No tests or live operations are claimed for this proposed revision. Required
later evidence includes:

1. A reviewed public constant under a sensitive-looking name succeeds only after
   public-reference matching, non-auth/effect review and exact native approval.
   Same-name equality, public static API credentials, empty auth fields, unknown
   role/evidence and private markers remain denied.
2. Secrets under ordinary names, in keys, arrays, nested strings, path segments,
   header names/values and supported encoded forms never leak into
   status/UI/audit/errors or unkeyed fingerprints. Complete body/query coverage
   cannot exempt another component. Unsupported derivations deny; no claim of
   general JavaScript provenance is made.
3. Strict profile negatives: duplicate keys, plus/percent/double encoding,
   malformed UTF-8, unsupported charset, JSON string/object changes, mixed opaque
   fields and ambiguous interpretations cannot inherit a grant or trigger fallback.
4. Byte-different but decoded-equivalent requests fail private wire comparison.
   Bind actual outbound header/cookie treatment; test Authorization, custom auth
   headers, account cookies and cookie/charset/order changes before dispatch.
5. Independent evidence and expected-reference matching cannot be replaced by a
   model claim, forged kind label or requesting page. No equality/hash oracle or
   readiness test of secret-derived state is exported.
   A public logical tree with unreviewed data encoded in raw ordering, escaping
   or whitespace must fail complete public-wire-reference coverage.
6. Native partial/mixed/bulk cases, human time reduction, late decisions,
   stale callbacks, revocation during TLS and evidence changes fail closed.
   No fifth grant or count/deadline reset through resource replacement.
   Exact structural coverage, empty-container/key accounting, parser/reference
   limits and per-request review groups cannot bypass unreviewed units.
7. Real original-supervisor/worker/native-helper/Edge fixtures verify zero POST
   and credential bytes before review, approval alone sends nothing, exact resume
   plus responses/readiness works, and authentication cannot be resubmitted.
8. Verify every unchanged timing/quota bound, per-document sealing, full audit
   durability and mixed-version rejection. Run the complete applicable suite,
   independent review and exact-candidate Windows CI before any approved release.
9. Real target acceptance remains separate: fresh supported browser access,
   queue/trust admission, trustworthy effect/public-role/response evidence, native
   review, one authentication submission and separately approved current-page
   reading. No business write. Report unsupported cookie/representation/evidence
   conditions rather than declare the site supported from this design alone.

## 13. Items For Human Review

Review as one design, especially the explicit revision-3 boundary; strict named
form-name review view without a fallback; independent expected-public-reference
matching plus non-auth role review; exact private outgoing-request binding
including headers/cookies; and unchanged 120-second/four-grant constraints.

This proposal does not assert that the previous target's actual field, handler,
cookie context or readiness schema has passed those checks. Do not implement,
change configuration, publish, install or reopen a real session until the next
stages are explicitly approved.
