# RemoteX Pre-Login Initialization Read Authorization

Status: review draft only. Not implemented, committed, published or installed.
Baseline: RemoteX 0.6.7, main commit
`93547d95b1a952810989e262d54ec972d0e9a504`.
Date: 2026-10-18, America/Tijuana.

## Review At A Glance

- Approve exact Initialization Read contracts in the native window; do not widen
  Bootstrap or infer read-only effects from POST/GET or get_* names.
- Keep resource and initialization permissions explicitly pre-authentication-only;
  preserve exact scopes across necessary same-session pre-login reloads.
- Require reviewed initialization readiness before inserting credentials, and a
  separate Login approval before the authentication request can forward.
- Preserve four active grants through explicit, bounded resource-only replacement,
  not automatic merging or a higher quota. This is a distinct review decision.
- Use a supervisor-bound permit type for authentication accounting. A caller label
  must never suppress the possible-authentication/no-resubmit fence.
- Keep all deadlines and isolation boundaries; unsupported effects, encodings or
  authentication-state changes remain denied. No center business-code changes.
- This is a proposed protocol and acceptance plan, not an implemented fix or a
  claim of successful target login.

## 1. Goal And Scope

Allow necessary, individually reviewed initialization POST requests before login
controls become usable. Authorization must come from the existing local human
window, not from an agent's classification, a command name or an endpoint match.

Retain credential isolation, supported host-browser access, exact HTTPS origin,
account, certificate/trust snapshot, original supervisor/browser session,
requester and queue-acquisition identity. Preserve all existing time and quota
limits. Do not modify the center's business code or expose a raw HTTP API.

This draft authorizes no real request or implementation. Design approval would
permit preparation of an implementation plan, not an unreviewed deployment or
real business write.

## 2. Evidence And Its Limits

The last 0.6.7 live attempt obtained four real native approved/active grants:
the initial document, two script/style batches and three additional static GETs.
No grant had expired or been revoked at the failure checkpoint. The final resume
issued 51 permissions in approximately 14.2 seconds, below the existing 45-second
startup budget. A permission record is not proof that its HTTP response completed.

The worker remained in `bootstrap`, with `loginSubmitted=false`,
`authenticationVerified=false` and denied POST descriptors for `/inter`.

Corresponding local frontend source performs `get_production_info`,
`get_db_info` and `get_guid_info` initialization POSTs. Its database-info success
callback sets the flag that makes the login controls visible. Current RemoteX
requires those controls to be visible before entering `login-once`, but
`setupContracts()` rejects Bootstrap POSTs. This identifies a protocol gap.

These command names are candidates for this site's review, NOT a built-in
allowlist or proof of read-only server behavior. Their deployed handler effects
and actual supported wire encoding still need trustworthy review. If a handler
creates configuration, rotates an identity or mutates business state, it is not
eligible for Initialization Read, even if login needs it.

Important implementation constraints already present:

- At most one pending request and four active grants.
- Startup descriptors expire after 120 seconds; listing does not refresh them.
- Changing phase invalidates in-flight checks. Existing setup scopes match one
  phase, so silently carrying an old grant into another phase is not acceptable.
- In `login-once`, every forwarded non-GET/HEAD currently increments the
  possible-authentication counter. Initialization POSTs need a trusted distinction,
  or they would incorrectly trigger the no-resubmit fence.

## 3. Alternatives And Decision

Recommended: add a distinct `initialization-read` purpose to a versioned setup
contract. It is a logical pre-login substage, not a new unrestricted network
phase. The existing Bootstrap classification remains GET/HEAD-only. Explicit
pre-authentication phase applicability is shown in the native scope.

A separate physical `prelogin-init` network phase is possible, but requires
additional phase handoffs, document reload contracts and grant migration. It
does not itself solve the four-grant limit or authentication accounting. It is
not the proposed first revision.

Do not permit all `/inter` POSTs, all `get_*` commands, same-origin requests in
general, or a profile-configured wildcard. Do not relabel these requests Login,
ordinary Read or Business Write to make an existing decoder accept them.

## 4. Purposes And Lifecycle

Introduce native **Effect Review: Initialization Read**, with internal semantic
value `initialization-read`. It is independent of the existing Bootstrap, Login,
Read and Business Write classifications.

The physical state sequence remains:

```text
bootstrap -> login-once -> discovery-only <-> grant-active
     any live state -> fenced/closed
```

Version-2 setup scopes have explicit purposes:

- `bootstrap-resource`: exact document/script/style/image/font GET/HEAD, no body.
- `initialization-read`: exact reviewed POST with non-secret, fixed parameters,
  needed before credential submission. No other method or transport is added.
- Login authentication retains its separate exact, one-use Login scope.

New resource and initialization-read scopes may explicitly cover
`bootstrap` and the pre-credential portion of `login-once`. This phase set is
fixed by the revision-2 protocol, shown to the human and included in the scope
digest. It is not caller-selectable. Existing revision-1 grants keep their
original single-phase meaning; they are not migrated or extended.

Every initialization permission additionally requires a currently active,
supervisor-bound explicit startup resume. The original startup context supplies
an immutable deadline, cancellation signal, phase/generation and private resume
identity. No request may borrow a context from another resume or page. A long
grant does not authorize idle polling or background requests between resumes.

The initial unapproved POST is aborted. Approval does not store or replay that
packet. A later explicit `remotex_web_login_resume` navigates the same configured
document and the page may issue a new request, which is checked again.

Before credentials are inserted into a document, all declared required
initialization reads must have received their permitted responses and passed
their reviewed readiness checks, no such request may be unsettled, and the
configured login controls must be visible.
Response receipt is a prerequisite receipt, not proof of an honest server or
successful business activity.

All Initialization Read rows in the reviewed plan are required in this first
revision. Partial approval permits only the selected reads but cannot satisfy
the omitted prerequisites or start login. Requirements are append-only during a
pre-authentication lifecycle; an agent cannot remove a rejected prerequisite or
mark it complete. A wrongly declared requirement must be resolved with the
operator, not silently downgraded.

Credential insertion seals initialization for that document. A new explicit
resume may reopen the reviewed initialization purposes only after replacing the
old document and confirming that no authentication exchange has possibly been
forwarded. It does not restore old in-flight checks or their deadlines.

Once authentication might have been forwarded, initialization cannot reopen.
Retire initialization/resource scopes; retain the original no-resubmit fence.
After verified authentication, no pre-login scope can become a task permission.
Post-login page reads still require their own native-approved Read items.

## 5. Versioned Setup Request

Keep the current public tools. Add a strict, mutually exclusive revision-2
shape to `remotex_web_authorization_request.setup`; legacy setup arguments
retain their existing behavior. There is still no approve or raw-network tool.

Illustrative proposal, not callable on 0.6.7:

```json
{
  "setup": {
    "revision": 2,
    "phase": "bootstrap",
    "requests": [
      {
        "network_ref": "<fresh opaque static descriptor reference>",
        "purpose": "bootstrap-resource",
        "max_uses": 4,
        "evidence": [{"kind": "operator-inspected", "reference": "<review reference>"}]
      },
      {
        "network_ref": "<fresh opaque initialization descriptor reference>",
        "purpose": "initialization-read",
        "max_uses": 2,
        "response_checks": [{"pointer": "/exist", "test": "equals-boolean", "expected": true}],
        "evidence": [{"kind": "source-review", "reference": "<reviewed handler revision and digest>"}]
      }
    ],
    "replace_grant_ids": []
  }
}
```

`phase` must equal the worker's current pre-authentication phase. The caller
supplies only opaque references, proposed purposes, bounded counts and evidence.
The worker resolves the actual descriptor. The caller cannot submit a URL,
method, payload, selector, cookie, header, secret or approved classification.

The normalized contract binds method, exact path, full canonical query/body,
content type and encoding, resource type, purpose, declared phase applicability,
readiness checks, prerequisite identity, evidence commitment, quotas and the existing session/
origin/account/trust/queue binding. Descriptor or binding changes require a new
review; no endpoint-only or field-name-only permission is accepted.

Existing strict JSON/form parsing remains in force. Duplicate keys, ambiguous
parameters, unsupported encodings, oversized descriptors or credential-bearing
dynamic keys remain unsupported. Do not add a generic content-type-sniffing or
legacy-body fallback in this revision. The site's actual encoding must fit the
supported contract before it can be authorized.

Advertise revision-2 support in read-only capability/status metadata. Old
clients and servers fail closed on unsupported revision/purpose; they do not
fall back to a wider legacy request.

## 6. Eligibility And Credential Isolation

An Initialization Read proposal must satisfy all structural requirements:

- Actual observed POST from the owned page, using the existing guarded XHR/fetch
  route and exact configured HTTPS origin.
- Unambiguous supported encoding and exact non-secret literal parameters.
- No internal authentication slot, password, token, account-session material,
  challenge/signature response, credential-management action, upload or arbitrary
  header injection. Existing secret-taint and dynamic-key rejection still apply.
- No login/authentication command, configuration change, database reset,
  identity rotation, task submission, grouping change or other business mutation.
- Independent human review of effects against trustworthy handler/API evidence.
  A method, `get_*` name or agent-provided evidence string is not that review.

Source literals that resemble session fields are not automatically treated as
safe placeholders. Their exact observed values and role must be reviewed; any
actual authentication slot or unsupported/tainted representation remains denied.
No classifier can prove remote read-only semantics from packet syntax alone.

The native review starts Unreviewed. Only a matching native Initialization Read
decision can supply `approved_semantics=initialization-read`. The model cannot
set that field or downgrade an unsupported/write request by choosing a label.

No saved credential is injected into an initialization request. This revision
does not expose credential values or add a credential retrieval interface.
Any secret already held in the original protected worker/supervisor memory
retains its existing isolation and lifetime. No new secret file, environment
variable, command-line argument or conversation output is introduced.

Browser-managed same-origin pre-login cookies remain internal to the existing
guarded transport. They cannot be imported, supplied or exported by the caller.
Initialization responses may update the owned page's normal runtime state;
they are not returned as general tool output, screenshots or raw response data.

Readiness checks are part of the native-reviewed contract, not a general response
query interface. Support only bounded JSON Pointer paths and fixed tests for
type, nonempty string, boolean equality or safe-integer equality. No arbitrary
code, regex, string guessing or caller-supplied success flag. Use at most 8 checks,
depth 8, with a 64-KiB initialization JSON response ceiling (tighter than a general
transport ceiling, never an increase). Reject ambiguous JSON, redirects, errors,
unmet checks or authentication challenges before advancing. The actual deployed
schema must be reviewed; the example `/exist` predicate is not an assertion that
every site's field has that type.

The private worker evaluates these checks and exports only a fixed readiness
state and counts, never the selected values or the response. Readiness can mean
database-present or GUID-present without exporting a connection setting or GUID.
It is not proof of server read-only behavior. An initialization response that
attempts Set-Cookie or authentication negotiation is unsupported in this first
revision; it cannot silently create authentication state under a read permit.
Inspect these headers and the bounded response before fulfilling the route or
applying any cookie. Readiness predicates cannot target credential/token/session
fields or act as a general secret-existence/equality oracle. A missing required
field, non-success transport status or failed predicate leaves login blocked.

## 7. Native Approval

Each request row shows purpose, exact method/path, sanitized non-secret
parameters, read-effect evidence, phase applicability, required-prerequisite
status, remaining/requested uses and lifetime. UI text remains English.

Suggested adjacent help:

`Initialization Read: reviewed pre-login initialization only. Exact POST;
no authentication, configuration changes or business writes.`

Mixed static/read batches retain independent checkboxes and classifications.
Apply to Checked must refuse incompatible mixed effects; it does not silently
classify an entire batch. Select All, help and classification do not approve.
Approve Selected remains the only final native decision.

The operator can approve subsets and reduce limits/lifetime. Missing required
initialization items leave login blocked. Closing an active window revokes its
remaining authority; revocation cannot undo work already accepted by the server.
Use the existing shown/closed/error and remaining-review diagnostics, without
equating shown with foreground, human presence or approval.

## 8. Four-Grant Capacity And Bounded Replacement

Do not raise the four-active-grant limit. The live flow already used all four
slots before an initialization or authentication grant could be added. Simply
adding a new purpose would therefore leave a second integration blocker.

Revision-2 may propose replacement of at most two task-owned, active,
Bootstrap-resource-only grants. No initialization, Login, business or mixed
grant is a replacement source in this first revision. Sources must belong to
the same original supervisor, session, requester, acquisition and pre-auth
lifecycle, and must themselves be revision-2 scopes with identical phase
applicability. Revision-1 grants cannot be converted through replacement.
No arbitrary source descriptor is accepted from the caller.

The server copies every source item from its immutable approved scope and
remaining budget into the new native proposal, alongside new observed rows.
Combined carried/new rows must remain within 32 items and 32 KiB. The native
window explicitly identifies the replaced grants and carried permissions.

Replacement is not automatic consolidation or a quota renewal:

- All carried source items must be selected for replacement to commit; their
  counts/lifetimes can be reduced, never increased past the source remainder.
- The replacement grant's single effective deadline is the minimum of the new
  human-approved deadline, all carried source deadlines, session/lease and any
  stronger task deadline. New rows share that shorter deadline, visibly shown;
  there is no hidden per-item extension or source TTL reset.
- New rows may be partially approved. Missing new initialization prerequisites
  still block login.
- If a carried item is omitted, a source is revoked/expired, its remaining scope
  changes, or its binding no longer matches, do not commit replacement or issue
  partial new authority. Preserve still-valid source grants and report the
  specific blocked result. Close only the failed replacement's new helper; never
  leave it reporting an active replacement or close the source windows as though
  replacement had succeeded. Read-back status is authoritative, not a local
  button click or window title.
- No resume or operation may overlap a pending replacement. Require the source
  scope to be idle; do not terminate work to make it replaceable.
- After an actual native decision, recheck source scopes, counters, fences,
  bindings and the active-grant capacity under the existing authority lock.
  Durably record the transition before new permission can forward. Retire old
  grants and activate the replacement as one logical authority transition.
  A persistence failure fences the affected transition/session; never leave
  both old and replacement authority forwarding.
- A pending replacement is still the sole pending request. Admission may use
  `active - replaced_sources + replacement <= 4`; at no instant may more than
  four grants be active. An unapproved replacement grants nothing.
- Mark old requests retired before stopping their native helpers. Record
  server-driven replacement, not operator rejection. Closing an old retired
  helper cannot revoke or resurrect the explicitly approved replacement.

Recommended target-site batching, using synthetic counts only:

1. Approve initial document alone; observe the actual script/style denials.
2. Replace that document-only grant with a batch carrying its remaining scope
   plus the first 24 resources: one active grant, not two.
3. Approve the remaining 23 resources: two active grants.
4. Approve the newly observed three static resources and three initialization
   reads as a mixed, independently classified batch: three active grants.
5. Request the separately observed, one-use Login authentication contract:
   fourth slot available. No authentication is inferred or pre-approved.

If actual sizes differ, re-plan within the same hard bounds. Do not truncate
scope, reset counts or reopen earlier approval windows in a loop. If no safe
replacement plan fits, report setup-plan-capacity-required and stop.

## 9. Authentication Accounting And Private Permits

The existing Login counter conservatively counts all non-GET/HEAD forwarding
as potentially authenticating. Do not merely exempt a POST because its name or
caller-declared purpose looks like initialization.

Only the original supervisor may return a typed Initialization Read permit
after checking the actual active human scope, exact descriptor and pre-credential
resume context. Bind the private reply to the outstanding check ID, descriptor
digest, binding, generation/resume identity and expiry. Consume it once for that
actual request; no reusable permit cache or caller-facing token is added.

The route must validate the permit again immediately before forwarding. An
Initialization Read receipt may increment a separate initialization-forwarded
counter only while credential insertion is not armed for the current document.
It cannot suppress authentication accounting for another request.

Unknown, mismatched or stale permit types deny forwarding. Every other possible
authentication exchange retains the conservative authentication-forwarded counter
and doNotResubmit behavior. A missing or forged label never produces an exception.

After login controls and declared initialization prerequisites are ready, seal
initialization before typing/clicking the existing saved-credential flow. A fresh
owned document may use remaining reviewed setup scopes only if the original
supervisor still proves that no authentication exchange might have been sent.
After possible authentication forwarding, there is no return to initialization,
no automatic credential retry and no fence reset by a new key or grant.

## 10. Existing Bounds Remain

- Human review: original 120 seconds, not restarted by shown or a refresh.
- Requested task TTL: default/maximum 43,200 seconds; human may reduce it.
- New browser session: default/maximum 46,800 seconds; covering lease plus 45s.
- Startup document/fragment budget: one total 45s; resume outer wait 55s.
- Issued permission check: 10s. Initialization POST uses the ordinary check path,
  not static JS/CSS queue waiting or static audit batching.
- Business operation 30s and high-risk one-use confirmation up to 30s unchanged.
- One pending request, four active grants, 32 items/32 KiB per proposal, existing
  per-item preview/descriptor bounds, 100 denied refs with 120s TTL.
- Setup uses remain 1..10; proposed Initialization Read default is 2, not unlimited.
  Human may reduce them. No quota refund after a consumed/cancelled permit.
- Existing component-reference 30s lifetime, output bounds, write-target quotas,
  uncertainty fencing and business-write previews are unchanged.

Purpose scope may end earlier than the requested TTL. It cannot outlive the
original process, session, trust/configuration snapshot, acquisition, operator
business approval or applicable deadline. This design extends no existing grant.

## 11. Failure, Revocation And Audit

Permission denial occurs before HTTP forwarding. Recheck cancellation, current
origin/account/trust, phase/generation, resume deadline, queue ownership and
actual quota after durability and immediately before dispatch.

Unknown or changed request shape requires a new exact review. Expired descriptor
refs remain invalid; only a new denied UI request can mint a replacement. Status
does not refresh refs or grant authority. Reuse unchanged active grants while
their bindings and budgets remain valid.

After possible transmission, report response-received versus outcome-unknown.
Do not automatically replay an initialization POST on timeout. A later explicit
UI resume can issue a new reviewed read only under its remaining count and
pre-authentication guards; it is not a replay of a captured packet. Possibly
transmitted authentication still prohibits resubmission regardless of init state.

Audit separately: request/decision/grant, replacement source/destination digests,
scope/counter transition, permit-issued, network-forwarded, prerequisite-response
received, controls-ready, authentication-forwarded and authentication-verified.
Keep existing full-chain verification and durability rules. Store hashes, IDs,
counts, timing and fixed outcomes, not payloads, page text, headers, cookies,
credentials, GUID values or response contents. No ledger deletion/prefix cache.

If an active grant is revoked during forwarding, cancel/fence the affected owned
work as required by the existing rules. Do not undo accepted remote work or touch
another session. Close the owned browser, separately read back closed state, then
release only the own queue lease.

## 12. Compatibility And Proposed Change Surface

Existing running sessions are not adopted, restarted or granted new purposes.
No profile/credential migration or center deployment is required. New protocol
support is exercised in a fresh explicitly admitted session. Existing SSH, VM,
RDP, certificate and credential APIs are unchanged.

Expected later implementation modules, not edited by this draft:

- `web_task_contracts.mjs`: strict revision-2 setup normalization/purposes.
- `web_network_authorization.mjs`, `web_login_worker.mjs`, worker runtime and
  private IPC: pre-credential resume guards and typed forwarding receipts.
- `web_task_service.py`, `web_authorization.py`: independent native semantic
  validation, binding/count checks and bounded grant replacement.
- Native approval UI: Initialization Read explanation and explicit replacement
  scope; existing partial-selection controls and mixed-effect refusal retained.
- Tool schema, status diagnostics, English skills/docs and focused regressions.

No new raw-request, arbitrary script, cookie export, browser attach or approve
endpoint. No authentication-encoding workaround is included. If the real site's
authentication payload is unsupported, review that separate compatibility gap
rather than disguising it as initialization.

## 13. Acceptance Plan For A Later Approved Implementation

This is a test plan, not a claim that tests have run for this revision.

1. Synthetic real-Edge fixture hides login controls until required read POSTs
   finish. Before native approval, verify zero initialization POST/credential
   bytes reach the server. Approval alone still sends nothing.
2. Exact Initialization Read approval plus explicit resume completes only the
   selected requests and reviewed readiness predicates. Partial/rejected or
   malformed/error responses keep credentials untouched. No response/GUID value
   or authentication cookie is exposed through this capability.
   A separate Login grant and separate post-login Read grant remain necessary.
3. Prove old Bootstrap, ordinary Read and Business Write labels cannot authorize
   the new pre-login POST; changed commands/parameters, extra targets and wildcard
   requests deny before dispatch. Trusted evidence/human review remains required.
4. Reject internal auth slots, tainted keys/values, ambiguous JSON/forms, duplicate
   parameters, unsupported media types, oversized bodies and misleading get_*
   writes. No generic legacy decoder or HTTP fallback.
5. Real worker/supervisor tests prove typed receipts cannot be forged, substituted,
   replayed, reused after cancellation or used to suppress authentication counting.
   Only the exact permitted init POST avoids the possible-authentication counter.
6. Exercise fresh document reloads in both pre-auth phases, per-resume cancellation,
   partial plans and all first-byte/unknown authentication outcomes. No init scope
   works after credential arming for that document or after possible authentication.
7. Replacement tests cover four-slot admission, old/new native window lifecycle,
   source expiry/revocation/count changes, omitted carried rows, partial new rows,
   persistence failure and concurrent operations. Never widen counts or activate
   a fifth grant, and never resurrect revoked source authority.
8. Retain TLS/pin/validity/redirect, origin/account/configuration, lease/acquisition,
   host-browser-policy, zero-secret output, audit-integrity and no-replay suites.
9. Assert the unchanged 45/55/10/120/30s bounds, 12h/13h ceilings and descriptor/
   component TTLs. Initialization POSTs never enter the static-only batch path.
10. After design and implementation-plan approval: run the complete local suite,
    independent review and exact-candidate Windows CI. Publication/merge/install
    need their applicable approval, separate from approval of this design.
11. Real target acceptance: fresh queue admission and native windows; verify required
    initialization, one authentication submission and a separately approved current
    page read. No business write. Login, HTTP 200 or an init response alone is not
    business acceptance. Report any encoding, certificate, MFA or semantic blocker.

## 14. Review Decisions

Review this proposal as one design, especially:

- Independent Initialization Read purpose, with explicit pre-auth phase applicability.
- No arbitrary POST and no automatic read-only inference from method/command names.
- Bounded resource-only grant replacement to preserve the existing four-grant cap.
- Supervisor-bound typed permit accounting, not a blanket non-authentication exception.
- All existing credential, site, queue, lifetime and business-write boundaries.

Only this document is proposed now. Do not start implementation, change settings,
open remote sessions, publish or install until the subsequent stages are approved.
