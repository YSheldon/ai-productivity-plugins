# Web Task Authorization

RemoteX 0.6.0 adds human-approved buttons, exact form input and scoped business
submission in the **same RemoteX-owned Edge session**. It does not adopt an
ordinary browser tab, share cookies, bypass host browser policy, or change the
center's business code. SSH, VM profiles and stored credentials are unchanged.
Use 0.6.2 or later for native batch-review controls; 0.6.1 fixed native window
startup. Version 0.6.3 adds bounded startup scheduling and late-reply recovery.
Version 0.6.4 adds non-authorizing native-window lifecycle receipts.
Version 0.6.5 adds 12-hour task grants and durable startup audit event pairs.
Version 0.6.6 groups already queued static checks into bounded private audit
transactions; it does not combine or bypass their human-approved scopes.
Version 0.6.7 adds inline classification explanations and limit/lifetime tooltips
without changing authority or deadlines.
Version 0.6.8 adds explicitly reviewed pre-login Initialization Read POSTs and
bounded replacement of revision-2 static grants. Bootstrap remains GET/HEAD
only; ordinary Login and authenticated Read approvals remain separate.
Version 0.6.9 adds independent public-reference review with exact frozen egress,
180-second new reviews and non-authorizing native notification hints.
For an interactive
Windows regression, set `REMOTEX_TEST_NATIVE_APPROVAL=1` when running
`plugins/remotex/tests/test_web_approval.py`. Its synthetic helper uses no saved
credential, network request or approval, and closes only its own test window.

## Ownership and Limits

Use only after the host's supported browser interface confirms current access.
Retain the original MCP supervisor, requester, session, account, exact HTTPS
origin, TLS/pin snapshot and covering queue lease. A web lease acquisition has a
distinct identity; reacquiring with the same requester does not restore grants.
Never preempt another task or copy its identifiers.

- Requests contain 1-32 items, including separately approvable network sub-items,
  and at most 32 KiB of canonical scope data.
- At most four grants are active and one proposal is pending per session.
  A proposal has at most 200 uses across its rows; replacement includes all
  carried rows and their remaining counts in these same limits.
- Requested TTL is 60-43,200 seconds, default 43,200 (12 hours), for exact
  approved read and write scopes. The human can lower it. The existing session
  and lease cap every grant; a short existing session is never extended.
  No executable grant is persisted, recovered across MCP processes or renewed
  automatically. Closing its active human window still revokes the grant.
- New review windows last at most 180 seconds, not 12 hours; a narrower original
  deadline is preserved and existing reviews are never extended. New Edge sessions default
  to and are capped at 46,800 seconds (13 hours), with a covering queue lease
  plus 45 seconds. Use a shorter explicit session for short tasks. See
  [Login and lifetime](web-credentials.md#login-and-lifetime).
- References expire after 30 seconds. Refresh component metadata after a page
  change or a stale reference; identity, uniqueness and before-state are checked.
  Blocked startup descriptor refs retain their separate 120-second lifetime.
  A long task grant does not lengthen either reference lifetime.
- Reads are bounded to 100 rows, 30 columns, 16,000 text characters and 96 KiB,
  further reduced by the approved output budget. Hidden/editable/embedded content
  is not included in general projections. Field inspection needs its own item.
- Each grant has finite operation counts and at most 200 target-write
  reservations. Destructive or declared protection/access/irreversibility risks
  require an additional exact, one-use action-time confirmation, valid up to
  30 seconds. Write traffic is armed only around the checked operation.

This is a cooperative same-user authorization boundary, not an OS guarantee of
physical human presence against a compromised account. A malicious center can
also lie about its own semantics/state. Human-reviewed effect evidence and exact
request matching are not proof of an honest server.

## Tools

All session tools require `session_id` and the original `requester`.

| Tool | Purpose |
| --- | --- |
| `remotex_web_components` | Discover bounded control/region/table metadata and window geometry; no general content read |
| `remotex_web_action_prepare` | Create an immutable non-executable target/change preview from approved reads |
| `remotex_web_authorization_request` | Launch a local human batch approval window; return a pending request |
| `remotex_web_authorization_status` | Inspect decisions, effective bounds, expiry, quotas and blocked descriptor refs |
| `remotex_web_execute` | Execute one approved item with fresh references and an idempotency key |
| `remotex_web_execution_status` | Read the original outcome; optionally reconcile with fresh approved read receipts |
| `remotex_web_authorization_revoke` | Cancel a pending request, revoke a grant/items, or end task authority |
| `remotex_web_login_resume` | Resume the owned UI after startup-contract approval; never replay a captured packet |

There is **no approve MCP method**, credential-value argument, arbitrary selector,
script, browser-attach, cookie export, raw URL or raw HTTP API. The legacy
`remotex_web_observe`, `remotex_web_navigate` and `remotex_web_read_result` entry
points return `approval-required`; they are not bypasses.

### Native Window Receipts

In 0.6.4, request/status results include `approval_ui` for their own native
helper. Action-time confirmation receipts also appear in the original attempt's
execute/execution-status result. These fields are diagnostic only:

| Field | Meaning |
| --- | --- |
| `state` | `starting`, `shown`, `closed` or `error` |
| `shown` | Whether a valid native Shown receipt was received before termination |
| `review_remaining_seconds` | Conservative remaining review time, capped by the original broker deadline; zero after a decision or terminal state |
| `exit_reason` | Review expiry, operator rejection/revocation, window closure, helper exit, grant expiry, protocol error or server cleanup; null while no exit is reported |
| `error_code` | A fixed diagnostic code, never raw exception text |
| `helper_exit_code` | Observed process exit code, or null while unavailable; an intentional job termination can also be nonzero |
| `notification_state` | `not-requested`, `requested`, `shown`, `unavailable` or `removed`; separate advisory metadata, never a grant |

`shown` records a Windows Forms event. It does not prove foreground, the
operator's desktop visibility, human presence, approval or business completion.
Since 0.6.9 an owned NotifyIcon requests one Windows native notification after
the form's Shown event, with only RemoteX, the short opaque digest and remaining
seconds. Clicking restores/focuses only that same pending, unexpired form. It
does not select, classify, compare, approve or renew anything. Decision/close
disposes the icon. Windows suppression or notification failure leaves normal
approval in force; RemoteX does not change notification settings. Requested is
not delivered, and a shown event still does not prove the operator saw it.
Do not describe `starting` or a process handle as a displayed window. On an
unseen/closed window, inspect the receipt and actual remaining seconds instead
of reopening requests in a loop or treating cancellation as operator rejection.

Receipts travel on a separate inherited stderr pipe with request/nonce/digest
binding and a strict small schema. Only eight bounded receipts are parsed;
additional output is drained without retention. Raw stderr, payloads and binding
secrets are not exported. Diagnostics never call the decision/revocation path,
refresh a reference, extend a timer or grant permission. Stdout still accepts
only the original decision/revocation frames. Immediate launch failures retain
the existing `approval-ui-unavailable` error. Receipts are local to the original
supervisor, not a new cross-session recovery or approval surface.

## Startup and Login Contracts

### Startup Audit Persistence

In 0.6.5, one non-writing startup JS/CSS GET/HEAD permission commits its original
`execution-reserved` and `execution-finished` records together. The complete
existing audit chain is still verified under the same process/file locks; both
new records are hash-linked and flushed/fsynced before permission can return.
Since 0.6.6, already queued startup JS/CSS GET checks can share one transaction,
up to 16 checks and a complete 32-KiB private request. There is no collection
delay. Oversized single descriptors keep the old single-check path rather than
being truncated. Each request independently matches its original active human
contract, classification and count; no unapproved sibling inherits permission.
A transaction retains two records per permitted request, at most 32 records,
and verifies the complete old chain once. All records must be flushed/fsynced
before any true result; authority is rechecked per item after durability.
Private replies must contain every unique member. Cancellation, revocation,
generation changes and expired checks remain denied without replay. Root
documents, images, XHR/fetch, POSTs and business operations use the existing
single-check path. This internal scheduling does not change human review batches.

There is no trusted-prefix cache, skipped audit event, automatic ledger cleanup
or change to business-write recovery. Corruption, partial writes and failed
durability deny permission. Revocation is rechecked after the commit.

The startup deadline is still 45 seconds, the issued-check limit 10 seconds,
and the outer resume wait 55 seconds. Increasing task TTL does not change these
budgets or permit Bootstrap POST requests. Static/login grants are retired at
authenticated discovery; they do not become business permissions.

Network traffic is default-deny from worker startup: bootstrap, login-once,
discovery-only, then task-grant traffic. A profile's origin is not a blanket
request permit. The first request to an unreviewed login document is blocked.
Denied owned top-level documents receive a local script-free 403 with no-store
and restrictive CSP, without contacting the endpoint. Other denied traffic is
aborted. Resuming explicitly GETs the same configured document and restores its
client-side fragment; it never reloads a prior POST.

1. Start the authorized owned login using its saved credential and exact pin.
2. When state is `authorization-contract-required`, inspect authorization status.
   It exposes only blocked refs, phase, method/path and parameter names, not
   passwords, cookies, headers or raw bodies.
3. Inspect trusted source/API information or have the operator inspect the
   contract. Submit `setup` with the current `phase`, `network_refs`, bounded
   `max_uses`, and `evidence` through the authorization-request tool.
4. The local window shows the complete sanitized finite contracts. Select only
   understood document/assets/authentication exchanges. Authentication slots are
   filled internally; do not put their values in the request or chat.
5. After approval, explicitly resume the same login UI. A blocked packet is never
   held and replayed. A potentially transmitted authentication exchange is never
   automatically resubmitted. Unknown additional traffic needs another bounded
   review, not an unrestricted discovery window.

At verified authentication, login authority cannot be re-entered. Background
business polling is blocked unless separately covered by an active task step.
Startup grants are retired after authentication; they do not become task grants.
Blocked descriptor references expire after 120 seconds. An expired reference
stays invalid; only a new denied UI request can produce a replacement. Listing
status neither renews metadata nor grants permission, and expired entries cannot
exhaust the unchanged 100-reference capacity. A metadata refresh never replays
traffic or retries an authentication exchange that may already have been sent.
MFA, CAPTCHA, unsupported request encodings and missing semantics remain operator
prerequisites. An isolated credential-free probe may report a missing contract
rather than opening an unrestricted page.

### Bounded Startup Waiting

In 0.6.3, pre-authentication same-origin JS/CSS GET checks without query/body
fields share a queue of at most 64 checks, including one in flight. Unknown
resources still require an exact active human-approved contract. The queue is
not an origin or file-extension permission, and does not cache earlier permits.
All check types together retain the existing maximum of 16 emitted checks.

Every emitted check still has at most 10 seconds. Queued checks keep the original
startup operation's deadline and are denied on cancellation, phase/generation
change or expiry; a later resume cannot renew an older request.
Queued routes are checked for cancellation again before broker emission;
already-emitted checks can still consume quota even if forwarding is cancelled.
Known expired reply IDs are deny-only metadata, bounded to 64 entries and 60 seconds. Their late
reply is discarded once, never converted into permission or a command. Unknown
or malformed protocol messages remain fail-closed.

Document navigation and fragment restoration share one total 45-second budget.
Only `remotex_web_login_resume` may wait up to 55 seconds for its original result,
further capped by the existing session. Business operations keep their 30-second
behavior. These limits do not extend the 180-second maximum native review, grant TTL,
quotas, session, lease or permission scope. Inspect the original session/outcome
after a timeout; never replay a request or retry potentially submitted credentials.

### Revision 2 Initialization Reads

Some login pages need information-only POSTs before displaying their controls.
Since 0.6.8 these use **Initialization Read**, not a Bootstrap exception or a
business Read grant. Before proposing them, inspect trustworthy deployed handler
source/API evidence for each exact operation, side effects and actual encoding.
A frontend call, `get_*` name or HTTP 200 is not proof of read-only behavior.
Do not guess handler semantics or modify the center to fit the connector.

Revision 2 uses this mutually exclusive `setup` shape inside
`remotex_web_authorization_request`:

```json
{
  "setup": {
    "revision": 2,
    "phase": "bootstrap",
    "requests": [
      {
        "network_ref": "<fresh denied static ref>",
        "purpose": "bootstrap-resource",
        "max_uses": 4,
        "evidence": [{"kind": "operator-inspected", "reference": "<inspected static resource>"}]
      },
      {
        "network_ref": "<fresh denied initialization ref>",
        "purpose": "initialization-read",
        "max_uses": 2,
        "evidence": [{"kind": "source-review", "reference": "<deployed handler revision and effect review>"}],
        "response_checks": [{"pointer": "/ready", "test": "equals-boolean", "expected": true}]
      }
    ],
    "replace_grant_ids": []
  }
}
```

The example is synthetic; `/ready` must not be assumed to exist in a real
response. Supply the usual owned `session_id`, `requester`, stable
`idempotency_key` and optional `ttl_seconds` outside `setup`. `phase` must match
the original supervisor's current `bootstrap` or `login-once` phase. Only fresh
opaque denied refs are accepted, not caller-provided URLs, bodies, headers,
lifecycles, approval labels or private receipt IDs. Do not combine revision 2
with legacy `network_refs`/top-level setup `evidence`/`max_uses` fields.

| Purpose | Exact scope | Native Effect Review |
| --- | --- | --- |
| `bootstrap-resource` | Bodyless static document/script/style/image/font GET/HEAD | Bootstrap |
| `initialization-read` | Reviewed non-secret JSON or form POST, XHR/fetch only | Initialization Read |

Each row needs 1-8 bounded evidence references and allows 1-10 uses, default 2.
Initialization rows need 1-8 `response_checks`; static rows forbid them.
In the local window, classify static and initialization rows in separate
compatible selections, then use **Approve Selected**. Applying Bootstrap to a
mixed checked batch refuses the update. Partial approval of new rows is valid
but does not remove an unapproved initialization prerequisite.

Response checks are fixed structural predicates on reviewed JSON pointers:

| `test` | Additional field |
| --- | --- |
| `type` | `expected`: object, array, string, boolean, integer or null |
| `nonempty-string` | None; the selected value is never returned |
| `equals-boolean` | Boolean `expected` |
| `equals-integer` | Safe integer `expected` |

Pointers have at most eight segments and cannot select authentication/secret
paths. There is no arbitrary script, regex, string-equality oracle or body export.
The response must be a bounded 2xx UTF-8 JSON document, at most 64 KiB, without
duplicate keys, ambiguous encoding, redirects, authentication negotiation or
Set-Cookie. Validation happens before browser fulfillment; cookies and response
values are not copied into tools, receipts or audit records. The reviewed page
can use its own initialization response internally.

Revision-2 scopes have a fixed, visible applicability to Bootstrap and
**pre-credential** Login-once. Declared required reads are append-only for the
original pre-auth lifecycle. Every new document must satisfy them again, with
no unsettled initialization calls and visible configured controls before the
worker can arm credential insertion. Status reports fixed required/ready/pending
counts, not selected values or private permits. Approval alone sends nothing;
explicitly resume the original UI to make new checks and requests.

An unexpected second top-level document navigation before the final UI login
submission invalidates that resume and closes only its owned browser;
completed or delayed responses cannot carry readiness into the new document.
Normal same-document fragment/history navigation is not a replacement. The
owned launch retains disabled back/forward caching, so fresh HTTPS documents
cannot bypass the navigation-request guard through a cached document restore.
After confirmed closure, a new owned session needs its own review, not recovered
grants or an automatic credential retry.
Starting the final UI submit is not network permission: its exact Login
exchange still needs independent native approval.

The private supervisor binds each one-request initialization permit to the
original worker, check, resume, document, generation and expiry. A caller label
cannot exempt an ordinary POST from conservative authentication accounting.
Once any authentication might have been sent, initialization cannot reopen and
credentials cannot be resubmitted. An outstanding approved Login response may
finish within its original transport/session limits; a later explicit resume
can only verify that same document, never issue a second login. Revoking its
grant before verification fences the owned session. Unknown stays unknown.

Legacy setup remains supported without `revision`; it keeps its original
single-phase behavior and cannot be migrated silently to revision 2. Use its
observed one-use Login contract for sign-in. After verified authentication,
startup authority is retired and a separate native Read grant is still required
to export current-page content. Initialization is not general Read or Write
permission. Legacy authentication codecs, MFA/CAPTCHA and unknown effects stay
unsupported; no decoder fallback, raw HTTP replay or alternate classification.

### Bounded Static Grant Replacement

Revision-2 `replace_grant_ids` may explicitly name at most two active, idle,
same-session/lifecycle **static-only** source grants. The supervisor, not the
caller, copies every approved source row and its remaining uses. Init/mixed,
legacy, expired, revoked or foreign sources cannot be replaced this way.

Every carried row must be selected in the native window; new rows can be
partially approved and all counts/lifetimes can only be narrowed. The combined
proposal retains the 32-item, 32-KiB, 4096-byte per-preview and 200-use limits.
One effective deadline is the earliest of the human limit, every source,
original session and covering lease. A source expiring in 20 minutes cannot be
renewed to 12 hours, even if a new task's requested default is 12 hours.

Pending replacement blocks new forwarding/resumes/operations without stopping
an already running one: a busy worker refuses admission. Passive status,
cancellation and revocation remain available. After a durable audited commit,
the supervisor atomically retires sources and activates the approved destination
without ever exposing a fifth active grant. Source windows then close with
`grant-replaced`; a stale source callback cannot revoke the destination.
A local button/title is not proof: read the server's final grant state.
Failure closes only the new helper and preserves still-valid source grants;
uncertain audit/worker state fences only its owned session.

For example, one root grant can be replaced by its carried root plus 24 static
resources, followed by 23 resources, then a mixed static/initialization batch.
That leaves a fourth slot for separately reviewed Login. This layout is not a
general capacity guarantee: inspect actual bytes, all carried rows and remaining
uses before requesting. `setup-plan-capacity-required` means choose a smaller
safe plan, not truncate carried scopes, reset quotas or raise the four-grant cap.
Expiry of a denied ref remains 120 seconds; new reviews are capped at 180 seconds;
neither replacement nor metadata readback refreshes them.

### Revision 3 Public Reference Review

Revision 3 is a generic compatibility protocol, not a business API allowlist.
Inspect loaded `setup_revisions` and `initialization_profiles` in the original
supervisor's status. Installing new files does not upgrade an old running worker;
missing/mixed worker or native components fail admission before credential access.

The three explicit profiles are `json-utf8-v1`, `form-utf8-v1` and
`form-json-name-view-v1`. The last requires a valid form with one structured
JSON-name carrier and an empty value; it is not automatic recursive decoding.
Structured query names are unsupported and cannot borrow this body-only profile.
Unsupported UTF-8/charset/percent spelling, duplicate/prototype keys, unsafe
numbers, unknown roles and real authentication/private slots stay blocked.
`userSession` is not automatically safe or private solely because of its name.
Public API keys, tokens and actual session material cannot become initialization
authority merely by being constant.

Public discovery exposes opaque request, representation and complete literal
refs for v3-only candidates, with positions/types/counts, never their captured
path, keys, headers, values or hashes. Legacy-safe discovery retains its existing
descriptor contract; v3-only requests cannot downgrade through it. Build a setup
using only fresh refs and independently proposed checks/evidence:

```json
{
  "revision": 3,
  "phase": "bootstrap",
  "requests": [{
    "network_ref": "<fresh opaque request ref>",
    "purpose": "initialization-read",
    "representation_ref": "<owned named-profile ref>",
    "literal_review_refs": ["<every literal ref, in the observed order>"],
    "max_uses": 2,
    "evidence": [{"kind": "api-document", "reference": "<deployed independent contract>"}],
    "response_checks": [{"pointer": "/ready", "test": "equals-boolean", "expected": true}]
  }]
}
```

This is a shape example, not the real site's schema. Do not guess `/ready` or
accept a `get_*` name, frontend call or HTTP success as effect evidence. V3 accepts
no raw public request values, caller approval flags, resources or replacement IDs.
Do not mix V2 and V3 initialization contracts within one preauth lifecycle;
existing V2 static and separately approved Login scopes remain usable.

In **Review Public Reference**, the human independently supplies complete public
wire-reference JSON: `profile_id`, `target_text`, `content_type`, `body_text`,
`public_headers` (ordered name/value rows). Include exact supported spelling,
spacing, ordering, escaping and every non-fixed effective header. The reference
does not come from copying an unknown intercepted value, and cannot change the
outgoing request. Separately review public invariance, non-auth role, deployed
initialization-read effects, source/revision/deployment/basis and response
predicates. A sensitive-name acknowledgment and original cookie-role evidence
are required where indicated. Real secrets must never be entered here.

**Compare Public Reference** is a bounded private comparison, not approval. Edits
invalidate its proof. Only a complete current match enables **Approve Selected**;
Select All and Apply to Checked cannot create reference judgments. Partial
approval leaves all declared prerequisites required. The original supervisor
must durably commit and report active authority before explicit UI resume.

Bounds: 32 complete reference units/request, 96/proposal, 32 KiB including capture,
view, context and native manifest, 32 items, 200 uses, four active grants, one
pending review. Path segments, keys, values, containers and all non-fixed public
header names/values count. Fixed transport headers are still exactly bound.
Split an oversized plan without dropping fields or increasing ceilings. The
original 180-second maximum includes reference comparisons and final commit;
comparisons are at most 10 seconds, one outstanding and eight attempts/proposal.

Forwarding consumes the newly captured immutable request, not a reconstructed
payload or a replay. Private memory-only proofs bind source and effective headers,
wire bytes, context and current resume/document/generation. An original-cookie
snapshot is checked at capture, permit preparation and after TLS before HTTP;
attribute-only changes also deny. Cookie bytes are not regenerated or exported.
Only exposed attributes of the pinned browser API are covered: snapshots cannot
prove absence of transient A-to-B-to-A changes or attributes the API omits.
Unsupported or ambiguous contexts fail closed; this is not universal taint tracking.

Initialization remains pre-credential only, with strict 64-KiB response validation
before fulfillment and no Set-Cookie/auth negotiation/redirect/unknown encoding.
Revocation invalidates issued work; expiry blocks delayed readiness and arming.
No business write follows from initialization. Obtain separate Login, then Read,
and never resubmit a potentially sent authentication exchange.

## Approve a Read or Button Batch

Discover components. Copy the returned `observationId` to `observation_id` and a
specific component's `ref` to `component_ref`. Request a batch such as:

```json
{
  "session_id": "<owned-session-id>",
  "requester": "<stable-requester>",
  "idempotency_key": "inventory-review-1",
  "ttl_seconds": 300,
  "items": [
    {
      "item_id": "inventory",
      "capability": "web.read_table",
      "observation_id": "<fresh-observation-id>",
      "component_ref": "<observed-table-ref>",
      "max_uses": 2,
      "limits": {"rows": 20, "columns": 6, "bytes": 32768}
    }
  ]
}
```

The human window starts with unchecked approval boxes. It shows the origin,
account, request digest, requested operations and details. Select items/targets,
lower uses/output/TTL as needed, and choose **Approve Selected**. **Select All**
and **Clear Selection** change only the approval checkboxes. To classify a
compatible checked batch, explicitly choose an **Effect Review** value and use
**Apply to Checked**. Mixed or unknown effects refuse the whole update; review
those rows separately. Non-network rows stay Not applicable. Neither batch
control grants authority or sends a decision; final approval is still separate.
The read-only Scope column and its tooltip show the sanitized request label,
while full details remain available. The countdown shows the existing
180-second maximum review deadline, not the separately bounded lifetime after approval.
Rejecting a prerequisite blocks its dependent items. The agent cannot approve
itself.

Network effects start **Unreviewed**, not implicitly read-only because their
parent is a navigation/query control. The operator must independently inspect
the effect/evidence and select the matching **Effect Review** classification.
A proposed business write cannot be classified as a read to avoid its draft,
targets, uncertainty journal or final confirmation. Unknown effects stay denied;
selecting Business Write for a non-business proposal requires a new matching
target/change draft, not a broader endpoint permission. The classification is
bound into the effective scope digest and has no model-facing approval field.

After status returns the effective grant, execute the selected item with its
`grant_id`, `item_id`, fresh references and a stable execution idempotency key.
`web.navigate`/`web.page_step` click the exact observed control; `web.query_input`
fills/selects/checks the exact approved non-secret literal. Region/table reads,
field inspection and passive result projection are separate capabilities.

Unknown requests caused by an approved local UI step are aborted. Add their refs
and inspected `network_evidence` to a subsequent request. Network rows are
independently selectable; approving a button does not approve its requests.
The initial implementation matches exact supported JSON/form descriptors rather
than arbitrary predicates or endpoint/method wildcards.

### Approval Help

The Effect Review dropdown shows an adjacent explanation immediately. Selecting
a grid row shows that row's current classification above its full details;
changing the batch dropdown does not classify that row or approve it. Compatible
checked rows change only when **Apply to Checked** is used. Help wraps at narrower
window widths without covering the commands.

| Classification | Meaning |
| --- | --- |
| Unreviewed | Effect/evidence has not been independently reviewed; no network permission |
| Bootstrap | Exact startup document/assets GET/HEAD only; no POST or business changes |
| Initialization Read | Reviewed exact pre-login POST with required bounded response checks; no authentication or business changes |
| Login | Exact reviewed sign-in exchanges for the bound site/account, not business permission |
| Read | Reviewed information retrieval without business changes; the HTTP method alone is not proof |
| Business Write | Exact target/change preview required; high-risk operations additionally need one-use confirmation |
| Not applicable | Non-network item with no network-effect classification; explicit approval is still required |

Hover over **Uses**, **Rows**, **Columns** or **Bytes** to inspect the execution or
read-output limit. **Lifetime (seconds)** bounds the authorization represented by
this window: task grants allow up to 43,200 seconds (12 hours), while one-use
action confirmations allow at most 30 seconds. The request, session and lease
may lower these bounds; neither extends the separate 180-second maximum pending review.
Limits can only be narrowed. **Approve Selected** is the final decision.
**Revoke** or closing an active task-grant window stops that grant. Cancelling
an action confirmation does not itself revoke its parent grant; revocation
during an in-flight operation can fence/close the session. None of these actions
can undo work already accepted by the server.

## Prepare a Business Write

First obtain approved table/field read receipts. Preparation accepts only observed
controls, opaque target/read refs, non-secret proposed values and effect evidence.
It does not select a checkbox, fill a field, click, or send a center request.

- `target_refs` must resolve to stable current table identities from approved
  reads. An ambiguous/absent identity is unsupported, not a row-position target.
- `target_state` maps changed business fields to exact observed table headers
  and proposed `after` literals. The preview obtains each target's actual `before`
  value from the authorized read, not from a destination input's default value.
- `changes` bind observed input controls and their approved inspection receipts
  to exact fill/select/check values. Execution rechecks both resource and input
  before-state, versions and current control identity before mutation.
- `effect` declares create/update/delete/assign/command/cancel/compensate semantics,
  affected fields, risks and source/API/verified-record/operator evidence.
- Each write `network_ref` needs a `network_bindings` entry mapping its supported
  request's exact target path and changed-field paths. Target IDs and approved
  values must mechanically match. Partial target approval narrows the transmitted
  target list; unapproved IDs, extra target locations and changed values refuse.

Show actual target IDs, resource before/after values, risks and restoration needs
to the user. Honor any requested chat preview checkpoint **before** requesting a
real business write grant. A generic implementation approval is not that write
confirmation. Then attach `action_draft_ref` to a `web.business_action` item and
request its UI/network batch through the native window.

The initial executor supports visible stable table targets with one checkbox per
row and observed single-page controls. Modal preparation can use separately
approved local steps. Unsupported selection widgets, missing target state,
unknown semantics, ambiguous controls and required but unenforceable server-side
CAS fail closed. No server URL or menu is compiled into the plugin. Extending a
site's unsupported control/contract shape requires a reviewed plugin change,
not changes to the center or a generic-script escape hatch.

## Results, Uncertainty and Revocation

Execution metadata distinguishes verified reads, pre-dispatch refusal, partial
results, accepted/running work and unknown outcomes. A button click, HTTP 200,
empty list or `nResult=0` alone is not verified business success.

For supported updates, perform a **new separately approved table read**, then
pass its `receipt_ref` in `read_receipts` to execution status. The worker checks
the original target identities and desired values; the model cannot submit a
success flag or fabricated result body. Unsupported job/deletion/global-result
reconciliation remains unknown and is not silently treated as successful.

Potentially dispatched writes create a protected, keyed deny-only local fence.
Until canonical server effect maps are available, that fence covers the entire
target object rather than caller-supplied field labels. This conservatively
blocks even different-field writes to an unresolved target; renaming a label
cannot bypass it.
Changing the idempotency key, grant, value or session cannot bypass an unresolved
overlapping write. After restart, grants are gone and uncertainty remains; there
is no automatic retry or model-facing force-clear. Investigate the original
outcome and use reviewed reconciliation/compensation, not a second click.

Closing an active human authorization window stops its own grant, not unrelated
readback grants. Rejection, pending cancellation and normal expiry are scoped
too; a late decision cannot restore fenced authority. API revocation
supports an own pending request, grant/item subset, or `end_task=true`. Revocation
during an active operation fences/closes the owned worker; unavailable audit
storage cannot keep forwarding alive. Already accepted remote work cannot be
undone by local revocation. Finish owned cleanup and read back closed state before
releasing the queue. Never close another requester's browser.

Audit records retain hashes, IDs, bounds, counters and outcome metadata, not page
text, form values, headers or credentials. The host may retain approved tool
outputs in conversation history. Runtime/fixture/CI, installed version, actual
authentication and real business acceptance are distinct evidence.
Authorization context survives the outer MCP audit and serialization. A final
transport check prevents buffered content being released after revocation or
expiry; bytes already logically committed to the pipe cannot be recalled.
Known credentials in URL paths, dynamic field names or other descriptor strings
are rejected before they can enter pending-request metadata.
Credential-bearing control metadata cannot mint action references, and tainted
target identities/versions cannot become write-draft targets. Exported route
metadata is redacted too; credential filtering is not limited to visible cells.
