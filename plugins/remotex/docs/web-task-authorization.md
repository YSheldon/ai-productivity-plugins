# Web Task Authorization

RemoteX 0.6.0 adds human-approved buttons, exact form input and scoped business
submission in the **same RemoteX-owned Edge session**. It does not adopt an
ordinary browser tab, share cookies, bypass host browser policy, or change the
center's business code. SSH, VM profiles and stored credentials are unchanged.
Use 0.6.2 or later for native batch-review controls; 0.6.1 fixed native window
startup. Version 0.6.3 adds bounded startup scheduling and late-reply recovery.
Version 0.6.4 adds non-authorizing native-window lifecycle receipts.
Version 0.6.5 adds 12-hour task grants and durable startup audit event pairs.
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
- Requested TTL is 60-43,200 seconds, default 43,200 (12 hours), for exact
  approved read and write scopes. The human can lower it. The existing session
  and lease cap every grant; a short existing session is never extended.
  No executable grant is persisted, recovered across MCP processes or renewed
  automatically. Closing its active human window still revokes the grant.
- The review window remains 120 seconds, not 12 hours. New Edge sessions default
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

`shown` records a Windows Forms event. It does not prove foreground, the
operator's desktop visibility, human presence, approval or business completion.
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
behavior. These limits do not extend the 120-second native review, grant TTL,
quotas, session, lease or permission scope. Inspect the original session/outcome
after a timeout; never replay a request or retry potentially submitted credentials.

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
120-second review deadline, not the separately bounded lifetime after approval.
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
