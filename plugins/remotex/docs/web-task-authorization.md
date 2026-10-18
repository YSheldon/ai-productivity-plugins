# Web Task Authorization

RemoteX 0.6.0 adds human-approved buttons, exact form input and scoped business
submission in the **same RemoteX-owned Edge session**. It does not adopt an
ordinary browser tab, share cookies, bypass host browser policy, or change the
center's business code. SSH, VM profiles and stored credentials are unchanged.
Use 0.6.1 or later for the native approval-window startup fix. For an interactive
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
- Requested TTL is 60-900 seconds, default 300; the human can lower it. The
  session and lease cap every grant. No executable grant is persisted.
- References expire after 30 seconds. Refresh component metadata after a page
  change or a stale reference; identity, uniqueness and before-state are checked.
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

## Startup and Login Contracts

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
MFA, CAPTCHA, unsupported request encodings and missing semantics remain operator
prerequisites. An isolated credential-free probe may report a missing contract
rather than opening an unrestricted page.

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
lower uses/output/TTL as needed, and choose **Approve Selected**. Rejecting a
prerequisite blocks its dependent items. The agent cannot approve itself.

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
