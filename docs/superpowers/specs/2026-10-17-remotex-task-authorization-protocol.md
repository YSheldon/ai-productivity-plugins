# RemoteX Task Approval and Time Limited Authorization

Status: Proposed for human review. This document does not authorize implementation.

Date: 2026-10-17

Protocol: `RemoteXTaskAuthorization/v1`

Source baseline: `642855a0096830cea53b91abf38026ac749591c2` (RemoteX 0.5.12).

## 1. Decision and Scope

Replace the proposed site-specific menu allowlist with a task approval protocol.
An agent requests a bounded set of observed UI capabilities. RemoteX presents
the immutable request in a local human approval window. The human may approve
all eligible items, approve a subset with lower limits, reject, or cancel.
Approved items then execute without repeated prompts until their budgets or
deadlines expire. New scope requires a new decision; it is never learned into
an implicit permanent permission.

The first implementation applies to the existing isolated Edge web session.
It must support navigation to a terminal list and reading its current rendered
page without changing the management center. It does not introduce SSH, RDP,
VM, or infrastructure approvals; those existing mechanisms remain unchanged.
The protocol can later gain separately reviewed adapters, but an unknown
capability or protocol version is rejected, not passed to a generic executor.

The deliverable at this stage is this English repository design. No runtime
change, local configuration change, release, merge, installation, or real
business action is part of design approval. The previous two uncommitted
navigation tests are superseded design experiments, not passing release tests;
they remain untouched until an implementation plan handles them explicitly.

### Success criteria

- One batch can describe multiple operations and their dependencies.
- The user can reduce the batch, counts, output scope, and lifetime.
- A tool argument, page text, receipt file, or chat message cannot substitute
  for the broker's local approval decision.
- Execution is restricted to approved components and parameters in the same
  authenticated session with a current queue lease.
- Revocation stops new dispatches and reports uncertainty for work already sent.
- Audit correlates the requested scope, actual approved subset, and each attempt
  without retaining credentials, raw request bodies, or terminal inventories.

## 2. Existing Integration Points

These are source facts at the baseline, not claims that this design is shipped.

| Existing component | Current behavior | Required change |
| --- | --- | --- |
| `plugins/remotex/src/web_adapter.py` | `_control` checks original process/channel, requester, lease, deadline, and unchanged profile | Add broker authorization before any expanded post-login operation |
| `plugins/remotex/src/web_channel.py` | One serialized supervisor-owned pipe; timeout closes the worker without replay | Preserve command correlation; add a separate cancellation/authorization path that cannot wait behind a long command |
| `plugins/remotex/scripts/web_control.mjs` | Reads the success region, exports fragment links with 30-second references, follows links without click handlers | Separate authentication, discovery, and approved content scope; add typed component operations and current-page table projection |
| `plugins/remotex/scripts/web_login_worker.mjs` | Same-origin TLS/pin broker, offline Edge, blocked redirects/service workers/WebSockets, bounded lifetime | Check request-level authority before forwarding post-login traffic caused by approved operations |
| `plugins/remotex/src/audit_log.py` | Locked, fsynced, hash-linked JSONL with summarized tool data | Add explicit authorization events and pre-dispatch audit gating; do not treat generic summaries as a complete approval journal |

Current `confirm=true` is an agent-supplied parameter. Current requester strings
are cooperative identifiers, not authenticated chat identities. Neither is
proof of a human approval. The hash-linked audit detects inconsistencies in the
retained chain; it is not externally anchored or tamper-proof against its owner.

## 3. Security Boundaries

The following restrictions remain mandatory even after human approval:

1. Current access to the intended browser surface must be established through
   the host's supported browser interface. Denial, disabled access, or unknown
   access stops web operations. RemoteX still reports
   `browserPolicyAttested=false`; a caller boolean is not a trusted policy receipt.
2. Keep the exact HTTPS origin/account binding, existing system TLS validation
   or separately approved certificate pin, and certificate validity checks.
   Approval cannot add an origin, approve a new pin, or bypass a browser warning.
3. Keep credentials in the established local secret path. No passwords, cookies,
   authorization headers, private keys, credential exports, or secret values in
   tool arguments, approval manifests, logs, or receipts.
4. Keep the original MCP process, isolated browser session, queue owner, covering
   lease, authenticated state, profile snapshot, and worker lifetime.
5. Do not attach another browser, export sessions, enable arbitrary CDP or script
   execution, send raw HTTP, open external protocols, or admit cross-origin frames.
6. No privileged center actions, downloads/uploads, generic form submission,
   credential entry, MFA/CAPTCHA solving, or irreversible operations in v1.
   Such requests are rejected as unsupported, not hidden in a navigation batch.
7. Browser/site content and agent descriptions are untrusted. They cannot create
   a capability, lower a risk label, approve an item, or instruct the operator UI.

### What local approval proves

The native approval helper is a separate process owned by RemoteX. It receives
the manifest through a private inherited IPC channel and returns a one-use
decision bound to the broker's nonce and digest. There is no MCP/CLI approve
method, loopback approval URL, editable approval file, or `approved=true` field.

The helper renders plain escaped text, has no page JavaScript, and never sends
its decision nonce to the model. An absent window, helper error, timeout, or
noninteractive desktop fails closed. No default selection, Enter key on window
appearance, timer, or window dismissal grants permission. The agent must never
automate the approval window through computer-use tools.

This is a cooperative human-in-the-loop boundary, not an OS security boundary
against arbitrary same-user code. A process with the user's privileges can
potentially inspect/replace RemoteX or manipulate normal desktop UI. Native IPC,
ACLs, and a visible window do not cryptographically prove physical human input.
An administrator, a compromised broker, and same-user malware are outside this
threat model. A stronger requirement needs a separately reviewed trusted
host/OS authenticator; v1 must not claim that protection or silently emulate it.

Likewise, without a trusted host caller identity, `requester` and a client task
label cannot prove which chat issued a call. Bind execution to the original
broker session and grant, prohibit cross-session adoption, and describe this
limit honestly. Do not call a random grant ID authenticated agent identity.

## 4. Components and Ownership

- **MCP surface:** accepts requests and reports status/results; it cannot approve.
- **Authorization broker:** owns immutable manifests, grant state, counters,
  idempotency records, monotonic deadlines, and the final dispatch decision.
- **Approval helper:** shows the broker's exact scope and records the local
  human decision; it cannot add capabilities absent from the request.
- **Web worker:** owns page/DOM references, rechecks targets, executes supported
  primitives, projects approved output, and enforces broker request permits.
- **Local approval journal:** retains protected metadata and revocation records;
  it is not an executable authority source. Restart cannot reconstruct grants.

Reuse the existing supervisor and kill-on-close process ownership. Do not add
a public listener, cloud account, service daemon, or generic policy language.
The broker-to-worker cancellation/authorization channel must be independent of
the existing serialized operation response channel to avoid a revocation
deadlock. Its exact implementation belongs in the reviewed implementation plan.

## 5. Discovery Before Approval

Login retains its existing separately authorized credential flow. After verified
authentication, the new approval-enabled session enters `discovery-only` mode.
The login success marker remains an authentication check; it is not a content
or navigation root. Login authorization does not approve later business actions.

The worker can enumerate a bounded metadata-only component inventory outside
the success region: visible navigation containers, links, menu items, buttons,
tables and input types. It excludes hidden/editable values, document text,
terminal rows, embedded frames, canvases, scripts, and secret-bearing attributes.
It returns opaque references plus bounded role/name/type and structural context,
never executable selectors, handlers, or markup. Names are untrusted and may
still be sensitive; responses are not persisted in audit and are visible to the
calling host. Links with userinfo, queries carrying unknown data, unsupported
schemes, or cross-origin targets are not usable navigation candidates.

Limits: 100 candidates, 160 characters per visible label, 30-second observation
references, and a 32 KiB serialized inventory. Ambiguous, obscured, disabled, or
unsupported controls are marked unavailable and cannot be silently substituted.
Discovery itself is not permission to click, enter input, fetch data, or read rows.

Batch approval covers components already grounded in observations. Controls on
an unseen destination page cannot be granted by guessing a selector or by saying
"all controls on this site." The agent may include a non-executable future intent
in the task description, but it must discover that page and submit an incremental
batch before new controls or data regions become executable. This may require
one navigation approval and one read approval on a first visit; it is not a
prompt per row or per repeated approved operation.

## 6. Capability Contract

The primitive vocabulary is fixed for safety. The selected site components,
parameter bounds, data projections, counts, and lifetime are approved dynamically.
No center route, menu name, or business command is hard-coded into RemoteX.

| Capability | Dynamic scope | Prohibited expansion |
| --- | --- | --- |
| `web.navigate` | One observed link/menu control, source page binding, exact expected destination when known, visible destination confirmation | Arbitrary URL, selector, script, generic click, or silently accepting an unexpected destination |
| `web.read_region` | One observed region, explicit text limit | Whole document fallback, hidden values, editable content |
| `web.read_table` | One observed table, approved visible columns, current rendered rows, row/byte limits | Background inventory fetch, invisible rows, auto-pagination, exports |
| `web.query_input` | One non-secret query control and finite approved values or bounded numeric range | Passwords, auth fields, free-form secret input, arbitrary text, implicit form submit |
| `web.page_step` | Observed pager control, bounded step count, source table binding | Unlimited crawling, other tables, business command buttons |
| `web.read_result` | Existing passive numeric/boolean response projection | Sending/replaying requests or returning raw JSON payloads |

Changing an input can trigger page handlers and network requests. It receives
the same dispatch and request checks as a navigation, even without a submit
button. A generic UI role or a read-like label is not evidence of server semantics.
Unknown or write-like effects cannot be downgraded by an agent's purpose string.

An item includes `item_id`, capability, observation/component references,
preconditions, parameter constraints, expected postcondition, output limits,
maximum uses, and `depends_on` item IDs. The broker resolves immutable binding
facts; callers cannot override them. Allowed item dependencies form an acyclic
graph in the same request or an explicitly named still-valid parent grant.

For repeated operations, each invocation must supply a fresh observation and
component reference. The worker rebinds only when the structural fingerprint
matches the approved page/region/role/name/type/href or form semantics uniquely.
No fuzzy matching, ordinal-only selection, or best-match click is permitted.
Row counts, approved query values and page numbers may vary only within their
declared bounds. Changed labels, duplicate matches, changed actions/destinations,
or structural ambiguity require a new request. A changed node between checking
and action fails as `component-stale`; it is not retried on another node.

## 7. Requests and Grants

### Request envelope

`remotex_web_authorization_request` accepts:

```json
{
  "session_id": "opaque-session-reference",
  "requester": "stable-task-requester",
  "idempotency_key": "client-generated-unique-request-key",
  "purpose": "Open the terminal list and read its current page",
  "requested_ttl_seconds": 300,
  "items": [
    {
      "item_id": "open-list",
      "capability": "web.navigate",
      "observation_id": "fresh-observation-reference",
      "component_ref": "observed-menu-reference",
      "max_uses": 1,
      "depends_on": []
    }
  ]
}
```

This is an illustrative input, not a currently available tool. Actual schemas
use exact types, reject unknown/duplicate JSON fields and reject secrets. The
server resolves the profile, exact origin/account, credential reference binding,
profile/trust digest, queue resource and acquisition identity, browser session,
worker incarnation, broker epoch, page binding and component fingerprint.
Those facts are rendered by the helper, not copied from an agent's description.

Canonicalization uses a versioned deterministic UTF-8 JSON encoding with sorted
object keys, unique ASCII item IDs, sorted dependency sets and integer limits;
floats and ambiguous Unicode identifiers are rejected. Display text is bounded
and escapes control/bidirectional characters without changing target semantics.
The broker hashes the fully resolved request. A different scope is a new digest.

One request contains 1-32 items and at most 32 KiB of canonical metadata.
One session has at most one pending prompt and four active grants. Exact retries
of an idempotency key return the original request status without another prompt;
the same key with different resolved input is rejected. Rejected/cancelled
requests do not reopen themselves. A new key never bypasses human review or the
single-prompt limit. No automatic prompt storm on repeated denial.

Check a duplicate key against its stored canonical submitted envelope before
resolving observations again, so reference expiry does not turn a status retry
into a new request. Only a new request resolves a fresh inventory. After request
creation, the immutable review snapshot may outlive its 30-second observation;
that does not extend execution references. Approval issuance rechecks session
binding and each selected component, and execution still requires a new reference.

### Approval receipt and executable grant

The local helper returns the request digest, one-use challenge, per-item decision,
reduced limits, and user decision time over its private channel. The broker
accepts it only from the launched helper instance before the prompt expires.
No externally submitted JSON receipt can create an executable grant.

The broker recomputes a distinct `approved_scope_digest` for the approved subset
and effective limits. It keeps the authority in memory. The agent receives an
opaque `grant_id`, digests, statuses, allowed item IDs, remaining budgets, and
expiry. That ID is a lookup handle, not a portable bearer credential. It is
useless in another process/session or after invalidation. Do not persist a grant
token that can be reloaded as authority after restart.

The human can only narrow a request. UI edits that add a control, change an
origin, widen an input set, increase an operation count, or add a destination
must create a new request for review. There is no "always allow" option.

### Time and count limits

- Requested grant TTL: 60-900 seconds, default 300.
- Effective expiry: minimum of human-approved TTL, remaining browser lifetime,
  and queue expiry minus the existing 45-second safety margin.
- Approval wait: 120 seconds by default, at most 300, additionally capped by
  the current session/lease. Insufficient lifetime returns `lifetime-insufficient`.
- Counts: 1-50 uses per item, at most 200 uses across one grant.
- Reads: at most 100 rendered rows, 30 approved columns, 16,000 total text
  characters and 96 KiB serialized output per call; explicitly flag truncation.
- Deadlines use monotonic time while active. Wall-clock times are for display
  and audit only. A restart invalidates grants rather than extending them.

Queue renewal cannot extend a grant. A new acquisition after release, expiry,
recovery, or ownership change cannot revive one. Bind a lease acquisition
identity in addition to the requester; renewal may retain that identity only
within the same uninterrupted ownership. The implementation must establish
this identity without invalidating unrelated SSH/VM queue records.

## 8. Batch and Partial Approval

The approval window lists individual operations, observed target names,
source/destination, input constraints, output scope, dependencies, expiry and
maximum uses. Show requested and effective scope separately. Agent-provided
purpose text is labeled as such and cannot hide or override broker-owned facts.
The window does not show passwords, cookies, raw HTML, or table contents.

All items begin unchecked. The user can select eligible items, lower limits,
reject all, or cancel. A deliberate "select eligible items" control is allowed;
it does not include unsupported or unresolved items. The UI must make dependent
items unavailable if a prerequisite is rejected. It must never automatically
approve a prerequisite merely because its dependent was selected.

Request outcomes are `approved`, `partially-approved`, `rejected`, `cancelled`,
`expired`, or `failed`. Individual item outcomes distinguish `approved`,
`rejected`, `dependency-blocked`, `unsupported`, and `stale`. A batch is not a
transaction on the website: successful earlier operations are not rolled back
when a later item fails. Return item-level evidence and partial completion.

Approval is not execution. Dependents become eligible only after the required
operation's postcondition is verified, not merely because its grant exists.
For example, reading a table cannot proceed if navigation was approved but
landed on an unexpected page. Independent approved items may continue only if
the session remains valid and their own preconditions still hold.

## 9. Post Login Network Effects

The current origin guard is necessary but insufficient for approved generic
menu actions: same-origin JavaScript may issue writes. v1 must not describe a
click as read-only solely because it is named "Terminals" or sends HTTP GET.
An expected destination check after clicking is also too late to prevent a
request that already left the machine.

The forwarding state machine exists from worker startup, not only after the
first agent operation: `bootstrap` -> `login-once` -> `discovery-only` ->
`grant-active` -> `fenced/closed`. Every phase has an explicit finite request
contract in addition to origin/TLS checks; no phase means "allow this origin."
Bootstrap permits only the reviewed login document/assets and credential-free
probe traffic. Login authority permits the separately authorized, bounded
authentication exchange and initial shell loads, not arbitrary business calls.
These contracts use the same descriptor mechanism and are prepared before
credential submission from inspected login behavior or a reviewed local login
contract. They may designate internal credential slots but never expose them.
Missing login contracts are a setup prerequisite, not an excuse for a temporary
unrestricted forwarding window. No server-specific URLs are compiled into code.

At the first verified authentication transition, the worker atomically removes
unused login permits and enters default-deny post-login forwarding before
publishing `authenticationVerified=true` or processing further commands. Each
forwarding decision checks the phase and a narrow request contract, so a
background business request is denied even if it races success detection while
the login phase is still active. A timer, elapsed delay or the agent's first
call cannot define this transition. Post-login requests need active task-grant
permits; login authority cannot be re-entered without a new authorized session.

Already transmitted login requests are reported as login-scoped in-flight work;
the transition cannot recall them or prove they had no server effect. Their
completions cannot mint grants, widen request bounds, or release business data
to the model. Do not use initial-shell authority to preload terminal inventories.

Request permits bind method, normalized path, query key/value constraints,
content type, supported bounded JSON/form command fields, parameter constraints,
maximum count and deadline. No method/path wildcard, arbitrary predicate code,
"all GETs", command-prefix heuristic, or automatic approval based on observing
a successful response is allowed. Unknown encoding, duplicate/ambiguous fields,
oversized bodies, unknown parameters or unsupported transport is blocked before
the network broker transmits it. Authentication material is handled internally
and never displayed or made into an agent-supplied constraint.

Asset and background-poll permissions are explicit too. They are not silently
inherited from "same origin" and do not gain unlimited use. The gate does not
claim to attribute every timer or asynchronous request to a particular DOM
click; it constrains the entire session's permitted traffic and aggregate
budgets. Concurrent site behavior cannot borrow an unbounded request allowance.

If a necessary request is not yet understood, intercept and abort it before
forwarding, then offer a sanitized non-executable request descriptor for an
incremental approval. Keep original body/header values only in transient worker
memory and discard on abort. Do not hold and later replay that HTTP packet.
The human review must distinguish a mechanically matched request from its
business semantics. Trusted API documentation or an explicitly reviewed local
read contract is needed to call it verified read-only; a new or unknown command
cannot be presented as harmless based on the agent's assertion.

In v1 this is an eligibility rule, not just a warning label: unknown business
effects, write contracts and unsupported payloads cannot receive forwarding
permission, even if the user selects their UI action. A local reviewed read
contract records its provenance and review digest independently from untrusted
page text. It may be proposed dynamically for human review; it is not built
into a site-specific plugin menu. A reviewed contract is evidence about the
declared server behavior, not a proof that a compromised server cannot write.
If that evidence is missing, the human may reject or defer the item, but cannot
convert it to a v1 executable request by dismissing a warning.

The worker assigns an opaque `request_descriptor_ref` to the sanitized contract.
`authorization_status` returns pending descriptor references and bounded
non-secret method/path/command metadata for that session, without bodies or
headers. A request item may attach `network_refs` and request lower counts or
narrower permitted non-secret parameter sets. The broker resolves the full
contract in memory and includes it in the immutable approval manifest. The
helper renders network sub-items independently; denying one means no permit for
that request, even when its UI action is approved. No "approve all future
requests" choice exists. A descriptor is not executable and cannot be supplied
to a raw request API. It expires with the review deadline/session and cannot
be imported from another origin, account, session or worker.

Before a first invocation, unknown network behavior is shown as blocked, not as
implicitly approved. The human may authorize the bounded UI action with zero
new network permits to discover blocked descriptors. This can change the local
page but cannot forward those requests. Subsequent request approval requires
the same human review and evidence of semantics, not automatic network learning.
If the local page cannot recover without replaying a potentially sent operation,
stop and report the prerequisite instead of silently broadening the grant.

A future invocation after additional approval is a fresh UI attempt, not an
automatic retry. It is permitted only after the previous outcome is resolved;
if any request might already have been sent, report `outcome-unknown` or
`partially-completed` and require outcome inspection. Never hide an uncertain
side effect behind a second click. If enforceable request bounds cannot be
established for a page, return `request-contract-unavailable` and fail that
automation path rather than weakening the browser boundary.

## 10. Execution Protocol

The proposed MCP surface consists of:

| Tool | Purpose |
| --- | --- |
| `remotex_web_components` | Bounded metadata-only discovery for the owned authenticated session |
| `remotex_web_authorization_request` | Validate a batch and launch one local approval prompt; return pending request ID |
| `remotex_web_authorization_status` | Return decisions, effective limits, expiry and remaining counters; never approve |
| `remotex_web_execute` | Execute one approved item with fresh component references, bounded parameters and an idempotency key |
| `remotex_web_authorization_revoke` | Cancel own pending request, revoke own grant/items or end own task authorization |

Revocation by the local human helper can target all grants in its broker-owned
session. An agent cannot revoke another requester/session by supplying its ID.
Status is scoped likewise. No tool accepts a password, script, raw URL, selector,
HTTP body, human decision, or replacement grant. Input values are restricted to
the already approved finite set or numeric range; no free-form text in v1.

Each `execute` performs, in order:

1. Validate the exact schema, current browser-policy prerequisite, original
   channel/session, requester and grant identity.
2. Recheck authentication, origin, profile/trust snapshot, acquisition identity,
   covering lease, grant state, dependency results and monotonic deadline.
3. Resolve the fresh component and compare its approved fingerprint, page
   preconditions, input/output bounds, and expected destination contract.
4. Under a per-session authorization lock, reserve one use and persist a
   sanitized execution-intent event. If persistence fails, dispatch nothing.
5. Send a typed command to the original worker. Revalidate the DOM immediately
   before action and request authority immediately before network forwarding.
6. Read the postcondition and return only the approved projection. Record
   `verified`, `failed-before-dispatch`, `partial`, or `outcome-unknown` separately
   from authentication, HTTP status and a site's result codes.

Before releasing business content to the calling host, recheck revocation,
deadline, output scope and session binding under the broker's authorization
lock. Revoked or expired reads return metadata-only failure and discard the
buffered content. Already delivered content cannot be recalled. Persist the
result metadata before output delivery; an audit failure must not leak the
pending output through an exception or a supposedly failed tool result.

Output release has its own final linearization point: after result persistence
returns and immediately before the host response is committed, recheck the
independent emergency fence, expiry and session validity. Serialize this final
commit with the one-way fence transition without holding the audit writer lock.
If the fence wins, discard buffered content; if output commit already won,
record it as delivered and do not claim revocation recalled it. A result write
that completes after emergency closure cannot authorize delayed content release.

An execution idempotency key is bound to grant, item, parameters and resolved
component scope. An identical retry returns the existing attempt status and
never reexecutes. Different input under the same key is a conflict. Attempts
consume budget when reserved, including failures; this avoids ambiguous refunds
and concurrency overspend. A timeout or worker crash is never auto-replayed.

Table extraction uses visible current-page DOM cells, not API inventories.
Omit hidden/editable/embedded content; redact known secrets. Return approved
column names, projected visible rows, page marker when actually visible, and
truncation flags. Do not assert that rendered/virtualized rows are the entire
inventory, infer an empty list as permission success, or paginate automatically.

## 11. Revocation and Race Semantics

A grant moves from `active` to `revoking` to `revoked`; expiry, exhausted budgets,
session closure and invalidation are terminal too. A revoked item remains
revoked, and its dependent items become blocked. Narrowing never resurrects
previously rejected items. Amendments create new requests and digests.

Revocation and operation/request reservation use the same authorization lock.
The linearization point is the broker's durable reservation/dispatch-permit
decision. If revocation wins, no later permit is issued. If an operation already
won, revocation marks it in flight, signals cancellation and stops new permits;
it does not claim that previously dispatched bytes or server effects were undone.
Use at most one outstanding action permit per session, with a short validity and
no reusable offline permit bundle.

`revoked` is returned only after the worker acknowledges the new generation with
no pending unused permits, or its owned process tree is confirmed stopped.
If acknowledgment exceeds two seconds, close only that owned session and verify
closure. Report still-uncertain outcomes and do not release the queue before
closure. A hung audit writer must not block emergency cancellation: fence in
memory and close the worker first, mark `audit-incomplete`, and persist the
revocation record when possible. New execution remains disabled while audit
integrity is unresolved.

The emergency fence is a separate one-way cancellation signal and does not
acquire the authorization/audit lock. The supervisor's owned-job kill path must
also remain independent of that lock. After any durable write and immediately
before sending a permit, the dispatcher rechecks this fence; a completed fsync
cannot resurrect a fenced grant. Once this path is used, only confirmed closure
and a new session can restore operation. Normal ordered revocation uses the
authorization lock; emergency fencing takes precedence when it is unavailable.

Ordinary revocation of the last grant returns the live page to discovery-only
mode and blocks further page traffic; session expiry/closure still applies.
The human UI offers a separate explicit "end task and close session" control.
Closing a local session does not revoke a server-side cookie already issued by
the site. Other sessions and unrelated SSH/VM queues are never interrupted.

## 12. Persistence and Audit

Use a protected authorization subdirectory under the existing local RemoteX web
state root. Apply and read back the established Windows private DACL, reject
network paths and reparse points, and atomically persist metadata with bounded
sizes. Do not modify the shared profile JSON or credential store for grants.

Keep active authority and ephemeral component bindings in broker memory. On
broker/helper failure, EOF, version change or process restart, invalidate active
and pending authority. Persistent manifests/receipts may explain history but
cannot restore it. Saved templates, if added later, are request drafts only.

Authorization events include `request-created`, `prompt-opened`,
`decision-recorded`, `grant-issued`, `execution-reserved`, `request-blocked`,
`execution-finished`, `item-revoked`, `grant-revoked`, `grant-expired`, and
`session-invalidated`. Record request/approved digests, opaque correlation IDs,
capability kinds, count/limit changes, timestamps, reason codes, outcome state,
local approver SID digest, and session/profile binding digests. Identity metadata
is not proof of trusted physical user presence.

Do not retain passwords, cookies, headers, request bodies, full URLs with query
values, raw selectors/DOM, terminal rows, screenshots, free-form purpose text,
query values or sensitive labels in the audit journal. Use random references
or keyed local digests for low-entropy sensitive identifiers; plain unsalted
hashes are not anonymization. The local approval UI may show necessary target
metadata, while its receipt remains minimal. Tool output may be retained by the
host conversation; the human must see which business columns will be returned
to that host before approving a read.

Reuse the existing hash-chain format for linked authorization metadata, but
validate private storage and fail closed on append/chain errors. Require durable
decision and intent events before grants or actions become usable. If result
logging fails after dispatch, fence the grant and report `audit-incomplete` plus
the true action uncertainty; do not call the action unexecuted or retry it.
No automatic deletion of audit history is introduced. Safe metadata export is
distinct from business-data export and creates no execution permission.

## 13. Compatibility and Failure Codes

No migration of SSH/VM profiles, credentials, certificate pins, or queue owners.
Existing running 0.5.12 sessions finish normally; never claim the new broker can
retroactively govern or revoke them. Status distinguishes legacy sessions from
approval-enabled sessions. Do not restart other clients or replace an in-use
plugin directory as part of activation.

New-version web sessions use the approval protocol for expanded post-login
operations. Legacy `web_navigate(confirm=true)` must not bypass it. Without an
explicit grant reference, it returns `approval-required`; it does not select a
grant automatically or silently downgrade to a legacy click path. Existing
observe/result tools also require an explicit valid grant and its approved
projection. Zero, expired or revoked grants never restore legacy content reads.
Only bounded component metadata discovery, authorization/session status and
owned-session cleanup remain available without an action grant.
Keep old schemas understandable through bounded diagnostics and skill guidance,
not through a compatibility switch that disables approval.

Stable failure codes include `approval-required`, `approval-ui-unavailable`,
`request-invalid`, `request-too-large`, `request-expired`, `request-conflict`,
`request-rejected`, `capability-unsupported`, `dependency-blocked`,
`component-stale`, `component-ambiguous`, `scope-mismatch`, `parameter-denied`,
`request-contract-unavailable`, `request-not-authorized`, `grant-expired`,
`grant-revoked`, `budget-exhausted`, `lease-changed`, `lifetime-insufficient`,
`outcome-unknown`, and `audit-incomplete`. Unknown failures expose sanitized
codes only, not raw browser traces, IPC contents or secret-bearing exception text.

## 14. Validation and Release Gates

Implementation must follow test-first development and real independent review.
The required evidence is distinct from this design's consistency review.

| Area | Required positive and negative evidence |
| --- | --- |
| Batch | Full approval; partial approval; rejected prerequisites; independent items; DAG cycle/missing dependency; request-size limits |
| Human decision | Cancel/timeout/unavailable UI; wrong nonce/digest/helper; duplicate decision; forged file; MCP `approved=true` rejected; no auto-approval on Enter |
| Binding | Different origin/account/profile/pin/session/process/requester; lease release/reacquire; changed worker; clock rollback; restart cannot resurrect grants |
| Dynamic components | Menu outside success region; JavaScript menu; unique rebinding; hidden/disabled/duplicate/changed node; hostile labels; no arbitrary selector or URL |
| Network | Click-triggered write, input-triggered fetch, GET with effects, unknown parameters, background request, expired permit, cross-origin/redirect; blocked requests send zero bytes |
| Execution | Budget races; dependency postconditions; exact idempotency; timeout before/after dispatch; partial results; no automatic replay |
| Revocation | Pending cancellation; subset/all grants; concurrent dispatch; long command; worker hang; revoke acknowledgment; only owned browser is closed |
| Privacy | Secret canaries in fields/labels/rows/errors; bounded UTF-8 output; table current-page limits; no sensitive audit/argv/environment/files |
| Compatibility | Full existing RemoteX and repository suites; old schemas cannot bypass grants; unchanged SSH/VM behavior and default configuration |

Windows integration must exercise the actual local approval helper and isolated
Edge with synthetic sites and credentials before real-site acceptance. UI
rendering tests may inject a test-only decision transport in test code; no
production auto-approve flag or environment variable is permitted. A human must
exercise the shipped prompt for the live acceptance; do not automate approval.
Verify screenshot readability of long scopes, partial selection, timeout,
unavailable UI and revocation, without exposing real credentials or inventories.

Real-site acceptance, after separate implementation approval and passing gates:

1. Check current supported browser access and acquire a fresh unowned queue for
   the already authorized existing profile. Never preempt another task.
2. Probe and log in once using the saved credential and approved TLS binding.
3. Discover the actual terminal-menu component and batch-request the grounded
   operations. The human approves in the local window; unavailable UI blocks.
4. Navigate with the grant. Inspect the real destination and, if first seen,
   request the incremental table read and any still-unknown request contract.
5. Return only the current page's approved visible columns with row/truncation
   evidence. Establish successful business readback separately from login.
6. Revoke the grant and verify another execution is refused. Close the owned
   session, read back closure, release its queue and verify shared config and
   credential references are unchanged. Keep all private evidence local.

No successful fixture, source merge, or package installation substitutes for
these real navigation/read/revocation checks. If request semantics or browser
policy cannot be established, record the concrete coverage gap without relaxing
the gate or changing the center's code.

Include tests for a duplicate request after its observation expires, a changed
component during human review, denied network sub-items in an approved action,
revocation/expiry after extraction but before output delivery, legacy reads with
zero grants, startup/initial-shell business requests and the authentication
transition's concurrent forwarding race.

Also simulate a hung result-journal write, emergency revocation while it is
blocked, and its eventual return: no buffered business content may be released.

## 15. Review Decisions and Next Stage

This proposal chooses local, process-bound, session-only grants; dynamic observed
components instead of static menus; a deliberately limited web capability set;
incremental approvals for unseen targets; and fail-closed request gating for
expanded actions. These choices avoid a persistent all-site permission while
making repeated, approved work automatic.

The human review should explicitly accept the following tradeoffs:

- Local approval is a cooperative workflow, not same-user malware isolation.
- A first visit can require incremental approval when controls or request
  contracts are not yet observable. Unknown future components are never silently
  covered by the initial task description.
- Existing credentials and pins are preserved, but the new strict session needs
  an inspected login request contract. If none exists, preparing it is a local
  setup prerequisite; the older permissive traffic path is not a fallback.
- v1 excludes business writes. Supporting isolation, policy deployment or deletion
  requires a later operation-specific design and approval path.
- Restart, relogin and queue reacquisition require a new grant; normal lease
  renewal does not prolong one.

After written-design approval, prepare the implementation plan with module
ownership, bounded IPC schemas, test order, compatibility rollout and live
acceptance steps. Do not start product implementation merely because this file
exists. Publication, merge, installation and live execution remain separately
reported stages under the user's applicable authorizations.
