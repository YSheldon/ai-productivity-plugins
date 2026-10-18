# RemoteX Task Approval and Time Limited Authorization

Status: Proposed for human review. This document does not authorize implementation.

Revision: 2, business writes included in the first implementation.

Date: 2026-10-17

Protocol: `RemoteXTaskAuthorization/v1`

Source baseline: `642855a0096830cea53b91abf38026ac749591c2` (RemoteX 0.5.12).

## Review Summary

The first release is an approval-controlled read/write workflow, not a read-only
browser. Agents may request all currently grounded components in one batch.
The human can approve individual operations or target subsets, with finite
lifetimes and budgets. Ordinary approved writes run automatically within that
scope; actions requiring final confirmation retain a one-use action-time gate.
Revocation stops future dispatch, while accepted remote tasks and uncertain
outcomes are reported honestly. No center business code, credentials, TLS policy,
host browser permissions or unrelated queue ownership is changed.

The main review points are the write contract and approval classes in section 6,
partial approval in section 8, execution/readback in section 10, and revocation
and audit in sections 11-12. Section 14 includes real write acceptance, which
requires a separately selected test target and explicit operation approval.

## 1. Decision and Scope

Replace the proposed site-specific menu allowlist with a task approval protocol.
An agent requests a bounded set of observed UI capabilities. RemoteX presents
the immutable request in a local human approval window. The human may approve
all eligible items, approve a subset with lower limits, reject, or cancel.
Approved items then execute without repeated prompts until their budgets or
deadlines expire, except where an action-time confirmation is required by the
host or the operation's risk policy. New scope requires a new decision; it is
never learned into an implicit permanent permission.

The first implementation applies to the existing isolated Edge web session.
It must support navigation, current-page reading, and explicitly approved
business writes through observed components and the center's existing behavior.
Examples include assigning an approved policy, moving selected terminals to a
group, starting a scan, isolation/release and deletion with the applicable
operation-specific approval. These are capability examples, not authorization
to perform any such action on a real target. No management-center business code
is changed. It does not introduce SSH, RDP, VM, or infrastructure approvals;
those existing mechanisms remain unchanged.
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
- Business writes bind exact target identities, approved changes, side effects,
  and cumulative impact limits, rather than only approving a button click.
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
6. Business writes require their own typed action contract and approval class;
   they cannot be hidden in navigation/read permissions. Retain required
   action-time confirmations and human handoffs. Downloads/uploads, credential
   changes, MFA/CAPTCHA automation, arbitrary form submission and new browser or
   OS security exceptions remain unsupported by this protocol.
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
| `web.inspect_action` | Explicit non-secret business fields and selection metadata from one observed action form, for approval preview | Passwords, tokens, unrelated editable fields, implicit field changes |
| `web.business_action` | Observed bounded UI workflow, immutable target set, exact approved field changes, request/effect contract and verification steps | Generic click/submit authority, unbounded selection, unapproved writes or different parameters |

Changing an input can trigger page handlers and network requests. It receives
the same dispatch and request checks as a navigation, even without a submit
button. A generic UI role or a read-like label is not evidence of server semantics.
Unknown or write-like effects cannot be downgraded by an agent's purpose string.

### Business write scope

`web.business_action` is supported in v1, not deferred to a later read-only
release. It covers a finite workflow of observed components: select exact
targets, set approved fields, invoke the business action, handle its observed
confirmation dialog, and verify results. Input, checkbox, selection and blur
events may auto-save; each such step is classified and gated before execution,
not treated as harmless preparation until a final submit button is clicked.
The action contract is dynamic reviewed data, not arbitrary code or a built-in
list of center menu names. An unknown action still cannot become executable
merely by requesting a generic write privilege.

Each write item adds the following immutable scope to the common envelope:

- `effect_contract_ref`: proposed or previously reviewed operation semantics and
  request mapping, including provenance, known risks, reversibility and affected
  object types. Proposed semantics cannot execute until accepted in this request.
- `target_set_ref`: exact stable object IDs collected through an authorized
  read, count, and broker-owned digest. Display names are explanatory only.
- `change_set_ref`: approved non-secret field names, old values/version
  preconditions, new literal values, and semantic operation such as assign or
  remove. The broker resolves these from a reviewed draft, not caller claims.
- `workflow_ref`: grounded component steps, side effects of each step,
  expected confirmation dialog and request contracts.
- `impact_limit`: maximum unique targets, total dispatched writes and
  per-target uses across the grant; a batch request does not reset these limits.
- `verification_ref`: separately approved readback and any existing center
  task/status IDs used to establish acceptance and completion.

The broker mints these references during a non-executing action preparation.
Preparing a draft does not select a checkbox, set a field, open a business
dialog or send a center request. Required page navigation/inspection must
already have its own permission. `web.inspect_action` may read only explicitly
approved non-secret business fields, including editable values needed for a
before/after preview; this is a narrow exception to general observation's
editable-content exclusion. Authentication and token fields remain unreadable.
Stable target IDs must be grounded in the approved page/object read and its
version evidence, not supplied as an unchecked list by the agent.
Approved row projections may return opaque `target_ref` handles backed by the
worker's stable-ID mapping for visible objects. Reading an allowed identifier
attribute does not authorize reading arbitrary hidden fields or application
memory. If the page and inspected effect contract cannot establish stable object
identity, that write remains unavailable.

New operation semantics do not require a precompiled menu rule or an executable
contract file. `action_prepare` may resolve an existing reviewed contract or
construct a proposed effect draft from observed components, blocked request
descriptors and supplied evidence references. Evidence may be inspected existing
API documentation, a reviewed existing center implementation or a previous
verified operation record; a label or an HTTP success code alone is insufficient.
The draft records its unresolved and proposed fields, and remains non-executable.
The local approval window renders this contract alongside its targets and
changes. A human can accept adequately evidenced semantics and the task scope
in the same decision, producing an approved contract digest bound to that grant.
Unsupported effects, missing target identity or unenforceable request bounds
remain ineligible. Nothing requires a real write merely to learn its contract,
and approval of a draft does not create standing permissions for later tasks.

Use stable IDs, not row positions, mutable names, a live filter, or "all matching
terminals." Re-read target identities and expected old state immediately before
dispatch. Added, disappeared, ambiguous or changed targets invalidate the
affected item; do not substitute another target. Finite parameter sets and
exact non-secret strings may be proposed for approval, including group/policy
names or descriptions, but cannot be changed at execution time. Rendering and
secret screening are not a license to accept credentials as business text.

If the center has an existing version/CAS or idempotency facility, use it through
the supported UI and existing request flow. RemoteX's last read followed by a
click is not atomic concurrency protection. Where no server precondition exists,
the approval must disclose that limitation; actions whose safety requires an
atomic old-state check are blocked as `precondition-unenforceable`. The effect
contract declares whether atomicity is safety-critical and why; the agent cannot
remove that flag. Do not add a server patch or silently weaken the condition to
complete automation.

Creation actions bind an existing stable parent/container ID, the exact approved
creation fields, an absence/uniqueness precondition and the maximum number of
new objects. They do not pretend that a server-generated object ID exists
before dispatch. Capture the returned ID through the existing center receipt
and approved readback, then bind further actions to that verified new object.
Unknown creation outcomes fence overlapping creation in that parent scope;
changing the proposed name cannot silently bypass the fence. For command-only
actions such as starting a scan, represent old/new field values as explicitly
not applicable and instead approve the exact command and state preconditions.
This does not waive object identity, impact accounting or outcome verification.

### Approval classes

The effect contract accepted by the human and applicable host policy determine
the minimum class. Proposed classes remain untrusted until that decision; agent
labels can raise but never lower the mechanically required policy floor.

| Class | Approval and reuse | Examples and restrictions |
| --- | --- | --- |
| `task-bounded` | Human may approve multiple exact items once; automatic execution within frozen targets, values, quotas and TTL | Ordinary reversible metadata/configuration writes whose effect contract and host policy permit preapproval |
| `action-bound` | Each concrete operation and target set is an explicit one-use item; several independent items may be reviewed together if host policy permits | Scans, policy assignments or isolation workflows where their actual effects require this class; a task title alone is insufficient |
| `action-time` | Final prepared operation requires fresh human confirmation immediately before its effect; task grant covers preparation only | Irreversible deletion, material security/access changes and other actions for which the host requires action-time confirmation |
| `handoff` or `unsupported` | Agent does not perform the final action | Credential changes, browser security warning bypass and other mandatory handoffs or unsupported effects |

Names alone do not classify risk: moving a terminal group may change inherited
policy, and a policy assignment may weaken protection. Review those effects in
the contract. For `action-time`, freeze the final target/change digest and show
it in the local prompt; issue a one-use execution ticket valid for at most 30
seconds and within the parent grant deadline. Consume it at the first affected
side effect, not at an arbitrarily chosen final button. Any scope or relevant
state change, timeout, revocation or uncertain dispatch invalidates the ticket.
No `confirm=true`, saved approval, or reusable task grant replaces this decision.
If a batch cannot be one concrete action under host policy, require separate
action-time decisions rather than turning one prompt into a reusable deletion
permission. Ordinary already approved writes do not gain extra prompts merely
because they pass through another tool or workflow step.

An action-time ticket authorizes one final concrete effect, not every write in
a multi-step workflow. If an earlier auto-save is itself a distinct effect that
requires action-time approval, it needs its own ticket. A predeclared sequence
cannot spread a single confirmation over unrelated later writes. RemoteX's
prompt also cannot replace a host-mandated approval UI; where the host requires
its own confirmation, that remains a prerequisite in addition to the grant.

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

For a multi-step action, each subsequent component must be re-observed after
the previous step. A still-matching approved fingerprint can be rebound without
a new human decision. A newly discovered dialog/control not in the approved
workflow is not covered, even if the page calls it a confirmation dialog.

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

For a business write, the item also references a broker-created
`action_draft_ref`. For example, after an approved inspection has grounded the
form and two selected test objects, an illustrative item is:

```json
{
  "item_id": "assign-group",
  "capability": "web.business_action",
  "observation_id": "fresh-observation-reference",
  "component_ref": "observed-action-reference",
  "action_draft_ref": "immutable-reviewed-draft-reference",
  "max_uses": 1,
  "depends_on": []
}
```

The resolved draft, not the short reference, is what the approval window shows:
both target identities, old group/version, exact requested new group, inherited
policy effects, operation class, request bounds and readback. This item may share
one batch with the approved verification reads. Refusing one target yields a
new approved subset digest, not permission to substitute another target.

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
- Writes: at most 100 exact targets per request and 200 target-write reservations
  per grant, further narrowed by the effect contract and human decision. A write
  item has an explicit per-target use bound; `action-bound` uses are one-shot.
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
The window does not show passwords, cookies, raw HTML or unrelated table
contents. For writes, it shows the complete selected-target list, changes
before/after, expected effects, approval class, cumulative impact, concurrency
limitations, and whether rollback is possible. Necessary business preview
values remain local and are not copied into the audit journal.

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

Partial approval may narrow a write's target set as well as its item set. The
broker recomputes the approved target and change digests and regenerates the
execution preview before issuing the grant. An atomic server-side batch may
only be narrowed if its existing operation safely supports that subset;
otherwise split and re-preview the request rather than pretending partial
approval can partially execute an indivisible server operation.

For non-atomic multi-target operations, track `not-started`, `reserved`,
`dispatched`, `accepted`, `running`, `verified`, `failed` and `outcome-unknown`
per target. These are execution states, separate from the item's approval state.
Reserve the complete dispatch unit's target-write budget before sending it;
never partially send a unit that exceeded its budget. Independent dispatch units
are serialized and recheck authority. On uncertainty, stop later writes by
default; read-only reconciliation may continue under its separate valid grant.
Continuing after a known per-target failure requires an explicit approved
`continue_on_known_failure` policy, and never skips a dependency or replays a
partially completed batch.

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

Request permits bind the reviewed read or write effect, workflow step, exact
target set, approved changes, method, normalized path, query key/value constraints,
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

A write request contract is never an ambient session-wide permission. Arm its
one-use forwarding permit only while the corresponding approved step is being
executed, after target/precondition checks and any action-time confirmation.
Bind its generation, target/change digest, request budget and short dispatch
deadline; disarm it on step completion, failure or revocation. Known background
reads use distinct bounded permissions and cannot borrow write permits. If
site traffic cannot be distinguished sufficiently to enforce that contract,
the write is unsupported rather than falling back to a broad endpoint permit.

If a necessary request is not yet understood, intercept and abort it before
forwarding, then offer a sanitized non-executable request descriptor for an
incremental approval. Keep original body/header values only in transient worker
memory and discard on abort. Do not hold and later replay that HTTP packet.
The human review must distinguish a mechanically matched request from its
business semantics. Trusted API documentation or an explicitly reviewed local
effect contract is needed to distinguish a read from a specific business write;
a new or unknown command cannot be declared harmless by the agent.

This is an eligibility rule, not just a warning label: unknown effects,
unapproved writes and unsupported payloads cannot receive forwarding permission.
A known, approved business write is eligible under its actual approval class,
target/change scope and budgets; it is not rejected simply for being a write.
The local effect contract records provenance and a review digest independently
from page text and matches the exact request version. It may be proposed
dynamically for human review, not compiled into a site-specific menu. The
contract is evidence about declared server behavior, not proof that a
compromised server cannot misbehave. Missing semantics cannot be replaced with
an "allow anything" warning dismissal.

The first request can include a proposed effect contract with its evidence and
mechanically resolved network bounds. The same local human decision may approve
the semantics and the specific task; a separate permanent site-contract approval
is not required. Descriptors lacking adequate evidence stay ineligible. The
broker does not infer a read/write classification from arbitrary request names
or let a previously approved read contract acquire new write fields.

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
| `remotex_web_action_prepare` | Create an immutable business-action draft from authorized read/inspection receipts, observed component refs and proposed non-secret field values; no page mutation or network dispatch |
| `remotex_web_authorization_request` | Validate a batch and launch one local approval prompt; return pending request ID |
| `remotex_web_authorization_status` | Return decisions, effective limits, expiry and remaining counters; never approve |
| `remotex_web_execute` | Execute one approved item with fresh component references, bounded parameters and an idempotency key |
| `remotex_web_execution_status` | Return the original attempt and per-target outcome metadata; does not send center requests or retry writes |
| `remotex_web_authorization_revoke` | Cancel own pending request, revoke own grant/items or end own task authorization |

Revocation by the local human helper can target all grants in its broker-owned
session. An agent cannot revoke another requester/session by supplying its ID.
Status is scoped likewise. No tool accepts a password, script, raw URL, selector,
HTTP body, human decision, or replacement grant. Input values are restricted to
the already approved finite set, numeric range or exact non-secret business
literal. Request preparation may propose such literals; execution cannot
substitute arbitrary text or any secret.

`action_prepare` accepts only grounded observation/read receipt references,
finite target selections from those receipts, observed field references and
proposed literal non-secret values (at most 1,024 UTF-8 bytes each), plus the
proposed or reviewed effect/workflow contract references and their evidence.
These references are server-created draft identifiers: if a new contract is
needed, the same prepare call supplies only a strict typed proposal of effect
kind, affected fields, risks, reversibility, observed step/request references
and bounded evidence citations. No script, raw HTTP payload or unvalidated
selector is accepted. The broker resolves the proposal into the referenced
draft in one call, rather than requiring an unavailable preexisting contract.
It validates and resolves these inputs into an in-memory draft with a digest.
An unreadable required old value, absent target/parent identity, missing effect
evidence or secret-bearing field fails rather
than producing a supposedly safe preview. Drafts expire after 300 seconds or
with the session, whichever is earlier; they cannot execute or become grants
without the local human decision.

For an `action-time` item, `execute` first freezes and validates the concrete
effect, then returns `awaiting-action-confirmation` while opening the local
prompt. After approval, the broker rechecks state and dispatches that exact
attempt once; the agent polls execution status, not a second execution call.
A changed precondition invalidates the prepared attempt and ticket. The agent
has no method to supply the human decision or approve the prompt itself.

Each `execute` performs, in order:

1. Validate the exact schema, current browser-policy prerequisite, original
   channel/session, requester and grant identity.
2. Recheck authentication, origin, profile/trust snapshot, acquisition identity,
   covering lease, grant state, dependency results and monotonic deadline.
3. Resolve the fresh component and compare its approved fingerprint, page
   preconditions, input/output bounds, and expected destination contract.
   For writes, also compare the exact target set, before-state/version, change
   digest, effect contract, permitted cumulative impact and required ticket.
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

Local idempotency prevents RemoteX from redispatching the same attempt; it does
not prove server-side exactly-once execution. A fresh idempotency key, request,
grant or session must not bypass an unresolved write. Persist a minimal,
non-executable uncertainty record before permitting a write dispatch. Its
conflict keys bind the normalized origin, stable object type/ID and affected
resource/field family, independently of profile alias, account, requester,
session, grant, idempotency key or newly requested value. Keep the exact approved
effect/change digests too, but do not use only an exact-payload hash to detect
conflicts: changing a value must not bypass an unresolved write on that field.
Indivisible batch/global effects reserve a corresponding aggregate conflict
scope. A write whose conflict scope cannot be defined is ineligible. This is
local protection at the canonical origin; it cannot detect another machine's
manual actions or silently identify arbitrary hostname aliases as one center.
The effect contract must disclose any such external concurrency limitation.
Remove its pending status only after a durable known result. On restart,
unresolved reservations are conservatively
treated as unknown and block overlapping writes until authorized reconciliation
or a separate human-reviewed recovery decision establishes a safe next action.
Never clear an uncertain record by deleting state or merely reauthorizing it.

Use existing center idempotency keys, operation IDs, version receipts and status
pages where available. Distinguish `dispatched` from `accepted`, an asynchronous
task's `running` state, and the verified target state. HTTP 200, a toast or a root
result code alone is insufficient. Known non-execution must be established by
evidence, not inferred from a timeout. A recovery decision may authorize a new
action only after showing the unresolved prior attempt and its duplication risk;
it cannot relabel the original result as success or failure without evidence.

Verification reads are separate grant items that may be approved in the same
batch. Give them enough bounded time for expected asynchronous completion.
Expiry of the write grant does not authorize more writes or polling; if the
read grant also expires, request a read-only extension. A revoked write does not
silently revoke independent readback unless the human revokes the whole task.
If session safety requires closing the browser, later reconciliation needs a
new authorized session and read grant, never adoption of old cookies.

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

Stopping local automation does not cancel a center task that has already been
accepted. Report submitted/running/verified/unknown effects separately from
local grant revocation. Canceling a center task, restoring a previous value,
releasing isolation or performing another compensating action is itself a
business write. It requires an explicitly approved compensation item or a new
approval with current preconditions, then independent outcome verification.
No automatic rollback is promised. A compensation cannot execute under a
revoked grant, and its side effects count against its own approved budgets.

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

For writes, additionally record action-draft and approved-change digests,
keyed target-set/per-target identifiers, impact reservations, approval class,
action-time decision correlation, center operation receipt references and
per-target state transitions. Persist uncertainty fences separately from active
grants: they can only deny or require reconciliation, never authorize an action.
Persisted files contain no replayable grant or center authentication material.

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
`precondition-unenforceable`, `target-state-changed`, `impact-limit-exceeded`,
`action-confirmation-required`, `unresolved-prior-write`, `outcome-unknown`,
and `audit-incomplete`. Unknown failures expose sanitized
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
| Business writes | Exact before/after preview; subset approval; changed stable target IDs; auto-save steps; version/CAS failure; actual inherited policy effects; approved write allowed, unapproved write blocked |
| Write confirmation | Ordinary task grant reuse without extra prompts; one-use action-bound items; action-time ticket expiry/reuse/state change; host confirmation retained; no generic click bypass |
| Write recovery | Per-target partial completion; delayed center task; unknown outcome across new key/grant/restart; independent readback; compensation separately approved and verified |
| First use and creation | Proposed effect reviewed in the task batch; no real write for learning; creation parent/absence bounds; returned-ID verification; scan command preconditions; changed names do not bypass creation uncertainty |
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

Real-site read acceptance, after separate implementation approval and passing gates:

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

Real-site write acceptance additionally requires a user-designated test object
and a concrete approved effect; none is authorized by this design. Select an
existing reversible low-impact center action whose contract is inspectable,
prepare the exact old/new-state preview and target IDs, obtain local human
approval, execute once, and verify the resulting object state through an approved
read. If restoration is needed, include and separately verify its approved
compensation item. Demonstrate partial approval and refusal of a denied target
without sending a request to it. Verify that revocation prevents another write.
Test irreversible, security-sensitive and failure scenarios using synthetic
fixtures unless their real targets/effects receive separate specific approval.

No successful fixture, source merge, or package installation substitutes for
these real navigation/read/write/revocation checks. If request semantics or browser
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
- v1 includes business writes with explicit effect, target and change contracts.
  Ordinary approved work is automatic within scope; action-time confirmations
  and human handoffs remain mandatory where required by the actual effects.
- Center acceptance is not target completion; uncertain writes block overlapping
  retries, and revocation is not remote task cancellation or rollback.
- Restart, relogin and queue reacquisition require a new grant; normal lease
  renewal does not prolong one.

After written-design approval, prepare the implementation plan with module
ownership, bounded IPC schemas, test order, compatibility rollout and live
acceptance steps. Do not start product implementation merely because this file
exists. Publication, merge, installation and live execution remain separately
reported stages under the user's applicable authorizations.
