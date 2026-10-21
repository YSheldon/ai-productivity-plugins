# Changelog

User-facing highlights for this multi-plugin repository. Versions are independent
per plugin; a marketplace commit is not a new version of every plugin. This
initial changelog summarizes recent merged changes, not the complete Git history.

[Current versions](docs/plugin-catalog.md) | [Installation and upgrades](docs/installation.md)

## Unreleased

### Project Documentation

- Reorganized the English homepage around recent capabilities, workflows, and quick starts.
- Added a manifest-derived plugin catalog, installation/upgrade guide, and synthetic RemoteX visuals.
- Added documentation consistency checks without changing plugin runtime behavior.

## RemoteX 0.7.0

- New web sessions default to one-click site authorization: review the exact HTTPS site, saved account and lifetime, then select Allow Automation. Initialization and saved-credential login start automatically after the private native decision is durably committed.
- The same task grant covers ordinary page/table reads, observed buttons, non-secret forms and business changes for up to 12 hours, without category selection, static-resource review or initialization reference packets. Added remotex_web_site_execute with fresh component references and idempotent execution status.
- Sensitive effects retain a separate concrete native confirmation and a 30-second execution ticket. Changed target context blocks dispatch; password changes, CAPTCHAs and consequential payments require manual handling. Caller risk hints cannot downgrade recognized sensitive labels.
- Preserved exact-origin TLS/pin checks, credential isolation, queue ownership, original session binding, revocation and audit. Interrupted mutations retain durable conflict records. Existing granular sessions remain unchanged; granular mode is explicit for new sessions.
- Added an explicit previewable recovery-protocol v2 upgrade before enabling site authority. It waits for naturally closed web sessions and no unresolved writes, preserves the integrity key and audit evidence, and makes old web writers fail closed. Installation alone never migrates shared state; SSH/VM work is unchanged and no process is forcibly stopped.
- Added owned loopback/fake-credential Edge integration coverage for a single grant completing initialization POST, login, page reading, form input and one ordinary save. Production acceptance and native human-window acceptance are separate release checks.

## RemoteX 0.6.9

- Added native Load Public Review for independently prepared, bounded strict-UTF-8 `RemoteXPublicReview/v1` JSON packets, with a readable summary, three initially unchecked human confirmations and expandable expert fields. Import resets every confirmation and prior proof; Compare Public Reference and final Approve Selected remain separate, and the original 180-second timer and authority boundaries are unchanged. The synthetic manual fixture prepares its source-bound packet before approval begins, without copying captured traffic.
- Added per-item effect recommendations with reasons and an explicit Apply Recommendations to Checked command for mixed known request types. Recommendations preserve unchecked rows, original scopes, independent public-reference review and final approval. Typed reads show Read only (fixed); navigation/input/business actions retain distinct fixed labels, and unknown types remain Needs review.
- Added revision-3 initialization compatibility with three explicit UTF-8 profiles: JSON, ordinary form pairs and the bounded structured form-name view. Public fixed constants in sensitive-looking names require complete independent reference, non-auth role and initialization-effect review in the native window; real authentication/private fields remain blocked. No business endpoint or sentinel is hardcoded.
- Frozen original request bytes, complete effective headers and the owned prelogin cookie context are bound to private memory-only reference proofs and fresh one-use execution receipts. No public compare/approve endpoint, raw capture, secret-derived public hash, automatic decoder fallback or arbitrary POST permission is added.
- Complete reference review is bounded to 32 units per request, 96 per proposal and 32 KiB including private capture/view/manifest/context data. Four active grants, one pending review and finite counts remain; large proposals must be split within those bounds, not truncated. Revision-2 static-only replacement remains separate.
- New native reviews last at most 180 seconds; existing requests are not extended. An owned Windows notification is requested once after the form is shown, containing only RemoteX, its short digest and remaining time. A click only focuses the same pending unexpired window; suppression does not bypass approval, and requested/shown is not proof of human visibility.
- Preserved the separate 120-second blocked-observation TTL, 10-second check, 45/55-second startup/resume, 30-second one-use action ticket, 12-hour grant and 13-hour session limits. API revocation fences issued initialization work; expiry also blocks delayed readiness and credential arming.
- Added actual worker/native component protocol admission before credential access, safe loaded-worker capabilities, strict public schemas and isolated Edge integration fixtures. Initialization, Login and authenticated Read remain separately approved. No center business-code, credential/profile migration, global notification setting or shared-session interruption.

## RemoteX 0.6.8

- Added revision-2 startup contracts with distinct native Initialization Read approval for exact non-secret JSON/form POSTs. Required bounded response checks, visible controls and no unsettled initialization calls precede credential insertion on every fresh document. Bootstrap remains bodyless static GET/HEAD; Login and authenticated page Read approvals remain separate.
- Initialization responses are bounded to 64 KiB and checked before browser fulfillment. Duplicate JSON keys, ambiguous encodings, authentication negotiation, Set-Cookie and secret-bearing request slots fail closed. Private one-request permits bind the original supervisor, worker, request, resume, document, generation and expiry; values, GUIDs, cookies and raw responses are not exported.
- Added explicit replacement of at most two idle, same-lifecycle revision-2 static-only grants. All approved source rows and remaining counts are carried; every carried row must be selected, new rows may be partially approved, and one deadline is capped by the earliest source/human/session/lease limit. Durable atomic retirement never exposes a fifth active grant or renews a source.
- Preserved legacy single-phase setup, conservative possible-authentication tracking and no password resubmission. A delayed, independently approved Login response can finish within its original limits; revocation before verification fences its owned session. Current-page export still requires a fresh separate human-approved read.
- Unexpected top-level document replacement before login submission invalidates old readiness/receipts and closes only the owned attempt. Fragment/history changes and the final separately permitted Login form navigation are preserved; disabled back/forward caching remains explicit. Original-worker regressions cover completed and delayed old-document initialization responses.
- Added the pinned jsonc-parser 3.3.1 alongside Playwright Core 1.62.1 in a complete versioned runtime, without overwriting runtimes used by active sessions. Updated English API, approval-category, capacity, failure and installation guidance.
- Kept four active grants/one pending proposal, all existing time/size/count bounds, credential isolation, exact origin/account/trust, cooperative queue ownership and business-write previews/confirmations. No center business-code, profile/credential migration, arbitrary POST permission or automatic decoder fallback.

## RemoteX 0.6.7

- The native Effect Review dropdown now shows an adjacent English explanation of the selected category. Selecting a request row shows its current classification above the full details; editing that row updates the explanation immediately without applying the batch dropdown to it.
- Added tooltips for execution counts, read-output limits, grant lifetime and approval/revocation controls. Help distinguishes the 120-second review, task grants of up to 12 hours and one-use confirmations of up to 30 seconds. Cancelling a confirmation does not itself revoke its parent grant; in-flight safety fencing and the inability to undo server-accepted work remain explicit.
- Approval help wraps with the window, preserving visible commands and request details at supported small and large sizes. Real WinForms regressions cover selection, row changes, tooltips, shrink/enlarge/restore, silent output and unchanged request bounds.
- Corrected the offline Edge resize fixture for fractional CSS pixels: at most one pixel of content/viewport rounding difference, with larger mismatches, fixed-size content and invalid dimensions still rejected. Exact window bounds, resize deltas, viewport mode and rounded public geometry readback remain checked; no production viewport code changed.
- Help, selection and classification do not approve anything. Explicit final approval, partial selection, target/change previews, revocation, exact request matching, credentials, certificates, cooperative queue ownership and all existing time limits are unchanged. No center business code or shared profile/credential migration.

## RemoteX 0.6.6

- Already queued startup JS/CSS GET checks use bounded private transactions of at most 16 checks and 32 KiB, without waiting to fill a batch. Each request still needs its own exact active human-approved contract, remaining count and original session/trust/queue binding. Root documents, images, login exchanges and business operations retain their existing paths.
- Every permitted static request retains its reserved/finished audit records. A transaction verifies the complete old chain once, writes at most 32 hash-linked records and flushes/fsyncs before any permission returns; each authority is then rechecked independently. No prefix cache, permission reuse, audit deletion or broader network grant.
- Private replies require complete, unique batch membership. Individual cancellation, revocation, generation changes and overdue or malformed replies cannot revive authority. Issued checks still expire after 10 seconds, including when their timer callback is delayed.
- Added a 51-request, four-grant mixed startup regression over a synthetic 97,000-record ledger using the real private worker/supervisor transport, plus corruption, durability and mixed-grant regressions. The 45-second startup, 55-second resume, 120-second review, 30-second high-risk confirmation, 12-hour task grants and 13-hour new sessions are unchanged. No Bootstrap POST exception or center business-code change.

## RemoteX 0.6.5

- Task read/write grants now request up to 43,200 seconds (12 hours) by default. Operators can reduce the lifetime; the original session, queue acquisition, origin, account, trust, process and finite operation budgets still bound authority. Existing grants are not extended.
- New Edge sessions default to and are capped at 46,800 seconds (13 hours), leaving initialization margin before a 12-hour grant. A queue lease must cover the complete session plus 45 seconds; existing profiles and leases are not rewritten or silently renewed. Callers can request shorter sessions.
- A single startup JS/CSS GET/HEAD permit persists its original reserved/finished audit records as one bounded transaction. The complete existing chain is verified once under the existing locks, both records remain hash-linked, and fsync completes before permission returns. Corruption or persistence failure remains fail-closed; no prefix cache, audit deletion, or business-write persistence change.
- Added concurrent-writer, partial-write, revoke-during-durability, long-lifetime and synthetic 97,000-record startup regressions. The 45-second startup, 55-second resume, 10-second issued-check, 120-second human review and 30-second high-risk action ticket remain unchanged. No Bootstrap POST exception or center business-code change.

## RemoteX 0.6.4

- Added nonce/digest-bound `shown`, `closed` and fixed-code `error` receipts on the native helper's private stderr pipe. Diagnostic frames cannot approve, revoke, replay or extend authority; the stdout decision/revocation protocol is unchanged.
- Authorization request/status and action-confirmation status now include `approval_ui`: lifecycle state, shown history, remaining review seconds, exit reason, fixed error code and helper exit code. Remaining time is capped by the original broker deadline; showing a window never restarts the 120-second review.
- Distinguish review expiry, operator rejection/revocation, unclassified helper exit and startup/UI errors without exporting raw PowerShell errors, manifests or credentials. A shown receipt is not proof of foreground or physical human presence.
- Added real private-pipe/native lifecycle and malformed-receipt regressions. No display positioning, desktop/focus policy, origin/pin, queue, credential or center business-code changes. Existing authorization and business-write boundaries remain intact.

## RemoteX 0.6.3

- Expired or cancelled private authorization checks remain denied. A bounded, deny-only ID cache consumes their one late reply instead of treating it as a UI command; unknown and malformed traffic still fails closed.
- Added single-flight scheduling for pre-authentication, exact-origin JS/CSS GET checks with no query or body fields. The queue is capped at 64 checks including its in-flight check; the overall emitted-check limit remains 16. Scheduling never grants permission or caches a permit.
- Queued checks retain an immutable operation deadline and are denied on cancellation, phase/generation change, expiry or disposal. The emitted-check timeout remains 10 seconds; login POSTs and business checks do not inherit static-resource queue waiting.
- The explicit startup document load now shares one total 45-second budget. Only resume-login has a 55-second outer response budget, capped by the existing session; business operations retain their 30-second behavior. Human review expiry, grant TTL/quotas, certificate checks, queue ownership and no-replay rules are unchanged.
- Pre-authentication contract mismatches are rejected before repeated grant lookups, while preserving fresh request-entry binding checks and all matching grant/quota/audit checks. Requests cancelled before checking do not consume permits; cancellation while awaiting a reply prevents forwarding without refunding a possibly consumed quota.
- Added delayed-broker real-Edge regressions for 15 approved assets with same-session login/readback and 47 competing checks with unknown traffic denied. No center business code, shared profile or stored credential changes.

## RemoteX 0.6.2

- Added explicit Select All / Clear Selection and a human-chosen Effect Review dropdown with Apply to Checked in the native task-approval window. Neither selection nor classification emits a decision; Approve Selected remains a separate final action.
- Batch classification changes only compatible checked network rows. Mixed or unknown effects refuse the entire update without relabelling writes as reads; unchecked and non-network rows remain unchanged.
- Added read-only sanitized request scope labels, full label tooltips, checked-item counts and a pending-review countdown. Existing 120-second review expiry, grant lifetime bounds, partial approval, target limits, revocation and final business-write confirmation remain unchanged.
- Fixed expired denied-request metadata preventing a fresh rejected request from obtaining a new reference. Only a new denial can mint a replacement; old refs stay invalid, unexpired refs retain their original expiry, and the 120-second TTL/100-entry cap remain unchanged. This does not permit or replay requests.
- Added real WinForms state and production-form callback regressions, including a 15-item batch and final 14-item partial decision, plus actual silent startup checks. No center business code or shared profile/credential changes.

## RemoteX 0.6.1

- Fixed native task-approval startup emitting WinForms collection indices into the private JSON decision pipe. The helper now stays pending until an actual human decision instead of cancelling on an unsolicited numeric frame.
- Added an opt-in interactive Windows regression that starts the actual credential-free helper, verifies silent startup, and closes only that test process. The strict decision decoder, human classification, expiry, revocation, credential isolation, and queue policy are unchanged.

## RemoteX 0.6.0

- Added metadata-only component discovery, immutable action preparation, local batch/subset approval, typed execution, execution status/readback, and revocation tools. No model-facing approve API exists.
- Approved operations can click observed buttons, fill/select/check exact non-secret values, and submit scoped business workflows. Write drafts include stable object identities, observed versions, actual resource before/after values, effect evidence, and bounded request contracts.
- Added independent network sub-items, target-subset request narrowing, finite request budgets, a short armed dispatch window, and default-deny startup/login/task phases. Unknown requests are aborted, described without credentials, and never replayed.
- Denied owned top-level documents receive an inert local 403 with restrictive CSP and zero remote transmission. Explicit same-document GET navigation restores the configured fragment without Chromium error-page races or POST reload/replay.
- Added one-use action-time confirmation for destructive or declared high-risk operations, durable deny-only uncertainty fences, metadata-only authorization audit events, and separately approved table readback. A click or HTTP success is not reported as business completion.
- Network effects require independent native operator classification rather than inheriting a read label from a button capability. Unresolved writes fence the entire target; scoped helper rejection/expiry and dependency revocation preserve unrelated grants. Output authority is rechecked after outer MCP audit/serialization, and secret-bearing paths/field names never enter pending-request metadata.
- Credential-bearing control/target metadata cannot become action references or drafts, and route metadata is redacted. Per-credential usage reports resolve current profile hashes so private web auditing does not lose profile attribution.
- Preserved exact origin/account/certificate binding, isolated credentials, the original supervisor/session, responsive windows, and cooperative queue ownership. Web leases now distinguish reacquisition from renewal without changing SSH/VM lease schemas.
- Upgrade note: new sessions require reviewed startup/login request contracts. Legacy observe/navigate/result tools return `approval-required`; use the task tools. Existing running sessions are not adopted or interrupted. No shared-profile or credential migration is performed.
- Initial scope is bounded JSON/form traffic, observed controls, and stable table targets. Ambiguous identities, unsupported selection/encoding, missing semantics, and required but unenforceable server-side compare-and-set fail closed. No center business code is modified.

## RemoteX 0.5.12

- Fixed the isolated Edge context inheriting Playwright's fixed 1280x720 viewport. Visible login and probe pages now follow the actual browser window without changing browser zoom, system display settings, or site code.
- Added bounded read-only window, viewport, and content-region dimensions to `remotex_web_observe`. `geometry.mode` distinguishes window sizing from viewport emulation.
- Added a real visible-Edge enlargement/shrink regression and an actual login-worker assertion. Existing origin, certificate, credential, queue, and lifetime checks are unchanged.
- No profile or credential migration is needed. Start a new session from the updated MCP process; existing windows retain their creation-time viewport settings.

## RemoteX 0.5.11

### Added

- `remotex_web_observe` reads bounded visible text and short-lived navigation references from the already authenticated isolated page.
- `remotex_web_navigate` previews or follows an observed same-document fragment route. It accepts no raw URL, selector, script, form value, or arbitrary click.
- `remotex_web_read_result` projects numeric/boolean status fields from responses the page already received. It sends no new request and does not infer business success or task permissions.
- An in-memory supervisor-owned pipe preserves page identity without exporting cookies or persisting page/network content. Requester, lease coverage, profile/trust snapshot, origin, authentication, and lifetime are rechecked.

### Upgrade Notes and Limits

- Reconnect only the affected idle MCP client. Existing configuration and credential aliases need no migration; old live sessions are not adopted by a new process.
- A RemoteX session ID is not a Codex browser tab ID. The isolated window remains outside other browser controllers; the new RemoteX tools operate it directly.
- The client must establish current supported-browser permission before using web tools. A denied or unknown host policy is a stop, never a reason to switch transports. RemoteX cannot attest that policy.
- Page text is untrusted data. Editable, hidden, embedded, and canvas content is not exported. Result summaries omit response bodies, headers, cookies, and query values.

## RemoteX 0.5.10

Source: [PR #40](https://github.com/YSheldon/ai-productivity-plugins/pull/40).

### Added

- Explicit exact-origin SHA-256 leaf-certificate trust, with preview, confirmed rotation, and pin-only revocation.
- Fingerprint and validity checks before HTTP headers or bodies are sent; cancellation of pending transport when a session closes.

### Fixed

- Windows credential-window startup when the parent supplies incompatible PowerShell 7 module paths.
- Sanitized failure-receipt classification and rejection of stale trust snapshots before credential reads.

### Upgrade Notes and Limits

- Reconnect running MCP clients after installation. Upgrade old consumers before adding pinned web profiles to shared configuration.
- Normal system TLS trust remains the default. Pinning replaces CA/hostname validation only for the approved origin, not for every website.
- Web sign-in is Windows/Edge only. MFA, CAPTCHA, and uncertain authentication need user handling; do not auto-retry passwords.

## RemoteX 0.5.9

Source: [PR #39](https://github.com/YSheldon/ai-productivity-plugins/pull/39).

- Added HTTPS-origin/account-bound aliases, secure local input, credential-free probes, and bounded isolated Edge sessions.
- Separated submitted, verified, and needs-user-check states, with owned queue/session cleanup.
- Requires Windows, Edge, Node.js 24+, and the pinned Playwright Core runtime. Version 0.5.10 adds optional exact-origin certificate trust.

## RemoteX 0.5.8

Source: [PR #38](https://github.com/YSheldon/ai-productivity-plugins/pull/38).

- Added per-credential system evidence, architecture labels/conflicts, call activity, queue reservations, and recent-use reports.
- Added local HTML, JSON, and CSV exports and 1-365-day filtering without remote probes or queue mutation.
- Historical system evidence and reservation lower bounds are not live CPU utilization or fresh architecture attestation.

## RemoteX 0.5.7

Source: [PR #37](https://github.com/YSheldon/ai-productivity-plugins/pull/37).

- Added one-step queue admission for authorized tasks, FIFO waiting, and reuse of the current task's lease.
- Preserved non-preemption, host/service conflicts, explicit mutation authority, and bounded leases.

## RemoteX 0.5.6

Source: [PR #36](https://github.com/YSheldon/ai-productivity-plugins/pull/36).

- Added fixed-purpose deployment of two management-center service keys from an approved archive location.
- Enforced authenticated root, SFTP staging, non-symlink destinations, root ownership, directory mode `0700`, file mode `0600`, and hash readback.
- Existing destination files are not overwritten. Archive layout and destination are constrained; this is not a generic secret distribution tool.

## Other Current Capabilities

These entries summarize current plugin guides; they do not imply that every
capability was introduced in the latest patch.

| Plugin | Highlights | Guide |
| --- | --- | --- |
| GitLab | MR approval inspection, CI analysis, candidate/scope binding with `CI_JOB_TOKEN`, policy-bound Windows Runner provisioning | [GitLab](plugins/gitlab/README.md) |
| IMAP/SMTP Mail | Windows setup compatibility, portable launcher, constrained thread evidence, opt-in atomic multi-recipient submission | [Mail](plugins/imap-smtp-mail/README.md) |
| Release Approval / Verifier | Independent role-bound controllers, local setup, CLI/scheduler operation, signed evidence | [Approval](plugins/release-approval/README.md) / [Verifier](plugins/release-approval-verifier/README.md) |
| Product material workflows | Explicit submission, mailbox gates, tester evidence, production authorization and readback as distinct stages | [Workflow](docs/product-material-release/installation-and-quickstart.md) |
| R&D Flywheel | Deterministic capability-gap governance through MCP, Skill, CLI, and scheduling | [R&D Flywheel](plugins/rd-flywheel/README.md) |

## Publishing Notes

For future tagged releases, use a plugin-scoped name such as `remotex-v0.5.10`
and bind it to the reviewed commit. This changelog does not itself create a
GitHub Release, tag, installed package, or runtime acceptance result.
Follow the [maintenance checklist](docs/maintaining-project-docs.md).
