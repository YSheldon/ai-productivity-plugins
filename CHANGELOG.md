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

## RemoteX 0.6.0

- Added metadata-only component discovery, immutable action preparation, local batch/subset approval, typed execution, execution status/readback, and revocation tools. No model-facing approve API exists.
- Approved operations can click observed buttons, fill/select/check exact non-secret values, and submit scoped business workflows. Write drafts include stable object identities, observed versions, actual resource before/after values, effect evidence, and bounded request contracts.
- Added independent network sub-items, target-subset request narrowing, finite request budgets, a short armed dispatch window, and default-deny startup/login/task phases. Unknown requests are aborted, described without credentials, and never replayed.
- Denied owned top-level documents receive an inert local 403 with restrictive CSP and zero remote transmission. Explicit same-document GET navigation restores the configured fragment without Chromium error-page races or POST reload/replay.
- Added one-use action-time confirmation for destructive or declared high-risk operations, durable deny-only uncertainty fences, metadata-only authorization audit events, and separately approved table readback. A click or HTTP success is not reported as business completion.
- Network effects require independent native operator classification rather than inheriting a read label from a button capability. Unresolved writes fence the entire target; scoped helper rejection/expiry and dependency revocation preserve unrelated grants. Output authority is rechecked after outer MCP audit/serialization, and secret-bearing paths/field names never enter pending-request metadata.
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
