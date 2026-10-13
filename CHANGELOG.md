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
