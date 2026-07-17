---
name: release-approval
description: Configure and operate one approver-side release workflow through MCP, standalone CLI, or unattended OS scheduling with one credential-free config.
---

# Release Approval

Use this Skill for the role-side release approval workflow. MCP is the preferred interactive surface; the standalone CLI is the equivalent fallback when Codex is unavailable. Codex is optional.

## First Setup

Run `py -3 ./src/release_approval_cli.py setup`. The wizard uses `default_config_path`, requires zero manual JSON edits, discovers the mailbox and scheduler, asks at most four prompts, stores no credentials, installs one hourly OS scheduler, runs preflight, and executes the first headless scan immediately.

The scheduler lifecycle command family is `scheduler install|status|remove`. Windows Task Scheduler, systemd, and cron all skip all missed intervals. A kernel lock returns `RUN_ALREADY_ACTIVE` with no business or audit side effects when another run is active.

## MCP Tools

- `release_approval_preflight`
- `release_approval_start_setup`
- `release_approval_run_once`
- `release_approval_status`
- `release_approval_doctor`
- `release_approval_list_pending`
- `release_approval_open_page`
- `release_approval_get_event`
- `release_approval_verify_audit_chain`

`release_approval_start_setup` uses the same config, controller, dependency lock, and OS scheduler as the CLI. In a loaded MCP process it stops with `FRESH_TASK_REQUIRED` after a dependency upgrade. Restart the task before continuing.

## Runtime Boundaries

- `release_approval_run_once` is always headless. It validates the frozen block, checkpoints `UIDVALIDITY`, `UID`, and `Message-ID`, records pending state, and retries known-unsent decisions without opening a browser or starting a page server.
- `release_approval_open_page` is the only UI action. It creates a fresh one-time loopback page session and never persists URL bearer material.
- Missing authenticated thread evidence stays `CAPABILITY_BLOCKED`; never fall back to subject-only trust.
- The role config is the single policy source and contains no password, token, or authorization code.
- A page click is role evidence only, not aggregate release approval.

## References

- [Configuration](references/configuration.md)
- [Automation Contract](references/automation-contract.md)