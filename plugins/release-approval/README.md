# Release Approval

Release Approval runs one approver-side release workflow through one controller, one credential-free config, and one SQLite state store. The same domain operations are exposed through MCP, Skill, standalone CLI, and an unattended OS scheduler. Codex is optional.

## Quick Start

From the plugin directory run:

```powershell
py -3 .\src\release_approval_cli.py setup
```

The setup wizard requires zero manual JSON edits. It discovers the platform scheduler, timezone, and existing mail profiles; a standard setup asks no more than four prompts and a repeated setup asks none. It runs dependency bootstrap, preflight, an immediate headless scan, external scheduler verification, and prints status, doctor, and rollback commands.

All surfaces resolve the same path through `default_config_path`:

- Windows: `%LOCALAPPDATA%\release-approval\config.json`
- Linux: `$XDG_CONFIG_HOME/release-approval/config.json` or `~/.config/release-approval/config.json`
- Override: `RELEASE_APPROVAL_CONFIG` or one global CLI `--config <path>`

The config never stores passwords, authorization codes, tokens, or mailbox secrets. Setup also freezes the product-release-gate sender with `--request-sender-email` (or `RELEASE_APPROVAL_REQUEST_SENDER_EMAIL`) and the trusted mail authentication issuer with `--trusted-authserv-ids` (or `RELEASE_APPROVAL_TRUSTED_AUTHSERV_IDS`); the interactive wizard remains within four prompts. An optional `--audit-document-url` (or `RELEASE_APPROVAL_AUDIT_DOCUMENT_URL`) enables Feishu/Lark cloud audit writeback and readback without adding another setup prompt.

## Standalone CLI

```text
release_approval_cli.py [--config PATH] setup
release_approval_cli.py [--config PATH] preflight
release_approval_cli.py [--config PATH] run-once
release_approval_cli.py [--config PATH] status
release_approval_cli.py [--config PATH] doctor
release_approval_cli.py [--config PATH] list-pending
release_approval_cli.py [--config PATH] open-page --event-id ID --round-id N
release_approval_cli.py [--config PATH] get-event --event-id ID --round-id N
release_approval_cli.py [--config PATH] verify-audit
release_approval_cli.py [--config PATH] scheduler install|status|remove
```

Commands return one JSON object and stable exit codes. `run-once` is always headless. `open-page` is the only command that starts a loopback page server or opens a browser, and the standalone process remains alive until a decision, expiry, or cancellation.

## MCP

The MCP server uses the same default config and controller:

- `release_approval_preflight`
- `release_approval_start_setup`
- `release_approval_run_once`
- `release_approval_status`
- `release_approval_doctor`
- `release_approval_list_pending`
- `release_approval_open_page`
- `release_approval_get_event`
- `release_approval_verify_audit_chain`

If an MCP bootstrap upgrades a loaded dependency it returns `FRESH_TASK_REQUIRED`; restart the task before continuing. The standalone setup process can re-preflight its external CLI dependencies directly.

## OS Scheduler

Auto mode selects Windows Task Scheduler, a user systemd timer, or cron. Every backend invokes the absolute Python executable and `release_approval_cli.py --config <path> run-once`.

- Missed intervals are skipped rather than caught up.
- Windows policy is externally read back as `MultipleInstancesPolicy=IgnoreNew` and `StartWhenAvailable=false`.
- systemd uses `Persistent=false`.
- Cron has no catch-up behavior.
- A non-expiring OS-kernel lock returns `RUN_ALREADY_ACTIVE` with zero mail, business, or audit side effects on overlap.
- Codex Automation is not required and is disabled unless equivalent misfire and overlap semantics can be proven.

## Trust Boundaries

Incoming requests must come from a configured allowlisted sender, present `Authentication-Results` from one configured authserv-id, pass one configured DMARC/DKIM/SPF path with sender/domain alignment, contain authenticated thread/readback evidence, and carry a valid frozen machine block. SPF now requires both `Authentication-Results` and `Received-SPF` to agree. Malformed messages are quarantined per message so they cannot stop later valid requests, and previously audited rejected messages are transport-checkpointed so one poison message cannot keep every later poll blocked. `UIDVALIDITY`, `UID`, and `Message-ID` provide checkpoint idempotency. Missing evidence stays `CAPABILITY_BLOCKED`; subject-only correlation is never trusted.

An explicit page open creates a fresh one-time loopback page session. URL bearer material is never persisted. A page decision is role evidence only; it does not aggregate approvals or authorize deployment.

Mail delivery, page-decision validity, local audit-chain validity, and cloud audit write/readback are separate facts. Optional cloud-audit failure is recorded as `AUDIT_DEGRADED` and never represented as successful cloud readback.

## Advanced Configuration

`config/config.example.json` documents every field for controlled non-interactive deployment. Its `dependency_lock` example remains under the inspected repository root; normal users should let `setup` generate the absolute lock path instead of copying or editing JSON.