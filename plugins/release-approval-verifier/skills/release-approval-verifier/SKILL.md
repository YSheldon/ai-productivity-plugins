---
name: release-approval-verifier
description: Independently verify multi-role release decisions, reminders, signed aggregate receipts, and the PRE_RELEASE_REQUESTED handoff through one shared runtime.
---

# Release Approval Verifier

Use this Skill for independent release-approval verification. It is the human-friendly fourth surface over the same controller, configuration, SQLite state, and audit chain used by MCP, the standalone CLI, and the OS scheduler.

## Operating Order

1. Use **MCP-first** when `release_approval_verifier_preflight` is available.
2. Use the **CLI fallback** when MCP is unavailable. Run `py -3 src/verifier_cli.py setup` once; standard setup requires zero manual JSON editing, and a valid existing configuration makes setup reruns use zero prompts.
3. Run preflight before state-changing work. Missing mail headers, role snapshots, audit signing keys, or handoff adapters remain `CAPABILITY_BLOCKED`.
4. Use `release_approval_verifier_run_once` or `py -3 src/verifier_cli.py run-once`. The unattended scheduler invokes exactly this headless operation.
5. Inspect events with `get-event` and `list-missing-roles`. Verify any aggregate artifact with `verify-receipt` before handoff.
6. Install unattended operation with `py -3 src/verifier_cli.py scheduler install`; verify with `scheduler status`; roll back only this plugin's schedule with `scheduler remove`.

Codex is optional. The Skill must never become a second policy implementation or a scheduler dependency.

## Hard Boundary

Only all required, current, authenticated approvals yield `APPROVAL_VERIFIED`. The next workflow state is `PRE_RELEASE_REQUESTED`; it is not `RELEASE_AUTHORIZED`, a deployment credential, or production completion. Reject, hold, ambiguity, expiry, quarantine, revocation, missing capabilities, and audit failure remain fail closed.

## Configuration

Use the single configuration selected by `verifier_config.default_config_path`. Do not pass a per-call configuration or policy override. See [configuration.md](references/configuration.md) and [automation-contract.md](references/automation-contract.md).
