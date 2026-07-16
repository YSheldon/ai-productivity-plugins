---
name: release-approval
description: Use when configuring or running the release-approval role plugin for hourly mail-driven approval collection, loopback page handling, and audit-chain checks.
---

# Release Approval

Use this plugin when the task is to operate the role-side release approval workflow.

## Tools

- `release_approval_preflight` checks the startup-locked config, dependency lock, loopback page boundary, and configured mail account binding.
- `release_approval_start_setup` runs the fixed allowlisted bootstrap, stops with `FRESH_TASK_REQUIRED` after dependency changes, creates exactly one hourly Codex automation, and runs the first scan immediately.
- `release_approval_run_once` searches recent release requests, validates the frozen machine block, uses `UIDVALIDITY`, `UID`, and `Message-ID` idempotency, creates or reuses the existing page, retries known-unsent decisions, and auto-opens only newly created pages.
- `release_approval_list_pending` lists pending and retry-queued role checkpoints.
- `release_approval_open_page` re-opens the current loopback approval page for an existing page session.
- `release_approval_get_event` reads the stored checkpoint, page artifact path, and latest decision/send state.
- `release_approval_verify_audit_chain` verifies the append-only SQLite audit chain.

## Required Boundaries

- The MCP server reads config once at startup. Do not pass `config_path` per call.
- The role config has no credentials.
- Missing thread or readback capability is `CAPABILITY_BLOCKED`; preserve the checkpoint and do not trust subject-only matching.
- Browser open happens only after durable artifacts exist.
- The page host stays loopback only.
- Page clicks are not aggregate approval and do not replace verifier-side checks.
- Task 6 stops at role-side setup and run_once behavior. Do not add verifier aggregation or Task 7+ behavior here.

## References

- [Configuration](references/configuration.md)
- [Automation Contract](references/automation-contract.md)
