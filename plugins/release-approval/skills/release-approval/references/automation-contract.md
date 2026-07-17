# Automation Contract

`release_approval_start_setup` and standalone CLI `setup` share the same controller, config, dependency bootstrap, and OS scheduler adapter.

Setup must:

- validate the configured mailbox binding
- install one idempotent hourly OS schedule
- execute the first headless `run-once` immediately
- verify external scheduler state
- expose status, doctor, and rollback commands
- return `FRESH_TASK_REQUIRED` in a loaded MCP task after dependencies change
- work without Codex through the standalone CLI

`release_approval_run_once` must:

- acquire a non-expiring OS-kernel lock before mail or audit work
- return `RUN_ALREADY_ACTIVE` with zero side effects on overlap
- recover orphan metadata only after acquiring the kernel lock
- validate the frozen machine block and authenticated thread evidence
- checkpoint `UIDVALIDITY`, `UID`, and `Message-ID`
- record pending state and retry known-unsent decisions
- remain headless and never start a page server or browser
- keep duplicate or unauthenticated checkpoints from repeating side effects
- write `REQUEST_CREATED` once for a new authenticated request when cloud audit is configured
- write `PAGE_DECISION` separately from SMTP delivery state
- report optional cloud-audit failures as degraded local evidence, never as verified cloud readback

Only `release_approval_open_page` may start UI. It creates a fresh one-time loopback page session without persisting URL bearer material.

Scheduler adapters must invoke the standalone CLI `run-once`, skip all missed intervals, reject overlap, support install/status/remove, and verify the external schedule before reporting ready.