# rd-flywheel

A deterministic, fail-closed runtime for capability-gap governance. One controller and one versioned config are exposed through four equivalent surfaces:

- MCP for tool clients.
- Skill for Codex-assisted operation.
- Standalone Python CLI for hosts without Codex.
- Windows Task Scheduler, systemd user timer, or cron for unattended scans.

Codex is optional. Production scheduling invokes the standalone CLI directly.

## Quick setup

No manual JSON editing is required:

~~~powershell
py -3 .\src\rd_flywheel_cli.py setup
~~~

Unattended setup uses deterministic defaults:

~~~powershell
py -3 .\src\rd_flywheel_cli.py --config C:\ProgramData\rd-flywheel\config.json setup --non-interactive
~~~

Setup discovers allowlisted tool and agent profiles, asks at most three questions, writes no credentials, installs one OS schedule, performs preflight, runs the first headless scan, and reads status back. Re-running setup reuses the same config with zero prompts.

The config path defaults to `%LOCALAPPDATA%\rd-flywheel\config.json` on Windows or `$XDG_CONFIG_HOME/rd-flywheel/config.json` on Linux. `RD_FLYWHEEL_CONFIG` overrides it for all surfaces.

## Operations

~~~powershell
py -3 .\src\rd_flywheel_cli.py preflight
py -3 .\src\rd_flywheel_cli.py run-once
py -3 .\src\rd_flywheel_cli.py status
py -3 .\src\rd_flywheel_cli.py doctor
py -3 .\src\rd_flywheel_cli.py list-events
py -3 .\src\rd_flywheel_cli.py get-event <idempotency-key>
py -3 .\src\rd_flywheel_cli.py retry-event <idempotency-key>
py -3 .\src\rd_flywheel_cli.py verify-audit
py -3 .\src\rd_flywheel_cli.py scheduler install --mode auto
py -3 .\src\rd_flywheel_cli.py scheduler status --mode auto
py -3 .\src\rd_flywheel_cli.py scheduler remove --mode auto
~~~

Every command emits one JSON object and stable exit codes: 0 ready/complete, 2 usage, 3 capability blocked, 4 evidence pending, 5 run already active, and 6 event not found.

## Managed adapter profiles

Agent and evidence-verifier commands are references supplied by the service environment, not copied into plugin config:

- `RD_FLYWHEEL_AGENT_COMMANDS_JSON`: JSON object mapping approved profile IDs to argv arrays.
- `RD_FLYWHEEL_VERIFIER_COMMANDS_JSON`: JSON object mapping evidence kinds to argv arrays.
- `RD_FLYWHEEL_TOOL_PROFILES`: optional comma-separated discovery hints restricted to the fixed tool allowlist.

Commands run with `shell=False` and canonical JSON on stdin. Agent output, a generated patch, a queued job, and a zero exit code are evidence references only. They never grant merge, publication, installation, deployment, or production authority.

## Safety model

- `CapabilityGapEvent/v1` binds the originating plugin, event, round, checkpoint digest, required evidence, allowed tool profiles, timestamp, and idempotency key.
- SQLite stores immutable input payloads, state transitions, evidence, and an append-only SHA-256 audit chain.
- A non-expiring OS kernel lock is acquired before every `run-once`; overlap returns `RUN_ALREADY_ACTIVE` without business or audit writes.
- All scheduler backends skip all missed intervals. Windows verifies `IgnoreNew` and `StartWhenAvailable=false`; systemd verifies `Persistent=false`; cron accepts only exact schedules.
- Missing tools, missing approved adapters, invalid contracts, evidence gaps, verifier failures, and audit tampering fail closed.
- `COMPLETE` requires separate verified evidence for tests, independent review, protected merge, package publication, installation, first practice, rollback, and original-checkpoint replay.
