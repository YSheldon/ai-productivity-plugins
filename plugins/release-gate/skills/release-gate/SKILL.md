---
name: release-gate
description: Configure and operate the service-side release gate workflow through MCP, standalone CLI, or unattended OS scheduling with one credential-free config.
---

# Release Gate

Use this Skill for the release-gate service account workflow. MCP is the preferred interactive surface; the standalone CLI is the equivalent fallback when Codex is unavailable.

## First Setup

Run `py -3 ./src/release_gate_cli.py setup`. The wizard uses `default_config_path`, requires zero manual JSON edits, bootstraps the locked product-release-gate and imap-smtp-mail dependencies, asks at most four prompts, stores no credentials, installs one hourly OS scheduler, runs preflight, executes the first headless scan immediately, and verifies the append-only audit chain.

The scheduler lifecycle command family is `scheduler install|status|remove`. Windows Task Scheduler, systemd, and cron all skip all missed intervals. A kernel lock returns `RUN_ALREADY_ACTIVE` with no business or audit side effects when another run is active. After the first setup, reruns use zero prompts and zero manual JSON editing as long as the config already exists.

## MCP Tools

- `release_gate_preflight`
- `release_gate_start_setup`
- `release_gate_run_once`
- `release_gate_status`
- `release_gate_doctor`
- `release_gate_verify_audit`

## Runtime Boundaries

- `release_gate_run_once` is always headless. It prefers a verified `ProductMaterialWorkflow/v1` machine event, but it can fall back to canonical human-readable mail when the machine event or HMAC is absent.
- A claimed machine event with an invalid HMAC is blocked as `AUTHENTICATION_FAILED`; it is never silently downgraded.
- A successful handoff sends `【发布申请】...` with `RELEASE_GATE_PASS`, includes the submitter email when available, and stops at `RELEASE_READY_NOTIFIED`.
- The plugin never performs production deployment; downstream approval and deployment stay outside this surface.
- For `retrieval_method=svn`, fixed revision and repository provenance are mandatory, while user-supplied hashes, signature evidence, and cloud-scan evidence are not required inputs.
- Required checks cannot be disabled, and removing any canonical required item causes `preflight` and `run-once` to fail closed.
