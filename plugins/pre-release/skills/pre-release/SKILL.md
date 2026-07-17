---
name: pre-release
description: Configure and operate the tester-side pre-release workflow through MCP, standalone CLI, or unattended OS scheduling with one credential-free config.
---

# Pre Release

Use this Skill for the tester-side pre-release workflow. MCP is the preferred interactive surface; the standalone CLI is the equivalent fallback when Codex is unavailable.

## First Setup

Run py -3 ./src/pre_release_cli.py setup. The wizard uses default_config_path, requires zero manual JSON edits, bootstraps the locked product-release-gate and imap-smtp-mail dependencies, asks at most four prompts on first setup, reruns with zero prompts when the config already exists, stores no credentials, installs one hourly OS scheduler, runs preflight, executes the first headless sync immediately, and verifies the append-only audit chain.

The scheduler lifecycle command family is scheduler install|status|remove. Windows Task Scheduler, systemd, and cron all skip all missed intervals. A kernel lock returns RUN_ALREADY_ACTIVE with no business or audit side effects when another run is active.

## MCP Tools

- pre_release_preflight
- pre_release_start_setup
- pre_release_run_once
- pre_release_status
- pre_release_doctor
- pre_release_verify_audit
- pre_release_list_tasks
- pre_release_create_request

## Runtime Boundaries

- pre_release_run_once is always headless. It accepts a verified ProductMaterialWorkflow/v1 machine event when present, but it can also fall back to canonical human-readable mail when the machine event or HMAC is absent.
- A claimed machine event with an invalid HMAC is blocked as AUTHENTICATION_FAILED; it is never silently downgraded.
- pre_release_create_request is the only action that accepts tester input. It auto-fills the tested Manifest digest and completion time, and it sends PRERELEASE_REQUEST only when the test result is PASS.
- For `retrieval_method=svn`, fixed revision and repository provenance are mandatory, while user-supplied hashes, signature evidence, and cloud-scan evidence are not required inputs.
- Installation config never stores a default final output directory or a test-result source.
