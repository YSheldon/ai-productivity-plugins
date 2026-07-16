# Release Approval

This plugin owns the role-side release approval loop for one configured approver mailbox.

Task 6 adds the startup-locked MCP server, the fixed-profile setup entrypoint, deterministic `run_once` mail scanning, and the hourly automation install boundary. It still does not implement verifier aggregation or Task 7+ behavior.

## Configuration

Define the inspected repository root before using the example:

```powershell
$env:RELEASE_APPROVAL_REPO_ROOT = "C:\absolute\path\to\inspected-repository"
```

Only after setting it, copy `config/config.example.json` to a protected path and set:

```powershell
$env:RELEASE_APPROVAL_CONFIG = "C:\path\to\release-approval.json"
```

The runtime configuration is read once at MCP startup. Tool calls must not override `config_path`; restart the process after an approved config change.

During installation, replace `dependency_lock` with the exact absolute path returned by `bootstrap_dependencies.py`. The example value `%RELEASE_APPROVAL_REPO_ROOT%\dependency-lock.json` preserves the inspected repo-root containment model, and the bootstrap-written lock file must not be copied elsewhere.

Required fields:

- `role_id`
- `role_email`
- `mail_account`
- `release_group`
- `mailbox`
- `page`
- `working_hours`
- `state_dir`
- `dependency_lock`
- `audit`

Validation is fail-closed:

- `page.host` must stay loopback-only.
- `poll_minutes` must stay within `5..1440`.
- `role_email` and `mail_account.email` must be valid and identical.
- The config must not contain passwords or authorization-code fields.

## Task 6 Tools

- `release_approval_preflight`
- `release_approval_start_setup`
- `release_approval_run_once`
- `release_approval_list_pending`
- `release_approval_open_page`
- `release_approval_get_event`
- `release_approval_verify_audit_chain`

`release_approval_start_setup` runs only the fixed allowlisted bootstrap. If dependencies changed, it returns `FRESH_TASK_REQUIRED` and stops before using the new capability in the same task. Otherwise it validates the configured account email, creates exactly one hourly Codex automation, and runs the first scan immediately.

`release_approval_run_once` reads recent release requests through the locked mail bridge, validates the frozen machine block, uses `UIDVALIDITY`, `UID`, and `Message-ID` idempotency, creates or reuses exactly one page, retries known-unsent decisions, and auto-opens only newly created pages. Missing thread or readback capability remains `CAPABILITY_BLOCKED`; there is no subject-only trust fallback.

The loopback page opens only after durable artifacts exist, and page clicks do not count as aggregate approval.
