# Release Approval

This plugin owns the durable local state for one release-approval role identity.

Task 4 only lands the frozen configuration contract, deterministic request validation, SQLite event store, and append-only audit-chain verification. It does not yet start a page server, launch a browser, send mail, write Feishu state, or perform verifier-side aggregation.

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

Task 4 leaves `.mcp.json` as an explicit empty scaffold. Task 6 will register the real startup-locked MCP server after the server implementation exists; no library module is exposed as a placeholder server in this task.

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

## State Core

The SQLite store persists:

- IMAP message identity keyed by account, mailbox, `UIDVALIDITY`, and UID, with unique `Message-ID`.
- Role-bound requests keyed by event, round, and role.
- Decision history with current-decision supersession.
- Local page metadata with HTML hash and nonce hash.
- SMTP outcome records.
- An append-only audit ledger with chained hashes for restart-safe tamper detection.

The audit chain is deterministic and restart-verifiable. Any row tamper or boundary mismatch fails closed.

The local database now carries an explicit `PRAGMA user_version` schema marker. A fresh empty database is initialized to the current schema version, and a current-version restart reuses it in place. A non-empty unversioned or mismatched-version database is treated as unsupported legacy state and startup fails closed; migrate it explicitly or remove it and let the plugin create a fresh state database.
