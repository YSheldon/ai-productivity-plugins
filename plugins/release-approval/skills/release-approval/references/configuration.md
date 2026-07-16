# Configuration

Copy `config/config.example.json` to a protected location and set `RELEASE_APPROVAL_CONFIG` before starting the MCP server.

Required points:

- `role_email` must match `mail_account.email` exactly.
- `release_group` must be the real delivery target address, not a display label.
- `page.host` stays loopback only.
- `dependency_lock` must point at the bootstrap-written lock file and must not be copied elsewhere.
- The config must not contain passwords, authorization codes, or other credentials.
