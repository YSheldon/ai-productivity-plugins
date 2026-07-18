# GitLab Codex Plugin

This plugin exposes a local MCP server for GitLab REST API workflows.

## Configuration

Set environment variables:

```powershell
$env:GITLAB_URL = "https://gitlab.example.com"
$env:GITLAB_TOKEN = "<personal-access-token>"
```

Or create a JSON config file and point `GITLAB_CONFIG` at it:

```powershell
$env:GITLAB_CONFIG = "C:\path\to\gitlab-config.json"
```

Use `config/config.example.json` as the template. Tokens may be supplied through
`token_env` instead of storing secrets in the file.

## Authentication

The default header is `PRIVATE-TOKEN`, which works for GitLab personal access
tokens. Set `auth_header` to `Authorization` to send `Bearer <token>`, or
`JOB-TOKEN` for GitLab CI job tokens.

## Security Boundaries

- API calls are restricted to relative paths on the configured GitLab origin. Absolute URLs, network paths, embedded query strings, and redirects are rejected so authentication headers cannot be forwarded to another host.
- On Windows, HTTPS verification automatically includes trusted root and intermediate CA certificates from the system certificate stores; certificate verification is never disabled.
- Structured tool results and JSON error bodies recursively redact token, password, secret, cookie, runner-registration fields, and GitLab CI variable values while preserving non-secret metadata.
- Unexpected exception details are suppressed. Supply authentication only through the configured environment variable or profile, never through raw API paths, query objects, or request bodies.
- If Python strict TLS rejects a Windows enterprise certificate chain, the plugin falls back to Schannel through a bundled non-redirecting helper launched by Windows PowerShell resolved from the Win32 system directory, without relying on inherited environment variables. Credentials are passed over stdin, never in process arguments.
