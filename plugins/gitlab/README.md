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
