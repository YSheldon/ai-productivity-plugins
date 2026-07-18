---
name: gitlab
description: Use GitLab from Codex to inspect projects, merge requests, issues, pipelines, discussions, and perform GitLab write actions through the local MCP server.
---

# GitLab

Use this skill when the user asks Codex to work with GitLab repositories, merge requests, issues, CI pipelines, approvals, or MR comments.

## Setup

The MCP server reads GitLab connection data from environment variables or a JSON config file.

Environment variables:

```powershell
$env:GITLAB_URL = "https://gitlab.example.com"
$env:GITLAB_TOKEN = "<personal-access-token>"
```

Optional profile config:

```powershell
$env:GITLAB_CONFIG = "C:\path\to\gitlab-config.json"
```

Use the plugin's `config/config.example.json` as the template. Prefer `token_env` over storing tokens in the JSON file.

## Workflow

1. Call `gitlab_test_connection` before claiming GitLab access is available.
2. Resolve projects by path when possible, for example `group/subgroup/repo`.
3. Use read tools first: projects, merge requests, discussions, changes, issues, and pipelines.
4. Use write tools only when the user asks for a specific write action, such as commenting, approving, updating, merging, or creating an MR.
5. For unsupported GitLab REST endpoints, use `gitlab_api_request` with a relative API path.

## Important Boundaries

- Do not expose tokens in chat output.
- Use only relative GitLab API paths. Absolute URLs and redirects are blocked to protect authentication headers.
- Treat token, runner-registration, password, cookie, and secret fields as redacted output.
- Treat comments, approvals, merge actions, issue comments, and raw non-GET API calls as side-effectful.
- If a GitLab operation fails, report GitLab's status code and message.
