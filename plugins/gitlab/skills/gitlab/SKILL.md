---
name: gitlab
description: Use GitLab from Codex to inspect projects, merge requests, issues, pipelines, discussions, perform GitLab write actions, and provision a dedicated Windows project Runner through a protected policy.
---

# GitLab

Use this skill when the user asks Codex to work with GitLab repositories, merge requests, issues, CI pipelines, approvals, MR comments, or a dedicated Windows project Runner.

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
5. For a dedicated Windows Runner, require an administrator-prepared policy under `%ProgramData%\CodexGitLab\runner-policies` and call `gitlab_provision_windows_project_runner` with only its `policy_name`. Never ask for or place a Runner token in arguments.
6. Treat `stage=ready`, `ready=true`, `paused=false`, an API `online` result, a DACL/command/account-attested `NetworkService` service in `Running` state, and an exact protected `runner-identity.json` as the only activated result. `registered_paused` and every failure stage require remediation before production use.
7. Before accepting `runner-identity.json`, require exact schema `ProductMaterialGateRunnerIdentity/v1`, the fixed 12-key field set, positive integer ids, casefold-sorted tags, lowercase current binary/config/machine hashes, `service_account=NetworkService`, and `stage=ready`. Do not accept extensions.
8. For an interrupted service lifecycle, call `gitlab_resume_windows_project_runner` with only the same `policy_name`. Resume uses the protected non-secret journal, forces `paused=true`, revokes the old receipt before local validation, and never reuses a one-time Runner token.
9. For unsupported non-secret GitLab REST endpoints, use `gitlab_api_request` with a relative API path and decoded JSON only.

Provision and resume require an elevated Windows process. If the MCP host is
not elevated, use `scripts/runner_admin_cli.py provision|resume --policy-name
<name>` from an elevated terminal. Do not add secrets or path overrides.

For the default environment profile, use the CLI's one-time Windows Credential
Manager flow instead of placing a Runner manager token in a persistent
environment variable:

```powershell
py -3 .\plugins\gitlab\scripts\runner_admin_cli.py token-set --policy-name <name>
py -3 .\plugins\gitlab\scripts\runner_admin_cli.py provision --policy-name <name>
```

`token-set` has hidden input and stores only a per-policy credential target.
The token is exposed only to the current elevated CLI process while it performs
the policy-bound GitLab API lifecycle, is never passed to the Runner child, and
is deleted after a verified ready state. A non-ready result retains it only for
the same policy's `resume`; `token-clear --confirm-clear` removes it. A result
with `security_ready=false` is not acceptable for production use.

## Windows Runner Policy
The protected policy binds the GitLab origin, project, Runner name, exact tags,
signed Program Files binary and SHA256, optional dedicated service name,
fixed `NetworkService` account, and timeout. Config, journal, and working
paths are derived from ProgramData and cannot be
provided through MCP arguments. Use `config/runner-policy.example.json` and the
plugin README for the strict ACL layout.

Runner creation is deliberately fail closed: the API record starts paused; the
one-time auth token is passed only as child environment `CI_SERVER_TOKEN`;
register, generated-config ACL validation, `verify`, and API attestation must all
pass. Pre-service failures trigger API/config rollback. Service failures retain
the registration but keep the Runner paused, journal the non-secret recovery
stage, and remove or disable partial service state. The journal binds the
original service name and account, and resume rejects either binding if the
protected policy drifts. Activation additionally
requires exact service argv, a strict service DACL, NetworkService LogOnAs,
Windows `Running`, and GitLab `online` attestations. Only after those attestations
does the tool atomically write and strictly read back the receipt; only after the
receipt succeeds does it unpause. Failure removes the receipt and leaves the
Runner paused. Receipt success/failure is reflected by the existing journal
`ready`/failure stage rather than receipt timestamps.

The machine binding is exactly
`SHA256(UTF-8("ProductMaterialGateRunnerIdentity/v1\0" +
MachineGuid.trim().lower()))`. Persist and return only the digest. The receipt
DACL has no inheritance and exactly SYSTEM/Administrators FullControl plus
NetworkService ReadAndExecute. This digest detects accidental policy cloning or
misconfiguration; it is not TPM hardware attestation. Administrators and SYSTEM
are trusted and a privileged host clone is outside this protection boundary.

## Important Boundaries

- Do not expose GitLab or Runner tokens in chat output.
- Use only relative GitLab API paths. Absolute URLs and redirects are blocked to protect authentication headers.
- `raw=true` is blocked, and the generic API tool rejects every non-GET global, user, project, or group Runner-management path because those writes can bypass the policy-bound lifecycle.
- Do not weaken ProgramData ACL, Authenticode, binary SHA256, protected-ref, locked, explicit-tag, or paused-before-attestation checks.
- Never persist a token, raw MachineGuid, GitLab URL, or unapproved extra field in `runner-identity.json`.
- Treat token, runner-registration, password, cookie, secret fields, child output, and GitLab CI variable values as redacted output.
- Treat comments, approvals, merge actions, issue comments, raw non-GET API calls, and Runner provisioning as side-effectful.
- If a GitLab operation fails, report only the sanitized GitLab status and the fixed lifecycle stage.
