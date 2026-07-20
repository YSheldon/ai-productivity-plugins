# GitLab Codex Plugin

This plugin exposes a local MCP server for GitLab REST API workflows. Version
`0.2.0` also provides a fail-closed, privileged workflow for provisioning a
dedicated Windows project Runner without exposing its one-time authentication
token.

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
`JOB-TOKEN` for GitLab CI job tokens. Creating a project Runner requires a token
whose GitLab identity can manage Runners for the policy-bound project.

## Dedicated Windows Runner Provisioning

Provision and resume operations require an elevated Windows process. When the
Codex MCP host is not elevated, run the policy-bound administrator CLI from an
elevated PowerShell session instead:

```powershell
py -3 .\plugins\gitlab\scripts\runner_admin_cli.py provision --policy-name product-material-gate
py -3 .\plugins\gitlab\scripts\runner_admin_cli.py resume --policy-name product-material-gate
```

The CLI accepts only `policy_name` and an optional GitLab profile. It invokes
the same reviewed handlers as the MCP tools, never accepts a token, executable,
path, service account, or command, and exits successfully only when the final
result is `ready=true`.

`gitlab_provision_windows_project_runner` accepts only `policy_name` and an
optional GitLab profile. It never accepts an executable, config path, working
directory, executor, command, password, or Runner token from MCP arguments.

An administrator must prepare this fixed layout. Policy, binary, runtime,
config, and journal trust paths allow writes only to SYSTEM, Administrators, or
TrustedInstaller. NetworkService receives write access only to the isolated
per-policy work subtree:

```text
%ProgramData%\CodexGitLab\
  runner-policies\<policy_name>.json
  runners\<policy_name>\
    config.toml
    provisioning-state.json
    runner-identity.json
    work\
      builds\
      cache\
```

The tool derives `config.toml` as
`%ProgramData%\CodexGitLab\runners\<policy_name>\config.toml`. It refuses an
existing config, journal, or identity receipt so that a repeated request cannot
silently add or replace a Runner registration.

A production-ready Runner has a deterministic `runner-identity.json` in that
same runtime directory. Its exact keys are `schema`, `policy_name`,
`project_id`, `runner_id`, `runner_name`, `tags`, `binary_sha256`,
`config_sha256`, `service_name`, `service_account`,
`machine_identity_sha256`, and `stage`; no extensions or timestamp are allowed.
The schema is exactly `ProductMaterialGateRunnerIdentity/v1`, ids are positive
JSON integers, tags are case-insensitively sorted, hashes are lowercase hex,
and `stage` is `ready`. The machine digest is exactly
`SHA256(UTF-8("ProductMaterialGateRunnerIdentity/v1\0" +
MachineGuid.trim().lower()))`; the raw MachineGuid is never persisted or
returned.

A baseline setup from an elevated PowerShell session is:

```powershell
$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'CodexGitLab'
$runtime = Join-Path $root 'runners\product-material-gate'
$work = Join-Path $runtime 'work'
New-Item -ItemType Directory -Force "$root\runner-policies", "$work\builds", "$work\cache" | Out-Null
icacls $root /setowner '*S-1-5-32-544' /T /C
icacls $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C
icacls $work /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-20:(OI)(CI)M' /T /C
```

Copy `config/runner-policy.example.json` to the protected policy directory and
replace every placeholder. `runner_binary_sha256` must equal the exact signed
`gitlab-runner.exe` under a Windows Program Files directory:

```powershell
Get-FileHash 'C:\Program Files\GitLab-Runner\gitlab-runner.exe' -Algorithm SHA256
Get-AuthenticodeSignature 'C:\Program Files\GitLab-Runner\gitlab-runner.exe'
```

The tool validates the ProgramData and Program Files path chains for reparse
points, broad write ACLs, and untrusted owners. It then performs this sequence:

1. Resolve the policy project to its numeric GitLab project id.
2. `POST /user/runners` as `project_type`, initially `paused=true`,
   `locked=true`, `run_untagged=false`, and `access_level=ref_protected` with
   the exact policy tags.
3. Pass the returned one-time token only in a private child environment as
   `CI_SERVER_TOKEN`; the token never appears in argv, tool output, errors, or
   logs, and the parent environment is not modified.
4. Run `gitlab-runner register`, validate the generated config ACL, run
   `gitlab-runner verify`, and attest all Runner fields through the API.
5. If `install_service` is true, install a policy-named service in the
   stopped state without a user or password argument. Attest its exact command
   line and service DACL, switch the built-in account to
   `NT AUTHORITY\NetworkService` through fixed system PowerShell/CIM, and
   re-attest the account before starting it.
6. Wait the full protected-policy `timeout_seconds` value (validated as 30-600 seconds) for both the Windows service to be `Running` and the GitLab API Runner status to be `online`. Only then unpause and re-attest the Runner.
7. Immediately before unpause, re-attest the running service and the still-paused
   API Runner as `online`, hash the current fixed Program Files binary and the
   sibling `config.toml`, and atomically replace and strictly read back
   `runner-identity.json`. Its DACL is non-inheriting and exact: SYSTEM and
   Administrators have FullControl; NetworkService has ReadAndExecute only.
   Only after that receipt verifies exactly may the API Runner be unpaused.

Any failure before service installation deletes the newly created GitLab Runner
and removes the dedicated config, journal, and identity receipt. Service
install/account/start failures preserve the valid registration but
keep it paused, remove or disable partial service state, and update a protected
non-secret journal. The journal binds the original `service_name` and
`service_account`; any policy drift is rejected before resume can perform a
service action. Retry only with
`gitlab_resume_windows_project_runner(policy_name=...)`; resume never needs
or persists the one-time token, re-pauses before validating local state,
revokes any prior identity receipt, and rebuilds and validates it before a new
unpause. Activation failure removes the receipt, re-pauses the Runner, stops
the service on a best-effort basis, and records the fixed failure stage in the
existing journal; a successful receipt/activation is represented by journal
stage `ready`. If `install_service` is false, the successful result is
deliberately `registered_paused`, not production-ready.

`machine_identity_sha256` is an anti-misconfiguration and accidental-clone
binding, not TPM-backed hardware attestation. Administrators and SYSTEM are in
the trusted computing base and can reproduce host state; this design does not
claim to resist a privileged host clone.

## Security Boundaries

- API calls are restricted to relative paths on the configured GitLab origin. Absolute URLs, network paths, embedded query strings, and redirects are rejected so authentication headers cannot be forwarded to another host.
- On Windows, HTTPS verification automatically includes trusted root and intermediate CA certificates from the system certificate stores; certificate verification is never disabled.
- Structured tool results and JSON error bodies recursively redact token, password, secret, cookie, runner-registration fields, and GitLab CI variable values while preserving non-secret metadata.
- Opaque `raw=true` responses are disabled because base64 bodies cannot be safely inspected or redacted. Every non-GET global, user, project, or group Runner-management path is blocked from the generic API tool; use a policy-bound dedicated tool instead.
- Unexpected exception details and all GitLab Runner stdout/stderr are suppressed. Supply GitLab authentication only through the configured environment variable or profile.
- If Python strict TLS rejects a Windows enterprise certificate chain, the plugin falls back to Schannel through a bundled non-redirecting helper launched by Windows PowerShell resolved from the Win32 system directory. Credentials are passed over stdin, never in process arguments.
