# RemoteX Credential Lifecycle Design

Status: Proposed

Date: 2026-09-01

Target release: RemoteX 0.5.0

## Context

RemoteX 0.4.1 keeps literal passwords and private-key bodies out of MCP tool
arguments and profile configuration. Profiles currently embed credential
references directly:

- SSH uses an identity-file path or the local SSH Agent.
- RDP references a Windows Credential Manager `TERMSRV/host` entry.
- Windows guest WinRM uses a Windows Generic Credential or the current Windows
  identity.
- vSphere and ESXi use a Windows Generic Credential or named environment
  variables.
- VMware Workstation uses the current local desktop session.

This model has two limitations. First, RemoteX can inspect references but has no
safe setup, rotation, deletion, or migration workflow. Users must create entries
outside the plugin and manually keep profile target names synchronized. Second,
resumable SSH tasks write `stdin.bin` and `secrets.json` before the worker reads
and removes them. On Windows, `os.chmod` does not remove inherited access-control
entries, so a task directory can temporarily expose reversible input and raw
redaction values to another permitted local principal.

## Goals

1. Never place a password, token, private-key body, or injected secret in MCP
   arguments, process arguments, configuration, logs, audit records, receipts,
   or persistent files.
2. Provide a local interactive Windows credential setup, rotation, and deletion
   workflow whose secure prompt is outside the model and MCP payload.
3. Add reusable named credential references without forcing existing version 1
   configurations to migrate immediately.
4. Separate configuration, reference presence, and verified authentication in
   status results.
5. Enforce effective local filesystem permissions for sensitive RemoteX state.
6. Preserve current SSH public-key-only, host-key, VM identity, queue, audit,
   timeout, output, and process-tree safeguards.

## Non-goals

- RemoteX will not become a general-purpose secrets manager.
- The release will not synchronize credentials between machines or users.
- Credential setup will not prove remote authentication. Existing protocol
  tests remain the authentication authority.
- The plugin will not accept a password through chat, an MCP tool field, a
  command-line option, standard input owned by the MCP client, or an environment
  variable created by the model.
- The plugin will not automatically rotate remote accounts or generate a new
  remote password.
- Local administrators, SYSTEM, the current user, and a fully compromised
  RemoteX process remain outside the local-secret isolation boundary.

## Threat Model

The design protects against accidental logging, command-line capture, crash
artifacts, loose inherited ACLs, stale task directories, malformed configuration,
and a different non-administrator local principal reading RemoteX state. It also
limits credential-reference confusion between profiles and protocols.

The design does not protect a secret after it reaches the authorized remote
process, a same-user debugger with process-memory access, or an administrator
that can replace the plugin or inspect Credential Manager in the user's security
context.

## Configuration Contract

### Version 2 aliases

Version 2 adds an optional top-level `credentials` object. Every key is a stable
ASCII alias. A profile uses exactly one of `credential_ref` or the existing
inline `credential` object.

```json
{
  "version": 2,
  "credentials": {
    "lab-rdp": {
      "source": "windows-credential-manager",
      "target": "TERMSRV/windows.example.internal"
    },
    "lab-winrm": {
      "source": "windows-credential-manager",
      "target": "RemoteX/lab-winrm"
    },
    "linux-admin-key": {
      "source": "identity-file",
      "identity_file": "~/.ssh/id_ed25519",
      "expected_public_key_sha256": "SHA256:base64-fingerprint"
    }
  },
  "defaults": {
    "rdp": "windows-lab"
  },
  "profiles": {
    "windows-lab": {
      "kind": "rdp",
      "host": "windows.example.internal",
      "credential_ref": "lab-rdp"
    }
  }
}
```

Credential aliases use exact provider schemas:

- `identity-file`: `identity_file` and optional
  `expected_public_key_sha256`.
- `ssh-agent`: optional `identity_file` and optional
  `expected_public_key_sha256`.
- `windows-credential-manager`: exact `target`.
- `windows-integrated`: no provider-specific fields.
- `environment`: exact `username_env` and `password_env`; this source is marked
  ephemeral and produces a security warning.

Provider-to-profile compatibility remains fail closed:

- SSH accepts only `identity-file` or `ssh-agent`.
- RDP accepts only a Windows Credential Manager target beginning with
  `TERMSRV/`.
- Windows guest accepts Windows Credential Manager or Windows integrated
  authentication.
- vSphere accepts Windows Credential Manager or environment references.
- VMware Workstation does not accept a credential reference.

Unknown fields, duplicate aliases, missing aliases, alias cycles, an inline
credential plus `credential_ref`, literal-secret field names, known token or PEM
patterns, URL userinfo, and incompatible providers are rejected before any
client process starts.

### Version 1 compatibility

Version 1 inline credential references remain supported without an automatic
rewrite. Status reports `configurationVersion=1` and
`migrationRecommended=true`. The credential setup workflow can operate on an
existing inline Windows Credential Manager reference, so migration is not a
prerequisite for restoring a missing credential.

A separate `--check` migration command renders a sanitized version 2 preview.
`--write` requires explicit confirmation, writes an adjacent backup, uses an
atomic replace, applies a private ACL or mode, reloads the result, and verifies
semantic equivalence before reporting success. It never reads credential values.

## Credential Store Boundary

A new `credential_store.py` module owns provider normalization, reference
status, Windows Credential Manager reads, writes, deletion, and sanitized public
metadata. Protocol adapters receive a normalized resolved reference and no
longer interpret raw profile credential objects independently.

Credential values have the shortest practical lifetime. Windows Credential
Manager access uses native `CredReadW`, `CredWriteW`, `CredDeleteW`, and
`CredFree`. The interactive writer passes a `SecureString` to native code,
zeroes unmanaged buffers in a `finally` block, and never converts the password
to a managed string. Python callers that must authenticate still receive a
short-lived value; they must not persist it and must release references after
the child process starts.

The credential store returns only:

- source and alias;
- a target digest and a bounded display-safe reference;
- reference presence;
- provider compatibility;
- consuming profile names;
- the protocol-specific tool required to verify authentication.

It never returns a username, password, token, private-key body, Credential
Manager blob, or environment value.

## Local Interactive Workflow

### Setup and rotation

`remotex_credential_setup` accepts only `profile` or `credential_ref`, plus
`confirm=true`. It resolves the non-secret target, starts a visible local
PowerShell helper in a new console, and waits for a bounded sanitized receipt.
The helper obtains username and password through `Get-Credential` and writes the
entry with native `CredWriteW`. Setup and rotation are the same operation: an
existing target is overwritten only after the helper shows that fact to the
user.

The MCP tool never accepts `username`, `password`, `token`, `secret`, arbitrary
target text, or a command to run. Cancellation returns `cancelled` without
changing the existing entry.

### Deletion

`remotex_credential_delete` accepts only a configured profile or alias and
`confirm=true`. Before deletion it reports how many profiles consume the
reference. It calls `CredDeleteW`, reads back absence, and returns only the alias,
consumer count, and target digest. Arbitrary Credential Manager targets cannot
be deleted through the tool.

### Doctor

`remotex_credential_doctor` is read only. It reports collection and optional
profile/alias results with these independent states:

- `referenceConfigured`;
- `referencePresent`;
- `providerCompatible`;
- `localProtectionReady`;
- `authenticationVerified` and `lastVerifiedAt` when evidence exists;
- `migrationRecommended`;
- `nextStep`.

Reference presence is never described as valid remote credentials.

## Secret-free Resumable Task IPC

New tasks use `RemoteXTaskSpec/v2`. `spec.json`, `state.json`, and `result.json`
remain non-secret. The manager must not create `stdin.bin`, `secrets.json`, a
secret-bearing temporary file, or a secret-bearing environment variable.

The manager starts the worker with an anonymous stdin pipe, writes one
size-bounded framed payload containing the remote stdin bytes and redaction
values, closes the pipe, and waits for the worker to acknowledge receipt by
atomically writing a non-secret `running` state. The task is returned to the MCP
caller only after acknowledgment. A pipe failure, worker exit, invalid frame,
timeout, or failure to protect the task directory kills the worker, removes the
task directory, and returns a fixed sanitized error.

The worker reads the frame exactly once, rejects trailing or oversized data,
keeps the values in memory only for the operation, and drops references in a
`finally` block. Resumability continues to mean that the worker survives the MCP
request; it does not promise replay after a worker or machine crash.

Version 2 never consumes legacy sensitive files. Status detects abandoned
`stdin.bin` or `secrets.json` files from version 1 and reports their count. A
separate explicit cleanup action deletes only those exact filenames below a
validated inactive task directory and reports path hashes, never contents.

## Local Protection

A new `secure_paths.py` module applies and verifies effective protection:

- POSIX directories use mode `0700`; files use `0600`; symlinks are rejected.
- Windows directories and files use a protected DACL granting full control only
  to the current user SID, SYSTEM, and Built-in Administrators.
- Windows ACL commands use SID forms rather than localized account names and
  perform effective readback before sensitive work.
- Reparse points, network paths, owner mismatches, unexpected allow entries,
  and failed ACL readback are hard failures for task and setup state.

Configuration and identity-file protection are reported by the doctor. An
existing configuration with an unsafe ACL is not rewritten silently. A new
credential setup or asynchronous task cannot proceed until its private state
directory passes protection verification.

## Authentication Evidence

Credential setup changes only reference presence. Authentication is verified by
the existing protocol operations:

- SSH: `remotex_ssh_test` with public-key-only options and host-key governance.
- RDP: TCP and saved-entry readiness remain separate; launching `mstsc` is not a
  successful-login receipt.
- Windows guest: `remotex_windows_guest_test` performs authenticated identity
  readback.
- vSphere: `remotex_vsphere_about` performs authenticated endpoint readback.

Successful evidence is stored only as a bounded timestamp, profile, provider,
endpoint identity digest, and result state. It expires after a documented
interval and never contains credentials or raw client output.

## Audit and Error Handling

Audit records include alias, provider, target digest, action, confirmation,
result state, and receipt hash. They exclude target values when a digest is
sufficient, helper output, usernames, secrets, and Credential Manager fields.

Expected errors use stable codes such as:

- `credential-reference-missing`;
- `credential-provider-incompatible`;
- `credential-setup-cancelled`;
- `credential-helper-failed`;
- `credential-delete-refused-consumers`;
- `local-protection-invalid`;
- `task-secret-pipe-failed`;
- `task-secret-ack-timeout`;
- `legacy-sensitive-artifacts-found`.

Unexpected exception text remains suppressed. Error paths must not interpolate
resolved credential values.

## Test Strategy

Implementation follows red-green-refactor. Required tests include:

1. Version 2 alias resolution, provider compatibility, version 1 compatibility,
   migration preview, conflict rejection, exact schemas, and secret-pattern
   rejection.
2. Credential doctor output with no username, secret, or raw Credential Manager
   blob.
3. Setup tool schemas with no secret fields; helper invocation arguments contain
   references only; cancellation and overwrite behavior are bounded.
4. Mocked native Credential Manager write/delete/readback and unmanaged-buffer
   cleanup on success and failure.
5. Resumable task start proving no `stdin.bin`, `secrets.json`, or secret-bearing
   environment is created before, during, or after worker startup.
6. Pipe framing, size limit, acknowledgment timeout, worker crash, queue-owner
   recheck, cancellation, collection, output redaction, and process-tree cleanup.
7. POSIX mode and Windows ACL allowlist/readback behavior, including inherited
   broad-read rejection.
8. Protocol adapters resolving both aliases and inline references without
   exposing values in argv, results, receipts, or audit records.
9. Plugin manifest, skill, MCP tool-schema, version, and example-configuration
   contracts.
10. Existing RemoteX tests and the repository-wide configured test suite.

An opt-in Windows manual test may create a uniquely named temporary Generic
Credential, verify presence, rotate it, delete it, and verify absence. It must
delete the entry in a guaranteed cleanup path. CI does not create persistent
real credentials by default.

## Rollout

1. Ship as RemoteX 0.5.0 on a topic branch and pull request.
2. Keep version 1 configuration and inline references readable.
3. Make version 2 aliases opt in; do not rewrite the installed configuration
   during plugin installation.
4. On first status after upgrade, report migration and legacy-sensitive-artifact
   findings without exposing profile secrets or deleting files.
5. Require explicit confirmation for configuration migration, credential setup,
   rotation, deletion, and legacy artifact cleanup.
6. Validate the source package and tests before updating the installed plugin.
7. Treat source merge, plugin installation, credential setup, reference
   presence, and remote authentication as separate acceptance gates.

## Acceptance Criteria

- No new MCP schema contains a secret-value field.
- New asynchronous tasks create no secret-bearing filesystem artifact.
- A broad Windows inherited ACL prevents sensitive task or helper startup.
- A user can select a configured profile, complete a native secure prompt, and
  obtain sanitized presence readback without editing a command or revealing a
  secret to Codex.
- Version 1 configurations retain their current behavior.
- Version 2 aliases resolve consistently across all supported protocols.
- Status distinguishes configuration, presence, local protection, and verified
  authentication.
- Tests cover success, failure, cancellation, crash, timeout, cleanup, redaction,
  compatibility, and ACL boundaries.
