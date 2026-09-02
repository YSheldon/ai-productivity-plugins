# RemoteX Credential Lifecycle

RemoteX `0.5.0` separates credential configuration, local reference presence,
and verified remote authentication. A saved entry or existing key file is not a
successful-login receipt.

## Configuration

Version 2 places non-secret references under top-level `credentials`. Profiles
select one with `credential_ref`:

```json
{
  "version": 2,
  "credentials": {
    "lab-admin": {
      "source": "windows-credential-manager",
      "target": "RemoteX/lab-admin"
    }
  },
  "defaults": {},
  "profiles": {
    "lab-guest": {
      "kind": "windows-guest",
      "credential_ref": "lab-admin"
    }
  }
}
```

Version 1 inline references remain readable. Preview migration without writing:

```powershell
python plugins/remotex/scripts/migrate_remotex_config.py `
  --config "$HOME/.config/remotex/config.json" --check
```

Writing requires `--write --confirm`. It creates a protected adjacent backup,
uses atomic replacement, reloads the candidate, and verifies semantic readback.
Migration reads reference metadata only; it never reads Credential Manager
values.

## Batch Missing Check

Call `remotex_credential_doctor` with no selector for the whole collection or
with one `profile` or `credential_ref`. Shared aliases are deduplicated, so one
missing entry reports every consumer without repeated setup work.

The result keeps these states separate:

- `referenceConfigured`;
- `referencePresent`;
- `providerCompatible`;
- `localProtectionReady`;
- `authenticationVerified` and `lastVerifiedAt`;
- `migrationRecommended`.

The doctor returns alias names, provider, counts, hashes, and next steps. It
does not return usernames, passwords, tokens, private-key contents, environment
values, or Credential Manager blobs.

## Setup and Rotation

For a configured Windows Credential Manager reference, call
`remotex_credential_setup` with a profile or `credential_ref` and
`confirm=true`. A visible local `Get-Credential` prompt opens. Enter credentials
only in that window. The MCP request and process arguments contain no credential
value.

The helper passes a `SecureString` to native `CredWriteW`, clears its unmanaged
buffer, emits only a protected sanitized receipt, and verifies entry presence.
Running setup for an existing reference rotates it. Cancellation preserves the
existing entry.

After setup, use the protocol authority:

- SSH: `remotex_ssh_test`;
- Windows guest: `remotex_windows_guest_test`;
- vSphere or ESXi: `remotex_vsphere_about`;
- RDP: `remotex_rdp_test` proves only TCP and saved-entry readiness; opening
  mstsc is not proof of successful authentication.

## Deletion

Run the doctor first and review every consumer. Then call
`remotex_credential_delete` with the configured selector and `confirm=true`.
RemoteX does not accept an arbitrary target. It deletes matching configured
Windows Credential Manager records, reads back absence, and reports only alias,
consumer count, target digest, and deletion state.

## Asynchronous Secret Transport

Resumable SSH tasks use a versioned, size-bounded anonymous pipe. The worker
acknowledges receipt before start returns. New tasks never create `stdin.bin` or
`secrets.json`, never place injected values in argv or child environment, and
keep non-secret state under a verified private directory.

`remotex_ssh_task_cleanup_sensitive_artifacts` can remove only those two exact
legacy filenames from an inactive validated task directory after
`confirm=true`. It does not read or return their contents.

## Boundaries

Environment providers are intended for ephemeral process-scoped use, not
long-lived passwords. Prefer SSH Agent or hardware-backed public keys for SSH
and Windows integrated Kerberos where the target and domain policy support it.

RemoteX cannot protect a value from the authorized destination process, a
same-user debugger, SYSTEM, or an administrator that can replace the plugin.
Source merge, plugin installation, local credential setup, reference presence,
and remote authentication remain separate acceptance gates.
