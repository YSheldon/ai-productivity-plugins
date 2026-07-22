# RemoteX

RemoteX replaces the repository's SSH-only plugin with one profile model for SSH, Windows Remote Desktop, vSphere/ESXi, and VMware Workstation. It wraps established local clients instead of reimplementing their protocols:

- OpenSSH: `ssh`, `scp`, `ssh-add`, and `ssh-keygen`
- RDP: Windows `mstsc` and Windows Credential Manager
- vSphere/ESXi: `govc`
- VMware Workstation: `vmrun`

The MCP entry point requires `node` and Python 3 on `PATH`. On Windows, the launcher prefers `py -3` and then tests `python3` and `python`; on other platforms it tests `python3` and `python`.

RemoteX never accepts a password, token, private-key body, or other secret as a tool argument. The config contains only endpoints, safe client settings, paths, and credential references.

## Configuration

Copy `config/config.example.json` to `~/.config/remotex/config.json`, or set `REMOTEX_CONFIG` to another protected JSON file. Run `remotex_status` before connecting. It reports missing clients, files, environment-variable references, and credential records without displaying credential values.

RemoteX automatically reads the old `SSH_CONFIG` file or `~/.config/codex-ssh/config.json` when the RemoteX config does not yet exist. Existing `SSH_HOST` and `SSH_USER` environment configuration is also recognized. This compatibility mode is read-only and prevents an SSH-only upgrade from immediately losing its existing profile.

### SSH

Use an `identity-file` credential reference or `ssh-agent`. Strict host-key checking, batch mode, public-key authentication, and disabled password authentication remain the defaults.

An agent-backed profile uses this credential block:

```json
{
  "source": "ssh-agent",
  "identity_file": "~/.ssh/id_ed25519"
}
```

The optional identity path lets `remotex_ssh_agent_add` load the key. The private-key contents are never read by RemoteX.

### RDP

Create a Windows Credential Manager entry whose target matches the configured `TERMSRV/<host>` value. Use the Windows Credential Manager UI so the password is not placed in chat, JSON, or shell history. `remotex_rdp_open` fails closed when the entry is absent, then starts `mstsc` without receiving or forwarding a password.

### vSphere and ESXi

Install `govc`, then reference either a Windows Generic Credential or two environment variables:

```json
{
  "source": "environment",
  "username_env": "REMOTEX_ESXI_USERNAME",
  "password_env": "REMOTEX_ESXI_PASSWORD"
}
```

For Windows Credential Manager, create a Generic Credential with a non-RDP target such as `RemoteX/esxi-lab`. RemoteX reads it only in memory and passes it to `govc` through the child process environment. TLS verification is enabled by default; use a CA file instead of setting `tls.insecure` unless the target is a disposable lab.

### VMware Workstation

Point a profile at `vmrun.exe` and a `.vmx` file. Local Workstation inventory and power operations use the current Windows user session and do not need a separate plugin credential.

## Tools

- `remotex_status`
- `remotex_ssh_test`, `remotex_ssh_run_command`, `remotex_ssh_run_script`
- `remotex_ssh_copy_to`, `remotex_ssh_copy_from`
- `remotex_ssh_agent_list`, `remotex_ssh_agent_add`, `remotex_ssh_agent_remove`
- `remotex_ssh_key_fingerprint`
- `remotex_rdp_test`, `remotex_rdp_open`
- `remotex_vsphere_about`, `remotex_vsphere_list_vms`, `remotex_vsphere_power`
- `remotex_vmware_list_running`, `remotex_vmware_power`

Connection tests and inventory operations are read-only. Remote commands, file transfers, RDP launch, and VM power operations are side-effectful and should be executed only after the target profile and requested action are confirmed.

## Security Boundaries

- Literal secret fields such as `password`, `secret`, `token`, and private-key data are rejected at config load time.
- External programs are invoked without a shell and with fixed option boundaries.
- SSH password and keyboard-interactive authentication are disabled.
- RDP will not open unless its named Windows credential already exists.
- vSphere credentials never appear in `govc` command-line arguments or tool output.
- Command output is bounded and scrubbed for common token, private-key, assignment, and URL-userinfo patterns.
