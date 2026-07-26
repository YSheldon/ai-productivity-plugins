# RemoteX

RemoteX provides one profile model for SSH, Windows Remote Desktop, vSphere/ESXi, and VMware Workstation. It wraps established local clients instead of implementing those protocols:

- OpenSSH: `ssh`, `sftp`, `scp`, `ssh-add`, `ssh-keygen`, and `ssh-keyscan`
- RDP: Windows `mstsc` and Windows Credential Manager
- vSphere/ESXi: `govc`
- VMware Workstation: `vmrun`

The MCP entry point requires `node` and Python 3.10 or newer on `PATH`. On Windows, the launcher prefers `py -3`, then checks `python3` and `python`. On other platforms it checks `python3` and `python`.

RemoteX does not accept passwords, tokens, private-key bodies, or other secret values as tool arguments. Configuration contains endpoints, safe client settings, paths, queue aliases, and credential references only.

## Configuration

Copy `config/config.example.json` to `~/.config/remotex/config.json`, or set `REMOTEX_CONFIG` to another protected JSON file. Run `remotex_status` with the intended `profile` before connecting. The response separates selected-profile readiness from the aggregate state of every configured profile.

RemoteX reads the old `SSH_CONFIG` file or `~/.config/codex-ssh/config.json` when the RemoteX config does not exist. Existing `SSH_HOST` and `SSH_USER` environment configuration is also recognized. This compatibility path is read-only.

### SSH

Set `platform` to `windows`, `posix`, or `auto`. Use an `identity-file` credential reference or `ssh-agent`. Batch mode, public-key authentication, disabled password authentication, and strict host-key checking are enforced.

An agent-backed profile may include an optional key path for `remotex_ssh_agent_add`:

```json
{
  "source": "ssh-agent",
  "identity_file": "~/.ssh/id_ed25519"
}
```

The key path is passed to OpenSSH. RemoteX does not read or return private-key contents.

`host_key_policy` supports:

- `known-hosts`: OpenSSH enforces the configured `known_hosts_file`.
- `managed`: RemoteX also scans the endpoint and requires an exact match with its local approved-fingerprint registry. Unregistered or changed keys block connections.

For `managed`, first call `remotex_ssh_host_key_status`. Verify a displayed fingerprint out of band, then call `remotex_ssh_host_key_approve` with that exact fingerprint and `confirm=true`. A changed key additionally requires `rotation=true`. `strict_host_key_checking=yes` is mandatory.

### RDP

Create a Windows Credential Manager entry whose target matches the configured `TERMSRV/<host>` value. Use the Credential Manager UI so the password is not placed in chat, JSON, or shell history. `remotex_rdp_open` fails closed when the entry is absent, then starts `mstsc` without receiving or forwarding a password.

### vSphere and ESXi

Install `govc`, then reference either a Windows Generic Credential or two environment-variable names:

```json
{
  "source": "environment",
  "username_env": "REMOTEX_ESXI_USERNAME",
  "password_env": "REMOTEX_ESXI_PASSWORD"
}
```

For Windows Credential Manager, create a Generic Credential with a non-RDP target such as `RemoteX/esxi-lab`. RemoteX reads it only in memory and passes it to `govc` through the child-process environment. TLS verification is enabled by default. Prefer a CA file instead of `tls.insecure`.

### VMware Workstation

Point a profile at `vmrun.exe` and a `.vmx` file. Local Workstation inventory and power operations use the current Windows session and do not require a separate plugin credential.

## Native Script Execution

Use `remotex_ssh_run_script` for PowerShell, `pwsh`, `cmd`, `sh`, or `bash`. The fixed launcher is the only remote command placed in the SSH argument vector. Script text and resolved environment values travel through SSH stdin, not command-line arguments.

Windows execution uses a PowerShell wrapper, UTF-8 transport, temporary `.ps1` or `.cmd` files where required, and a Windows Job Object. POSIX execution uses a temporary script and an isolated process group. The result reports exit code, stdout, stderr, timeout state, duration, local and remote PIDs, detected encodings, raw byte counts, truncation flags, process-tree termination, and applied limits.

Optional limits include wall time, CPU time, memory, process count, and stdout/stderr bytes. A Windows Job Object assignment failure is a hard stop. POSIX hosts must provide `setsid`; RemoteX fails closed when it cannot create a separate process group. Timeout or output-limit termination targets the full local and remote process tree.

Map remote environment names to local references with `environment_refs`. Supported sources are named environment variables and Windows Credential Manager fields. Values are resolved only for execution, injected over stdin, redacted from output, and represented in audit records by reference metadata.

## Verified File Transfer

`remotex_ssh_copy_to` and `remotex_ssh_copy_from` use SFTP first. Windows paths with spaces, Chinese characters, parentheses, or apostrophes are preserved as requested. SCP is used only when SFTP is unavailable and the path can be represented safely without shell interpretation.

Transfer controls:

- `recursive`: enable directory transfer.
- `overwrite`: `fail`, `replace`, or file-only `resume`.
- `verify`: `none`, `size`, or `sha256`; the default is `sha256`.

Results include requested and actual paths, local and remote sizes and hashes, protocol, integrity outcome, transferred bytes, duration, and retry count. A completed transfer whose requested verification does not match is an error.

## Resumable Tasks

Use `remotex_ssh_task_start`, `remotex_ssh_task_status`, `remotex_ssh_task_cancel`, and `remotex_ssh_task_collect` for work that must survive the initiating MCP call.

The task manager stores a script hash, fixed command arguments, limits, public credential-reference metadata, and state. It does not persist script text or resolved secret values in the task specification. Transient stdin and secret files are removed when the worker reads them. Cancellation is idempotent and terminates the worker process tree.

## Local FIFO Queue And Leases

RemoteX maintains a persistent, process-safe FIFO queue for shared VM access. SSH, RDP, VMware Workstation, and vSphere profiles that refer to the same VM must use the same `queue_resource`.

The default queue state is `%LOCALAPPDATA%\RemoteX\vm-queue.json` on Windows and `${XDG_STATE_HOME:-~/.local/state}/remotex/vm-queue.json` elsewhere. Lease state is stored beside it. `REMOTEX_VM_QUEUE_FILE` and `REMOTEX_VM_QUEUE_LEASE_FILE` override those protected local paths.

Use this workflow:

1. Call `remotex_vm_queue_status` with the target profile.
2. Call `remotex_vm_queue_request` with a stable ASCII `requester`.
3. If the resource is unowned and this requester is first, show the returned prompt and obtain confirmation.
4. Call `remotex_vm_queue_claim` with `confirm=true`.
5. Pass the same `requester` to SSH side effects, RDP launch, or VM power operations.
6. Call `remotex_vm_queue_renew` for long work.
7. Release ownership after use. If a waiter exists, notify the first waiter; ownership is never transferred silently.

Leases default to four hours and may be configured from 60 seconds to seven days. Expiry releases an owner but does not assign a waiter. The first waiter must still explicitly confirm and claim. Legacy unleased ownership remains valid, is clearly marked, and can be migrated in place with `remotex_vm_queue_renew`.

The resource operation lock remains held for the duration of synchronous SSH or VM operations. Resumable SSH task workers reacquire and validate the persisted owner before execution. Another requester cannot preempt, release, or bypass an active owner.

This queue coordinates RemoteX processes on one machine. It is not an authorization boundary and cannot detect clients that connect directly outside RemoteX.

## Audit Ledger

Every MCP tool call writes start and finish records to a local hash-linked JSONL ledger. The default path is under the local RemoteX state directory; set `REMOTEX_AUDIT_FILE` to override it.

Records contain operation and session identifiers, tool name, profile metadata, timestamps, result status, duration, previous-record hash, and current-record hash. Scripts are represented by SHA-256, and credential values are excluded. `remotex_audit_export` verifies the chain before returning bounded records.

The chain detects modification, reordering, and gaps between retained records. Without an external anchor it cannot prove that the entire file was not truncated or replaced.

## Tools

- `remotex_status`
- `remotex_ssh_test`, `remotex_ssh_run_command`, `remotex_ssh_run_script`
- `remotex_ssh_copy_to`, `remotex_ssh_copy_from`
- `remotex_ssh_task_start`, `remotex_ssh_task_status`, `remotex_ssh_task_cancel`, `remotex_ssh_task_collect`
- `remotex_ssh_host_key_status`, `remotex_ssh_host_key_approve`
- `remotex_ssh_agent_list`, `remotex_ssh_agent_add`, `remotex_ssh_agent_remove`
- `remotex_ssh_key_fingerprint`
- `remotex_rdp_test`, `remotex_rdp_open`
- `remotex_vsphere_about`, `remotex_vsphere_list_vms`, `remotex_vsphere_power`
- `remotex_vmware_list_running`, `remotex_vmware_power`
- `remotex_vm_queue_status`, `remotex_vm_queue_request`, `remotex_vm_queue_claim`
- `remotex_vm_queue_renew`, `remotex_vm_queue_release`, `remotex_vm_queue_cancel`
- `remotex_audit_export`

Connection tests, queue inspection, host-key inspection, audit export, and inventory operations are read-only. Commands, scripts, file transfers, RDP launch, VM power changes, queue mutation, host-key approval, and task cancellation have side effects.

## Security Boundaries

- Literal secret fields such as `password`, `secret`, `token`, and private-key data are rejected at config load time.
- External programs are invoked without a local shell and with fixed option boundaries.
- SSH password and keyboard-interactive authentication are disabled.
- Managed SSH host keys block unregistered endpoints and unapproved changes.
- Script and secret values do not enter SSH command-line arguments.
- Output capture is byte-safe, bounded, encoding-aware, and secret-redacted.
- SFTP paths are quoted as protocol data; unsafe SCP fallback paths are rejected.
- RDP and VM power operations fail closed when credentials or queue ownership are unavailable.
- SSH side effects require the same queue owner when their profile declares `queue_resource`.
- Queue files use OS locks and atomic replacement; invalid state blocks operations.
- Local audit hashes detect ledger modification, reordering, and internal gaps.

RemoteX does not make remote commands intrinsically safe, replace remote authorization, prevent direct out-of-band access, or prove a final remote state without a separate readback.
