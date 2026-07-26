# RemoteX

RemoteX provides named profiles for SSH, Windows Remote Desktop, authenticated Windows guest management, vSphere or ESXi, and VMware Workstation. It uses established local clients:

- ssh and sftp for SSH profiles
- mstsc for RDP profiles
- local PowerShell WinRM sessions for Windows guest profiles
- govc for vSphere or ESXi API profiles
- vmrun for VMware Workstation profiles

RemoteX does not accept passwords, tokens, private-key bodies, or other secret values as tool arguments. Configuration contains endpoints, safe client settings, paths, queue aliases, identity bindings, and credential references only.

## Setup

Copy config/config.example.json to ~/.config/remotex/config.json, or set REMOTEX_CONFIG to another protected JSON file. Run remotex_status with the intended profile before connecting. Selected-profile readiness is the target boundary; aggregate readiness reports all configured profiles separately.

RemoteX reads the old SSH_CONFIG file or ~/.config/codex-ssh/config.json when the RemoteX config does not exist. Existing SSH_HOST and SSH_USER environment configuration is also recognized. This compatibility path is read-only.

## Credentials

RemoteX accepts only credential references:

- SSH Agent, managed identity-file paths, or named environment variables for SSH
- Windows Credential Manager entries named TERMSRV/host for RDP
- Windows Credential Manager Generic Credentials or native Windows integrated authentication for Windows guest WinRM
- Windows Credential Manager or named environment references for vSphere or ESXi

Do not put a password in a profile, tool argument, script, shell command, VMX path, audit record, or standard output. RemoteX never uses VMware vmrun -gp or -gu guest-password arguments.

For RDP, create the matching TERMSRV/host entry with the Windows Credential Manager UI. remotex_rdp_open fails closed when it is absent, then starts mstsc without receiving or forwarding a password.

For a Windows guest profile, use a Generic Credential such as RemoteX/windows-guest-lab, or windows-integrated when the current Windows identity is authorized. RemoteX passes credential material only through a local PowerShell stdin envelope and redacts it from process output, errors, receipts, and audit records.

## Composite VM Identity

Any mutating VMware Workstation or Windows guest operation requires a vm_identity group. The group must contain exactly one of each:

- VMware Workstation profile with vmx_path and vmware_uuid
- RDP profile
- Windows guest profile with guest_machine_id

Every member must use the same exact queue_resource. RemoteX reads the VMX UUID before a VMware mutation, records the RDP and guest endpoint bindings, and probes the authenticated Windows guest machine identifier before guest mutations. A VMX UUID, guest machine identifier, endpoint configuration, or queue mismatch fails closed before the operation starts.

Use sanitized stable identifiers only: vm_identity and guest_machine_id accept ASCII letters, digits, dots, underscores, and hyphens; vmware_uuid must be a 128-bit VMware UUID.

remotex_status exposes a per-profile capability matrix for power, snapshot, guest_exec, guest_copy, and reboot_wait, with a failure code when a required client, credential reference, or identity binding is unavailable.

## Shared VM Queue

RemoteX maintains a persistent, process-safe FIFO queue for shared VM access. SSH, RDP, Windows guest, VMware Workstation, and vSphere profiles that address the same VM must use one queue_resource.

The default queue state is under the local RemoteX state directory. REMOTEX_VM_QUEUE_FILE and REMOTEX_VM_QUEUE_LEASE_FILE override these protected local paths.

1. Call remotex_vm_queue_status with the target profile.
2. Call remotex_vm_queue_request with a stable ASCII requester.
3. If another requester owns it, report the FIFO position and stop.
4. If unowned, request it, obtain confirmation, then call remotex_vm_queue_claim with confirm=true.
5. Pass the same requester to every mutating operation.
6. Call remotex_vm_queue_heartbeat or remotex_vm_queue_renew before lease expiry.
7. Call remotex_vm_queue_release after the work is complete.

Leases default to four hours and may be configured from 60 seconds to seven days. Expiry never assigns a waiter. remotex_vm_queue_recover_stale requires confirm=true, verifies that the expired lease still matches the queue owner, and releases it only to the unowned state. It records the stale owner recovery and never silently transfers ownership.

The queue coordinates RemoteX processes on one machine. It is not an authorization boundary and cannot detect clients that connect directly outside RemoteX.

## Windows Guest Operations

Windows guest profiles use WinRM only, with Kerberos or Negotiate authentication. Before any guest operation, RemoteX probes an authenticated machine and boot identity. Guest scripts are sent through a fixed local PowerShell wrapper, bounded by timeout, memory, process-count, and output limits.

Use remotex_windows_guest_preflight before snapshot or test-sensitive work. It runs a PowerShell 2.0-compatible read-only probe with a caller-supplied policy. The bounded receipt includes operating system and architecture, PowerShell and .NET versions, required KB and cmdlet checks, pending reboot state, free system-drive space, guest UTC and boot identity, and declared process, service, driver, and ETW inactivity checks.

Each failed condition is returned independently in failureCodes. A passing preflight receipt is hash-bound to the composite VM identity and expires according to its declared maximum age.

Use remotex_windows_guest_run_script for bounded PowerShell. It exports no output by default; output_allowlist can expose only named scalar JSON fields. Use remotex_windows_guest_copy_to and remotex_windows_guest_copy_from only with a declared relative_path below staging_root; both return size and SHA-256 readback rather than file contents. remotex_windows_guest_reboot requires confirm=true and succeeds only after a newly authenticated boot identity is observed.

## VMware Workstation Snapshots

Use remotex_vmware_list_snapshots for read-only inventory. Snapshot mutations require the queue owner, a valid composite identity, an existing fresh passing Windows guest preflight receipt, and exact inventory readback:

1. Run remotex_windows_guest_preflight and retain receiptSha256.
2. Call remotex_vmware_snapshot_create with a safe exact snapshot_name, an idempotency_key, and that receipt hash.
3. Use the same key and name to retry safely; changing the name for the same key fails.
4. Call remotex_vmware_snapshot_revert or remotex_vmware_snapshot_delete only with confirm=true.

RemoteX rejects path-like, ambiguous, duplicate, or untracked snapshot names. Revert and delete work only for snapshots previously created by RemoteX under the same VM identity. Every operation returns bounded client metadata, inventory before and after hashes, exact target readback, receipt hash, timeout or return code state, and rawOutputExported=false.

## SSH, RDP, And vSphere

For host_key_policy=managed, call remotex_ssh_host_key_status before the first SSH connection. Verify the fingerprint out of band, then call remotex_ssh_host_key_approve with the exact value and confirm=true. A changed key additionally requires rotation=true; do not weaken strict host-key checking.

Use remotex_ssh_run_script for PowerShell, pwsh, cmd, sh, or bash. The fixed launcher is the only remote command placed in the SSH argument vector. Script text and resolved environment values travel through SSH stdin. remotex_ssh_copy_to and remotex_ssh_copy_from use SFTP first and return requested and actual paths, byte counts, hashes, and integrity state.

Use remotex_rdp_test to distinguish TCP reachability from saved-credential readiness. Use remotex_vsphere_about for a read-only endpoint check and remotex_vsphere_list_vms for inventory. remotex_vsphere_power requires an explicit profile, inventory path, action, and queue owner. Keep TLS verification enabled and prefer a configured CA.

## Audit And Completion

Every MCP tool call writes start and finish records to a local hash-linked JSONL ledger. The default path is under the local RemoteX state directory; REMOTEX_AUDIT_FILE overrides it. Use remotex_audit_export when an operation needs local provenance or chain verification.

Records contain operation and session identifiers, tool name, timestamps, selected non-secret request metadata, result state, duration, previous-record hash, and current-record hash. Scripts are represented by SHA-256. Raw script output, file contents, credentials, and credential-manager values are excluded.

Report reachability, credential readiness, composite identity status, queue ownership, command acceptance, client return code, timeout, receipt hash, integrity verification, and target readback separately. Starting a GUI, accepting a command, or receiving exit code zero is not proof that the remote system reached the requested final state.

## Tool Summary

- remotex_status
- SSH: test, command or script execution, transfer, resumable tasks, agent and host-key governance
- RDP: remotex_rdp_test and remotex_rdp_open
- Windows guest: test, preflight, bounded script, verified copy, authenticated reboot wait
- vSphere or ESXi: about, VM inventory, power
- VMware Workstation: running inventory, power, snapshot list, create, revert, delete
- Queue: status, request, claim, renew, heartbeat, stale recovery, release, cancel
- remotex_audit_export

## Boundaries

RemoteX does not make remote commands intrinsically safe, replace remote authorization, prevent direct out-of-band access, prove a state not covered by an explicit readback, or turn a local cooperative queue into a distributed lock. Use a disposable VM integration environment for real guest, snapshot, and reboot validation before a production rollout.
