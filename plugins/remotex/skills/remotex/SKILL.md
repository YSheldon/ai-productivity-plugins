---
name: remotex
description: Use configured RemoteX profiles to inspect or operate SSH hosts, Windows RDP targets, vSphere or ESXi environments, and local VMware Workstation virtual machines without passing credentials in chat.
---

# RemoteX

Use this skill for remote-system and virtual-machine work that should reuse named local profiles, credential references, host-key policy, and cooperative queue ownership.

## Required First Step

Call `remotex_status` with the intended `profile`. Use `selectedProfileReady` as the boundary for that target and report `overallStatus` separately. A missing client, profile, credential reference, host-key registration, or queue file is a configuration gap, not proof of invalid credentials.

Never ask the user to paste a password, token, authorization code, private key, or credential-manager export into chat. RemoteX accepts credential references from SSH Agent, identity-file paths, Windows Credential Manager, or named environment variables.

## Shared Queue

Before an SSH side effect, `remotex_rdp_open`, `remotex_vsphere_power`, or `remotex_vmware_power` on a profile with `queue_resource`:

1. Choose a stable ASCII requester for the current user or task.
2. Inspect the profile with `remotex_vm_queue_status`.
3. If another requester owns it, join with `remotex_vm_queue_request`, report the FIFO position, and stop.
4. If it is unowned, request it and show the returned prompt.
5. Claim with `confirm=true` only after explicit confirmation.
6. Pass the same requester to every side-effectful operation.
7. Renew long work before lease expiry.
8. Release after use and report the first waiter. Never transfer ownership silently.

Expiry releases ownership but never assigns a waiter. A legacy unleased owner may renew in place to obtain a bounded lease. Corrupt or locked state is a hard stop.

Profiles for the same VM must share one `queue_resource`, including SSH, RDP, VMware, and vSphere views. The queue is cooperative and local to this machine; do not claim it detects direct access outside RemoteX.

## SSH Host Keys

For `host_key_policy=managed`, call `remotex_ssh_host_key_status` before the first connection. Show the fingerprints and require out-of-band verification before `remotex_ssh_host_key_approve`.

Approval requires the exact observed fingerprint and `confirm=true`. A changed key is blocked and requires both independent verification and `rotation=true`. Do not weaken strict host-key checking.

## SSH Execution

1. Call `remotex_ssh_test` before commands or transfers.
2. Prefer read-only inspection before maintenance work.
3. Use `remotex_ssh_run_script` for PowerShell, `pwsh`, `cmd`, `sh`, or `bash`; scripts and referenced environment values travel through stdin.
4. Set wall, CPU, memory, process-count, and output limits according to the operation.
5. Treat `timedOut`, truncation flags, process-tree termination, exit code, stdout, and stderr as separate facts.
6. Use task start/status/collect for resumable work, and cancel only when interruption is intended.

Use `environment_refs` for named local environment variables or Windows Credential Manager fields. Never place a resolved secret in script text, command text, or a tool argument.

## File Transfer

Use `remotex_ssh_copy_to` and `remotex_ssh_copy_from` with explicit paths. Keep `verify=sha256` unless a documented reason requires `size` or `none`. Select `overwrite=fail`, `replace`, or file-only `resume` deliberately.

Report requested and actual paths, protocol, byte counts, hashes, and `integrityMatched`. A client exit code of zero is not enough when verification fails.

## RDP

Use `remotex_rdp_test` to separate TCP reachability from saved-credential readiness. `remotex_rdp_open` starts the Windows RDP client and must fail when the configured `TERMSRV/...` credential or matching queue owner is absent.

## vSphere And ESXi

Use `remotex_vsphere_about` for a read-only endpoint check and `remotex_vsphere_list_vms` for inventory. `remotex_vsphere_power` requires an explicit profile, inventory path, action, and queue owner. Keep TLS verification enabled and prefer a configured CA.

An ESXi shell over SSH is an SSH profile. ESXi or vCenter API work through `govc` is a `vsphere` or `esxi` profile.

## VMware Workstation

Use `remotex_vmware_list_running` for local inventory. `remotex_vmware_power` operates only on the `.vmx` bound to the selected profile and only for its queue owner. Confirm `hard`, `reset`, and `suspend` because they may discard guest state.

## Audit And Completion

Use `remotex_audit_export` when an operation needs local provenance or chain verification. The ledger contains hashes and reference metadata, not scripts or credential values.

Report reachability, credential readiness, queue ownership, host-key state, executed action, exit code, integrity verification, and target readback separately. Starting a GUI, accepting a command, or receiving exit code zero is not proof that the remote system reached the requested final state.
