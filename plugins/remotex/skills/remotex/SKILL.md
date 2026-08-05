---
name: remotex
description: Use configured RemoteX profiles to inspect or operate SSH hosts, Windows RDP targets, authenticated Windows guests, vSphere or ESXi environments, and local VMware Workstation virtual machines without passing credentials in chat.
---

# RemoteX

Use this skill for remote-system and virtual-machine work that should reuse named local profiles, credential references, host-key policy, composite VM identity, and cooperative queue ownership.

## Required First Step

Call remotex_status with the intended profile. For SSH, selectedProfileReady proves only local configuration, client availability, and host-key readiness; it does not prove that the server has authorized the selected public key. Run remotex_ssh_test to verify server-side authentication, then report overallStatus separately. A missing client, profile, credential reference, host-key registration, identity binding, or queue file is a configuration gap, not proof of invalid credentials.

Never ask the user to paste a password, token, authorization code, private key, or credential-manager export into chat. RemoteX accepts credential references from SSH Agent, identity-file paths, Windows Credential Manager, Windows integrated authentication, or named environment variables.

## Shared Queue

Before any SSH side effect, remotex_rdp_open, Windows guest mutation, VMware Workstation mutation, or vSphere power operation:

1. Choose a stable ASCII requester for the current user or task.
2. Inspect the profile with remotex_vm_queue_status.
3. If another requester owns it, join with remotex_vm_queue_request, report the FIFO position, and stop.
4. If it is unowned, request it and show the returned prompt.
5. Claim with confirm=true only after explicit confirmation.
6. Pass the same requester to every side-effectful operation.
7. Call remotex_vm_queue_heartbeat or remotex_vm_queue_renew for long work.
8. Release after use and report the first waiter.

Expiry and stale recovery release ownership only to the unowned state. Never transfer ownership silently. remotex_vm_queue_recover_stale needs confirm=true and must report the recovered owner and first waiter.

Profiles for one VM must share one queue_resource. This queue is cooperative and local to this machine; it does not detect direct access outside RemoteX.

## Composite VM Identity

VMware Workstation and Windows guest mutations require one vm_identity group with exactly one VMware Workstation profile, one RDP profile, and one Windows guest profile. The profiles must share the same queue_resource.

Before VMware changes, RemoteX compares vmware_uuid with the selected VMX UUID. Before Windows guest changes, it compares an authenticated guest machine identifier with guest_machine_id. RDP and WinRM endpoints are part of the binding. Any mismatch is a hard stop before the operation.

## Windows Guest And Preflight

Use remotex_windows_guest_test for authenticated readiness. Windows guest profiles use WinRM with Kerberos or Negotiate and only a Windows Credential Manager or native Windows-integrated credential reference.

Before snapshot or test-sensitive work, call remotex_windows_guest_preflight with a stable run_id and explicit policy. Treat a passing receiptSha256 as a prerequisite, not as proof of a later operation. Report each failureCode separately: operating system, architecture, PowerShell, .NET, KB, cmdlet, reboot, disk, and inert-runtime checks are independent.

Use remotex_windows_guest_run_script only for bounded PowerShell. Output is scrubbed unless an explicit scalar JSON allowlist is requested. Copy operations use only relative paths below the configured staging_root and require hash readback. Reboot requires confirm=true and is successful only when a new authenticated boot identity is observed.

## VMware Workstation Snapshots

Use remotex_vmware_list_snapshots for inventory. To create a snapshot:

1. Hold the matching queue owner.
2. Obtain a fresh passing Windows guest preflight receipt.
3. Call remotex_vmware_snapshot_create with snapshot_name, idempotency_key, and preflight_receipt_sha256.
4. Report request acceptance, client return code, timeout, inventory before and after, exactSnapshotMatch, targetStateReadback, receiptSha256, and rawOutputExported.

Retry only with the same key and name. A same-key different-name request is a conflict. Snapshot names cannot be paths or ambiguous values. Revert and delete require confirm=true, an existing RemoteX-created snapshot receipt, the queue owner, and readback.

## SSH, RDP, And vSphere

For host_key_policy=managed, call remotex_ssh_host_key_status before the first connection. Show fingerprints and require out-of-band verification before remotex_ssh_host_key_approve. Do not weaken strict host-key checking.

remotex_ssh_test is public-key only. When it returns configured-public-key-rejected, use authentication.publicKey.fingerprint when available to authorize the configured key through an approved out-of-band channel, then rerun the test. Do not request or use a password fallback.

Use remotex_ssh_run_script for PowerShell, pwsh, cmd, sh, or bash. Script text and referenced environment values travel through stdin. For transfer, preserve verify=sha256 unless there is a documented reason to use another mode.

Use remotex_rdp_test to separate TCP reachability from saved-credential readiness. remotex_rdp_open starts the Windows RDP client only when the matching queue owner and saved TERMSRV credential are present.

Use remotex_vsphere_about for a read-only endpoint check and remotex_vsphere_list_vms for inventory. remotex_vsphere_power requires an explicit profile, inventory path, action, and queue owner. Keep TLS verification enabled.

## Audit And Completion

Use remotex_audit_export when an operation needs local provenance or chain verification. The ledger contains hashes and reference metadata, not scripts, file contents, or credential values.

Report reachability, credential readiness, VM identity status, queue ownership, action acceptance, client result, timeout, receipt hash, integrity verification, and target readback separately. A GUI launch, accepted command, or zero exit code is not proof that the requested final state was reached.
