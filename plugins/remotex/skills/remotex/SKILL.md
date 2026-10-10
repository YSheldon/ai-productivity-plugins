---
name: remotex
description: Use configured RemoteX profiles and credential_ref aliases to diagnose or securely configure credentials, inspect or operate SSH and RDP hosts, manage authenticated Windows guests, vSphere or ESXi, and local VMware Workstation VMs without passing credential values in chat.
---

# RemoteX

Use this skill for remote-system and virtual-machine work that should reuse named local profiles, credential references, host-key policy, composite VM identity, and cooperative queue ownership.

## Required First Step

Call remotex_status with the intended profile. For SSH, selectedProfileReady proves only local configuration, client availability, and host-key readiness; it does not prove that the server has authorized the selected public key. Run remotex_ssh_test to verify server-side authentication, then report overallStatus separately. A missing client, profile, credential reference, host-key registration, identity binding, or queue file is a configuration gap, not proof of invalid credentials.

Never ask the user to paste a password, token, authorization code, private key, or credential-manager export into chat. RemoteX accepts credential references from SSH Agent, identity-file paths, Windows Credential Manager, Windows integrated authentication, or named environment variables.

## Credential Lifecycle

Use `remotex_credential_doctor` for collection-wide or selected profile checks.
Treat `referencePresent`, `localProtectionReady`, and
`authenticationVerified` as independent evidence. A present Credential Manager
entry is not proof that the remote system accepts it.

When the intended Profile does not exist, do not stop at the old credential
setup flow and do not edit JSON ad hoc:

1. Collect only non-secret metadata required by the selected kind: Profile
   name, endpoint, SSH user when applicable, credential Provider and alias,
   and `queue_resource`. A VM Windows guest requires `vm_identity`,
   `guest_machine_id`, and `staging_root`; a physical Windows host requires
   `host_identity`, `guest_machine_id`, and `staging_root` instead.
2. Call `remotex_profile_setup` with `confirm=false` and show its sanitized
   preview. Never add `target`, credential username, password, token, secret,
   or private-key material.
3. Report whether v1 migration, a protected backup, and a local credential
   prompt will be required. Obtain explicit confirmation.
4. Repeat the identical request with `confirm=true`. Enter Windows credential
   values only in the visible local `Get-Credential` window.
5. Run the returned protocol-specific host-key, reachability, or authentication
   test and report it separately from configuration and reference presence.

New profiles must use a local `queue_resource`. The wizard derives bounded
Credential Manager targets, rejects collisions and cross-kind fields, and
rolls back a newly written Profile and alias when the prompt is cancelled or
fails. Identical requests are idempotent. SSH remains public-key only and never
opens a password prompt.

When a configured Windows Credential Manager reference is missing:

1. Report its alias, source, consumer count, and sanitized next step.
2. Ask for confirmation to open the local secure prompt.
3. Call `remotex_credential_setup` with the profile or `credential_ref` and
   `confirm=true`.
4. Tell the user to enter the username and password only in the visible local
   `Get-Credential` window.
5. Run the protocol-specific authentication test after presence readback.

Calling setup for an existing entry performs rotation through the same local
prompt. Before deletion, run the doctor, report every consuming profile, obtain
explicit confirmation, then call `remotex_credential_delete`. Never construct
an arbitrary target or add a credential-value field to a tool call.

Version 1 inline references remain readable. Use the migration script in
`docs/credential-lifecycle.md` for a preview and explicit protected v2 write.
Long-lived passwords should not use environment references; those are
ephemeral-only and must remain process scoped.

## Shared Queue

Before any SSH side effect, remotex_rdp_open, Windows guest mutation, VMware Workstation mutation, or vSphere power operation:

1. For an authorized operation, choose an ASCII requester unique to the current
   task and keep it stable through acquisition, execution, renewal, and release.
   Never adopt another task's requester from the owner/waiter list.
2. Call `remotex_vm_queue_acquire` with the intended profile, requester, and a
   bounded `lease_seconds` appropriate to the operation. A separate confirmation
   is not required for normal queue admission of an already authorized task.
3. If `acquired=true`, continue the authorized operation. `acquireStatus=acquired`
   means a free FIFO resource was claimed; `already-owned` reuses this task's
   lease without extending it.
4. If `acquired=false`, the request has joined the FIFO queue without preemption.
   Report its position, owner/lease, and `blocking_resources`, continue independent
   work, then retry with the same requester. Do not execute on that target while
   queued. Retry acquisition when the task resumes or the queue changes; avoid
   tight polling, and do not claim merely to answer a read-only status question.
5. On an older runtime without `remotex_vm_queue_acquire`, inspect status and
   join with `remotex_vm_queue_request`. For an already authorized task, call
   `remotex_vm_queue_claim` with `confirm=true` when unowned and first in FIFO;
   no additional conversational confirmation is needed. The claim itself
   rechecks ownership and fairness. Inspect its returned `claimed` value.
6. Pass the same requester to every side-effectful operation, renew before
   expiry during long work, and release after use. Cancel this task's own wait
   item if it no longer needs the resource.

Queue acquisition only reserves a local cooperative resource. It does not
authorize power changes, reboot, snapshots, credentials, SSH host trust, or
other unapproved remote actions; their existing checks still apply. The legacy
manual `remotex_vm_queue_claim` API retains its `confirm` argument.

Expiry and stale recovery release ownership only to the unowned state. Never transfer ownership silently. remotex_vm_queue_recover_stale needs confirm=true and must report the recovered owner and first waiter.

Profiles for one VM or physical host must share one queue_resource. This queue
is cooperative and local to this machine; it does not detect direct access
outside RemoteX.

## Composite VM Identity

VMware Workstation mutations require one `vm_identity` group with exactly one
VMware Workstation profile, one RDP profile, and one Windows guest profile. A
physical Windows guest uses `host_identity`, `guest_machine_id`, and one exact
queue resource instead; it may have one matching RDP profile and must not bind
a VMware profile.

Before VMware changes, RemoteX compares vmware_uuid with the selected VMX UUID. Before Windows guest changes, it compares an authenticated guest machine identifier with guest_machine_id. RDP and WinRM endpoints are part of the binding. Any mismatch is a hard stop before the operation. Physical hosts skip VMX validation but retain authenticated machine and queue checks.

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
The local scan preserves complete key lines even when `ssh-keyscan` reports a
partial algorithm mismatch. If no key is returned for an algorithm-only error,
it makes one modern `rsa,ecdsa,ed25519` discovery retry; it never enables DSA
or changes the algorithms used by the subsequent SSH connection.

remotex_ssh_test is public-key only. When it returns configured-public-key-rejected, use authentication.publicKey.fingerprint when available to authorize the configured key through an approved out-of-band channel, then rerun the test. Do not request or use a password fallback.

Use remotex_ssh_run_script for PowerShell, pwsh, cmd, sh, or bash. Script text and referenced environment values travel through stdin. For transfer, preserve verify=sha256 unless there is a documented reason to use another mode.

For the fixed `lite-cloudquery` management-center service-key set, use
`remotex_ssh_service_key_deploy` instead of the generic copy tool. It accepts
only a local ZIP path, extracts only
`private/management-center/tls-client-key.pem` and
`private/management-center/response-key.pem` (with one optional archive-root
directory), and requires `confirm=true` plus the SSH queue requester. On
Windows the archive path must be under `C:\Work\AI\CloudQuery`. The tool
uses SFTP staging, rejects symlinks, requires authenticated root, and verifies
the fixed target directory and both file hashes/permissions after installation.
It refuses to overwrite existing destination files and never accepts or returns
private-key contents.

Resumable SSH tasks pass input and redaction values through a one-shot local
pipe. They must never create `stdin.bin` or `secrets.json`. If the doctor or task
status reports legacy sensitive artifacts, clean only an inactive validated
task with `remotex_ssh_task_cleanup_sensitive_artifacts` and `confirm=true`.

Use remotex_rdp_test to separate TCP reachability from saved-credential readiness. remotex_rdp_open starts the Windows RDP client only when the matching queue owner and saved TERMSRV credential are present.

Use remotex_vsphere_about for a read-only endpoint check and remotex_vsphere_list_vms for inventory. remotex_vsphere_power requires an explicit profile, inventory path, action, and queue owner. Keep TLS verification enabled.

## Audit And Completion

Use remotex_audit_export when an operation needs local provenance or chain verification. The ledger contains hashes and reference metadata, not scripts, file contents, or credential values.

Report reachability, credential readiness, VM identity status, queue ownership, action acceptance, client result, timeout, receipt hash, integrity verification, and target readback separately. A GUI launch, accepted command, or zero exit code is not proof that the requested final state was reached.
