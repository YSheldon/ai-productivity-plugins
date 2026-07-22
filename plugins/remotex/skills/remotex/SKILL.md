---
name: remotex
description: Use configured RemoteX profiles to inspect or operate SSH hosts, Windows RDP targets, vSphere or ESXi environments, and local VMware Workstation virtual machines without passing credentials in chat.
---

# RemoteX

Use this skill for remote-system and virtual-machine work that should reuse named local profiles rather than asking the user for credentials on every task.

## Required First Step

Call `remotex_status` before selecting a connection tool. Treat its profile kind, target, client availability, and credential readiness as the current boundary. A missing profile is a configuration gap, not proof of invalid credentials.

Never ask the user to paste a password, token, authorization code, private key, or credential-manager export into chat. RemoteX accepts only credential references from SSH Agent, an identity-file path, Windows Credential Manager, or named environment variables.

## SSH

1. Call `remotex_ssh_test` before any remote command or transfer.
2. Prefer read-only inspection commands before maintenance commands.
3. Use `remotex_ssh_run_script` for multi-line work; the script is sent through stdin.
4. Use the SCP tools only with explicit local and remote paths.
5. If a key is temporarily loaded with `remotex_ssh_agent_add`, remove it with `remotex_ssh_agent_remove` after the operation.

Do not weaken strict host-key checking unless the user explicitly identifies a disposable environment and accepts that boundary.

## RDP

Use `remotex_rdp_test` to separate TCP reachability from saved-credential readiness. `remotex_rdp_open` launches the Windows RDP client and is side-effectful. It must fail when the configured `TERMSRV/...` credential is absent instead of requesting a password through Codex.

## vSphere and ESXi

Use `remotex_vsphere_about` for a read-only endpoint check and `remotex_vsphere_list_vms` for inventory. `remotex_vsphere_power` changes VM state and requires an explicit profile, inventory path, and action. Keep TLS verification enabled; a configured CA file is preferred for private infrastructure.

An ESXi shell accessed over SSH is an SSH profile. ESXi or vCenter API operations through `govc` are a `vsphere` or `esxi` profile.

## VMware Workstation

Use `remotex_vmware_list_running` for local inventory. `remotex_vmware_power` operates only on the `.vmx` path already bound to the selected profile. Confirm `hard`, `reset`, or `suspend` actions because they can discard guest state.

## Completion Evidence

Report connection reachability, authentication readiness, the executed operation, process return code, and target readback separately. Starting a GUI or issuing a power command is not proof that the remote system reached the requested final state.
