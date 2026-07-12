---
name: ssh
description: Use SSH from Codex to connect to configured hosts, inspect remote systems, run explicit commands or stdin scripts, transfer files, and manage local ssh-agent identities.
---

# SSH

Use this skill when the user asks Codex to connect to an SSH host, inspect or administer a remote Linux/Unix system, copy files with SCP, or load/remove a local SSH key for a controlled operation.

## Setup

For one host, set environment variables in the shell that launches Codex:

```powershell
$env:SSH_HOST = "ssh.example.internal"
$env:SSH_USER = "root"
$env:SSH_IDENTITY_FILE = "$env:USERPROFILE\.ssh\id_ed25519"
$env:SSH_KNOWN_HOSTS_FILE = "$env:USERPROFILE\.ssh\known_hosts"
```

For multiple hosts, set `SSH_CONFIG` to a JSON file based on `config/config.example.json`. Select a profile with `SSH_PROFILE` or the tool `profile` argument. Keep private keys outside the plugin and never put private key contents, passphrases, or host secrets in the config file.

The plugin uses the system OpenSSH executables. Confirm that `ssh`, `scp`, `ssh-add`, and `ssh-keygen` are available before diagnosing remote failures.

## Connection workflow

1. Call `ssh_list_profiles` when the active profile is unclear.
2. Call `ssh_test_connection` before making changes. It performs a non-writing `hostname` probe and reports the return code, host, user, and redacted output.
3. Prefer read-only `ssh_run_command` calls for inspection. It accepts one command line; use `ssh_run_script` for multi-line work.
4. Treat `ssh_run_script`, `ssh_copy_to`, `ssh_copy_from`, and agent changes as side-effectful. Confirm the target and scope from the user request before using them.
5. After a temporary key load, call `ssh_agent_remove` and verify the agent state with `ssh_agent_list`.

## First-time public-key authorization

If the server has no `/root/.ssh` directory, create it on the host console or an already trusted administration channel. Do not put the key in a container unless the container is the SSH endpoint:

```sh
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chown -R root:root /root/.ssh
```

Append the complete local `.pub` line to `authorized_keys`. Do not transmit or display the private key. Validate the public-key fingerprint before and after authorization when possible.

On Windows OpenSSH, load a key without a lifetime flag when the agent does not support `ssh-add -t`:

```powershell
ssh-add "$env:USERPROFILE\.ssh\id_ed25519"
ssh-add -l
```

Remove it after the task:

```powershell
ssh-add -d "$env:USERPROFILE\.ssh\id_ed25519"
ssh-add -l
```

## Security boundaries

- The plugin never prompts for or stores SSH passwords.
- Host-key verification is strict by default. Do not weaken it to bypass a changed-host-key error; verify the host key through a trusted channel first.
- `BatchMode=yes`, password authentication disabled, keyboard-interactive authentication disabled, and public-key authentication are fixed defaults.
- The plugin passes local subprocess arguments as an argument list. Remote command strings are intentionally executed by the remote login shell; do not interpolate untrusted data into them. Use stdin scripts for structured multi-line operations.
- Tool output is redacted for common token forms, secret key-value assignments, and PEM private-key blocks, but output redaction is a defense in depth. Do not ask the remote host to print credentials or whole secret-bearing configuration files.
- Never expose `ssh -vvv` output, private key contents, agent sockets, or remote registration tokens in chat.
