# SSH

The SSH plugin gives Codex a small MCP wrapper around the local OpenSSH tools. It supports connection checks, explicit remote commands, scripts sent through stdin, SCP uploads and downloads, SSH-agent lifecycle operations, and public-key fingerprint checks.

It does not implement SSH in Python, accept passwords, or store private keys. Configure a host profile and let the installed `ssh`, `scp`, `ssh-add`, and `ssh-keygen` executables handle authentication.

Configuration is read from `SSH_CONFIG`, or from `~/.config/codex-ssh/config.json` when the variable is not set. Use `config/config.example.json` as the starting point. Environment variables are convenient for a single host:

```powershell
$env:SSH_HOST = "ssh.example.internal"
$env:SSH_USER = "root"
$env:SSH_IDENTITY_FILE = "$env:USERPROFILE\.ssh\id_ed25519"
$env:SSH_KNOWN_HOSTS_FILE = "$env:USERPROFILE\.ssh\known_hosts"
```

The server defaults to `StrictHostKeyChecking=yes`, `BatchMode=yes`, `IdentitiesOnly=yes`, public-key authentication, password authentication disabled, and a ten-second connection timeout. A profile may explicitly select `accept-new` or `no` host-key checking, but those weaker modes should be reserved for disposable environments.

The `ssh_agent_add` tool deliberately calls `ssh-add` without a lifetime constraint. Some Windows OpenSSH agent implementations reject `ssh-add -t`; load the key without `-t` and remove it with `ssh_agent_remove` after the operation.

Remote commands and scripts are side-effectful. Use `ssh_test_connection` and read-only commands first, review output, and use `ssh_run_script` for multi-line work so the script is carried over stdin instead of being embedded in the SSH argument list.
