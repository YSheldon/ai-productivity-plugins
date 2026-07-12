# AI Productivity Plugins

This repository is a local Codex plugin marketplace maintained by Sheldon. The marketplace entrypoint is:

- `.agents/plugins/marketplace.json`

## Included Plugins

- `imap-smtp-mail`: an IMAP/SMTP mail plugin adapted from the original `imap-smtp-email` skill by [gzlicanyi](https://github.com/gzlicanyi). Original source: [openclaw/skills: skills/gzlicanyi/imap-smtp-email](https://github.com/openclaw/skills/tree/main/skills/gzlicanyi/imap-smtp-email). This local adaptation supports QQ Mail, NetEase 163/126/yeah, Tencent Exmail, Ali Mail, 139 Mail, and custom IMAP/SMTP mailboxes.
- `lark-cli`: a Lark/Feishu CLI plugin packaged and maintained by Sheldon. It bundles the existing `lark-*` skills and uses the locally installed `lark-cli` to work with docs, wikis, calendars, messages, Base tables, sheets, and related workflows.
- `gitlab`: a GitLab REST API plugin for Codex. It supports project discovery, merge request and issue inspection, discussions, CI pipeline lookup, comments, approvals, merge actions, repository file reads, and a raw API escape hatch for unsupported GitLab REST endpoints.
- `ssh`: an OpenSSH plugin for Codex. It supports strict-key connection tests, explicit remote commands and stdin scripts, SCP transfers, SSH-agent lifecycle operations, and public-key fingerprint checks.

## Use In Codex

Open this repository in Codex App. Codex reads `.agents/plugins/marketplace.json` and shows the `IMAP/SMTP Mail`, `Lark / Feishu CLI`, `GitLab`, and `SSH` plugins under this local marketplace.

After installing the IMAP/SMTP Mail plugin, the recommended setup path is the local setup wizard. Ask Codex:

```text
Open the mail setup wizard
```

The wizard opens a local browser page. Choose the mail provider, enter the mailbox address and client authorization code, then save. You do not need to edit JSON by hand.

Manual configuration is also supported:

```bash
mkdir -p ~/.imap-smtp-mail
cp ./plugins/imap-smtp-mail/config/accounts.example.json ~/.imap-smtp-mail/accounts.json
```

Edit `~/.imap-smtp-mail/accounts.json` with the email address, username, and client authorization code.

Do not use a web login password. Providers such as QQ Mail and NetEase usually require IMAP/SMTP to be enabled in the web mailbox settings first, then an authorization code or app-specific password must be generated.

After installing the Lark / Feishu CLI plugin, use the existing Lark skill prompts, for example:

```text
Read and summarize a Lark document
Check my Lark calendar
```

The plugin does not add a separate MCP wrapper and does not reimplement Lark OpenAPI calls. It packages the existing `lark-*` skills and keeps using the locally installed and authenticated `lark-cli`.

After installing the GitLab plugin, configure a personal access token or a profile config:

```powershell
$env:GITLAB_URL = "https://gitlab.example.com"
$env:GITLAB_TOKEN = "<personal-access-token>"
```

For multiple GitLab instances, set `GITLAB_CONFIG` to a JSON profile file based on `plugins/gitlab/config/config.example.json`. Store tokens in environment variables through `token_env` rather than committing secrets.

After installing the SSH plugin, configure either `SSH_HOST` and `SSH_USER` or a JSON profile based on `plugins/ssh/config/config.example.json`:

```powershell
$env:SSH_HOST = "ssh.example.internal"
$env:SSH_USER = "root"
$env:SSH_IDENTITY_FILE = "$env:USERPROFILE\.ssh\id_ed25519"
$env:SSH_KNOWN_HOSTS_FILE = "$env:USERPROFILE\.ssh\known_hosts"
```

The plugin uses the local OpenSSH tools with strict host-key checking and public-key-only authentication. It does not store passwords or private keys. Use `ssh_test_connection` before remote commands, and remove temporary keys from `ssh-agent` after the task.

## Install From GitHub

Clone or open this repository in Codex App to load the local plugin marketplace.

To publish these plugins in the official public marketplace, follow the official review and submission process. This repository already contains the local marketplace structure.

Only plugin source, skills, and example configuration are committed. Real mailbox accounts, authorization codes, GitLab tokens, Lark tokens, SSH private keys, SSH profiles, and local runtime caches are not included. Real mailbox configuration belongs in each user's local `~/.imap-smtp-mail/accounts.json`.
