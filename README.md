# AI Productivity Plugins

This repository is a local Codex plugin marketplace maintained by Sheldon. The marketplace entrypoint is:

- `.agents/plugins/marketplace.json`

## Included Plugins

- `imap-smtp-mail`: an IMAP/SMTP mail plugin adapted from the original `imap-smtp-email` skill by [gzlicanyi](https://github.com/gzlicanyi). Original source: [openclaw/skills: skills/gzlicanyi/imap-smtp-email](https://github.com/openclaw/skills/tree/main/skills/gzlicanyi/imap-smtp-email). This local adaptation supports QQ Mail, NetEase 163/126/yeah, Tencent Exmail, Ali Mail, 139 Mail, and custom IMAP/SMTP mailboxes.
- `lark-cli`: a Lark/Feishu CLI plugin packaged and maintained by Sheldon. It bundles the existing `lark-*` skills and uses the locally installed `lark-cli` to work with docs, wikis, calendars, messages, Base tables, sheets, and related workflows.
- `gitlab`: a GitLab REST API plugin for Codex. It supports project discovery, merge request and issue inspection, discussions, CI pipeline lookup, comments, approvals, merge actions, repository file reads, and a raw API escape hatch for unsupported GitLab REST endpoints.
- `product-release-gate`: a fail-closed product material gate for immutable submission manifests, submission checks, test evidence and approval, final-material generation, release checks, and auditable reports.
- `ssh`: an OpenSSH plugin for Codex. It supports strict-key connection tests, explicit remote commands and stdin scripts, SCP transfers, SSH-agent lifecycle operations, and public-key fingerprint checks.
- `wecom-codex-usage`: a WeCom / Enterprise WeChat plugin packaged and maintained by Sheldon. It connects to a self-built WeCom internal application for message delivery and summarizes local Codex usage signals from the current machine's Codex config and logs.

## Use In Codex

Open this repository in Codex App. Codex reads `.agents/plugins/marketplace.json` and shows the `IMAP/SMTP Mail`, `Lark / Feishu CLI`, `GitLab`, `Product Release Gate`, `SSH`, and `WeCom Codex Usage` plugins under this local marketplace.

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

After installing the Product Release Gate plugin, copy and customize `plugins/product-release-gate/config/config.example.json`, then point the plugin at the protected local configuration:

```powershell
$env:PRODUCT_RELEASE_GATE_CONFIG = "C:\path\to\product-release-gate.json"
```

Run `release_gate_preflight` before creating a release event. The plugin exposes a fail-closed flow:

```text
submission -> submission gate -> test evidence -> approval
-> final material -> release gate -> RELEASE_READY -> report
```

The cloud-scan and automated-test commands are local adapter contracts and must return JSON. Missing adapters, invalid signatures, non-clean scan results, failed tests, missing files, extra files, or SHA1 drift block the event. `RELEASE_READY` proves gate completion only; deployment credentials and production deployment remain outside the plugin.

After installing the SSH plugin, configure either `SSH_HOST` and `SSH_USER` or a JSON profile based on `plugins/ssh/config/config.example.json`:

```powershell
$env:SSH_HOST = "ssh.example.internal"
$env:SSH_USER = "root"
$env:SSH_IDENTITY_FILE = "$env:USERPROFILE\.ssh\id_ed25519"
$env:SSH_KNOWN_HOSTS_FILE = "$env:USERPROFILE\.ssh\known_hosts"
```

The plugin uses the local OpenSSH tools with strict host-key checking and public-key-only authentication. It does not store passwords or private keys. Use `ssh_test_connection` before remote commands, and remove temporary keys from `ssh-agent` after the task.

After installing the WeCom Codex Usage plugin, configure a WeCom self-built internal application:

```text
打开企业微信配置向导
```

The wizard stores `corp_id`, app `corp_secret`, and `agent_id` in `~/.wecom-codex-usage/config.json`. The plugin can then test the connection, send WeCom app messages, and build a local Codex usage summary from `~/.codex/config.toml` plus recent `~/.codex/log/codex-tui.log` token usage lines. It does not claim to read a stable hosted profile-usage API.

## Install From GitHub

Clone or open this repository in Codex App to load the local plugin marketplace.

To publish these plugins in the official public marketplace, follow the official review and submission process. This repository already contains the local marketplace structure.

Only plugin source, skills, and example configuration are committed. Real mailbox accounts, authorization codes, GitLab tokens, WeCom app secrets, Lark tokens, SSH private keys, SSH profiles, release-gate adapter settings, and local runtime caches are not included. Real mailbox configuration belongs in each user's local `~/.imap-smtp-mail/accounts.json`; real WeCom configuration belongs in `~/.wecom-codex-usage/config.json`; real release-gate configuration belongs in a protected local file referenced by `PRODUCT_RELEASE_GATE_CONFIG`.
