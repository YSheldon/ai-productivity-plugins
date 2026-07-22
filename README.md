# AI Productivity Plugins

This repository is a local Codex plugin marketplace maintained by Sheldon. The marketplace entrypoint is:

- `.agents/plugins/marketplace.json`

## Included Plugins

- `imap-smtp-mail`: an IMAP/SMTP mail plugin adapted from the original `imap-smtp-email` skill by [gzlicanyi](https://github.com/gzlicanyi). Original source: [openclaw/skills: skills/gzlicanyi/imap-smtp-email](https://github.com/openclaw/skills/tree/main/skills/gzlicanyi/imap-smtp-email). This local adaptation supports QQ Mail, NetEase 163/126/yeah, Tencent Exmail, Ali Mail, 139 Mail, and custom IMAP/SMTP mailboxes.
- `lark-cli`: a Lark/Feishu CLI plugin packaged and maintained by Sheldon. It bundles the existing `lark-*` skills and uses the locally installed `lark-cli` to work with docs, wikis, calendars, messages, Base tables, sheets, and related workflows.
- `gitlab`: a GitLab REST API plugin for Codex. It supports project discovery, merge requests, issues, pipelines, decoded API calls, and policy-bound atomic provisioning of a dedicated Windows project Runner with paused-first activation, token-safe child-process registration, Authenticode/SHA256/ACL validation, API attestation, and rollback.
- `product-release-gate`: a fail-closed product material gate for immutable submission manifests, submission checks, test evidence and approval, final-material generation, release checks, scoped production authorization, four-stage deployment/rollback, production readback, and auditable report delivery.
- `test-submission`: a submitter-side product material role plugin that freezes one explicit module submission, previews the request through the locked shared gate, and sends test-request mail through the locked IMAP/SMTP CLI.
- `submission-gate`: a service-side role plugin that scans signed test-request mail, executes the authoritative submission gate through the locked shared gate, and sends pass or blocked notices.
- `pre-release`: a tester-side role plugin that records one final `PASS` or `FAIL`, builds `Manifest-R` through the locked shared gate, and sends release-gate-check mail.
- `release-gate`: a service-side role plugin that scans signed `PRERELEASE_REQUEST` mail, runs release-gate checks through the locked shared gate, and emits release-request or blocking notices while stopping at `RELEASE_READY_NOTIFIED`.
- `rd-flywheel`: an evidence-first R&D workflow skill for turning new requirements, projects, and tasks into real production-proven capability, with versioned visual decision gates and post-production experience harvest.
- `remotex`: a credential-reference-first remote operations plugin for SSH, Windows RDP, vSphere/ESXi, and VMware Workstation. It uses local OpenSSH, `mstsc`, `govc`, and `vmrun` clients, keeps secrets out of repository configuration and tool arguments, and enforces a process-safe local FIFO queue before RDP launch or VM power changes.
- `wecom-codex-usage`: a WeCom / Enterprise WeChat plugin packaged and maintained by Sheldon. It connects to a self-built WeCom internal application for message delivery and summarizes local Codex usage signals from the current machine's Codex config and logs.
- `daily-vuln-bulletin-email`: a verified daily vulnerability bulletin workflow. It uses live Feishu subscribers, severity-safe text/HTML content, exact MIME Subject and Message-ID readback, and recipient-header privacy checks while reusing the existing Lark and IMAP/SMTP plugins.

## Use In Codex

Open this repository in Codex App. Codex reads `.agents/plugins/marketplace.json` and shows the `IMAP/SMTP Mail`, `Lark / Feishu CLI`, `GitLab`, `Product Release Gate`, `Test Submission`, `Submission Gate`, `Pre Release`, `Release Gate`, `RemoteX`, `WeCom Codex Usage`, and `Daily Vulnerability Bulletin` plugins under this local marketplace.

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

After installing the Product Release Gate plugin, use the built-in production bootstrap for filesystem targets. It writes a disabled, fail-closed configuration and an exact adapter dependency lock without writing secret values:

```powershell
py -3 plugins/product-release-gate/scripts/bootstrap_filesystem_production.py `
  --output-config C:\ProgramData\ProductReleaseGate\config.json `
  --preproduction-target D:\ReleaseTargets\Preproduction `
  --canary-target D:\ReleaseTargets\Canary `
  --production-target D:\ReleaseTargets\Production
```

For another adapter type, copy and customize `plugins/product-release-gate/config/config.example.json`. Then point the plugin at the protected configuration:

```powershell
$env:PRODUCT_RELEASE_GATE_CONFIG = "C:\path\to\product-release-gate.json"
```

Run `release_gate_preflight` before creating a release event. The plugin exposes a fail-closed flow:

```text
submission -> submission gate -> test evidence -> approval
-> final material -> release gate -> RELEASE_READY
-> unified approval -> RELEASE_AUTHORIZED
-> pre-production -> canary -> full deployment -> production readback
-> PRODUCTION_VERIFIED -> sealed report -> SMTP delivery + exact IMAP readback
```

The cloud-scan, automated-test, deployment, rollback, and production-readback commands are locked local adapter contracts and must return schema-bound JSON. Missing adapters, invalid signatures, non-clean scan results, failed tests, missing files, extra files, SHA1/SHA256 drift, approval drift, deployment evidence drift, or production readback mismatch block the event. `RELEASE_READY` proves gate completion only. The independent production controller then requires unified approval, issues an expiring stage-scoped credential, executes the configured stages, verifies production state, and can deliver the sealed completion report with deterministic Message-ID and exact IMAP readback. All production automation and report delivery remain explicit opt-ins and default to disabled.

The four product-material role plugins are moving to one build-embedded shared `release_workflow_core` copy per plugin so they no longer depend on a runtime `product-release-gate` bridge, while still keeping submitter, gate, tester, and release-mailbox responsibilities separate:

- `test-submission`: explicit `kernel` / `client` / `server` submission only, no default module, retry-only scheduler, and standalone CLI or MCP without a Codex runtime requirement after setup.
- `submission-gate`: fail-closed mailbox automation with one credential-free config, no `allowed_senders` list escape hatch, and unattended scheduler support on Windows Task Scheduler, systemd, or cron.
- `pre-release`: final `test_result` and `output_dir` stay task-level inputs instead of installation defaults, with the same MCP, Skill, CLI, setup, and unattended scheduler surfaces.
- `release-gate`: validates `PRERELEASE_REQUEST` handoffs, emits `RELEASE_GATE_PASS`, and stops at `RELEASE_READY_NOTIFIED`; it never claims deployment success or production authorization.

After installing the R&D Flywheel plugin, invoke it for new requirements, projects, automations, and engineering tasks that must become reusable production capability:

```text
Use this new requirement as the first R&D Flywheel practice
Confirm this project's design through the visual decision gate
```

The skill uses local Visual Companion click events as versioned design-decision evidence. Those clicks never replace Feishu approval, protected-branch policy, release authorization, or deterministic production gates.

After installing RemoteX, copy `plugins/remotex/config/config.example.json` to `~/.config/remotex/config.json` and replace the example endpoints with local profile values. Keep only credential references in this file. SSH uses an identity-file path or SSH Agent, RDP uses a `TERMSRV/...` Windows credential, vSphere/ESXi uses environment-variable names or a Windows Generic Credential target, and VMware Workstation uses the current local user session.

Run `remotex_status` before connecting. It separates missing configuration, missing client programs, unreachable targets, unavailable credential references, and VM queue state instead of treating every setup gap as a missing password. An unowned VM is offered for explicit claim; another owner cannot be preempted. The old SSH config remains readable in compatibility mode when no RemoteX config exists. See `plugins/remotex/README.md` for the profile schema and safety boundaries.

After installing the WeCom Codex Usage plugin, configure a WeCom self-built internal application:

```text
Open the WeCom configuration wizard
```

The wizard stores `corp_id`, app `corp_secret`, and `agent_id` in `~/.wecom-codex-usage/config.json`. The plugin can then test the connection, send WeCom app messages, and build a local Codex usage summary from `~/.codex/config.toml` plus recent `~/.codex/log/codex-tui.log` token usage lines. It does not claim to read a stable hosted profile-usage API.

## How Codex & GPT-5.6 were used

Codex and GPT-5.6 were used as engineering assistants to inspect existing plugin contracts, implement narrowly scoped changes, generate and run tests, review security boundaries, and maintain the English documentation. The generated work was not accepted on model output alone: repository validators, unit tests, MCP protocol smoke tests, diff review, and secret-pattern scans remain required before publication. Runtime credentials and private infrastructure values were neither requested for documentation nor committed to this repository.

## Install From GitHub

Register the repository marketplace, then install each workflow plugin independently:

```powershell
codex plugin marketplace add https://github.com/YSheldon/ai-productivity-plugins.git
codex plugin add release-approval@ai-productivity-plugins
codex plugin add release-approval-verifier@ai-productivity-plugins
codex plugin add product-release-gate@ai-productivity-plugins
codex plugin add test-submission@ai-productivity-plugins
codex plugin add submission-gate@ai-productivity-plugins
codex plugin add pre-release@ai-productivity-plugins
codex plugin add release-gate@ai-productivity-plugins
codex plugin add rd-flywheel@ai-productivity-plugins
codex plugin add remotex@ai-productivity-plugins
```

The release workflow plugins also provide standalone CLIs and OS schedulers, so those workflows can run without Codex after setup.

To publish these plugins in the official public marketplace, follow the official review and submission process. This repository already contains the local marketplace structure.

Only plugin source, skills, and example configuration are committed. Real mailbox accounts, authorization codes, GitLab tokens, WeCom app secrets, Lark tokens, SSH private keys, RemoteX profiles, remote-management credentials, release-gate adapter settings, and local runtime caches are not included. Real mailbox configuration belongs in each user's local `~/.imap-smtp-mail/accounts.json`; real WeCom configuration belongs in `~/.wecom-codex-usage/config.json`; real RemoteX configuration belongs in `~/.config/remotex/config.json` or a protected file referenced by `REMOTEX_CONFIG`; real release-gate configuration belongs in a protected local file referenced by `PRODUCT_RELEASE_GATE_CONFIG`.
