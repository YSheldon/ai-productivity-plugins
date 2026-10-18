# Installation and Upgrades

[Home](../README.md) | [Plugin catalog](plugin-catalog.md) | [Changelog](../CHANGELOG.md)

Install only the plugins required for your workflow. This is a community
marketplace, not a claim of listing in an official public plugin directory.

## Prerequisites

| Capability | Requirements |
| --- | --- |
| Python-backed MCP plugins | Python 3.11+ baseline; see each plugin for optional dependencies |
| Node launchers | Node.js on the client PATH; some operations require a newer version |
| RemoteX web credentials | Windows, Microsoft Edge, Node.js 24+, Playwright Core 1.62.1 |
| RemoteX SSH / SFTP | OpenSSH clients, approved host keys, public-key authentication |
| RemoteX RDP / Windows guests | Windows RDP client or the configured WinRM prerequisites |
| RemoteX VMware / vSphere | Local `vmrun` or `govc`, identity bindings, credential references |
| Lark / Feishu | Separately installed and authenticated `lark-cli` |
| Mail / WeCom / GitLab | An authorized account and plugin-specific local configuration |
| Release automation | Protected adapter configuration and explicit release/sending authority |

Client-index membership is listed in the catalog. Current generated Cursor MCP
wrappers invoke Windows `cmd.exe`; do not infer macOS/Linux support from a Cursor
entry. Some standalone CLIs support other operating systems, as documented in
their own guides.

## Codex

```powershell
codex plugin marketplace add https://github.com/YSheldon/ai-productivity-plugins.git
codex plugin add remotex@ai-productivity-plugins
codex plugin list --marketplace ai-productivity-plugins --json
```

Replace `remotex` with an available name from the [catalog](plugin-catalog.md).
Opening the repository locally in Codex also exposes its marketplace through
`.agents/plugins/marketplace.json`.

### Engineering workflow plugins

Install individual roles only where they are needed:

```powershell
codex plugin add release-approval@ai-productivity-plugins
codex plugin add release-approval-verifier@ai-productivity-plugins
codex plugin add product-release-gate@ai-productivity-plugins
codex plugin add test-submission@ai-productivity-plugins
codex plugin add submission-gate@ai-productivity-plugins
codex plugin add pre-release@ai-productivity-plugins
codex plugin add release-gate@ai-productivity-plugins
codex plugin add rd-flywheel@ai-productivity-plugins
```

These roles share versioned contracts and build-embedded shared
`release_workflow_core` modules. Some operations still invoke configured,
integrity-locked adapter commands or the product-release-gate kernel; installing
a role does not prove that all its dependencies are configured. Follow the
role's preflight and the product-material guide before activation.

After installation, check that the runtime exposes the expected tools. A package
on disk and a running MCP process can have different versions. Reconnect using
the client's supported controls, or start a fresh conversation, before declaring
a new tool available. Do not stop unrelated sessions to refresh one plugin.

### Updating a Git marketplace

```powershell
codex plugin marketplace upgrade ai-productivity-plugins --json
codex plugin list --marketplace ai-productivity-plugins --json
```

Marketplace refresh can update more than one installed plugin. Coordinate an idle
window first, inspect individual outcomes, and do not treat one overall exit code
as proof that every plugin updated. Recheck installed versions and tool readiness.
Do not assume a source update automatically refreshes every running conversation.

## Cursor

### Team marketplace

On a team plan that supports repository imports, add this repository through
Dashboard > Plugins > Import from Repo, then install from **Customize**:

```text
https://github.com/YSheldon/ai-productivity-plugins
```

Cursor reads `.cursor-plugin/marketplace.json`. Team Auto Refresh depends on the
repository integration and team policy; it is distinct from reconnecting a live
MCP process. See [Cursor's plugin documentation](https://cursor.com/docs/plugins).

With the Cursor Agent CLI installed, marketplace registration is also available:

```powershell
cursor-agent plugin marketplace add https://github.com/YSheldon/ai-productivity-plugins
```

### Local Windows installation

Clone the repository and copy the *contents* of one plugin. This first-install
example intentionally refuses to overwrite an existing installation:

```powershell
git clone https://github.com/YSheldon/ai-productivity-plugins.git
Set-Location ai-productivity-plugins
$source = (Resolve-Path .\plugins\remotex).Path
$target = Join-Path $env:USERPROFILE '.cursor\plugins\local\remotex'
if (Test-Path -LiteralPath $target) {
    throw 'RemoteX already exists. Follow the upgrade checklist before replacing it.'
}
New-Item -ItemType Directory -Path $target -Force | Out-Null
Get-ChildItem -LiteralPath $source -Force | Copy-Item -Destination $target -Recurse
```

The result must contain `remotex/.cursor-plugin/plugin.json` and
`remotex/src/remotex_mcp.py`, not `remotex/remotex/...` or `src/src/...`.
Local plugin imports must be allowed by your Cursor policy. Do not replace the
copy with a symlink to a location outside Cursor's local plugin directory.

For first discovery, reload an idle window following Cursor's documented flow.
For an existing connection, reconnect only RemoteX from Customize when no RemoteX
operation is active. Verify manifest version, process start, connection success,
and expected tool inventory separately.

## Grok

Grok reads `.grok-plugin/marketplace.json`, not the Codex index. Current entries
are `gitlab`, `remotex`, and `imap-smtp-mail`:

```powershell
grok plugin marketplace add YSheldon/ai-productivity-plugins
grok plugin install gitlab --trust
grok plugin install remotex --trust
grok plugin install imap-smtp-mail --trust
```

If installed plugins remain disabled, inspect `~/.grok/config.toml`. Preserve
other enabled plugins when updating its list:

```toml
[plugins]
enabled = ["gitlab", "remotex", "imap-smtp-mail"]
```

Trust the source only after reviewing it. CLI behavior varies by client version;
check the installed command's `--help` before applying an upgrade procedure.

## First Use

| Plugin | First action | Configuration boundary |
| --- | --- | --- |
| RemoteX | Preview a profile, then use the local secure setup flow | `~/.config/remotex/config.json` or `REMOTEX_CONFIG`; references, not passwords |
| IMAP/SMTP Mail | Ask to open the mail setup wizard | Use an app password or authorization code where required |
| GitLab | Configure the instance and token reference | Follow the [GitLab guide](../plugins/gitlab/README.md); never commit tokens |
| Lark / Feishu | Authenticate `lark-cli`, then request an operation | Packages existing Lark skills, not a separate API implementation |
| WeCom | Ask to open the WeCom configuration wizard | Use a self-built internal application; keep its local config private |
| Release workflows | Run each role's `setup`, `preflight`, and `doctor` | Installation does not authorize production changes or real mail |
| R&D Flywheel | Run setup and inspect preflight/status | MCP, Skill, CLI, and scheduling share one versioned config |

Read the [release-workflow quickstart](product-material-release/installation-and-quickstart.md)
for role separation and the [RemoteX showcase](remotex-showcase.md) for web sign-in.
Never paste secrets into an AI conversation, shell arguments, screenshots, or a PR.

## Safe Upgrade Checklist

1. Read the selected plugin's [upgrade notes](../CHANGELOG.md), and record its source revision.
2. Inspect active operations and local queue owners. Do not preempt another task.
3. Back up the plugin directory and protected configuration separately. Keep backups outside the discovery directory.
4. Preserve user-modified files; stage a complete replacement and verify hashes before switching directories. Do not recursively copy a directory onto itself.
5. Reconnect only the affected idle MCP server. A disk update does not update already imported Python modules.
6. Verify initialization/version, tool inventory, credential presence, and a read-only probe. Run authenticated acceptance only when authorized.
7. Close the verification session and release only its own queue resource.

Older RemoteX runtimes may reject a `web` profile or certificate-pin field while
reading the entire shared config. Upgrade/reconnect all consumers before merging
new profile kinds into that config. Do not remove trust or identity checks as a
workaround. A successful credential-presence check is not login proof.

RemoteX 0.6.0 adds task-level human approval without changing the profile schema.
After reconnecting, check `remotex_web_components`, `remotex_web_action_prepare`,
`remotex_web_authorization_request`, `remotex_web_authorization_status`,
`remotex_web_execute`, `remotex_web_execution_status`, and
`remotex_web_authorization_revoke` in the tool inventory. The login-resume tool
supports reviewed startup contracts. Legacy content/navigation APIs return
`approval-required`; see [Task authorization](../plugins/remotex/docs/web-task-authorization.md).
Start a new owned login session;
do not try to adopt an old process's session or move cookies between windows.
Confirm supported-browser access through the host before any web operation.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| New tool missing | Installed version versus running version; reconnect/discovery state |
| Credential window absent | Use RemoteX 0.5.10+; older launchers could inherit incompatible PowerShell module paths |
| Certificate error | Use valid TLS, or explicitly verify and approve one exact-origin leaf pin; never globally ignore TLS |
| Queue busy | Join the FIFO queue; do not reuse another requester's identity |
| Config rejected after upgrade | Check every client reading the shared config for old runtimes |
| Browser-control request-header policy error | Diagnose the host browser interface separately from site credentials |
| Isolated Edge not in the browser list | Use RemoteX task tools in the process that started login; a session ID is not a generic tab ID |
| Button/form interface absent | Upgrade/reconnect to 0.6.2, discover components, request a local human grant, then use typed execution |
| `authorization-contract-required` | Inspect blocked descriptor refs, review exact startup/login contracts locally, then resume the same UI; never replay raw requests |
| Page stays at 1280x720 when resizing Edge | Use a new window-sized session; inspect `remotex_web_components.geometry` to separate viewport behavior from site CSS |
| Host browser access denied or unknown | Stop web operations; do not use RemoteX, CDP, or shell automation as an alternate route |

Keep installation, runtime readiness, authentication, and production acceptance
as separate results. Report failures without exposing local secrets or profiles.
