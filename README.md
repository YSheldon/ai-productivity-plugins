# AI Productivity Plugins

Practical plugins for remote operations, engineering delivery, and workplace automation.

[![Release gate CI](https://github.com/YSheldon/ai-productivity-plugins/actions/workflows/release-gate-ci.yml/badge.svg?branch=main)](https://github.com/YSheldon/ai-productivity-plugins/actions/workflows/release-gate-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-16856b)](LICENSE)

[Quick Start](#quick-start) | [Plugin Catalog](docs/plugin-catalog.md) | [What's New](CHANGELOG.md) | [Security](#security-and-compatibility)

A community-maintained marketplace by Sheldon for **Codex, Cursor, and Grok**.
Install the plugins you need, keep credentials local, and reuse named profiles
across supported clients. Selected engineering workflows also provide standalone
CLIs and OS schedulers; they do not require Codex after setup.

## What's New

| Plugin version | New capability | Details |
| --- | --- | --- |
| RemoteX 0.6.4 | Approval-window lifecycle receipts, bounded Edge startup, scoped buttons/forms/writes, and target readback | [Task authorization](plugins/remotex/docs/web-task-authorization.md) |
| RemoteX 0.5.12 | Isolated Edge pages resize with the window, with read-only geometry diagnostics | [Responsive windows](plugins/remotex/docs/web-credentials.md#responsive-windows) |
| RemoteX 0.5.11 | Read the authenticated page and passive business results in the same isolated session | [Same-session control](plugins/remotex/docs/web-credentials.md#same-session-controlled-operations) |
| RemoteX 0.5.10 | Exact-origin certificate trust and a more reliable Windows credential window | [Web credentials](plugins/remotex/docs/web-credentials.md) |
| RemoteX 0.5.9 | Origin/account-bound credentials and isolated Edge sign-in | [Login workflow](docs/remotex-showcase.md#secure-web-sign-in) |
| RemoteX 0.5.8 | Per-credential systems, architecture evidence, calls, queues, and last-use reports | [Usage reports](plugins/remotex/docs/usage-reports.md) |
| RemoteX 0.5.7 | One-step FIFO admission for authorized tasks, without preemption | [Queue behavior](plugins/remotex/README.md#shared-vm-queue) |
| RemoteX 0.5.6 | Verified deployment of a fixed management-center service-key set | [Scope and limits](CHANGELOG.md#remotex-056) |

[Full change history and upgrade notes](CHANGELOG.md). Versions belong to individual
plugins, not to the marketplace as a whole.

## RemoteX Spotlight

**One profile-based toolkit for SSH, RDP, Windows guests, VMware, and secure Edge sign-in.**
RemoteX combines local credential aliases, physical-host and VM identity checks,
bounded execution, verified transfers, and cooperative queue ownership.

**Report preview: synthetic demo data**

| Credential alias | Historical OS evidence | Configured architecture | Remote calls | Reservation lower bound | Last use (UTC) |
| --- | --- | --- | --- | --- | --- |
| lab-x86-operator | 10.0.19045 | x86 | 18 | 0.8% | Jan 14, 09:20 |
| lab-amd64-operator | 10.0.22631 | AMD64 | 42 | 1.9% | Jan 15, 10:45 |
| lab-arm64-operator | 10.0.26100 | ARM64 | 27 | 1.3% | Jan 15, 11:10 |

*Illustrative 30-day summary, not a live inventory or application screenshot.
System observations are historical; reservations are recorded lower bounds,
not CPU utilization or proof of global machine exclusivity. [Full demo context](docs/remotex-showcase.md#per-credential-reports).*

Try these prompts after installing RemoteX:

```text
Use RemoteX to check all missing credential references without modifying anything.
Use RemoteX to export a 30-day per-credential usage report as HTML, JSON, and CSV.
Use RemoteX to probe the configured web-console profile, then sign in once if ready.
```

[Explore RemoteX](docs/remotex-showcase.md) for local secure input, certificate-pin
approval, platform requirements, and the distinction between submitted and verified sign-in.

## Choose Your Workflow

| Goal | Start here |
| --- | --- |
| Operate shared hosts and VMs, inspect usage, or sign in to a web console | [RemoteX](plugins/remotex/README.md) |
| Review merge requests, analyze CI, bind approvals to scope, or provision a Windows Runner | [GitLab](plugins/gitlab/README.md) |
| Submit artifacts, verify gates, collect approvals, and authorize staged releases | [Release workflow guide](docs/product-material-release/installation-and-quickstart.md) |
| Read and send mail, work in Lark, or send WeCom application messages | [Collaboration plugins](docs/plugin-catalog.md#collaboration-and-reporting) |
| Deliver an audited vulnerability bulletin | [Daily Vulnerability Bulletin](plugins/daily-vuln-bulletin-email/README.md) |
| Govern capability gaps through MCP, CLI, and scheduling | [R&D Flywheel](plugins/rd-flywheel/README.md) |
| Display a Beijing taskbar clock with duty reminders on Windows | [World Time Reminder](plugins/world-time-reminder/README.md) |

The [complete catalog](docs/plugin-catalog.md) includes every available plugin,
its manifest version, and its client-index membership. The original `ssh` entry
is legacy and unavailable for new installation; use RemoteX instead.

## Quick Start

### Codex

```powershell
codex plugin marketplace add https://github.com/YSheldon/ai-productivity-plugins.git
codex plugin add remotex@ai-productivity-plugins
```

Then ask: `Use RemoteX to check runtime readiness and preview a new profile.`
Enter credentials only through the plugin's local setup flow, never in chat.

### Cursor

Import this repository into your team marketplace, then install the desired
plugin from **Customize**. For a local Windows installation, use the
[copy-and-verify instructions](docs/installation.md#cursor); avoid nested copies
when updating an already populated plugin directory.

### Grok

```powershell
grok plugin marketplace add YSheldon/ai-productivity-plugins
grok plugin install remotex --trust
```

Only GitLab, RemoteX, and IMAP/SMTP Mail are currently indexed for Grok. Follow the
[installation guide](docs/installation.md) for prerequisites, authentication,
update checks, and safe reconnection of running clients.

## Security and Compatibility

- **References, not chat secrets.** Keep real tokens, passwords, keys, profiles,
  and environment-specific configuration outside this repository. Storage
  mechanisms differ by plugin; consult its security notes.
- **Narrow trust.** Web pins require trusted-channel confirmation of the exact
  origin and leaf certificate. They replace CA/hostname checks only for that
  origin; validity dates remain enforced. There is no global TLS-ignore switch.
- **No queue preemption.** RemoteX queues are cooperative and local to the
  machine. Queue admission does not authorize reboot, snapshots, or deployment.
- **Evidence has a scope.** Credential presence is not authentication. A passing
  gate is not deployment. Historical system receipts are not fresh host probes.
- **Client discovery is not platform certification.** An indexed plugin may have
  Windows-only operations or require installed clients and configured adapters.
  See the [compatibility notes](docs/plugin-catalog.md#compatibility-and-evidence).

## Documentation and Contributing

- [Plugin catalog](docs/plugin-catalog.md): choose a plugin and inspect its current version.
- [Installation and upgrades](docs/installation.md): configure a client without overwriting local state.
- [RemoteX showcase](docs/remotex-showcase.md): examples, report preview, and web credential flow.
- [Changelog](CHANGELOG.md): user-facing changes and version-specific limits.
- [Documentation maintenance](docs/maintaining-project-docs.md): regenerate the catalog and validate a release update.

For a contribution, use a focused branch, preserve existing behavior, add relevant
tests, update affected documentation, and run the full repository test suite.
Public examples must use synthetic data and reserved example endpoints.

## Attribution and License

Licensed under [MIT](LICENSE). IMAP/SMTP Mail is adapted from the original
`imap-smtp-email` skill by [gzlicanyi](https://github.com/gzlicanyi), available in
[openclaw/skills](https://github.com/openclaw/skills/tree/main/skills/gzlicanyi/imap-smtp-email).
Preserve upstream notices and plugin-specific attribution when redistributing.

## How Codex & GPT-5.6 were used

Codex and GPT-5.6 assisted with contract inspection, scoped implementation,
regression tests, security review, and English documentation. Changes were checked
with repository validators, unit tests, MCP smoke tests, diff review, and
secret-pattern scans. Generated code and passing fixtures alone do not establish
production acceptance. Real credentials and private infrastructure values are not
part of the published examples.
