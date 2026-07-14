# Plugin Preflight And Installation Contract

## Purpose

This contract gates plugins used by a formal daily vulnerability bulletin. It separates three states: a capability is ready, installable with user consent, or blocked.

## Required Capability Mapping

| Delivery capability | Plugin ID | When required |
| --- | --- | --- |
| Feishu realtime subscriber source | `lark-cli@ai-productivity-plugins` | Every formal bulletin that uses the Feishu subscription document. |
| Plugin-native SMTP/IMAP transport and readback | `imap-smtp-mail@ai-productivity-plugins` | Only when the selected transport uses this plugin. |

A validated local delivery script is not represented by a plugin ID. Its executable, scope, and prior transport/readback proof must be recorded separately; it cannot be inferred from a cached plugin.

## Consent Boundary

The preflight command is read-only. It may return the exact install commands, but it never executes them.

For an `installable` result, ask the user to approve the exact set of `PLUGIN@MARKETPLACE` IDs. The approval request must include:

- the exact plugin IDs and configured marketplace names
- that installation persists plugin configuration and cache state
- whether the plugin reports `authPolicy=ON_INSTALL`
- that no extra plugins, marketplace additions, marketplace updates, source URL changes, or credential export are included

Only an explicit approval of the listed IDs permits execution of `codex plugin add PLUGIN@MARKETPLACE --json`.

## Fail-Closed Rules

- `unavailable`, `disabled`, inventory-query failure, malformed inventory, or post-install recheck failure blocks the formal send.
- Never use `codex plugin marketplace add`, marketplace upgrade, a Git URL, or a repository URL as an automatic recovery step.
- Never put credentials, access tokens, raw authentication prompts, or plugin configuration secrets in report artifacts, email bodies, or automation memory.
- Installation does not prove a capability works. Re-run preflight, perform the selected source/transport check, and retain those results separately.
- If the current session cannot discover a newly installed plugin, require a fresh session before running the formal send.
