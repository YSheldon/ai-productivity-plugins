# Daily Vulnerability Bulletin Codex Plugin

This plugin packages the production `每日漏洞播报` workflow for Codex. It is
skill-only by design: Feishu access and IMAP/SMTP transport remain in the
existing `lark-cli` and `imap-smtp-mail` plugins, while this plugin provides the
workflow contract, deterministic MIME checks, and recipient-privacy audit.

## Marketplace Entry

The plugin is registered in `.agents/plugins/marketplace.json` and appears as
`每日漏洞播报` in the `AI 生产力插件集` marketplace.

## Required Capabilities

- `lark-cli@ai-productivity-plugins` for the realtime Feishu subscriber source.
- `imap-smtp-mail@ai-productivity-plugins` only when the selected transport uses
  that plugin. A separately validated SMTP/IMAP script must be recorded as a
  separate capability and is not silently substituted.

The bundled preflight is read-only. If a required plugin is available but not
installed, it reports the exact install command and waits for explicit user
approval. It never installs a plugin, changes marketplace sources, or exports
credentials on its own.

## Privacy Boundary

The default delivery mode is one message per subscriber with one visible
`To:` address. Putting all subscribers in one `To:` header exposes the complete
list to every recipient and is reported as a disclosure risk. `From:` is visible
by design. `Received:` may expose relay hostnames and public IP metadata; the
plugin audits and records only counts, not raw header values.

Use `scripts/verify_recipient_privacy.py` together with
`scripts/verify_bulletin_mime.py` before SMTP and on exact IMAP readback files.

## No Secrets In Source

The plugin contains no mailbox accounts, authorization codes, Feishu tokens,
subscriber addresses, API keys, private keys, or local runtime paths. Keep
those values in the provider's protected local configuration and do not put
them in reports, email bodies, audit JSON, or automation memory.
