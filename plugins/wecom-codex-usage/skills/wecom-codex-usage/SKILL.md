---
name: wecom-codex-usage
description: Use WeCom/Enterprise WeChat to send internal application messages from Codex, and summarize local Codex token usage signals from logs and config.
---

# WeCom Codex Usage

## Overview

Use this skill when the user wants Codex to connect to WeCom, send a WeCom application message, test a WeCom app credential, or summarize local Codex usage/token signals.

## Setup Expectations

- The WeCom side needs a self-built internal application with `corp_id`, app `corp_secret`, and `agent_id`.
- Prefer `wecom_codex_usage_start_setup` so secrets are entered in a local browser page instead of chat.
- The account config is saved to `~/.wecom-codex-usage/config.json`, and can be overridden with `WECOM_CODEX_USAGE_CONFIG` or `WECOM_CORP_ID`, `WECOM_CORP_SECRET`, and `WECOM_AGENT_ID`.
- Codex usage collection is local-only. It reads `~/.codex/config.toml` and recent `~/.codex/log/codex-tui.log` token usage lines. It does not claim to read a stable hosted account-usage API.

## Workflow

1. Call `wecom_codex_usage_list_accounts` first if the user did not specify an account.
2. If no accounts are configured, call `wecom_codex_usage_start_setup` and give the user the returned local URL.
3. Use `wecom_codex_usage_test_connection` before sending real messages from a newly configured account.
4. Use `wecom_codex_usage_get_codex_usage` for a local usage summary.
5. Use `wecom_codex_usage_send_message` with `dry_run: true` first unless the user explicitly asked to send immediately.

## Write Safety

- Never expose `corp_secret` or access tokens.
- Treat `dry_run: false` as a real WeCom send operation.
- Prefer targeting an explicit `to_user`, `to_party`, or `to_tag`; use `@all` only when the user explicitly wants a broad broadcast.
- Do not imply that local log-derived token totals equal the official billing/account quota.

## Output Conventions

- Usage summaries should state the local source path and time window.
- Send results should state whether the operation was a dry run or a real WeCom API send.
- If quota/profile data is unavailable locally, say so plainly and report the local evidence that was available.
