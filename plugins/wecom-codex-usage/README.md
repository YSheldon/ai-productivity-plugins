# WeCom Codex Usage Codex Plugin

This plugin connects Codex to WeCom (Enterprise WeChat) through a self-built internal application, and exposes a local-only Codex usage summary based on the current machine's Codex config and logs.

## MVP Scope

- List configured WeCom accounts without exposing secrets.
- Start a local setup wizard for `corp_id`, app `corp_secret`, and `agent_id`.
- Test WeCom app credentials by fetching an access token.
- Send text or markdown application messages through WeCom, with `dry_run` enabled by default.
- Summarize local Codex token usage signals from `~/.codex/log/codex-tui.log` and status-line configuration from `~/.codex/config.toml`.

## Marketplace Entry

This plugin is registered by the repository marketplace file:

```text
.agents/plugins/marketplace.json
```

When this repository is opened in Codex App, it appears as `企业微信 / Codex 用量` in the `AI 生产力插件集` marketplace.

## WeCom Requirements

Create or reuse a WeCom self-built internal application and collect:

- `corp_id`: the enterprise ID.
- `corp_secret`: the secret for the application or address-book scope you want to use.
- `agent_id`: the numeric app agent ID.

For message sending, the app must have permission to send application messages to the selected users, departments, or tags.

## Configuration

The recommended path is the local setup wizard. After installing the plugin, ask Codex:

```text
打开企业微信配置向导
```

The wizard opens a local browser page on `127.0.0.1` and writes the account file for you.

Manual configuration is also supported:

```bash
mkdir -p ~/.wecom-codex-usage
cp ./config/config.example.json ~/.wecom-codex-usage/config.json
```

Then edit `~/.wecom-codex-usage/config.json`.

You can also point the plugin at another file:

```bash
export WECOM_CODEX_USAGE_CONFIG=/absolute/path/to/config.json
```

Or configure one account directly with environment variables:

```bash
export WECOM_ACCOUNT_NAME=work
export WECOM_CORP_ID=ww0000000000000000
export WECOM_CORP_SECRET=your-secret
export WECOM_AGENT_ID=1000002
export WECOM_DEFAULT_TO_USER=@all
```

## Codex Usage Notes

`wecom_codex_usage_get_codex_usage` reads local evidence only:

- `~/.codex/config.toml` for configured status-line fields such as `five-hour-limit`, `weekly-limit`, `used-tokens`, `total-input-tokens`, and `total-output-tokens`.
- `~/.codex/log/codex-tui.log` for recent `codex.turn.token_usage.*` telemetry lines and usage-limit errors.

It does not scrape the ChatGPT/Codex profile page and does not depend on an undocumented hosted account-usage API. If the official profile page exposes more quota data than local logs do, this plugin reports that as unavailable instead of fabricating a value.

## Local MCP Test

Run the server directly:

```bash
python3 ./src/wecom_codex_usage_mcp.py
```

Then send JSON-RPC messages over stdin:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual","version":"0.0.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wecom_codex_usage_get_codex_usage","arguments":{}}}
```

## Security Notes

- Do not commit real WeCom credentials.
- Enter `corp_secret` through the local setup wizard or local config file, not chat.
- Keep `dry_run` enabled until the recipient and message content are confirmed.
- Treat `@all` as a broadcast target.

## Windows Notes

The checked-in `.mcp.json` uses `python3`, which works on macOS and many developer machines. For Windows, change the command to `py` or to the absolute path of a Python executable if needed:

```json
{
  "mcpServers": {
    "wecom-codex-usage": {
      "command": "py",
      "args": ["-3", "./src/wecom_codex_usage_mcp.py"],
      "cwd": "."
    }
  }
}
```
