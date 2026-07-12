#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import os
import pathlib
import random
import re
import secrets
import string
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable


SERVER_NAME = "wecom-codex-usage"
SERVER_VERSION = "0.1.0"
DEFAULT_PROTOCOL_VERSION = "2025-06-18"
DEFAULT_CONFIG_PATH = pathlib.Path.home() / ".wecom-codex-usage" / "config.json"
DEFAULT_CODEX_HOME = pathlib.Path.home() / ".codex"
DEFAULT_SETUP_TTL_SECONDS = 900
WECOM_API_BASE = "https://qyapi.weixin.qq.com/cgi-bin"

ACCESS_TOKEN_CACHE: dict[str, dict[str, Any]] = {}
SETUP_SERVERS: dict[str, dict[str, Any]] = {}


class ToolError(Exception):
    pass


def eprint(message: str) -> None:
    print(f"[{SERVER_NAME}] {message}", file=sys.stderr, flush=True)


def env_first(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def expand_path(value: str | None) -> pathlib.Path | None:
    if not value:
        return None
    return pathlib.Path(value).expanduser()


def config_path() -> pathlib.Path:
    return expand_path(env_first("WECOM_CODEX_USAGE_CONFIG")) or DEFAULT_CONFIG_PATH


def load_raw_accounts() -> tuple[list[dict[str, Any]], str | None]:
    env_corp_id = env_first("WECOM_CORP_ID", "WECOM_CODEX_USAGE_CORP_ID")
    env_secret = env_first("WECOM_CORP_SECRET", "WECOM_CODEX_USAGE_CORP_SECRET")
    env_agent_id = env_first("WECOM_AGENT_ID", "WECOM_CODEX_USAGE_AGENT_ID")
    if env_corp_id and env_secret and env_agent_id:
        return (
            [
                {
                    "name": env_first("WECOM_ACCOUNT_NAME", "WECOM_CODEX_USAGE_ACCOUNT_NAME") or "default",
                    "corp_id": env_corp_id,
                    "corp_secret": env_secret,
                    "agent_id": env_agent_id,
                    "default_to_user": env_first("WECOM_DEFAULT_TO_USER"),
                    "default_to_party": env_first("WECOM_DEFAULT_TO_PARTY"),
                    "default_to_tag": env_first("WECOM_DEFAULT_TO_TAG"),
                }
            ],
            "environment",
        )

    path = config_path()
    if not path.exists():
        return [], str(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ToolError(f"Invalid JSON config at {path}: {exc}") from exc
    if isinstance(payload, dict) and isinstance(payload.get("accounts"), list):
        return [item for item in payload["accounts"] if isinstance(item, dict)], str(path)
    if isinstance(payload, dict):
        return [payload], str(path)
    raise ToolError(f"Config at {path} must be a JSON object or an object with accounts[].")


def normalize_account(raw: dict[str, Any]) -> dict[str, Any]:
    name = str(raw.get("name") or "default")
    corp_id = raw.get("corp_id") or raw.get("corpId") or raw.get("corpid")
    corp_secret = raw.get("corp_secret") or raw.get("corpSecret") or raw.get("secret")
    agent_id = raw.get("agent_id") or raw.get("agentId") or raw.get("agentid")
    if not corp_id:
        raise ToolError(f"Account {name} is missing corp_id.")
    if not corp_secret:
        raise ToolError(f"Account {name} is missing corp_secret.")
    if agent_id in (None, ""):
        raise ToolError(f"Account {name} is missing agent_id.")
    try:
        parsed_agent_id = int(agent_id)
    except (TypeError, ValueError) as exc:
        raise ToolError(f"Account {name} agent_id must be numeric.") from exc
    return {
        "name": name,
        "corp_id": str(corp_id),
        "corp_secret": str(corp_secret),
        "agent_id": parsed_agent_id,
        "default_to_user": raw.get("default_to_user") or raw.get("defaultToUser"),
        "default_to_party": raw.get("default_to_party") or raw.get("defaultToParty"),
        "default_to_tag": raw.get("default_to_tag") or raw.get("defaultToTag"),
    }


def load_accounts() -> tuple[list[dict[str, Any]], str | None]:
    raw_accounts, source = load_raw_accounts()
    accounts = []
    names: set[str] = set()
    for raw in raw_accounts:
        account = normalize_account(raw)
        if account["name"] in names:
            raise ToolError(f"Duplicate account name: {account['name']}")
        names.add(account["name"])
        accounts.append(account)
    return accounts, source


def resolve_account(name: str | None = None) -> dict[str, Any]:
    accounts, _ = load_accounts()
    if not accounts:
        raise ToolError(
            "No WeCom accounts configured. Use wecom_codex_usage_start_setup or create "
            "~/.wecom-codex-usage/config.json."
        )
    if name:
        for account in accounts:
            if account["name"] == name:
                return account
        raise ToolError(f"Unknown account: {name}")
    if len(accounts) == 1:
        return accounts[0]
    available = ", ".join(account["name"] for account in accounts)
    raise ToolError(f"Multiple accounts configured. Specify account. Available accounts: {available}")


def redacted_account(account: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": account["name"],
        "corp_id": redact_middle(account["corp_id"]),
        "agent_id": account["agent_id"],
        "has_corp_secret": bool(account.get("corp_secret")),
        "default_to_user": account.get("default_to_user"),
        "default_to_party": account.get("default_to_party"),
        "default_to_tag": account.get("default_to_tag"),
    }


def redact_middle(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def save_raw_account(raw_account: dict[str, Any]) -> pathlib.Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    accounts: list[dict[str, Any]] = []
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("accounts"), list):
            accounts = [item for item in payload["accounts"] if isinstance(item, dict)]
        elif isinstance(payload, dict):
            accounts = [payload]
        else:
            raise ToolError(f"Config at {path} must be a JSON object.")
    replaced = False
    for index, existing in enumerate(accounts):
        if existing.get("name") == raw_account["name"]:
            accounts[index] = raw_account
            replaced = True
            break
    if not replaced:
        accounts.append(raw_account)
    path.write_text(json.dumps({"accounts": accounts}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def http_json(url: str, payload: dict[str, Any] | None = None, timeout: int = 20) -> dict[str, Any]:
    data = None
    headers = {"User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if payload is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ToolError(f"WeCom HTTP {exc.code}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise ToolError(f"WeCom network error: {exc}") from exc
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ToolError(f"WeCom returned non-JSON response: {body[:500]}") from exc
    if not isinstance(parsed, dict):
        raise ToolError("WeCom returned an unexpected JSON shape.")
    return parsed


def get_access_token(account: dict[str, Any]) -> dict[str, Any]:
    cache_key = f"{account['name']}:{account['corp_id']}:{hash(account['corp_secret'])}"
    cached = ACCESS_TOKEN_CACHE.get(cache_key)
    now = int(time.time())
    if cached and cached.get("expires_at", 0) - 60 > now:
        return cached

    query = urllib.parse.urlencode({"corpid": account["corp_id"], "corpsecret": account["corp_secret"]})
    url = f"{WECOM_API_BASE}/gettoken?{query}"
    payload = http_json(url)
    if payload.get("errcode") != 0:
        raise ToolError(f"WeCom gettoken failed: {payload.get('errcode')} {payload.get('errmsg')}")
    token = payload.get("access_token")
    if not token:
        raise ToolError("WeCom gettoken succeeded but no access_token was returned.")
    expires_in = int(payload.get("expires_in") or 7200)
    cached = {"access_token": token, "expires_at": now + expires_in, "expires_in": expires_in}
    ACCESS_TOKEN_CACHE[cache_key] = cached
    return cached


def list_accounts(_: dict[str, Any]) -> dict[str, Any]:
    accounts, source = load_accounts()
    return {"ok": True, "source": source, "accounts": [redacted_account(account) for account in accounts]}


def test_connection(arguments: dict[str, Any]) -> dict[str, Any]:
    account = resolve_account(arguments.get("account"))
    token = get_access_token(account)
    return {
        "ok": True,
        "account": account["name"],
        "corp_id": redact_middle(account["corp_id"]),
        "agent_id": account["agent_id"],
        "access_token_obtained": True,
        "expires_at": token["expires_at"],
    }


def target_value(arguments: dict[str, Any], account: dict[str, Any], arg_name: str, default_name: str) -> str | None:
    value = arguments.get(arg_name)
    if value in (None, ""):
        value = account.get(default_name)
    if isinstance(value, list):
        return "|".join(str(item) for item in value if str(item))
    if value in (None, ""):
        return None
    return str(value)


def send_message_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    content = arguments.get("content")
    if not content:
        raise ToolError("content is required.")
    account = resolve_account(arguments.get("account"))
    msgtype = str(arguments.get("msgtype") or "text").lower()
    if msgtype not in {"text", "markdown"}:
        raise ToolError("msgtype must be text or markdown.")
    touser = target_value(arguments, account, "to_user", "default_to_user")
    toparty = target_value(arguments, account, "to_party", "default_to_party")
    totag = target_value(arguments, account, "to_tag", "default_to_tag")
    if not (touser or toparty or totag):
        raise ToolError("A recipient is required: to_user, to_party, to_tag, or a configured default target.")

    dry_run = bool(arguments.get("dry_run", True))
    message: dict[str, Any] = {
        "touser": touser or "",
        "toparty": toparty or "",
        "totag": totag or "",
        "msgtype": msgtype,
        "agentid": account["agent_id"],
        "safe": 1 if arguments.get("safe") else 0,
        "enable_id_trans": 1 if arguments.get("enable_id_trans") else 0,
        "enable_duplicate_check": 1 if arguments.get("enable_duplicate_check") else 0,
    }
    if msgtype == "text":
        message["text"] = {"content": str(content)}
    else:
        message["markdown"] = {"content": str(content)}

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "account": account["name"],
            "target": {"touser": touser, "toparty": toparty, "totag": totag},
            "message": redact_empty_targets(message),
        }

    token = get_access_token(account)
    query = urllib.parse.urlencode({"access_token": token["access_token"]})
    response_payload = http_json(f"{WECOM_API_BASE}/message/send?{query}", message)
    ok = response_payload.get("errcode") == 0
    return {
        "ok": ok,
        "dry_run": False,
        "account": account["name"],
        "target": {"touser": touser, "toparty": toparty, "totag": totag},
        "wecom": response_payload,
    }


def redact_empty_targets(message: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in message.items() if value not in ("", None)}


def codex_home(arguments: dict[str, Any]) -> pathlib.Path:
    return expand_path(arguments.get("codex_home") or env_first("CODEX_HOME")) or DEFAULT_CODEX_HOME


def read_tail(path: pathlib.Path, max_bytes: int) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - max_bytes), os.SEEK_SET)
        data = handle.read()
    return data.decode("utf-8", errors="replace")


def parse_status_line(config_path_value: pathlib.Path) -> list[str]:
    if not config_path_value.exists():
        return []
    text = config_path_value.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"(?m)^\s*status_line\s*=\s*\[(.*?)\]", text, re.S)
    if not match:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def parse_token_usage_lines(log_text: str, max_turns: int) -> dict[str, Any]:
    metric_pattern = re.compile(r"codex\.turn\.token_usage\.([a-z_]+)=([0-9]+)")
    model_pattern = re.compile(r"\bmodel=([^\s}:]+)")
    thread_pattern = re.compile(r"\bthread\.id=([0-9a-f-]+)")
    timestamp_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^\s]+)")
    aggregate = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "non_cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
        "total_tokens": 0,
    }
    by_model: dict[str, dict[str, int]] = {}
    turns: list[dict[str, Any]] = []

    for line in log_text.splitlines():
        pairs = metric_pattern.findall(line)
        if not pairs:
            continue
        metrics = {key: int(value) for key, value in pairs}
        model_match = model_pattern.search(line)
        thread_match = thread_pattern.search(line)
        timestamp_match = timestamp_pattern.search(line)
        model = model_match.group(1) if model_match else "unknown"
        entry = {
            "timestamp": timestamp_match.group(1) if timestamp_match else None,
            "model": model,
            "thread_id": thread_match.group(1) if thread_match else None,
            "metrics": metrics,
        }
        turns.append(entry)
        if len(turns) > max_turns:
            turns.pop(0)
        model_totals = by_model.setdefault(model, {"turns": 0, "total_tokens": 0, "input_tokens": 0, "output_tokens": 0})
        model_totals["turns"] += 1
        for key in aggregate:
            value = int(metrics.get(key) or 0)
            aggregate[key] += value
            if key in model_totals:
                model_totals[key] += value

    return {
        "turn_count_in_scanned_log": sum(model_info["turns"] for model_info in by_model.values()),
        "aggregate": aggregate,
        "by_model": by_model,
        "latest_turns": turns,
    }


def parse_usage_limit_errors(log_text: str, limit: int = 5) -> list[dict[str, Any]]:
    errors = []
    timestamp_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^\s]+)")
    for line in log_text.splitlines():
        if "You've hit your usage limit" not in line:
            continue
        timestamp_match = timestamp_pattern.search(line)
        message = line.split("Turn error:", 1)[-1].strip()
        errors.append({"timestamp": timestamp_match.group(1) if timestamp_match else None, "message": message[:500]})
    return errors[-limit:]


def get_codex_usage(arguments: dict[str, Any]) -> dict[str, Any]:
    home = codex_home(arguments)
    max_log_bytes = int(arguments.get("max_log_bytes") or 8_000_000)
    max_turns = int(arguments.get("max_turns") or 20)
    config_file = home / "config.toml"
    log_file = home / "log" / "codex-tui.log"
    log_text = read_tail(log_file, max_log_bytes)
    token_usage = parse_token_usage_lines(log_text, max_turns=max_turns)
    usage_limit_errors = parse_usage_limit_errors(log_text)
    status_line = parse_status_line(config_file)
    quota_fields = [
        field
        for field in status_line
        if field in {"five-hour-limit", "weekly-limit", "used-tokens", "total-input-tokens", "total-output-tokens"}
    ]
    return {
        "ok": True,
        "source": {
            "codex_home": str(home),
            "config": str(config_file),
            "log": str(log_file),
            "max_log_bytes": max_log_bytes,
        },
        "status_line_fields": status_line,
        "configured_usage_fields": quota_fields,
        "token_usage_from_recent_log": token_usage,
        "usage_limit_errors": usage_limit_errors,
        "official_profile_usage": {
            "available": False,
            "reason": "No stable local or documented account-usage API was found. Profile-page quota values may exist in the UI, but this tool only reports local evidence.",
        },
    }


def build_usage_report(arguments: dict[str, Any]) -> dict[str, Any]:
    usage = get_codex_usage(arguments)
    aggregate = usage["token_usage_from_recent_log"]["aggregate"]
    lines = [
        "Codex local usage summary",
        f"- Source: {usage['source']['log']}",
        f"- Scanned turns: {usage['token_usage_from_recent_log']['turn_count_in_scanned_log']}",
        f"- Total tokens in scanned log: {aggregate['total_tokens']}",
        f"- Input tokens: {aggregate['input_tokens']} (cached: {aggregate['cached_input_tokens']}, non-cached: {aggregate['non_cached_input_tokens']})",
        f"- Output tokens: {aggregate['output_tokens']} (reasoning: {aggregate['reasoning_output_tokens']})",
        f"- Configured status fields: {', '.join(usage['configured_usage_fields']) or 'none'}",
        "- Official profile quota: unavailable from local stable API",
    ]
    if usage["usage_limit_errors"]:
        latest = usage["usage_limit_errors"][-1]
        lines.append(f"- Latest usage-limit error: {latest.get('timestamp')} {latest.get('message')}")
    return {"ok": True, "usage": usage, "text": "\n".join(lines)}


def start_setup(arguments: dict[str, Any]) -> dict[str, Any]:
    ttl_seconds = int(arguments.get("ttl_seconds") or DEFAULT_SETUP_TTL_SECONDS)
    token = secrets.token_urlsafe(18)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_setup_handler(token, ttl_seconds))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, name=f"{SERVER_NAME}-setup", daemon=True)
    thread.start()
    expires_at = int(time.time()) + ttl_seconds
    SETUP_SERVERS[token] = {"server": server, "expires_at": expires_at}
    return {
        "ok": True,
        "url": f"http://127.0.0.1:{port}/setup/{token}",
        "expires_at": expires_at,
        "config_path": str(config_path()),
    }


def make_setup_handler(token: str, ttl_seconds: int) -> type[BaseHTTPRequestHandler]:
    class SetupHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            eprint(format % args)

        def do_GET(self) -> None:
            if not self.valid_path():
                self.send_error(404)
                return
            self.send_html(setup_html())

        def do_POST(self) -> None:
            if not self.valid_path():
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(length).decode("utf-8")
            fields = urllib.parse.parse_qs(body, keep_blank_values=True)
            raw_account = {
                "name": one(fields, "name") or "work",
                "corp_id": one(fields, "corp_id"),
                "corp_secret": one(fields, "corp_secret"),
                "agent_id": one(fields, "agent_id"),
                "default_to_user": one(fields, "default_to_user"),
                "default_to_party": one(fields, "default_to_party"),
                "default_to_tag": one(fields, "default_to_tag"),
            }
            try:
                normalize_account(raw_account)
                path = save_raw_account(raw_account)
                self.send_html(success_html(path))
            except Exception as exc:
                self.send_html(error_html(str(exc)), status=400)

        def valid_path(self) -> bool:
            state = SETUP_SERVERS.get(token)
            if not state or state["expires_at"] < int(time.time()):
                return False
            return self.path.split("?", 1)[0] == f"/setup/{token}"

        def send_html(self, content: str, status: int = 200) -> None:
            data = content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return SetupHandler


def one(fields: dict[str, list[str]], name: str) -> str:
    values = fields.get(name) or [""]
    return values[0].strip()


def setup_html() -> str:
    account_suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(4))
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>企业微信配置向导</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 40px; color: #202124; }}
    main {{ max-width: 720px; }}
    label {{ display: block; margin: 16px 0 6px; font-weight: 650; }}
    input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #c7c7c7; border-radius: 6px; }}
    button {{ margin-top: 22px; padding: 10px 16px; border: 0; border-radius: 6px; color: white; background: #1AAD19; font-weight: 700; cursor: pointer; }}
    p {{ line-height: 1.55; }}
  </style>
</head>
<body>
<main>
  <h1>企业微信配置向导</h1>
  <p>配置企业微信自建应用。凭据只会写入本机 <code>{html.escape(str(config_path()))}</code>。</p>
  <form method="post">
    <label>账户名称</label>
    <input name="name" value="work-{account_suffix}" required>
    <label>Corp ID</label>
    <input name="corp_id" placeholder="ww..." required>
    <label>应用 Secret</label>
    <input name="corp_secret" type="password" autocomplete="off" required>
    <label>Agent ID</label>
    <input name="agent_id" inputmode="numeric" required>
    <label>默认接收成员 ID（可选，例如 @all 或 user1|user2）</label>
    <input name="default_to_user" placeholder="@all">
    <label>默认接收部门 ID（可选，例如 1|2）</label>
    <input name="default_to_party">
    <label>默认接收标签 ID（可选）</label>
    <input name="default_to_tag">
    <button type="submit">保存配置</button>
  </form>
</main>
</body>
</html>"""


def success_html(path: pathlib.Path) -> str:
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>已保存</title></head>
<body><h1>已保存企业微信配置</h1><p>配置已写入 <code>{html.escape(str(path))}</code>。可以回到 Codex 测试连接。</p></body></html>"""


def error_html(message: str) -> str:
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>保存失败</title></head>
<body><h1>保存失败</h1><p>{html.escape(message)}</p><p>返回上一页修正后重试。</p></body></html>"""


def run_setup_wizard_cli() -> None:
    result = start_setup({})
    print(result["url"], flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps({"ok": False, "error": message}, ensure_ascii=False)}], "isError": True}


def tool_result(data: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}]}


TOOLS: dict[str, dict[str, Any]] = {
    "wecom_codex_usage_start_setup": {
        "description": "Start a local setup wizard for WeCom app credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {"ttl_seconds": {"type": "integer", "default": DEFAULT_SETUP_TTL_SECONDS}},
            "additionalProperties": False,
        },
        "handler": start_setup,
    },
    "wecom_codex_usage_list_accounts": {
        "description": "List configured WeCom accounts without exposing secrets.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": list_accounts,
    },
    "wecom_codex_usage_test_connection": {
        "description": "Fetch a WeCom access token to validate a configured account.",
        "inputSchema": {
            "type": "object",
            "properties": {"account": {"type": "string"}},
            "additionalProperties": False,
        },
        "handler": test_connection,
    },
    "wecom_codex_usage_send_message": {
        "description": "Send or preview a WeCom application text/markdown message. dry_run defaults to true.",
        "inputSchema": {
            "type": "object",
            "required": ["content"],
            "properties": {
                "account": {"type": "string"},
                "content": {"type": "string"},
                "msgtype": {"type": "string", "enum": ["text", "markdown"], "default": "text"},
                "to_user": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
                "to_party": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
                "to_tag": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
                "safe": {"type": "boolean", "default": False},
                "enable_id_trans": {"type": "boolean", "default": False},
                "enable_duplicate_check": {"type": "boolean", "default": False},
                "dry_run": {"type": "boolean", "default": True},
            },
            "additionalProperties": False,
        },
        "handler": send_message_tool,
    },
    "wecom_codex_usage_get_codex_usage": {
        "description": "Summarize local Codex token usage signals from config and recent logs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "codex_home": {"type": "string"},
                "max_log_bytes": {"type": "integer", "default": 8000000},
                "max_turns": {"type": "integer", "default": 20},
            },
            "additionalProperties": False,
        },
        "handler": get_codex_usage,
    },
    "wecom_codex_usage_build_usage_report": {
        "description": "Build a short text report from local Codex usage signals.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "codex_home": {"type": "string"},
                "max_log_bytes": {"type": "integer", "default": 8000000},
                "max_turns": {"type": "integer", "default": 20},
            },
            "additionalProperties": False,
        },
        "handler": build_usage_report,
    },
}


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if request_id is None:
        return None
    try:
        if method == "initialize":
            protocol_version = params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION
            return response(
                request_id,
                {
                    "protocolVersion": protocol_version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            )
        if method == "ping":
            return response(request_id, {})
        if method == "tools/list":
            return response(
                request_id,
                {
                    "tools": [
                        {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}
                        for name, spec in TOOLS.items()
                    ]
                },
            )
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if tool_name not in TOOLS:
                raise ToolError(f"Unknown tool: {tool_name}")
            handler: Callable[[dict[str, Any]], dict[str, Any]] = TOOLS[tool_name]["handler"]
            return response(request_id, tool_result(handler(arguments)))
        return error_response(request_id, -32601, f"Method not found: {method}")
    except ToolError as exc:
        return response(request_id, error_result(str(exc)))
    except Exception as exc:
        eprint(traceback.format_exc())
        return response(request_id, error_result(f"Unexpected {type(exc).__name__}: {exc}"))


def response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def send_json(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_stdio_server() -> None:
    eprint("MCP stdio server started")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            send_json(error_response(None, -32700, f"Parse error: {exc}"))
            continue
        result = handle_request(message)
        if result is not None:
            send_json(result)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        run_setup_wizard_cli()
    else:
        run_stdio_server()
