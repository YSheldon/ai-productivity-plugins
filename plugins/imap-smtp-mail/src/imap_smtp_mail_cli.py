#!/usr/bin/env python3
"""Locked JSON CLI bridge for selected imap-smtp-mail tools."""

from __future__ import annotations

import json
import sys
from typing import Any

import imap_smtp_mail_mcp as server

ALLOWED_TOOLS = {
    "list_accounts": "imap_smtp_mail_list_accounts",
    "test_connection": "imap_smtp_mail_test_connection",
    "search_messages": "imap_smtp_mail_search_messages",
    "read_message": "imap_smtp_mail_read_message",
    "create_draft": "imap_smtp_mail_create_draft",
    "send_email": "imap_smtp_mail_send_email",
}


def unwrap_result(result: Any) -> Any:
    if isinstance(result, dict) and "structuredContent" in result:
        return result["structuredContent"]
    return result


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print("Expected one JSON object on stdin.", file=sys.stderr)
        return 1

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON input: {exc}", file=sys.stderr)
        return 1

    if not isinstance(payload, dict):
        print("Input must be a JSON object.", file=sys.stderr)
        return 1

    tool = str(payload.get("tool") or "")
    mapped = ALLOWED_TOOLS.get(tool)
    if not mapped:
        print(f"Unsupported tool: {tool}", file=sys.stderr)
        return 2

    arguments = payload.get("arguments") or {}
    if not isinstance(arguments, dict):
        print("arguments must be a JSON object.", file=sys.stderr)
        return 1

    handler = server.TOOLS[mapped]["handler"]
    try:
        result = unwrap_result(handler(arguments))
        sys.stdout.write(json.dumps({"ok": True, "result": result}, ensure_ascii=False) + "\n")
        return 0
    except server.ToolError as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False) + "\n")
        return 1
    except Exception as exc:  # pragma: no cover - defensive CLI bridge
        sys.stdout.write(json.dumps({"ok": False, "error": f"Unexpected {type(exc).__name__}: {exc}"}, ensure_ascii=False) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
