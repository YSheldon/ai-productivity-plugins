from __future__ import annotations

import json
import sys
from typing import Any

from submission_gate_core import SubmissionGateController, SubmissionGateError, default_config_path
from submission_gate_scheduler import SubmissionGateScheduler
from submission_gate_setup import run_setup_operation


SERVER_NAME = "submission-gate"
SERVER_VERSION = "0.1.3"
_CONTROLLER = SubmissionGateController(default_config_path()) if default_config_path().is_file() else None


def _controller() -> SubmissionGateController:
    global _CONTROLLER
    if _CONTROLLER is None:
        _CONTROLLER = SubmissionGateController(default_config_path())
    return _CONTROLLER


def _text_result(data: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


TOOLS = {
    "submission_gate_setup": {
        "description": "Create or refresh one managed submission-gate configuration and install the scan scheduler.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "non_interactive": {"type": "boolean", "default": False},
                "scheduler_mode": {
                    "type": "string",
                    "enum": ["auto", "windows", "systemd", "cron"],
                    "default": "auto",
                },
                "submission_group_address": {"type": "string"},
                "blocked_notice_address": {"type": "string"},
                "mail_profile": {"type": "string"},
                "mail_email": {"type": "string"},
                "gate_adapter_command": {"type": "array", "items": {"type": "string"}},
                "gate_adapter_entrypoint": {"type": "string"},
                "gate_adapter_entrypoint_sha256": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "handler": lambda args: run_setup_operation(
            config_path=default_config_path(),
            non_interactive=bool(args.get("non_interactive", False)),
            scheduler_mode=str(args.get("scheduler_mode") or "auto"),
            provided=args,
        ),
    },
    "submission_gate_preflight": {
        "description": "Validate mailbox access and the locked GitLab gate adapter. Workflow HMAC is optional.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().preflight(),
    },
    "submission_gate_run_once": {
        "description": "Scan canonical and legacy submission mail, dispatch trusted retrieval to GitLab, and notify test only after CLEAN evidence.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().run_once(),
    },
    "submission_gate_status": {
        "description": "Report processed, blocked, retryable, and pending-mail counts.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().status(),
    },
    "submission_gate_doctor": {
        "description": "Show configuration, dependency, adapter, auth, and audit health.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().doctor(),
    },
    "submission_gate_verify_audit": {
        "description": "Verify the local append-only workflow audit chain.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().verify_audit(),
    },
    "submission_gate_scheduler_install": {
        "description": "Install the configured scan scheduler.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: SubmissionGateScheduler(
            config_path=_controller().config_path,
            state_dir=_controller().state_dir,
            poll_minutes=int(_controller().config.get("poll_minutes") or 60),
        ).install(mode=str(_controller().config.get("scheduler_mode") or "auto")),
    },
}


def _reply(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _handle_request(request: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "capabilities": {"tools": {}},
            },
        }
    if method == "tools/list":
        tools = [
            {"name": name, "description": metadata["description"], "inputSchema": metadata["inputSchema"]}
            for name, metadata in TOOLS.items()
        ]
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": tools}}
    if method == "tools/call":
        params = request.get("params") or {}
        name = str(params.get("name") or "")
        tool = TOOLS.get(name)
        if tool is None:
            raise SubmissionGateError("UNKNOWN_TOOL", f"unknown tool: {name}")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise SubmissionGateError("INVALID_ARGUMENT", "tool arguments must be an object")
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": _text_result(tool["handler"](arguments)),
        }
    raise SubmissionGateError("UNSUPPORTED_METHOD", f"unsupported method: {method}")


def main() -> int:
    for line in sys.stdin:
        raw = line.strip()
        if not raw:
            continue
        try:
            request = json.loads(raw)
            response = _handle_request(request)
        except Exception as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(exc)}}
        _reply(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
