from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from test_submission_core import SubmissionError, TestSubmissionController, default_config_path
from test_submission_scheduler import TestSubmissionScheduler
from test_submission_setup import run_setup_operation


SERVER_NAME = "test-submission"
SERVER_VERSION = "0.1.4"
_CONTROLLER = TestSubmissionController(default_config_path()) if default_config_path().is_file() else None


def _controller() -> TestSubmissionController:
    global _CONTROLLER
    if _CONTROLLER is None:
        _CONTROLLER = TestSubmissionController(default_config_path())
    return _CONTROLLER


def _text_result(data: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}]}


def _error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def tool_setup(args: dict[str, Any]) -> dict[str, Any]:
    result = run_setup_operation(
        config_path=default_config_path(),
        non_interactive=bool(args.get("non_interactive", False)),
        scheduler_mode=str(args.get("scheduler_mode") or "auto"),
        provided=args,
    )
    return result


def tool_scheduler_install(args: dict[str, Any]) -> dict[str, Any]:
    controller = _controller()
    return TestSubmissionScheduler(
        config_path=controller.config_path,
        state_dir=controller.state_dir,
        poll_minutes=int(controller.config.get("poll_minutes") or 60),
    ).install(mode=str(controller.config.get("scheduler_mode") or "auto"))


TOOLS = {
    "test_submission_setup": {
        "description": "Create or refresh one managed test-submission configuration and install the retry scheduler.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "non_interactive": {"type": "boolean", "default": False},
                "scheduler_mode": {"type": "string", "enum": ["auto", "windows", "systemd", "cron"], "default": "auto"},
                "submission_gate_address": {"type": "string"},
                "mail_profile": {"type": "string"},
                "mail_email": {"type": "string"},
                "feishu_directory_url": {"type": "string"}
            },
            "additionalProperties": False
        },
        "handler": tool_setup,
    },
    "test_submission_preflight": {
        "description": "Validate mail account, HMAC key, and preview gate readiness.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().preflight(),
    },
    "test_submission_submit": {
        "description": "Create one explicit local-artifact or fixed-revision SVN submission and send one signed request mail.",
        "inputSchema": {
            "type": "object",
            "required": ["task_name", "module"],
            "properties": {
                "task_name": {"type": "string"},
                "module": {"type": "string", "enum": ["kernel", "client", "server"]},
                "artifacts": {"type": "array"},
                "retrieval_method": {
                    "type": "string",
                    "enum": ["local", "unc", "https", "gitlab-package", "ssh", "svn"],
                    "default": "local",
                },
                "source_locator": {"type": "string"},
                "repository_path": {"type": "string"},
                "revision": {"type": "string"},
                "version": {"type": "string"},
                "retrieval_instructions": {"type": "string"},
            },
            "allOf": [
                {
                    "if": {
                        "properties": {"retrieval_method": {"const": "svn"}},
                        "required": ["retrieval_method"],
                    },
                    "then": {
                        "required": ["revision", "version"],
                        "anyOf": [
                            {"required": ["source_locator"]},
                            {"required": ["repository_path"]},
                        ],
                    },
                    "else": {"required": ["artifacts"]},
                }
            ],
            "additionalProperties": True,
        },
        "handler": lambda args: _controller().submit(args),
    },
    "test_submission_run_once": {
        "description": "Retry durable pending outbound submission mail.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().run_once(),
    },
    "test_submission_status": {
        "description": "Report local test-submission event and pending-mail counts.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().status(),
    },
    "test_submission_doctor": {
        "description": "Show the merged health view for test-submission configuration and dependencies.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": lambda _args: _controller().doctor(),
    },
    "test_submission_scheduler_install": {
        "description": "Install the configured retry scheduler.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": tool_scheduler_install,
    },
}


def _reply(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _handle_request(request: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}, "capabilities": {"tools": {}}}}
    if method == "tools/list":
        tools = []
        for name, metadata in TOOLS.items():
            tools.append({"name": name, "description": metadata["description"], "inputSchema": metadata["inputSchema"]})
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": tools}}
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        tool = TOOLS.get(str(name))
        if tool is None:
            raise SubmissionError("UNKNOWN_TOOL", f"unknown tool: {name}")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise SubmissionError("INVALID_ARGUMENT", "tool arguments must be an object")
        result = tool["handler"](arguments)
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": _text_result(result)}
    raise SubmissionError("UNSUPPORTED_METHOD", f"unsupported method: {method}")


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
