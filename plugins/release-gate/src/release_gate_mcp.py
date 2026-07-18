from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from release_gate_cli import _default_controller_factory
from release_gate_config import default_config_path
from release_gate_controller import ReleaseGateError
from release_workflow_gate_scheduler import SchedulerError
from release_workflow_gate_setup import SetupError, run_setup_operation


SERVER_NAME = "release-gate"
SERVER_VERSION = "0.1.3"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"


class ReleaseGateMcpError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def text_result(data: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}], "structuredContent": data}


def error_result(code: str, message: str) -> dict[str, Any]:
    payload = {"ok": False, "error_code": code, "message": message}
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}], "structuredContent": payload, "isError": True}


def _active_config_path() -> Path:
    return default_config_path()


def _controller(_args: dict[str, Any]) -> Any:
    return _default_controller_factory(_active_config_path())


def start_setup(args: dict[str, Any]) -> dict[str, Any]:
    if args.get("config_path") is not None:
        raise ReleaseGateMcpError("INVALID_ARGUMENT", "config_path cannot be supplied per call; set RELEASE_GATE_CONFIG before server startup")
    if args.get("non_interactive") is False:
        raise ReleaseGateMcpError("INVALID_ARGUMENT", "setup requires non_interactive=true")
    return run_setup_operation(
        config_path=_active_config_path(),
        non_interactive=True,
        scheduler_mode=str(args.get("scheduler_mode") or "auto"),
        provided={
            "mail_profile": args.get("mail_profile"),
            "mail_email": args.get("mail_email"),
            "release_gate_group": args.get("release_gate_group"),
            "release_group": args.get("release_group"),
            "state_dir": args.get("state_dir"),
            "product_gate_config_path": args.get("product_gate_config_path"),
        },
    )


def preflight(args: dict[str, Any]) -> dict[str, Any]:
    return _controller(args).preflight()


def run_once(args: dict[str, Any]) -> dict[str, Any]:
    return _controller(args).run_once()


def workflow_status(args: dict[str, Any]) -> dict[str, Any]:
    return _controller(args).status()


def doctor(args: dict[str, Any]) -> dict[str, Any]:
    return _controller(args).doctor()


def verify_audit(args: dict[str, Any]) -> dict[str, Any]:
    return _controller(args).verify_audit()


TOOLS = {
    "release_gate_preflight": {"handler": preflight, "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    "release_gate_start_setup": {
        "handler": start_setup,
        "inputSchema": {
            "type": "object",
            "properties": {
                "non_interactive": {"type": "boolean", "const": True, "default": True},
                "scheduler_mode": {"type": "string"},
                "mail_profile": {"type": "string"},
                "mail_email": {"type": "string"},
                "release_gate_group": {"type": "string"},
                "release_group": {"type": "string"},
                "state_dir": {"type": "string"},
                "product_gate_config_path": {"type": "string"}
            },
            "additionalProperties": False,
        },
    },
    "release_gate_run_once": {"handler": run_once, "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    "release_gate_status": {"handler": workflow_status, "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    "release_gate_doctor": {"handler": doctor, "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    "release_gate_verify_audit": {"handler": verify_audit, "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
}


def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"protocolVersion": DEFAULT_PROTOCOL_VERSION, "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}, "capabilities": {"tools": {}}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": [{"name": name, "inputSchema": spec["inputSchema"]} for name, spec in TOOLS.items()]}}
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name not in TOOLS:
            return {"jsonrpc": "2.0", "id": request.get("id"), "result": error_result("INVALID_ARGUMENT", f"unknown tool: {name}")}
        try:
            payload = TOOLS[name]["handler"](dict(arguments))
            return {"jsonrpc": "2.0", "id": request.get("id"), "result": text_result(payload)}
        except (ReleaseGateMcpError, SetupError, SchedulerError, ReleaseGateError) as exc:
            code = exc.code if hasattr(exc, "code") else "UNEXPECTED_ERROR"
            return {"jsonrpc": "2.0", "id": request.get("id"), "result": error_result(str(code), str(exc))}
    return {"jsonrpc": "2.0", "id": request.get("id"), "result": error_result("INVALID_ARGUMENT", f"unsupported method: {method}")}


def main() -> int:
    while True:
        line = sys.stdin.readline()
        if not line:
            return 0
        response = handle_request(json.loads(line))
        print(json.dumps(response, ensure_ascii=False))
        sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
