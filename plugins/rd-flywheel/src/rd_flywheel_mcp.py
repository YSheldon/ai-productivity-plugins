from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

_SOURCE_ROOT = Path(__file__).resolve().parent
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from rd_flywheel_adapters import AdapterError, load_runtime_adapters
from rd_flywheel_config import (
    ConfigError,
    default_config_path,
    load_config,
    reject_per_call_config_override,
)
from rd_flywheel_controller import ControllerError, RDFlywheelController
from rd_flywheel_protocol import ProtocolError, STATES
from rd_flywheel_scheduler import RDFlywheelScheduler, SchedulerError
from rd_flywheel_setup import SetupError, run_setup_operation
from rd_flywheel_store import AuditTamperError, StoreError


SERVER_NAME = "rd-flywheel"
SERVER_VERSION = "0.2.1"
PROTOCOL_VERSION = "2025-06-18"


def _default_controller_factory(config_path: Path) -> RDFlywheelController:
    config = load_config(config_path)
    agents, verifiers = load_runtime_adapters(config)
    return RDFlywheelController(
        config,
        agent_adapters=agents,
        evidence_verifiers=verifiers,
    )


def _default_scheduler_factory(config_path: Path) -> RDFlywheelScheduler:
    config = load_config(config_path)
    return RDFlywheelScheduler(
        config_path=config_path,
        cli_path=Path(__file__).with_name("rd_flywheel_cli.py"),
        state_dir=config.state_dir,
        poll_minutes=config.poll_minutes,
    )


_controller_factory: Callable[[Path], Any] = _default_controller_factory
_scheduler_factory: Callable[[Path], Any] = _default_scheduler_factory
_setup_runner: Callable[..., Mapping[str, Any]] = run_setup_operation


def _object_schema(
    properties: Mapping[str, Any] | None = None,
    *,
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": dict(properties or {}),
        "required": list(required or []),
    }


TOOLS: dict[str, dict[str, Any]] = {
    "rd_flywheel_setup": {
        "description": "Create or reuse the single credential-free runtime config and activate scheduling.",
        "inputSchema": _object_schema(
            {
                "non_interactive": {"type": "boolean", "default": False},
                "governance_inbox": {"type": "string"},
                "state_dir": {"type": "string"},
                "agent_profile": {"type": "string"},
                "scheduler_mode": {
                    "type": "string",
                    "enum": ["auto", "windows", "systemd", "cron"],
                    "default": "auto",
                },
            }
        ),
    },
    "rd_flywheel_preflight": {
        "description": "Verify configuration, audit integrity, tool profiles, and agent availability.",
        "inputSchema": _object_schema(),
    },
    "rd_flywheel_run_once": {
        "description": "Run one headless, kernel-locked capability-gap scan.",
        "inputSchema": _object_schema(),
    },
    "rd_flywheel_status": {
        "description": "Return durable event and audit status.",
        "inputSchema": _object_schema(),
    },
    "rd_flywheel_doctor": {
        "description": "Diagnose runtime readiness without granting authority.",
        "inputSchema": _object_schema(),
    },
    "rd_flywheel_list_events": {
        "description": "List capability-gap events, optionally filtered by state.",
        "inputSchema": _object_schema(
            {"state": {"type": "string", "enum": list(STATES)}}
        ),
    },
    "rd_flywheel_get_event": {
        "description": "Read one event, its immutable checkpoint, evidence, and transitions.",
        "inputSchema": _object_schema(
            {"idempotency_key": {"type": "string"}},
            required=["idempotency_key"],
        ),
    },
    "rd_flywheel_retry_event": {
        "description": "Retry the same frozen blocked event after capability becomes available.",
        "inputSchema": _object_schema(
            {"idempotency_key": {"type": "string"}},
            required=["idempotency_key"],
        ),
    },
    "rd_flywheel_verify_audit": {
        "description": "Verify the SQLite append-only audit hash chain.",
        "inputSchema": _object_schema(),
    },
    "rd_flywheel_scheduler": {
        "description": "Install, inspect, or remove the OS scheduler entry.",
        "inputSchema": _object_schema(
            {
                "action": {
                    "type": "string",
                    "enum": ["install", "status", "remove"],
                },
                "mode": {
                    "type": "string",
                    "enum": ["auto", "windows", "systemd", "cron"],
                    "default": "auto",
                },
            },
            required=["action"],
        ),
    },
}


def handle_tool_call(
    name: str,
    arguments: Mapping[str, Any] | None,
    *,
    config_path: str | Path | None = None,
    controller_factory: Callable[[Path], Any] | None = None,
    setup_runner: Callable[..., Mapping[str, Any]] | None = None,
    scheduler_factory: Callable[[Path], Any] | None = None,
) -> Mapping[str, Any]:
    if name not in TOOLS:
        raise ProtocolError(f"unknown tool: {name}")
    args = dict(reject_per_call_config_override(arguments))
    path = Path(config_path or default_config_path()).expanduser().resolve(strict=False)
    make_controller = controller_factory or _controller_factory
    run_setup = setup_runner or _setup_runner
    make_scheduler = scheduler_factory or _scheduler_factory

    if name == "rd_flywheel_setup":
        return run_setup(
            config_path=path,
            non_interactive=bool(args.get("non_interactive", False)),
            governance_inbox=args.get("governance_inbox"),
            state_dir=args.get("state_dir"),
            agent_profile=args.get("agent_profile"),
            scheduler_mode=str(args.get("scheduler_mode") or "auto"),
        )
    if name == "rd_flywheel_scheduler":
        action = str(args.get("action") or "")
        if action not in {"install", "status", "remove"}:
            raise ProtocolError("scheduler action must be install, status, or remove.")
        scheduler = make_scheduler(path)
        return getattr(scheduler, action)(mode=str(args.get("mode") or "auto"))

    controller = make_controller(path)
    if name == "rd_flywheel_preflight":
        return controller.preflight()
    if name == "rd_flywheel_run_once":
        return controller.run_once()
    if name == "rd_flywheel_status":
        return controller.status()
    if name == "rd_flywheel_doctor":
        return controller.doctor()
    if name == "rd_flywheel_list_events":
        return controller.list_events(state=args.get("state"))
    if name == "rd_flywheel_get_event":
        return controller.get_event(_required_argument(args, "idempotency_key"))
    if name == "rd_flywheel_retry_event":
        return controller.retry_event(_required_argument(args, "idempotency_key"))
    if name == "rd_flywheel_verify_audit":
        return controller.verify_audit()
    raise ProtocolError(f"unhandled tool: {name}")


def _required_argument(arguments: Mapping[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(f"{key} is required.")
    return value.strip()


def _tool_result(payload: Mapping[str, Any], *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
        ],
        "structuredContent": dict(payload),
        "isError": is_error,
    }


def _domain_error(exc: Exception) -> dict[str, Any]:
    code = str(getattr(exc, "code", type(exc).__name__.upper()))
    return {
        "status": "error",
        "error": {"code": code, "message": str(exc)},
    }


def handle_request(message: Mapping[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None and method != "initialize":
        return None
    if method == "initialize":
        params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
        return _response(
            request_id,
            {
                "protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    if method == "ping":
        return _response(request_id, {})
    if method == "tools/list":
        return _response(
            request_id,
            {
                "tools": [
                    {
                        "name": name,
                        "description": spec["description"],
                        "inputSchema": spec["inputSchema"],
                    }
                    for name, spec in TOOLS.items()
                ]
            },
        )
    if method == "tools/call":
        params = message.get("params")
        if not isinstance(params, Mapping):
            return _error_response(request_id, -32602, "params must be an object")
        name = str(params.get("name") or "")
        arguments = params.get("arguments")
        if arguments is not None and not isinstance(arguments, Mapping):
            return _error_response(request_id, -32602, "arguments must be an object")
        try:
            payload = handle_tool_call(name, arguments)
            return _response(request_id, _tool_result(payload))
        except (
            ConfigError,
            SetupError,
            SchedulerError,
            AdapterError,
            ProtocolError,
            StoreError,
            AuditTamperError,
            ControllerError,
        ) as exc:
            return _response(request_id, _tool_result(_domain_error(exc), is_error=True))
        except Exception as exc:
            return _response(
                request_id,
                _tool_result(
                    {
                        "status": "error",
                        "error": {
                            "code": "INTERNAL_ERROR",
                            "message": f"{type(exc).__name__}: {exc}",
                        },
                    },
                    is_error=True,
                ),
            )
    return _error_response(request_id, -32601, f"method not found: {method}")


def _response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def run_stdio_server() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            if not isinstance(message, Mapping):
                raise ValueError("JSON-RPC message must be an object")
            result = handle_request(message)
        except Exception as exc:
            result = _error_response(None, -32700, f"parse error: {exc}")
        if result is not None:
            sys.stdout.write(
                json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()
