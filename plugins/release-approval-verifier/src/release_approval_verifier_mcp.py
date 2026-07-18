from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, Mapping

_SOURCE_ROOT = Path(__file__).resolve().parent
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from verifier_config import ConfigError, default_config_path, load_config, reject_per_call_config_override
from verifier_scheduler import SchedulerError
from verifier_setup import SetupError, run_setup_operation


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "release-approval-verifier"
SERVER_VERSION = "0.2.3"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"


class VerifierMcpError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


def _controller_type():
    from verifier_controller import VerifierController

    return VerifierController


_STARTUP_CONTROLLER: Any | None = None
_STARTUP_ERROR: VerifierMcpError | None = None


def startup_controller(arguments: Mapping[str, Any] | None) -> Any:
    global _STARTUP_CONTROLLER, _STARTUP_ERROR
    reject_per_call_config_override(arguments)
    if _STARTUP_CONTROLLER is not None:
        return _STARTUP_CONTROLLER
    if _STARTUP_ERROR is not None:
        raise _STARTUP_ERROR
    config_path = default_config_path()
    try:
        controller_type = _controller_type()
        _STARTUP_CONTROLLER = controller_type(
            config=load_config(config_path),
            config_path=config_path,
        )
        return _STARTUP_CONTROLLER
    except VerifierMcpError as exc:
        _STARTUP_ERROR = exc
        raise
    except Exception as exc:
        _STARTUP_ERROR = VerifierMcpError("STARTUP_CONFIG_ERROR", str(exc))
        raise _STARTUP_ERROR from exc


def preflight(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).preflight()


def start_setup(args: dict[str, Any]) -> dict[str, Any]:
    global _STARTUP_CONTROLLER, _STARTUP_ERROR
    reject_per_call_config_override(args)
    if args.get("non_interactive", True) is not True:
        raise VerifierMcpError(
            "INVALID_ARGUMENT",
            "MCP setup is non-interactive; omit non_interactive or set it to true.",
        )
    scheduler_mode = str(args.get("scheduler_mode") or "auto").strip().lower()
    if scheduler_mode not in {"auto", "windows", "systemd", "cron", "codex"}:
        raise VerifierMcpError("INVALID_ARGUMENT", "unsupported scheduler_mode.")
    provided_keys = (
        "mail_profile",
        "release_group",
        "role_document_url",
        "audit_document_url",
        "trusted_authserv_ids",
        "state_dir",
        "product_gate_config_path",
    )
    payload = dict(
        run_setup_operation(
            config_path=default_config_path(),
            repo_root=_PLUGIN_ROOT.parents[1],
            non_interactive=True,
            scheduler_mode=scheduler_mode,
            provided={key: args.get(key) for key in provided_keys},
        )
    )
    _STARTUP_CONTROLLER = None
    _STARTUP_ERROR = None
    return payload


def run_once(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).run_once()


def status(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).status()


def doctor(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).doctor()


def _event_arguments(args: Mapping[str, Any]) -> dict[str, Any]:
    event_id = str(args.get("event_id") or "").strip()
    round_id = args.get("round_id")
    if not event_id:
        raise VerifierMcpError("INVALID_ARGUMENT", "event_id is required.")
    if not isinstance(round_id, int) or isinstance(round_id, bool) or round_id <= 0:
        raise VerifierMcpError("INVALID_ARGUMENT", "round_id must be a positive integer.")
    return {"event_id": event_id, "round_id": round_id}


def get_event(args: dict[str, Any]) -> dict[str, Any]:
    arguments = _event_arguments(args)
    return startup_controller(args).get_event(**arguments)


def list_missing_roles(args: dict[str, Any]) -> dict[str, Any]:
    arguments = _event_arguments(args)
    return startup_controller(args).list_missing_roles(**arguments)


def verify_receipt(args: dict[str, Any]) -> dict[str, Any]:
    path_text = str(args.get("path") or "").strip()
    if not path_text:
        raise VerifierMcpError("INVALID_ARGUMENT", "path is required.")
    path = Path(path_text).expanduser().resolve(strict=False)
    return startup_controller(args).verify_receipt(path=path)


def verify_audit_chain(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).verify_audit_chain()


_EMPTY_SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}
_EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "event_id": {"type": "string"},
        "round_id": {"type": "integer", "minimum": 1},
    },
    "required": ["event_id", "round_id"],
    "additionalProperties": False,
}

TOOLS: dict[str, dict[str, Any]] = {
    "release_approval_verifier_preflight": {
        "description": "Verify the locked verifier configuration, mail profile, role source, audit key, and dependency capabilities.",
        "inputSchema": _EMPTY_SCHEMA,
        "handler": preflight,
    },
    "release_approval_verifier_start_setup": {
        "description": "Cold-start the shared non-interactive verifier setup, install one OS scheduler, and run once immediately.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "non_interactive": {"type": "boolean", "const": True, "default": True},
                "scheduler_mode": {
                    "type": "string",
                    "enum": ["auto", "windows", "systemd", "cron", "codex"],
                    "default": "auto",
                },
                "mail_profile": {"type": "string"},
                "release_group": {"type": "string"},
                "role_document_url": {"type": "string"},
                "audit_document_url": {"type": "string"},
                "trusted_authserv_ids": {"type": "string", "description": "Comma-separated trusted Authentication-Results authserv-id values."},
                "state_dir": {"type": "string"},
                "product_gate_config_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "handler": start_setup,
    },
    "release_approval_verifier_run_once": {
        "description": "Headlessly ingest requests and authenticated replies, send due reminders, seal aggregate receipts, and reconcile handoff.",
        "inputSchema": _EMPTY_SCHEMA,
        "handler": run_once,
    },
    "release_approval_verifier_status": {
        "description": "Read verifier state and externally verify the unattended scheduler.",
        "inputSchema": _EMPTY_SCHEMA,
        "handler": status,
    },
    "release_approval_verifier_doctor": {
        "description": "Diagnose role, mail, signing, audit, scheduler, and product-gate handoff capabilities.",
        "inputSchema": _EMPTY_SCHEMA,
        "handler": doctor,
    },
    "release_approval_verifier_get_event": {
        "description": "Read one frozen verifier event, role decisions, receipt, and handoff state.",
        "inputSchema": _EVENT_SCHEMA,
        "handler": get_event,
    },
    "release_approval_verifier_list_missing_roles": {
        "description": "List required roles without a current valid decision for one event round.",
        "inputSchema": _EVENT_SCHEMA,
        "handler": list_missing_roles,
    },
    "release_approval_verifier_verify_receipt": {
        "description": "Verify a signed aggregate receipt, frozen bindings, expiry, and local audit chain.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "handler": verify_receipt,
    },
    "release_approval_verifier_verify_audit_chain": {
        "description": "Verify the append-only verifier audit hash chain.",
        "inputSchema": _EMPTY_SCHEMA,
        "handler": verify_audit_chain,
    },
}


def tool_result(payload: Any) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
        "structuredContent": payload,
    }


def error_result(
    code: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"ok": False, "error_code": code, "message": message}
    if details:
        payload["details"] = dict(details)
    return {
        "content": [{"type": "text", "text": message}],
        "structuredContent": payload,
        "isError": True,
    }


def response(request_id: Any, value: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if request_id is None:
        return None
    try:
        if method == "initialize":
            return response(
                request_id,
                {
                    "protocolVersion": params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION,
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
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if tool_name not in TOOLS:
                raise VerifierMcpError("UNKNOWN_TOOL", f"Unknown tool: {tool_name}")
            handler: Callable[[dict[str, Any]], dict[str, Any]] = TOOLS[tool_name]["handler"]
            return response(request_id, tool_result(handler(arguments)))
        return error_response(request_id, -32601, f"Method not found: {method}")
    except VerifierMcpError as exc:
        return response(request_id, error_result(exc.code, str(exc), details=exc.details))
    except (SetupError, SchedulerError) as exc:
        return response(request_id, error_result(exc.code, str(exc)))
    except ConfigError as exc:
        return response(request_id, error_result("CONFIG_ERROR", str(exc)))
    except Exception as exc:
        code = str(getattr(exc, "code", "") or "")
        if code:
            return response(request_id, error_result(code, str(exc)))
        print(traceback.format_exc(), file=sys.stderr)
        return response(
            request_id,
            error_result("UNEXPECTED_ERROR", f"Unexpected {type(exc).__name__}: {exc}"),
        )


def send_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_stdio_server() -> None:
    print("Release Approval Verifier MCP stdio server started", file=sys.stderr)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            send_message(error_response(None, -32700, f"Parse error: {exc}"))
            continue
        result = handle_request(message)
        if result is not None:
            send_message(result)


if __name__ == "__main__":
    run_stdio_server()
