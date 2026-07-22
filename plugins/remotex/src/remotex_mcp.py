from __future__ import annotations

import json
import sys
import traceback
from typing import Any, Callable

import rdp_adapter
import remotex_core as core
import ssh_adapter
import vmware_adapter
import vsphere_adapter


SERVER_NAME = "remotex"
SERVER_VERSION = "0.1.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

STATUS_HANDLERS: dict[str, Callable[[str, dict[str, Any]], dict[str, Any]]] = {
    "ssh": ssh_adapter.profile_status,
    "rdp": rdp_adapter.profile_status,
    "vsphere": vsphere_adapter.profile_status,
    "vmware-workstation": vmware_adapter.profile_status,
}


def status(_: dict[str, Any]) -> dict[str, Any]:
    bundle = core.load_config()
    profiles: list[dict[str, Any]] = []
    for name, raw in sorted(bundle.data["profiles"].items()):
        try:
            kind = core.normalize_kind(raw.get("kind"))
            handler = STATUS_HANDLERS[kind]
            profiles.append(handler(name, raw))
        except core.ToolError as exc:
            profiles.append(
                {
                    "profile": name,
                    "kind": str(raw.get("kind") or "unknown"),
                    "ready": False,
                    "errors": [str(exc)],
                }
            )
    ready_count = sum(1 for profile in profiles if profile.get("ready"))
    result = {
        "ok": bool(profiles) and ready_count == len(profiles),
        "config": {
            "path": str(bundle.path),
            "source": bundle.source,
            "exists": bundle.exists,
            "legacy_ssh_compatibility": bundle.source == "legacy-ssh",
        },
        "defaults": bundle.data["defaults"],
        "profiles": profiles,
        "summary": {
            "configured": len(profiles),
            "ready": ready_count,
            "not_ready": len(profiles) - ready_count,
        },
    }
    if not profiles:
        result["next_step"] = (
            f"Create {bundle.path} from plugins/remotex/config/config.example.json. "
            "Store only credential references in the file; RemoteX does not accept literal secrets."
        )
    elif bundle.source == "legacy-ssh":
        result["next_step"] = (
            "Legacy SSH profiles are active. Copy them into the RemoteX v1 format when adding "
            "RDP, vSphere/ESXi, or VMware Workstation profiles."
        )
    return core.tool_result(result)


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_status": {
        "description": (
            "List RemoteX profiles, client availability, and credential-reference readiness "
            "without exposing credentials or opening a connection."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": status,
    },
    **ssh_adapter.TOOLS,
    **rdp_adapter.TOOLS,
    **vsphere_adapter.TOOLS,
    **vmware_adapter.TOOLS,
}


def response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if request_id is None:
        return None
    if not isinstance(params, dict):
        return error_response(request_id, -32602, "params must be an object")
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
            tools = [
                {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}
                for name, spec in TOOLS.items()
            ]
            return response(request_id, {"tools": tools})
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise core.ToolError("tool arguments must be an object")
            if tool_name not in TOOLS:
                raise core.ToolError(f"Unknown tool: {tool_name}")
            handler: Callable[[dict[str, Any]], dict[str, Any]] = TOOLS[tool_name]["handler"]
            return response(request_id, handler(arguments))
        return error_response(request_id, -32601, f"Method not found: {method}")
    except core.ToolError as exc:
        return response(request_id, core.error_result(str(exc)))
    except Exception as exc:
        core.eprint(traceback.format_exc())
        return response(request_id, core.error_result(f"Unexpected {type(exc).__name__}: {exc}"))


def send_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_stdio_server() -> None:
    core.eprint("RemoteX MCP stdio server started")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            send_message(error_response(None, -32700, f"Parse error: {exc}"))
            continue
        if not isinstance(message, dict):
            send_message(error_response(None, -32600, "Request must be a JSON object"))
            continue
        result = handle_request(message)
        if result is not None:
            send_message(result)


if __name__ == "__main__":
    run_stdio_server()
