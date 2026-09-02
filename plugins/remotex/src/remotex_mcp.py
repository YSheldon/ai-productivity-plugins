from __future__ import annotations

import json
import sys
import time
import traceback
from typing import Any, Callable

import audit_log
import credential_tools
import host_keys
import profile_tools
import queue_leases
import rdp_adapter
import remotex_core as core
import ssh_vnext
import task_manager
import vm_queue
import vmware_adapter
import vsphere_adapter
import windows_guest


SERVER_NAME = "remotex"
SERVER_VERSION = "0.5.1"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
queue_leases.install_hooks()


STATUS_HANDLERS: dict[str, Callable[[str, dict[str, Any]], dict[str, Any]]] = {
    "ssh": ssh_vnext.profile_status,
    "rdp": rdp_adapter.profile_status,
    "vsphere": vsphere_adapter.profile_status,
    "vmware-workstation": vmware_adapter.profile_status,
    "windows-guest": windows_guest.profile_status,
}


def _queue_status_for_profile(
    name: str,
    raw: dict[str, Any],
    kind: str,
) -> dict[str, Any] | None:
    if kind == "ssh":
        configured = raw.get("queue_resource")
        if configured in (None, ""):
            return None
        resource = vm_queue._validate_resource(configured)
        lease = queue_leases.inspect_resource(resource)
        result = vm_queue.inspect(resource)
        result["lease"] = lease or (
            queue_leases._legacy_lease_view() if result.get("owner") else None
        )
        return result
    if kind in {"rdp", "vmware-workstation", "windows-guest"}:
        target = vm_queue.resolve_profile_resource(name)
        lease = queue_leases.inspect_resource(target["resource"])
        result = vm_queue.inspect(target["resource"])
        result["lease"] = lease or (
            queue_leases._legacy_lease_view() if result.get("owner") else None
        )
        return result
    if kind == "vsphere":
        return {
            "state": "virtual-machine-required",
            "preemption_allowed": False,
            "scope": "local-cooperative",
            "prompt": "Select a virtual_machine to inspect or request its queue resource.",
        }
    return None


def status(args: dict[str, Any]) -> dict[str, Any]:
    bundle = core.load_config()
    requested = core._text(args.get("profile")).strip()
    profiles: list[dict[str, Any]] = []
    for name, raw in sorted(bundle.data["profiles"].items()):
        try:
            kind = core.normalize_kind(raw.get("kind"))
            handler = STATUS_HANDLERS[kind]
            profile_status = handler(name, raw)
            queue_status = _queue_status_for_profile(name, raw, kind)
            if queue_status is not None:
                profile_status["vm_queue"] = queue_status
            if kind == "ssh":
                host_key = host_keys.profile_summary(name, raw)
                profile_status["hostKey"] = host_key
                if (
                    host_key.get("policy") == "managed"
                    and host_key.get("governanceState") != "registered"
                ):
                    errors = list(profile_status.get("errors") or [])
                    message = "managed SSH host key is not registered for this endpoint"
                    if message not in errors:
                        errors.append(message)
                    profile_status["errors"] = errors
                    profile_status["ready"] = False
                profile_status.setdefault(
                    "readinessScope",
                    "local-configuration-and-host-key",
                )
                profile_status.setdefault(
                    "authentication",
                    {
                        "state": "not-tested",
                        "verified": False,
                        "nextStep": (
                            "Run remotex_ssh_test to verify server-side public-key "
                            "authorization."
                        ),
                    },
                )
            profiles.append(profile_status)
        except core.ToolError as exc:
            profiles.append(
                {
                    "profile": name,
                    "kind": str(raw.get("kind") or "unknown"),
                    "ready": False,
                    "status": "not-ready",
                    "errors": [str(exc)],
                }
            )
    try:
        queue_health = queue_leases.health()
    except core.ToolError as exc:
        queue_health = {
            "ok": False,
            "state_file": str(vm_queue.queue_path()),
            "lease_file": str(queue_leases.lease_path()),
            "error": str(exc),
            "preemption_allowed": False,
            "scope": "local-cooperative",
        }
    for profile in profiles:
        profile["status"] = "ready" if profile.get("ready") else "not-ready"
    ready_count = sum(1 for profile in profiles if profile.get("ready"))
    overall_ready = bool(profiles) and ready_count == len(profiles) and queue_health["ok"]
    selected = next(
        (profile for profile in profiles if profile.get("profile") == requested),
        None,
    ) if requested else None
    if requested and selected is None:
        raise core.ToolError(f"RemoteX profile not found: {requested}")
    overall_status = (
        "empty"
        if not profiles
        else ("ready" if overall_ready else "not-ready")
    )
    result = {
        "ok": overall_ready,
        "overallStatus": overall_status,
        "selectedProfile": selected,
        "selectedProfileReady": bool(selected.get("ready")) if selected else None,
        "selectedProfileReadinessScope": (
            selected.get("readinessScope") if selected else None
        ),
        "selectedProfileAuthenticationVerified": (
            bool((selected.get("authentication") or {}).get("verified"))
            if selected
            else None
        ),
        "config": {
            "path": str(bundle.path),
            "source": bundle.source,
            "exists": bundle.exists,
            "legacy_ssh_compatibility": bundle.source == "legacy-ssh",
            "version": bundle.data.get("version", 1),
            "migrationRecommended": bool(
                bundle.exists
                and bundle.source == "remotex"
                and bundle.data.get("version", 1) == 1
            ),
        },
        "defaults": bundle.data["defaults"],
        "vm_queue": queue_health,
        "sessionCleanup": {
            "heldResources": queue_health.get("held_resources", []),
            "promptRequired": queue_health.get("session_end_prompt_required", False),
        },
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
            "Store only credential references in the file; RemoteX rejects literal secrets."
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
            "Return collection-wide and selected-profile readiness, host-key governance, "
            "queue leases, and cleanup prompts without opening a connection. SSH readiness "
            "is local only; use remotex_ssh_test to verify server-side authorization."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {
                    "type": "string",
                    "description": "Optional profile whose independent readiness is required.",
                }
            },
            "additionalProperties": False,
        },
        "handler": status,
    },
    **profile_tools.TOOLS,
    **credential_tools.TOOLS,
    **ssh_vnext.TOOLS,
    **task_manager.TOOLS,
    **host_keys.TOOLS,
    **rdp_adapter.TOOLS,
    **vsphere_adapter.TOOLS,
    **vmware_adapter.TOOLS,
    **windows_guest.TOOLS,
    **queue_leases.TOOLS,
    **audit_log.TOOLS,
}


def response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _call_tool(
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    if tool_name not in TOOLS:
        raise core.ToolError(f"Unknown tool: {tool_name}")
    handler: Callable[[dict[str, Any]], dict[str, Any]] = TOOLS[tool_name]["handler"]
    if tool_name == "remotex_audit_export":
        return handler(arguments)
    started = time.monotonic()
    operation_id = audit_log.begin(tool_name, arguments, SERVER_VERSION)
    try:
        result = handler(arguments)
    except core.ToolError as exc:
        result = core.error_result(str(exc))
    except Exception as exc:
        core.eprint(core.redact_text(traceback.format_exc()))
        result = core.error_result(f"Unexpected {type(exc).__name__}: {exc}")
    audit_log.finish(
        operation_id,
        tool_name,
        result,
        SERVER_VERSION,
        started,
    )
    return audit_log.attach_metadata(result, operation_id)


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
                {
                    "name": name,
                    "description": spec["description"],
                    "inputSchema": spec["inputSchema"],
                }
                for name, spec in TOOLS.items()
            ]
            return response(request_id, {"tools": tools})
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise core.ToolError("tool arguments must be an object")
            if not isinstance(tool_name, str):
                raise core.ToolError("tool name must be a string")
            return response(request_id, _call_tool(tool_name, arguments))
        return error_response(request_id, -32601, f"Method not found: {method}")
    except core.ToolError as exc:
        return response(request_id, core.error_result(str(exc)))
    except Exception as exc:
        core.eprint(core.redact_text(traceback.format_exc()))
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
    try:
        held = queue_leases.held_resources()
    except core.ToolError as exc:
        core.eprint(f"RemoteX could not inspect held queue resources at shutdown: {exc}")
        return
    if held:
        core.eprint(
            "RemoteX session ended while queue resources are still held; renew or release them: "
            + ", ".join(item["resource"] for item in held)
        )


if __name__ == "__main__":
    run_stdio_server()
