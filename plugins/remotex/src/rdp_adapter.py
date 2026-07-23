from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import remotex_core as core
import vm_queue
import windows_credentials


DEFAULT_PORT = 3389


def _credential_target(raw: dict[str, Any], host: str) -> str:
    credential = raw.get("credential")
    if not isinstance(credential, dict):
        raise core.ToolError(
            "RDP profile credential must reference Windows Credential Manager"
        )
    source = str(credential.get("source") or "").strip().lower()
    if source != "windows-credential-manager":
        raise core.ToolError(
            "RDP credential.source must be windows-credential-manager; passwords are not accepted"
        )
    target = core._required_text(
        credential.get("target") or f"TERMSRV/{host}", "credential.target"
    )
    if not target.upper().startswith("TERMSRV/"):
        raise core.ToolError("RDP credential.target must start with TERMSRV/")
    return target


def connection_config(profile: Any = None) -> dict[str, Any]:
    name, raw, bundle = core.select_profile("rdp", profile)
    host = core.validate_host(raw.get("host"))
    rdp_file: Path | None = None
    if raw.get("rdp_file"):
        rdp_file = core.expand_path(raw.get("rdp_file"), "rdp_file")
        if rdp_file.suffix.lower() != ".rdp":
            raise core.ToolError("rdp_file must use the .rdp extension")
    width = raw.get("width")
    height = raw.get("height")
    if (width is None) != (height is None):
        raise core.ToolError("RDP width and height must be configured together")
    if width is not None:
        try:
            width = int(width)
            height = int(height)
        except (TypeError, ValueError) as exc:
            raise core.ToolError("RDP width and height must be integers") from exc
        if not 640 <= width <= 16384 or not 480 <= height <= 16384:
            raise core.ToolError("RDP width and height are outside the supported range")
    return {
        "profile": name,
        "config_source": bundle.source,
        "host": host,
        "port": core.validate_port(raw.get("port"), DEFAULT_PORT),
        "credential_target": _credential_target(raw, host),
        "rdp_file": rdp_file,
        "admin": core.as_bool(raw.get("admin"), False),
        "fullscreen": core.as_bool(raw.get("fullscreen"), False),
        "width": width,
        "height": height,
        "mstsc_path": raw.get("mstsc_path"),
    }


def _credential_present(target: str) -> bool:
    return windows_credentials.credential_exists(target, credential_types=(1, 2))


def profile_status(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "profile": name,
        "kind": "rdp",
        "client_available": core.executable_available("mstsc", raw.get("mstsc_path")),
    }
    errors: list[str] = []
    try:
        host = core.validate_host(raw.get("host"))
        core.validate_port(raw.get("port"), DEFAULT_PORT)
        target = _credential_target(raw, host)
        result["credential_source"] = "windows-credential-manager"
        result["credential_target"] = target
        result["credential_present"] = _credential_present(target)
        if not result["credential_present"]:
            errors.append(f"Windows Credential Manager entry is missing: {target}")
        if raw.get("rdp_file"):
            rdp_file = core.expand_path(raw.get("rdp_file"), "rdp_file")
            result["rdp_file_exists"] = rdp_file.is_file()
            if not rdp_file.is_file():
                errors.append("rdp_file does not exist")
    except (core.ToolError, ValueError) as exc:
        errors.append(str(exc))
    if not result["client_available"]:
        errors.append("mstsc is unavailable")
    result["ready"] = not errors
    result["errors"] = errors
    return result


def test_connection(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 5)
    try:
        with socket.create_connection((cfg["host"], cfg["port"]), timeout=timeout):
            reachable = True
            error = None
    except OSError as exc:
        reachable = False
        error = core.redact_text(exc)
    return core.tool_result(
        {
            "ok": reachable,
            "profile": cfg["profile"],
            "host": cfg["host"],
            "port": cfg["port"],
            "tcp_reachable": reachable,
            "credential_present": _credential_present(cfg["credential_target"]),
            "error": error,
        }
    )


def rdp_arguments(cfg: dict[str, Any]) -> list[str]:
    args = [core.find_executable("mstsc", cfg.get("mstsc_path"))]
    if cfg.get("rdp_file"):
        if not cfg["rdp_file"].is_file():
            raise core.ToolError(f"rdp_file does not exist: {cfg['rdp_file']}")
        args.append(str(cfg["rdp_file"]))
    else:
        args.append(f"/v:{cfg['host']}:{cfg['port']}")
    if cfg["admin"]:
        args.append("/admin")
    if cfg["fullscreen"]:
        args.append("/f")
    elif cfg.get("width") and cfg.get("height"):
        args.extend([f"/w:{cfg['width']}", f"/h:{cfg['height']}"])
    return args


def open_connection(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    if not _credential_present(cfg["credential_target"]):
        raise core.ToolError(
            f"RDP credential is not stored under {cfg['credential_target']}. Add it through "
            "Windows Credential Manager before opening RDP; RemoteX never accepts a password."
        )
    popen_args: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        popen_args["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        )
    else:
        popen_args["start_new_session"] = True
    with vm_queue.profile_owner_operation(
        cfg["profile"], args.get("requester")
    ) as ownership:
        try:
            process = subprocess.Popen(rdp_arguments(cfg), **popen_args)
        except OSError as exc:
            raise core.ToolError(f"Unable to launch Remote Desktop: {exc}") from exc
    return core.tool_result(
        {
            "ok": True,
            "launched": True,
            "profile": cfg["profile"],
            "host": cfg["host"],
            "port": cfg["port"],
            "credential_target": cfg["credential_target"],
            "queue_resource": ownership["resource"],
            "queue_owner": ownership["owner"]["requester"],
            "process_id": process.pid,
        }
    )


COMMON_PROFILE = {
    "profile": {
        "type": "string",
        "description": "Optional RDP profile name from the RemoteX config.",
    }
}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_rdp_test": {
        "description": "Test TCP reachability and saved-credential readiness for an RDP profile.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": core.MAX_TIMEOUT_SECONDS,
                },
            },
            "additionalProperties": False,
        },
        "handler": test_connection,
    },
    "remotex_rdp_open": {
        "description": "Open mstsc only when the saved credential exists and this requester owns the VM queue resource.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                "requester": {"type": "string"},
            },
            "required": ["requester"],
            "additionalProperties": False,
        },
        "handler": open_connection,
    },
}
