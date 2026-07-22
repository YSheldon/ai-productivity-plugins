from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import remotex_core as core


WINDOWS_VMRUN_PATH = Path(
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
) / "VMware" / "VMware Workstation" / "vmrun.exe"


def _vmrun_path(configured: Any = None) -> str:
    if configured not in (None, ""):
        return core.find_executable("vmrun", configured)
    if os.name == "nt" and WINDOWS_VMRUN_PATH.is_file():
        return str(WINDOWS_VMRUN_PATH)
    return core.find_executable("vmrun")


def _vmrun_available(configured: Any = None) -> bool:
    try:
        _vmrun_path(configured)
    except core.ToolError:
        return False
    return True


def connection_config(profile: Any = None, *, require_vmx: bool) -> dict[str, Any]:
    name, raw, bundle = core.select_profile("vmware-workstation", profile)
    host_type = str(raw.get("host_type") or "ws").strip().lower()
    if host_type != "ws":
        raise core.ToolError("VMware Workstation host_type must be ws")
    vmx_path: Path | None = None
    if raw.get("vmx_path"):
        vmx_path = core.expand_path(raw.get("vmx_path"), "vmx_path")
        if vmx_path.suffix.lower() != ".vmx":
            raise core.ToolError("vmx_path must use the .vmx extension")
    if require_vmx and vmx_path is None:
        raise core.ToolError("vmx_path is required for this VMware operation")
    return {
        "profile": name,
        "config_source": bundle.source,
        "host_type": host_type,
        "vmrun_path": raw.get("vmrun_path"),
        "vmx_path": vmx_path,
    }


def profile_status(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "profile": name,
        "kind": "vmware-workstation",
        "client_available": _vmrun_available(raw.get("vmrun_path")),
        "credential_source": "local-user-session",
    }
    errors: list[str] = []
    host_type = str(raw.get("host_type") or "ws").strip().lower()
    if host_type != "ws":
        errors.append("host_type must be ws")
    if raw.get("vmx_path"):
        try:
            vmx_path = core.expand_path(raw.get("vmx_path"), "vmx_path")
            result["vmx_file_exists"] = vmx_path.is_file()
            if not vmx_path.is_file():
                errors.append("vmx_path does not exist")
        except core.ToolError as exc:
            errors.append(str(exc))
    else:
        result["vmx_file_exists"] = None
    if not result["client_available"]:
        errors.append("vmrun is unavailable")
    result["ready"] = not errors
    result["errors"] = errors
    return result


def _run(cfg: dict[str, Any], arguments: list[str], timeout: int) -> dict[str, Any]:
    return core.run_process(
        [_vmrun_path(cfg.get("vmrun_path")), "-T", cfg["host_type"], *arguments],
        timeout=timeout,
    )


def _result(cfg: dict[str, Any], outcome: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "ok": outcome["returncode"] == 0 and not outcome["timed_out"],
        "profile": cfg["profile"],
        "returncode": outcome["returncode"],
        "timed_out": outcome["timed_out"],
        "stdout": outcome["stdout"],
        "stderr": outcome["stderr"],
        **extra,
    }


def list_running(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"), require_vmx=False)
    timeout = core.validate_timeout(args.get("timeout_seconds"), 30)
    outcome = _run(cfg, ["list"], timeout)
    lines = [line.strip() for line in outcome["stdout"].splitlines() if line.strip()]
    running = lines[1:] if lines and lines[0].lower().startswith("total running") else lines
    result = _result(cfg, outcome, operation="list-running", running_vms=running)
    result.pop("stdout", None)
    return core.tool_result(result)


def power(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"), require_vmx=True)
    action = str(args.get("action") or "").strip().lower()
    default_mode = "nogui" if action == "start" else "soft"
    mode = str(args.get("mode") or default_mode).strip().lower()
    if action not in {"start", "stop", "reset", "suspend", "pause", "unpause"}:
        raise core.ToolError("action must be start, stop, reset, suspend, pause, or unpause")
    if mode not in {"soft", "hard", "gui", "nogui"}:
        raise core.ToolError("mode must be soft, hard, gui, or nogui")
    if action == "start":
        if mode not in {"gui", "nogui"}:
            raise core.ToolError("start mode must be gui or nogui")
        arguments = [action, str(cfg["vmx_path"]), mode]
    elif action in {"stop", "reset", "suspend"}:
        if mode not in {"soft", "hard"}:
            raise core.ToolError(f"{action} mode must be soft or hard")
        arguments = [action, str(cfg["vmx_path"]), mode]
    else:
        arguments = [action, str(cfg["vmx_path"])]
    if not cfg["vmx_path"].is_file():
        raise core.ToolError(f"vmx_path does not exist: {cfg['vmx_path']}")
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    outcome = _run(cfg, arguments, timeout)
    return core.tool_result(
        _result(
            cfg,
            outcome,
            operation="power",
            vmx_path=str(cfg["vmx_path"]),
            action=action,
            mode=None if action in {"pause", "unpause"} else mode,
        )
    )


COMMON_PROFILE = {
    "profile": {
        "type": "string",
        "description": "Optional VMware Workstation profile name from the RemoteX config.",
    }
}

COMMON_TIMEOUT = {
    "timeout_seconds": {
        "type": "integer",
        "minimum": 1,
        "maximum": core.MAX_TIMEOUT_SECONDS,
    }
}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_vmware_list_running": {
        "description": "List running local VMware Workstation virtual machines through vmrun.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT},
            "additionalProperties": False,
        },
        "handler": list_running,
    },
    "remotex_vmware_power": {
        "description": "Change a configured VMware Workstation VM power state through vmrun.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "reset", "suspend", "pause", "unpause"],
                },
                "mode": {"type": "string", "enum": ["soft", "hard", "gui", "nogui"]},
            },
            "required": ["action"],
            "additionalProperties": False,
        },
        "handler": power,
    },
}
