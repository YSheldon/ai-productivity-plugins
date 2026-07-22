from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import remotex_core as core
import vm_queue


def _validate_url(value: Any) -> str:
    url = core._required_text(value, "url")
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise core.ToolError("vSphere/ESXi url must be an absolute https URL")
    if parsed.username or parsed.password:
        raise core.ToolError("vSphere/ESXi url must not contain credentials")
    return url.rstrip("/")


def connection_config(profile: Any = None) -> dict[str, Any]:
    name, raw, bundle = core.select_profile("vsphere", profile)
    credential = raw.get("credential")
    if not isinstance(credential, dict):
        raise core.ToolError(
            "vSphere/ESXi credential must reference environment variables or Windows Credential Manager"
        )
    tls = raw.get("tls") or {}
    if not isinstance(tls, dict):
        raise core.ToolError("tls must be an object")
    ca_file: Path | None = None
    if tls.get("ca_file"):
        ca_file = core.expand_path(tls.get("ca_file"), "tls.ca_file")
    return {
        "profile": name,
        "config_source": bundle.source,
        "url": _validate_url(raw.get("url")),
        "credential": credential,
        "insecure": core.as_bool(tls.get("insecure"), False),
        "ca_file": ca_file,
        "datacenter": str(raw.get("datacenter") or "").strip() or None,
        "govc_path": raw.get("govc_path"),
    }


def profile_status(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "profile": name,
        "kind": "vsphere",
        "client_available": core.executable_available("govc", raw.get("govc_path")),
    }
    errors: list[str] = []
    try:
        _validate_url(raw.get("url"))
        credential = core.credential_status(raw.get("credential"))
        result["credential"] = credential
        if not credential.get("ready"):
            errors.append("vSphere/ESXi credential reference is not ready")
        tls = raw.get("tls") or {}
        if not isinstance(tls, dict):
            raise core.ToolError("tls must be an object")
        if tls.get("ca_file"):
            ca_file = core.expand_path(tls.get("ca_file"), "tls.ca_file")
            result["ca_file_exists"] = ca_file.is_file()
            if not ca_file.is_file():
                errors.append("tls.ca_file does not exist")
        result["tls_verification"] = not core.as_bool(tls.get("insecure"), False)
    except core.ToolError as exc:
        errors.append(str(exc))
    if not result["client_available"]:
        errors.append("govc is unavailable")
    result["ready"] = not errors
    result["errors"] = errors
    return result


def _govc_environment(cfg: dict[str, Any]) -> dict[str, str]:
    credentials = core.resolve_username_password(cfg["credential"])
    environment = dict(os.environ)
    environment.update(
        {
            "GOVC_URL": cfg["url"],
            "GOVC_USERNAME": credentials.username,
            "GOVC_PASSWORD": credentials.password,
            "GOVC_INSECURE": "true" if cfg["insecure"] else "false",
        }
    )
    if cfg.get("datacenter"):
        environment["GOVC_DATACENTER"] = cfg["datacenter"]
    if cfg.get("ca_file"):
        if not cfg["ca_file"].is_file():
            raise core.ToolError(f"tls.ca_file does not exist: {cfg['ca_file']}")
        environment["GOVC_TLS_CA_CERTS"] = str(cfg["ca_file"])
    return environment


def _run_govc(
    cfg: dict[str, Any], arguments: list[str], timeout: int
) -> dict[str, Any]:
    executable = core.find_executable("govc", cfg.get("govc_path"))
    return core.run_process(
        [executable, *arguments],
        timeout=timeout,
        environment=_govc_environment(cfg),
    )


def _result(cfg: dict[str, Any], outcome: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "ok": outcome["returncode"] == 0 and not outcome["timed_out"],
        "profile": cfg["profile"],
        "url": cfg["url"],
        "returncode": outcome["returncode"],
        "timed_out": outcome["timed_out"],
        "stdout": outcome["stdout"],
        "stderr": outcome["stderr"],
        **extra,
    }


def about(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 30)
    outcome = _run_govc(cfg, ["about", "-json"], timeout)
    return core.tool_result(_result(cfg, outcome, operation="about"))


def list_vms(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 60)
    outcome = _run_govc(cfg, ["find", "-type", "m"], timeout)
    virtual_machines = [line for line in outcome["stdout"].splitlines() if line.strip()]
    result = _result(cfg, outcome, operation="list-vms")
    result["virtual_machines"] = virtual_machines
    result.pop("stdout", None)
    return core.tool_result(result)


def power(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    virtual_machine = core.validate_selector(args.get("virtual_machine"), "virtual_machine")
    action = str(args.get("action") or "").strip().lower()
    switches = {
        "on": "-on",
        "off": "-off",
        "reset": "-reset",
        "suspend": "-suspend",
    }
    if action not in switches:
        raise core.ToolError("action must be on, off, reset, or suspend")
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    with vm_queue.profile_owner_operation(
        cfg["profile"], args.get("requester"), virtual_machine
    ) as ownership:
        outcome = _run_govc(cfg, ["vm.power", switches[action], virtual_machine], timeout)
    return core.tool_result(
        _result(
            cfg,
            outcome,
            operation="vm-power",
            virtual_machine=virtual_machine,
            action=action,
            queue_resource=ownership["resource"],
            queue_owner=ownership["owner"]["requester"],
        )
    )


COMMON_PROFILE = {
    "profile": {
        "type": "string",
        "description": "Optional vSphere/ESXi profile name from the RemoteX config.",
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
    "remotex_vsphere_about": {
        "description": "Read vCenter or ESXi identity/build information through govc.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT},
            "additionalProperties": False,
        },
        "handler": about,
    },
    "remotex_vsphere_list_vms": {
        "description": "List virtual-machine inventory paths through govc without exposing credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT},
            "additionalProperties": False,
        },
        "handler": list_vms,
    },
    "remotex_vsphere_power": {
        "description": "Change one vSphere/ESXi VM power state through govc; this is side-effectful.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                "virtual_machine": {"type": "string"},
                "action": {"type": "string", "enum": ["on", "off", "reset", "suspend"]},
                "requester": {"type": "string"},
            },
            "required": ["virtual_machine", "action", "requester"],
            "additionalProperties": False,
        },
        "handler": power,
    },
}
