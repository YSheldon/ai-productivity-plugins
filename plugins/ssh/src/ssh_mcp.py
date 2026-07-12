from __future__ import annotations

from pathlib import Path
from typing import Any

import ssh_mcp_core as core


def run_script(args: dict[str, Any]) -> dict[str, Any]:
    cfg = core.connection_config(args.get("profile"))
    script = core._text(args.get("script"))
    if not script.strip():
        raise core.ToolError("script is required")
    if "\x00" in script:
        raise core.ToolError("script must not contain NUL characters")
    if len(script) > core.MAX_SCRIPT_LENGTH:
        raise core.ToolError(f"script exceeds {core.MAX_SCRIPT_LENGTH} characters")
    shell = str(args.get("shell") or "sh")
    if shell not in {"sh", "bash"}:
        raise core.ToolError("shell must be sh or bash")
    timeout = core._validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    outcome = core.run_process(
        core.ssh_arguments(cfg, timeout, f"{shell} -s"),
        timeout=timeout,
        input_text=script,
    )
    return core.tool_result(core._connection_result(cfg, outcome))


def _identity_path(args: dict[str, Any], profile: str | None = None) -> Path:
    raw_config = core.profile_config(profile)
    if args.get("identity_file"):
        path = core._expand_path(args["identity_file"], "identity_file")
    elif raw_config.get("identity_file"):
        path = core._expand_path(raw_config["identity_file"], "identity_file")
    else:
        raise core.ToolError("identity_file is required for this agent operation")
    if not path.exists() or not path.is_file():
        raise core.ToolError(f"identity_file does not exist: {path}")
    return path


def agent_add(args: dict[str, Any]) -> dict[str, Any]:
    path = _identity_path(args, args.get("profile"))
    outcome = core.run_process([core._executable("ssh-add"), str(path)], timeout=30)
    return core.tool_result(
        {
            "ok": outcome["returncode"] == 0,
            "identity_file": str(path),
            "returncode": outcome["returncode"],
            "stdout": outcome["stdout"],
            "stderr": outcome["stderr"],
            "lifetime_constraint_used": False,
        }
    )


def agent_remove(args: dict[str, Any]) -> dict[str, Any]:
    path = _identity_path(args, args.get("profile"))
    outcome = core.run_process([core._executable("ssh-add"), "-d", str(path)], timeout=30)
    return core.tool_result(
        {
            "ok": outcome["returncode"] == 0,
            "identity_file": str(path),
            "returncode": outcome["returncode"],
            "stdout": outcome["stdout"],
            "stderr": outcome["stderr"],
        }
    )


def key_fingerprint(args: dict[str, Any]) -> dict[str, Any]:
    raw_config = core.profile_config(args.get("profile"))
    if args.get("public_key_file"):
        public_key = core._expand_path(args["public_key_file"], "public_key_file")
    elif raw_config.get("identity_file"):
        public_key = Path(str(core._expand_path(raw_config["identity_file"], "identity_file")) + ".pub")
    else:
        raise core.ToolError("public_key_file or profile identity_file is required")
    if not public_key.exists() or not public_key.is_file():
        raise core.ToolError(f"public key file does not exist: {public_key}")
    outcome = core.run_process(
        [core._executable("ssh-keygen"), "-lf", str(public_key), "-E", "sha256"],
        timeout=15,
    )
    return core.tool_result(
        {
            "ok": outcome["returncode"] == 0,
            "public_key_file": str(public_key),
            "returncode": outcome["returncode"],
            "stdout": outcome["stdout"],
            "stderr": outcome["stderr"],
        }
    )


core.TOOLS["ssh_run_script"]["handler"] = run_script
core.TOOLS["ssh_agent_add"]["handler"] = agent_add
core.TOOLS["ssh_agent_remove"]["handler"] = agent_remove
core.TOOLS["ssh_key_fingerprint"]["handler"] = key_fingerprint


if __name__ == "__main__":
    core.run_stdio_server()
