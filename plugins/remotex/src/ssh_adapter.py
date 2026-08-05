from __future__ import annotations

from pathlib import Path
from typing import Any

import remotex_core as core


DEFAULT_PORT = 22


def _strict_host_key_mode(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    mode = str(value or "yes").strip().lower()
    if mode in {"yes", "accept-new", "no"}:
        return mode
    raise core.ToolError("strict_host_key_checking must be yes, accept-new, or no")


def _credential_config(raw: dict[str, Any]) -> tuple[str, Path | None]:
    credential = raw.get("credential")
    if credential is not None and not isinstance(credential, dict):
        raise core.ToolError("credential must be an object")
    credential = credential or {}
    identity_value = credential.get("identity_file") or raw.get("identity_file")
    identity_file = (
        core.expand_path(identity_value, "credential.identity_file") if identity_value else None
    )
    source = str(credential.get("source") or ("identity-file" if identity_file else "ssh-agent"))
    source = source.strip().lower()
    if source not in {"identity-file", "ssh-agent"}:
        raise core.ToolError("SSH credential.source must be identity-file or ssh-agent")
    if source == "identity-file" and identity_file is None:
        raise core.ToolError("SSH identity-file credentials require credential.identity_file")
    return source, identity_file


def connection_config(profile: Any = None) -> dict[str, Any]:
    name, raw, bundle = core.select_profile("ssh", profile)
    source, identity_file = _credential_config(raw)
    known_hosts = (
        core.expand_path(raw.get("known_hosts_file"), "known_hosts_file")
        if raw.get("known_hosts_file")
        else None
    )
    identities_only = core.as_bool(raw.get("identities_only"), source == "identity-file")
    return {
        "profile": name,
        "config_source": bundle.source,
        "host": core.validate_host(raw.get("host")),
        "user": core.validate_user(raw.get("user")),
        "port": core.validate_port(raw.get("port"), DEFAULT_PORT),
        "credential_source": source,
        "identity_file": identity_file,
        "known_hosts_file": known_hosts,
        "strict_host_key_checking": _strict_host_key_mode(raw.get("strict_host_key_checking")),
        "identities_only": identities_only,
        "connect_timeout_seconds": core.validate_timeout(
            raw.get("connect_timeout_seconds"), core.DEFAULT_CONNECT_TIMEOUT_SECONDS
        ),
    }


def profile_status(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "profile": name,
        "kind": "ssh",
        "client_available": all(
            core.executable_available(binary) for binary in ("ssh", "scp", "ssh-add", "ssh-keygen")
        ),
    }
    errors: list[str] = []
    try:
        core.validate_host(raw.get("host"))
        core.validate_user(raw.get("user"))
        core.validate_port(raw.get("port"), DEFAULT_PORT)
        source, identity_file = _credential_config(raw)
        result["credential_source"] = source
        if source == "identity-file":
            result["identity_file_exists"] = bool(identity_file and identity_file.is_file())
            if not result["identity_file_exists"]:
                errors.append("identity file does not exist")
        else:
            result["credential_managed_by"] = "ssh-agent"
            if result["client_available"]:
                outcome = core.run_process([core.find_executable("ssh-add"), "-l"], timeout=15)
                result["ssh_agent_has_identities"] = outcome["returncode"] == 0
                if not result["ssh_agent_has_identities"]:
                    errors.append("ssh-agent has no available identities")
        if raw.get("known_hosts_file"):
            known_hosts = core.expand_path(raw.get("known_hosts_file"), "known_hosts_file")
            result["known_hosts_file_exists"] = known_hosts.is_file()
            if not known_hosts.is_file():
                errors.append("known_hosts_file does not exist")
    except core.ToolError as exc:
        errors.append(str(exc))
    if not result["client_available"]:
        errors.append("one or more OpenSSH clients are unavailable")
    result["ready"] = not errors
    result["errors"] = errors
    return result


def _common_options(cfg: dict[str, Any], timeout: int) -> list[str]:
    options = [
        "-o",
        "BatchMode=yes",
        "-o",
        f"StrictHostKeyChecking={cfg['strict_host_key_checking']}",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "GSSAPIAuthentication=no",
        "-o",
        f"IdentitiesOnly={'yes' if cfg['identities_only'] else 'no'}",
    ]
    if cfg["known_hosts_file"]:
        options.extend(["-o", f"UserKnownHostsFile={cfg['known_hosts_file']}"])
    if cfg["identity_file"]:
        if not cfg["identity_file"].is_file():
            raise core.ToolError(f"identity_file does not exist: {cfg['identity_file']}")
        options.extend(["-i", str(cfg["identity_file"])])
    return options


def ssh_arguments(cfg: dict[str, Any], timeout: int, command: str | None = None) -> list[str]:
    args = [core.find_executable("ssh"), "-T"]
    args.extend(_common_options(cfg, timeout))
    args.extend(["-p", str(cfg["port"]), "-l", cfg["user"], cfg["host"]])
    if command is not None:
        args.append(command)
    return args


def scp_arguments(cfg: dict[str, Any], timeout: int) -> list[str]:
    args = [core.find_executable("scp")]
    args.extend(_common_options(cfg, timeout))
    args.extend(["-P", str(cfg["port"])])
    return args


def _remote_path(value: Any) -> str:
    return core.validate_selector(value, "remote_path")


def _quote_remote_path(path: str) -> str:
    return "'" + path.replace("'", "'\\''") + "'"


def _remote_spec(cfg: dict[str, Any], path: str) -> str:
    host = cfg["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{cfg['user']}@{host}:{_quote_remote_path(path)}"


def _connection_result(cfg: dict[str, Any], outcome: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": outcome["returncode"] == 0 and not outcome["timed_out"],
        "profile": cfg["profile"],
        "host": cfg["host"],
        "user": cfg["user"],
        "port": cfg["port"],
        "credential_source": cfg["credential_source"],
        "returncode": outcome["returncode"],
        "timed_out": outcome["timed_out"],
        "stdout": outcome["stdout"],
        "stderr": outcome["stderr"],
    }


def test_connection(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), cfg["connect_timeout_seconds"])
    outcome = core.run_process(ssh_arguments(cfg, timeout, "hostname"), timeout=timeout)
    return core.tool_result(_connection_result(cfg, outcome))


def run_command(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    command = core._required_text(args.get("command"), "command")
    if len(command) > core.MAX_COMMAND_LENGTH:
        raise core.ToolError(
            f"command exceeds {core.MAX_COMMAND_LENGTH} characters; use remotex_ssh_run_script"
        )
    if "\r" in command or "\n" in command:
        raise core.ToolError("command must be one line; use remotex_ssh_run_script")
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    outcome = core.run_process(ssh_arguments(cfg, timeout, command), timeout=timeout)
    return core.tool_result(_connection_result(cfg, outcome))


def run_script(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
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
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    outcome = core.run_process(
        ssh_arguments(cfg, timeout, f"{shell} -s"),
        timeout=timeout,
        input_text=script,
    )
    return core.tool_result(_connection_result(cfg, outcome))


def _local_source(value: Any) -> Path:
    path = core.expand_path(value, "local_path")
    if not path.exists():
        raise core.ToolError(f"local_path does not exist: {path}")
    if path.is_symlink():
        raise core.ToolError(f"local_path must not be a symlink: {path}")
    return path


def _local_destination(value: Any) -> Path:
    path = core.expand_path(value, "local_path")
    if path.exists() and path.is_symlink():
        raise core.ToolError(f"local_path must not be a symlink: {path}")
    if not path.parent.is_dir():
        raise core.ToolError(f"local_path parent directory does not exist: {path.parent}")
    return path


def copy_to(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    local_path = _local_source(args.get("local_path"))
    recursive = core.as_bool(args.get("recursive"), False)
    if local_path.is_dir() and not recursive:
        raise core.ToolError("local_path is a directory; set recursive=true to copy it")
    remote_path = _remote_path(args.get("remote_path"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    argv = scp_arguments(cfg, timeout)
    if recursive:
        argv.append("-r")
    argv.extend([str(local_path), _remote_spec(cfg, remote_path)])
    outcome = core.run_process(argv, timeout=timeout)
    return core.tool_result(_connection_result(cfg, outcome))


def copy_from(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    remote_path = _remote_path(args.get("remote_path"))
    local_path = _local_destination(args.get("local_path"))
    recursive = core.as_bool(args.get("recursive"), False)
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    argv = scp_arguments(cfg, timeout)
    if recursive:
        argv.append("-r")
    argv.extend([_remote_spec(cfg, remote_path), str(local_path)])
    outcome = core.run_process(argv, timeout=timeout)
    return core.tool_result(_connection_result(cfg, outcome))


def _identity_path(args: dict[str, Any]) -> Path:
    cfg = connection_config(args.get("profile"))
    raw = args.get("identity_file")
    path = core.expand_path(raw, "identity_file") if raw else cfg.get("identity_file")
    if not path:
        raise core.ToolError("identity_file is required for this ssh-agent operation")
    if not path.is_file():
        raise core.ToolError(f"identity_file does not exist: {path}")
    return path


def agent_list(_: dict[str, Any]) -> dict[str, Any]:
    outcome = core.run_process([core.find_executable("ssh-add"), "-l"], timeout=15)
    return core.tool_result(
        {
            "ok": outcome["returncode"] == 0,
            "returncode": outcome["returncode"],
            "stdout": outcome["stdout"],
            "stderr": outcome["stderr"],
        }
    )


def agent_add(args: dict[str, Any]) -> dict[str, Any]:
    path = _identity_path(args)
    outcome = core.run_process([core.find_executable("ssh-add"), str(path)], timeout=30)
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
    path = _identity_path(args)
    outcome = core.run_process([core.find_executable("ssh-add"), "-d", str(path)], timeout=30)
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
    cfg = connection_config(args.get("profile"))
    if args.get("public_key_file"):
        public_key = core.expand_path(args.get("public_key_file"), "public_key_file")
    elif cfg.get("identity_file"):
        public_key = Path(str(cfg["identity_file"]) + ".pub")
    else:
        raise core.ToolError("public_key_file or profile identity_file is required")
    if not public_key.is_file():
        raise core.ToolError(f"public key file does not exist: {public_key}")
    outcome = core.run_process(
        [core.find_executable("ssh-keygen"), "-lf", str(public_key), "-E", "sha256"],
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


COMMON_PROFILE = {
    "profile": {
        "type": "string",
        "description": "Optional SSH profile name from the RemoteX config.",
    }
}

COMMON_TIMEOUT = {
    "timeout_seconds": {
        "type": "integer",
        "minimum": 1,
        "maximum": core.MAX_TIMEOUT_SECONDS,
        "description": "Local subprocess timeout in seconds.",
    }
}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_ssh_test": {
        "description": "Test a configured SSH profile with strict host-key and public-key-only defaults.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT},
            "additionalProperties": False,
        },
        "handler": test_connection,
    },
    "remotex_ssh_run_command": {
        "description": "Run one explicit command on a configured SSH host; this is side-effectful.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                "command": {"type": "string", "description": "One remote command line."},
            },
            "required": ["command"],
            "additionalProperties": False,
        },
        "handler": run_command,
    },
    "remotex_ssh_run_script": {
        "description": "Send a shell script through SSH stdin and run it with sh or bash; this is side-effectful.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                "shell": {"type": "string", "enum": ["sh", "bash"]},
                "script": {"type": "string"},
            },
            "required": ["script"],
            "additionalProperties": False,
        },
        "handler": run_script,
    },
    "remotex_ssh_copy_to": {
        "description": "Copy a local file or directory to a configured SSH host with SCP.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                "local_path": {"type": "string"},
                "remote_path": {"type": "string"},
                "recursive": {"type": "boolean"},
            },
            "required": ["local_path", "remote_path"],
            "additionalProperties": False,
        },
        "handler": copy_to,
    },
    "remotex_ssh_copy_from": {
        "description": "Copy a remote file or directory from a configured SSH host with SCP.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                "remote_path": {"type": "string"},
                "local_path": {"type": "string"},
                "recursive": {"type": "boolean"},
            },
            "required": ["remote_path", "local_path"],
            "additionalProperties": False,
        },
        "handler": copy_from,
    },
    "remotex_ssh_agent_list": {
        "description": "List local ssh-agent identities without exposing private key material.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": agent_list,
    },
    "remotex_ssh_agent_add": {
        "description": "Add a configured local key to ssh-agent; remove it after the task.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, "identity_file": {"type": "string"}},
            "additionalProperties": False,
        },
        "handler": agent_add,
    },
    "remotex_ssh_agent_remove": {
        "description": "Remove a configured local key from ssh-agent.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, "identity_file": {"type": "string"}},
            "additionalProperties": False,
        },
        "handler": agent_remove,
    },
    "remotex_ssh_key_fingerprint": {
        "description": "Return the SHA-256 fingerprint of a configured public key file.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, "public_key_file": {"type": "string"}},
            "additionalProperties": False,
        },
        "handler": key_fingerprint,
    },
}
