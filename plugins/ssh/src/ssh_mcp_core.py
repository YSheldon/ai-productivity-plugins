from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any, Callable


SERVER_NAME = "ssh"
SERVER_VERSION = "0.1.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "codex-ssh" / "config.json"
DEFAULT_PORT = 22
DEFAULT_CONNECT_TIMEOUT_SECONDS = 10
DEFAULT_COMMAND_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 600
MAX_COMMAND_LENGTH = 64 * 1024
MAX_SCRIPT_LENGTH = 1024 * 1024


class ToolError(Exception):
    pass


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def tool_result(data: Any) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(data, ensure_ascii=False, indent=2),
            }
        ]
    }


def error_result(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def config_path() -> Path:
    raw = os.environ.get("SSH_CONFIG")
    return Path(os.path.expandvars(os.path.expanduser(raw))) if raw else DEFAULT_CONFIG_PATH


def load_config() -> dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ToolError(f"Unable to read SSH config at {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ToolError(f"Invalid SSH config JSON at {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ToolError(f"SSH config at {path} must contain a JSON object")
    return value


def profile_config(profile: str | None = None) -> dict[str, Any]:
    config = load_config()
    profiles = config.get("profiles") if isinstance(config.get("profiles"), dict) else {}
    selected = profile or config.get("default") or config.get("default_profile") or os.environ.get("SSH_PROFILE")
    data: dict[str, Any] = {}

    if selected:
        if profiles:
            if selected not in profiles:
                raise ToolError(f"SSH profile not found: {selected}")
            selected_data = profiles.get(selected)
            if not isinstance(selected_data, dict):
                raise ToolError(f"SSH profile must be an object: {selected}")
            data.update(selected_data)
        elif selected not in {"env", "default"}:
            raise ToolError(f"SSH profile not found: {selected}")
        data["profile"] = str(selected)
    elif profiles:
        first_name = next(iter(profiles))
        first_data = profiles.get(first_name)
        if not isinstance(first_data, dict):
            raise ToolError(f"SSH profile must be an object: {first_name}")
        data.update(first_data)
        data["profile"] = str(first_name)
    else:
        data["profile"] = "env"

    environment_defaults = {
        "host": os.environ.get("SSH_HOST"),
        "user": os.environ.get("SSH_USER"),
        "port": os.environ.get("SSH_PORT"),
        "identity_file": os.environ.get("SSH_IDENTITY_FILE"),
        "known_hosts_file": os.environ.get("SSH_KNOWN_HOSTS_FILE"),
        "strict_host_key_checking": os.environ.get("SSH_STRICT_HOST_KEY_CHECKING"),
        "identities_only": os.environ.get("SSH_IDENTITIES_ONLY"),
        "connect_timeout_seconds": os.environ.get("SSH_CONNECT_TIMEOUT_SECONDS"),
    }
    for key, value in environment_defaults.items():
        if key not in data or data[key] in (None, ""):
            if value not in (None, ""):
                data[key] = value
    data.setdefault("port", DEFAULT_PORT)
    data.setdefault("strict_host_key_checking", "yes")
    data.setdefault("identities_only", True)
    data.setdefault("connect_timeout_seconds", DEFAULT_CONNECT_TIMEOUT_SECONDS)
    return data


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


TOKEN_PATTERN = re.compile(
    r"(?i)\b(?:glpat-[A-Za-z0-9_\-]+|ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|"
    r"xox[baprs]-[A-Za-z0-9-]+|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_\-]{16,})\b"
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(\b(?:password|passwd|secret|token|private[_-]?key|client_secret)\b\s*[:=]\s*)([^\s,;]+)"
)
PEM_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.+?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def redact_text(value: Any) -> str:
    text = _text(value)
    text = PEM_PATTERN.sub("[REDACTED PRIVATE KEY]", text)
    text = TOKEN_PATTERN.sub("[REDACTED TOKEN]", text)
    return SECRET_ASSIGNMENT_PATTERN.sub(r"\1[REDACTED]", text)


def _required_text(value: Any, field: str) -> str:
    text = _text(value).strip()
    if not text:
        raise ToolError(f"{field} is required")
    if "\x00" in text or "\r" in text or "\n" in text:
        raise ToolError(f"{field} must not contain NUL or newline characters")
    return text


def _validate_host(value: Any) -> str:
    host = _required_text(value, "host")
    if any(char.isspace() for char in host) or host.startswith("-"):
        raise ToolError("host must be a hostname or address, not an option or whitespace-delimited value")
    return host


def _validate_user(value: Any) -> str:
    user = _required_text(value, "user")
    if any(char.isspace() for char in user) or user.startswith("-") or "@" in user:
        raise ToolError("user contains unsupported characters")
    return user


def _validate_port(value: Any) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ToolError("port must be an integer between 1 and 65535") from exc
    if not 1 <= port <= 65535:
        raise ToolError("port must be an integer between 1 and 65535")
    return port


def _validate_timeout(value: Any, default: int) -> int:
    try:
        timeout = int(value or default)
    except (TypeError, ValueError) as exc:
        raise ToolError("timeout must be an integer number of seconds") from exc
    if not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ToolError(f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds")
    return timeout


def _as_bool(value: Any, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ToolError(f"invalid boolean value: {value}")


def _strict_host_key_mode(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    mode = str(value or "yes").strip().lower()
    if mode in {"yes", "accept-new", "no"}:
        return mode
    raise ToolError("strict_host_key_checking must be yes, accept-new, or no")


def _expand_path(value: Any, field: str) -> Path:
    raw = _required_text(value, field)
    return Path(os.path.expandvars(os.path.expanduser(raw)))


def connection_config(profile: str | None = None) -> dict[str, Any]:
    raw = profile_config(profile)
    host = _validate_host(raw.get("host"))
    user = _validate_user(raw.get("user"))
    port = _validate_port(raw.get("port", DEFAULT_PORT))
    strict = _strict_host_key_mode(raw.get("strict_host_key_checking", "yes"))
    identities_only = _as_bool(raw.get("identities_only"), True)
    connect_timeout = _validate_timeout(
        raw.get("connect_timeout_seconds"), DEFAULT_CONNECT_TIMEOUT_SECONDS
    )
    identity = _expand_path(raw["identity_file"], "identity_file") if raw.get("identity_file") else None
    known_hosts = (
        _expand_path(raw["known_hosts_file"], "known_hosts_file")
        if raw.get("known_hosts_file")
        else None
    )
    return {
        "profile": raw.get("profile") or "env",
        "host": host,
        "user": user,
        "port": port,
        "strict_host_key_checking": strict,
        "identities_only": identities_only,
        "connect_timeout_seconds": connect_timeout,
        "identity_file": identity,
        "known_hosts_file": known_hosts,
    }


def _executable(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise ToolError(f"OpenSSH executable not found in PATH: {name}")
    return path


def _common_ssh_options(cfg: dict[str, Any], timeout: int) -> list[str]:
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
    ]
    if cfg["identities_only"]:
        options.extend(["-o", "IdentitiesOnly=yes"])
    if cfg["known_hosts_file"]:
        options.extend(["-o", f"UserKnownHostsFile={cfg['known_hosts_file']}"])
    if cfg["identity_file"]:
        if not cfg["identity_file"].exists():
            raise ToolError(f"identity_file does not exist: {cfg['identity_file']}")
        options.extend(["-i", str(cfg["identity_file"])])
    return options


def ssh_arguments(cfg: dict[str, Any], timeout: int, command: str | None = None) -> list[str]:
    args = [_executable("ssh"), "-T"]
    args.extend(_common_ssh_options(cfg, timeout))
    args.extend(["-p", str(cfg["port"]), "-l", cfg["user"], cfg["host"]])
    if command is not None:
        args.append(command)
    return args


def scp_arguments(cfg: dict[str, Any], timeout: int) -> list[str]:
    args = [_executable("scp")]
    args.extend(_common_ssh_options(cfg, timeout))
    args.extend(["-P", str(cfg["port"])])
    return args


def _remote_path(value: Any) -> str:
    path = _required_text(value, "remote_path")
    if path.startswith("-"):
        raise ToolError("remote_path must not start with an option marker")
    return path


def _quote_remote_path(path: str) -> str:
    return "'" + path.replace("'", "'\\''") + "'"


def _remote_spec(cfg: dict[str, Any], path: str) -> str:
    host = cfg["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{cfg['user']}@{host}:{_quote_remote_path(path)}"


def run_process(
    argv: list[str],
    *,
    timeout: int,
    input_text: str | None = None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "check": False,
    }
    if input_text is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = input_text
    try:
        completed = subprocess.run(argv, **kwargs)
    except FileNotFoundError as exc:
        raise ToolError(f"Executable not found: {argv[0]}") from exc
    except OSError as exc:
        raise ToolError(f"Unable to start {argv[0]}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": None,
            "timed_out": True,
            "stdout": redact_text(getattr(exc, "stdout", "")),
            "stderr": redact_text(getattr(exc, "stderr", "")),
        }
    return {
        "returncode": completed.returncode,
        "timed_out": False,
        "stdout": redact_text(completed.stdout),
        "stderr": redact_text(completed.stderr),
    }


def _connection_result(cfg: dict[str, Any], outcome: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": outcome["returncode"] == 0 and not outcome["timed_out"],
        "profile": cfg["profile"],
        "host": cfg["host"],
        "user": cfg["user"],
        "port": cfg["port"],
        "returncode": outcome["returncode"],
        "timed_out": outcome["timed_out"],
        "stdout": outcome["stdout"],
        "stderr": outcome["stderr"],
    }


def list_profiles(_: dict[str, Any]) -> dict[str, Any]:
    config = load_config()
    profiles = config.get("profiles") if isinstance(config.get("profiles"), dict) else {}
    env_ready = bool(os.environ.get("SSH_HOST") and os.environ.get("SSH_USER"))
    selected = config.get("default") or config.get("default_profile") or os.environ.get("SSH_PROFILE")
    return tool_result(
        {
            "config_path": str(config_path()),
            "default": selected or ("env" if env_ready else None),
            "profiles": sorted(str(name) for name in profiles),
            "environment": {
                "SSH_HOST_set": bool(os.environ.get("SSH_HOST")),
                "SSH_USER_set": bool(os.environ.get("SSH_USER")),
                "SSH_IDENTITY_FILE_set": bool(os.environ.get("SSH_IDENTITY_FILE")),
            },
        }
    )


def test_connection(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    timeout = _validate_timeout(args.get("timeout_seconds"), cfg["connect_timeout_seconds"])
    outcome = run_process(ssh_arguments(cfg, timeout, "hostname"), timeout=timeout)
    return tool_result(_connection_result(cfg, outcome))


def run_command(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    command = _required_text(args.get("command"), "command")
    if len(command) > MAX_COMMAND_LENGTH:
        raise ToolError(f"command exceeds {MAX_COMMAND_LENGTH} characters; use ssh_run_script")
    if "\r" in command or "\n" in command:
        raise ToolError("command must be one line; use ssh_run_script for multi-line work")
    timeout = _validate_timeout(args.get("timeout_seconds"), DEFAULT_COMMAND_TIMEOUT_SECONDS)
    outcome = run_process(ssh_arguments(cfg, timeout, command), timeout=timeout)
    return tool_result(_connection_result(cfg, outcome))


def run_script(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    script = _required_text(args.get("script"), "script")
    if len(script) > MAX_SCRIPT_LENGTH:
        raise ToolError(f"script exceeds {MAX_SCRIPT_LENGTH} characters")
    shell = str(args.get("shell") or "sh")
    if shell not in {"sh", "bash"}:
        raise ToolError("shell must be sh or bash")
    timeout = _validate_timeout(args.get("timeout_seconds"), DEFAULT_COMMAND_TIMEOUT_SECONDS)
    outcome = run_process(ssh_arguments(cfg, timeout, f"{shell} -s"), timeout=timeout, input_text=script)
    return tool_result(_connection_result(cfg, outcome))


def _local_source(value: Any) -> Path:
    path = _expand_path(value, "local_path")
    if not path.exists():
        raise ToolError(f"local_path does not exist: {path}")
    if path.is_symlink():
        raise ToolError(f"local_path must not be a symlink: {path}")
    return path


def _local_destination(value: Any) -> Path:
    path = _expand_path(value, "local_path")
    if path.exists() and path.is_symlink():
        raise ToolError(f"local_path must not be a symlink: {path}")
    if not path.parent.exists() or not path.parent.is_dir():
        raise ToolError(f"local_path parent directory does not exist: {path.parent}")
    return path


def copy_to(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    local_path = _local_source(args.get("local_path"))
    recursive = _as_bool(args.get("recursive"), False)
    if local_path.is_dir() and not recursive:
        raise ToolError("local_path is a directory; set recursive=true to copy it")
    remote_path = _remote_path(args.get("remote_path"))
    timeout = _validate_timeout(args.get("timeout_seconds"), DEFAULT_COMMAND_TIMEOUT_SECONDS)
    argv = scp_arguments(cfg, timeout)
    if recursive:
        argv.append("-r")
    argv.extend([str(local_path), _remote_spec(cfg, remote_path)])
    outcome = run_process(argv, timeout=timeout)
    return tool_result(_connection_result(cfg, outcome))


def copy_from(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    remote_path = _remote_path(args.get("remote_path"))
    local_path = _local_destination(args.get("local_path"))
    recursive = _as_bool(args.get("recursive"), False)
    timeout = _validate_timeout(args.get("timeout_seconds"), DEFAULT_COMMAND_TIMEOUT_SECONDS)
    argv = scp_arguments(cfg, timeout)
    if recursive:
        argv.append("-r")
    argv.extend([_remote_spec(cfg, remote_path), str(local_path)])
    outcome = run_process(argv, timeout=timeout)
    return tool_result(_connection_result(cfg, outcome))


def _identity_path(args: dict[str, Any], cfg: dict[str, Any]) -> Path:
    raw = args.get("identity_file")
    if raw:
        path = _expand_path(raw, "identity_file")
    elif cfg.get("identity_file"):
        path = cfg["identity_file"]
    else:
        raise ToolError("identity_file is required for this agent operation")
    if not path.exists() or not path.is_file():
        raise ToolError(f"identity_file does not exist: {path}")
    return path


def agent_list(_: dict[str, Any]) -> dict[str, Any]:
    outcome = run_process([_executable("ssh-add"), "-l"], timeout=15)
    return tool_result(
        {
            "ok": outcome["returncode"] == 0,
            "returncode": outcome["returncode"],
            "stdout": outcome["stdout"],
            "stderr": outcome["stderr"],
        }
    )


def agent_add(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    path = _identity_path(args, cfg)
    outcome = run_process([_executable("ssh-add"), str(path)], timeout=30)
    return tool_result(
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
    cfg = connection_config(args.get("profile"))
    path = _identity_path(args, cfg)
    outcome = run_process([_executable("ssh-add"), "-d", str(path)], timeout=30)
    return tool_result(
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
        public_key = _expand_path(args["public_key_file"], "public_key_file")
    elif cfg.get("identity_file"):
        public_key = Path(str(cfg["identity_file"]) + ".pub")
    else:
        raise ToolError("public_key_file or profile identity_file is required")
    if not public_key.exists() or not public_key.is_file():
        raise ToolError(f"public key file does not exist: {public_key}")
    outcome = run_process([_executable("ssh-keygen"), "-lf", str(public_key), "-E", "sha256"], timeout=15)
    return tool_result(
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
        "description": "Optional SSH profile name from SSH_CONFIG.",
    }
}

COMMON_TIMEOUT = {
    "timeout_seconds": {
        "type": "integer",
        "minimum": 1,
        "maximum": MAX_TIMEOUT_SECONDS,
        "description": "Local subprocess timeout in seconds.",
    }
}


TOOLS: dict[str, dict[str, Any]] = {
    "ssh_list_profiles": {
        "description": "List SSH profile names and configuration readiness without exposing private key contents.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": list_profiles,
    },
    "ssh_test_connection": {
        "description": "Test one configured SSH connection with strict host-key and public-key-only defaults; runs a read-only hostname probe.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT},
            "additionalProperties": False,
        },
        "handler": test_connection,
    },
    "ssh_run_command": {
        "description": "Run one explicit, side-effectful command on a configured SSH host. Use ssh_run_script for multi-line work.",
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
    "ssh_run_script": {
        "description": "Send a multi-line shell script over SSH stdin and run it with sh -s or bash -s; this is side-effectful.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                "shell": {"type": "string", "enum": ["sh", "bash"]},
                "script": {"type": "string", "description": "Remote shell script sent through stdin."},
            },
            "required": ["script"],
            "additionalProperties": False,
        },
        "handler": run_script,
    },
    "ssh_copy_to": {
        "description": "Copy a local file or directory to a configured SSH host with SCP; this is side-effectful.",
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
    "ssh_copy_from": {
        "description": "Copy a remote file or directory to a local path with SCP; this is side-effectful locally.",
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
    "ssh_agent_list": {
        "description": "List local ssh-agent identities without exposing private key material.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": agent_list,
    },
    "ssh_agent_add": {
        "description": "Add one local private key to ssh-agent without using a lifetime constraint; remove it after the task.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, "identity_file": {"type": "string"}},
            "additionalProperties": False,
        },
        "handler": agent_add,
    },
    "ssh_agent_remove": {
        "description": "Remove one local private key from ssh-agent without displaying its contents.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, "identity_file": {"type": "string"}},
            "additionalProperties": False,
        },
        "handler": agent_remove,
    },
    "ssh_key_fingerprint": {
        "description": "Return the SHA-256 fingerprint of a configured or explicitly provided public key file.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, "public_key_file": {"type": "string"}},
            "additionalProperties": False,
        },
        "handler": key_fingerprint,
    },
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
            if tool_name not in TOOLS:
                raise ToolError(f"Unknown tool: {tool_name}")
            handler: Callable[[dict[str, Any]], dict[str, Any]] = TOOLS[tool_name]["handler"]
            return response(request_id, handler(arguments))
        return error_response(request_id, -32601, f"Method not found: {method}")
    except ToolError as exc:
        return response(request_id, error_result(str(exc)))
    except Exception as exc:
        eprint(traceback.format_exc())
        return response(request_id, error_result(f"Unexpected {type(exc).__name__}: {exc}"))


def send_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_stdio_server() -> None:
    eprint("SSH MCP stdio server started")
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
