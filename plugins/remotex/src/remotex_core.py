from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "remotex" / "config.json"
LEGACY_SSH_CONFIG_PATH = Path.home() / ".config" / "codex-ssh" / "config.json"
DEFAULT_CONNECT_TIMEOUT_SECONDS = 10
DEFAULT_COMMAND_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 600
MAX_COMMAND_LENGTH = 64 * 1024
MAX_SCRIPT_LENGTH = 1024 * 1024
MAX_OUTPUT_CHARS = 256 * 1024

KIND_ALIASES = {
    "ssh": "ssh",
    "rdp": "rdp",
    "esxi": "vsphere",
    "vcenter": "vsphere",
    "vsphere": "vsphere",
    "vmware": "vmware-workstation",
    "vmware-workstation": "vmware-workstation",
    "workstation": "vmware-workstation",
}

FORBIDDEN_LITERAL_SECRET_KEYS = {
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "private_key",
    "private_key_data",
    "private_key_pem",
}

TOKEN_PATTERN = re.compile(
    r"(?i)\b(?:glpat-[A-Za-z0-9_\-]+|ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|"
    r"xox[baprs]-[A-Za-z0-9-]+|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_\-]{16,})\b"
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(\b(?:password|passwd|passphrase|secret|token|private[_-]?key|client_secret)\b\s*[:=]\s*)([^\s,;]+)"
)
PEM_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.+?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
URL_USERINFO_PATTERN = re.compile(r"(?i)(https?://)[^/@\s:]+:[^@\s]+@")
ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ToolError(Exception):
    pass


@dataclass(frozen=True)
class ConfigBundle:
    data: dict[str, Any]
    path: Path
    source: str
    exists: bool


@dataclass(frozen=True)
class CredentialValue:
    username: str
    password: str


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def redact_text(value: Any) -> str:
    text = _text(value)
    text = PEM_PATTERN.sub("[REDACTED PRIVATE KEY]", text)
    text = TOKEN_PATTERN.sub("[REDACTED TOKEN]", text)
    text = URL_USERINFO_PATTERN.sub(r"\1[REDACTED]@", text)
    text = SECRET_ASSIGNMENT_PATTERN.sub(r"\1[REDACTED]", text)
    if len(text) > MAX_OUTPUT_CHARS:
        return text[:MAX_OUTPUT_CHARS] + "\n[OUTPUT TRUNCATED]"
    return text


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


def _required_text(value: Any, field: str) -> str:
    text = _text(value).strip()
    if not text:
        raise ToolError(f"{field} is required")
    if "\x00" in text or "\r" in text or "\n" in text:
        raise ToolError(f"{field} must not contain NUL or newline characters")
    return text


def validate_host(value: Any) -> str:
    host = _required_text(value, "host")
    if any(char.isspace() for char in host) or host.startswith("-"):
        raise ToolError("host must be a hostname or address, not an option")
    return host


def validate_user(value: Any) -> str:
    user = _required_text(value, "user")
    if any(char.isspace() for char in user) or user.startswith("-") or "@" in user:
        raise ToolError("user contains unsupported characters")
    return user


def validate_port(value: Any, default: int) -> int:
    try:
        port = int(default if value in (None, "") else value)
    except (TypeError, ValueError) as exc:
        raise ToolError("port must be an integer between 1 and 65535") from exc
    if not 1 <= port <= 65535:
        raise ToolError("port must be an integer between 1 and 65535")
    return port


def validate_timeout(value: Any, default: int) -> int:
    try:
        timeout = int(default if value in (None, "") else value)
    except (TypeError, ValueError) as exc:
        raise ToolError("timeout must be an integer number of seconds") from exc
    if not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ToolError(f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds")
    return timeout


def as_bool(value: Any, default: bool) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ToolError(f"invalid boolean value: {value}")


def expand_path(value: Any, field: str) -> Path:
    raw = _required_text(value, field)
    return Path(os.path.expandvars(os.path.expanduser(raw)))


def validate_selector(value: Any, field: str) -> str:
    selected = _required_text(value, field)
    if selected.startswith("-"):
        raise ToolError(f"{field} must not start with an option marker")
    return selected


def normalize_kind(value: Any) -> str:
    raw = _required_text(value, "kind").lower()
    if raw not in KIND_ALIASES:
        supported = ", ".join(sorted(set(KIND_ALIASES.values())))
        raise ToolError(f"unsupported profile kind '{raw}'; expected one of: {supported}")
    return KIND_ALIASES[raw]


def config_path() -> Path:
    raw = os.environ.get("REMOTEX_CONFIG")
    return expand_path(raw, "REMOTEX_CONFIG") if raw else DEFAULT_CONFIG_PATH


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ToolError(f"Unable to read {label} at {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ToolError(f"Invalid JSON in {label} at {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ToolError(f"{label} at {path} must contain a JSON object")
    return value


def _reject_literal_secrets(value: Any, path: str = "config") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in FORBIDDEN_LITERAL_SECRET_KEYS:
                raise ToolError(
                    f"{path}.{key} is not allowed; use an environment-variable or "
                    "Windows Credential Manager reference"
                )
            _reject_literal_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_literal_secrets(child, f"{path}[{index}]")


def _validate_config(data: dict[str, Any]) -> dict[str, Any]:
    _reject_literal_secrets(data)
    version = data.get("version", 1)
    if version != 1:
        raise ToolError("RemoteX config version must be 1")
    profiles = data.get("profiles", {})
    defaults = data.get("defaults", {})
    if not isinstance(profiles, dict):
        raise ToolError("RemoteX config field 'profiles' must be an object")
    if not isinstance(defaults, dict):
        raise ToolError("RemoteX config field 'defaults' must be an object")
    for name, profile in profiles.items():
        if not isinstance(name, str) or not name.strip() or len(name) > 128:
            raise ToolError("RemoteX profile names must be non-empty strings up to 128 characters")
        if not isinstance(profile, dict):
            raise ToolError(f"RemoteX profile '{name}' must be an object")
        normalize_kind(profile.get("kind"))
    return {"version": 1, "defaults": defaults, "profiles": profiles}


def _legacy_ssh_config_path() -> Path:
    raw = os.environ.get("SSH_CONFIG")
    return expand_path(raw, "SSH_CONFIG") if raw else LEGACY_SSH_CONFIG_PATH


def _convert_legacy_ssh(data: dict[str, Any]) -> dict[str, Any]:
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ToolError("Legacy SSH config field 'profiles' must be an object")
    converted: dict[str, Any] = {}
    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ToolError(f"Legacy SSH profile '{name}' must be an object")
        converted[str(name)] = {"kind": "ssh", **profile}
    default_name = data.get("default") or data.get("default_profile")
    defaults = {"ssh": str(default_name)} if default_name else {}
    return {"version": 1, "defaults": defaults, "profiles": converted}


def _ssh_environment_config() -> dict[str, Any] | None:
    host = os.environ.get("SSH_HOST")
    user = os.environ.get("SSH_USER")
    if not host or not user:
        return None
    profile: dict[str, Any] = {
        "kind": "ssh",
        "host": host,
        "user": user,
        "port": os.environ.get("SSH_PORT") or 22,
        "identity_file": os.environ.get("SSH_IDENTITY_FILE"),
        "known_hosts_file": os.environ.get("SSH_KNOWN_HOSTS_FILE"),
        "strict_host_key_checking": os.environ.get("SSH_STRICT_HOST_KEY_CHECKING") or "yes",
        "connect_timeout_seconds": os.environ.get("SSH_CONNECT_TIMEOUT_SECONDS") or 10,
    }
    profile = {key: value for key, value in profile.items() if value not in (None, "")}
    return {
        "version": 1,
        "defaults": {"ssh": "ssh-env"},
        "profiles": {"ssh-env": profile},
    }


def load_config() -> ConfigBundle:
    path = config_path()
    if path.exists():
        return ConfigBundle(_validate_config(_read_json(path, "RemoteX config")), path, "remotex", True)

    if os.environ.get("REMOTEX_CONFIG"):
        return ConfigBundle({"version": 1, "defaults": {}, "profiles": {}}, path, "missing", False)

    legacy_path = _legacy_ssh_config_path()
    if legacy_path.exists():
        converted = _convert_legacy_ssh(_read_json(legacy_path, "legacy SSH config"))
        return ConfigBundle(_validate_config(converted), legacy_path, "legacy-ssh", True)

    environment_config = _ssh_environment_config()
    if environment_config:
        return ConfigBundle(_validate_config(environment_config), path, "ssh-environment", False)

    return ConfigBundle({"version": 1, "defaults": {}, "profiles": {}}, path, "missing", False)


def select_profile(kind: str, requested: Any = None) -> tuple[str, dict[str, Any], ConfigBundle]:
    canonical_kind = normalize_kind(kind)
    bundle = load_config()
    profiles = bundle.data["profiles"]
    candidates = [
        name
        for name, profile in profiles.items()
        if normalize_kind(profile.get("kind")) == canonical_kind
    ]
    selected = _text(requested).strip() or _text(bundle.data["defaults"].get(canonical_kind)).strip()
    if not selected:
        if len(candidates) == 1:
            selected = candidates[0]
        elif not candidates:
            raise ToolError(
                f"No {canonical_kind} profile is configured. Create {bundle.path} from the "
                "RemoteX config example; credentials must be references, not literal secrets."
            )
        else:
            raise ToolError(
                f"Multiple {canonical_kind} profiles are configured; pass profile or set "
                f"defaults.{canonical_kind}."
            )
    if selected not in profiles:
        raise ToolError(f"RemoteX profile not found: {selected}")
    profile = profiles[selected]
    actual_kind = normalize_kind(profile.get("kind"))
    if actual_kind != canonical_kind:
        raise ToolError(
            f"RemoteX profile '{selected}' has kind '{actual_kind}', not '{canonical_kind}'"
        )
    return selected, dict(profile), bundle


def find_executable(name: str, configured: Any = None) -> str:
    if configured not in (None, ""):
        path = expand_path(configured, f"{name}_path")
        if not path.exists() or not path.is_file():
            raise ToolError(f"Configured {name} executable does not exist: {path}")
        return str(path)
    found = shutil.which(name)
    if not found:
        raise ToolError(f"Required executable not found: {name}")
    return found


def executable_available(name: str, configured: Any = None) -> bool:
    try:
        find_executable(name, configured)
    except ToolError:
        return False
    return True


def run_process(
    argv: list[str],
    *,
    timeout: int,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "check": False,
        "env": environment,
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


def _environment_name(value: Any, field: str) -> str:
    name = _required_text(value, field)
    if not ENV_NAME_PATTERN.fullmatch(name):
        raise ToolError(f"{field} must be an environment variable name")
    return name


def _decode_credential_blob(blob: bytes) -> str:
    if not blob:
        return ""
    if len(blob) % 2 == 0:
        try:
            decoded = blob.decode("utf-16-le").rstrip("\x00")
            if decoded:
                return decoded
        except UnicodeDecodeError:
            pass
    return blob.decode("utf-8", errors="replace").rstrip("\x00")


def read_windows_generic_credential(target: Any) -> CredentialValue:
    target_name = _required_text(target, "credential.target")
    if os.name != "nt":
        raise ToolError("Windows Credential Manager is only available on Windows")

    from ctypes import wintypes

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    credential_pointer = ctypes.POINTER(CREDENTIALW)()
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    advapi32.CredReadW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(CREDENTIALW)),
    ]
    advapi32.CredReadW.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    advapi32.CredFree.restype = None

    if not advapi32.CredReadW(target_name, 1, 0, ctypes.byref(credential_pointer)):
        error_code = ctypes.get_last_error()
        if error_code == 1168:
            raise ToolError(f"Windows generic credential not found: {target_name}")
        raise ToolError(
            f"Unable to read Windows generic credential '{target_name}' (Win32 error {error_code})"
        )
    try:
        credential = credential_pointer.contents
        blob = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        username = credential.UserName or ""
        password = _decode_credential_blob(blob)
        if not username or not password:
            raise ToolError(f"Windows generic credential is incomplete: {target_name}")
        return CredentialValue(username=username, password=password)
    finally:
        advapi32.CredFree(credential_pointer)


def credential_status(credential: Any) -> dict[str, Any]:
    if not isinstance(credential, dict):
        return {"source": None, "ready": False, "reason": "credential reference is missing"}
    source = _text(credential.get("source")).strip().lower()
    if source == "environment":
        username_env = _environment_name(credential.get("username_env"), "credential.username_env")
        password_env = _environment_name(credential.get("password_env"), "credential.password_env")
        missing = [name for name in (username_env, password_env) if not os.environ.get(name)]
        return {
            "source": source,
            "ready": not missing,
            "missing_environment_variables": missing,
        }
    if source == "windows-credential-manager":
        target = _required_text(credential.get("target"), "credential.target")
        if os.name != "nt":
            return {
                "source": source,
                "target": target,
                "ready": False,
                "reason": "Windows Credential Manager is only available on Windows",
            }
        from windows_credentials import credential_exists

        if not credential_exists(target, credential_types=(1,)):
            return {
                "source": source,
                "target": target,
                "ready": False,
                "reason": f"Windows generic credential was not found: {target}",
            }
        return {"source": source, "target": target, "ready": True}
    return {"source": source or None, "ready": False, "reason": "unsupported credential source"}


def resolve_username_password(credential: Any) -> CredentialValue:
    status = credential_status(credential)
    if not status.get("ready"):
        raise ToolError(_text(status.get("reason")) or f"Credential is not ready: {status}")
    source = _text(credential.get("source")).strip().lower()
    if source == "environment":
        username_env = _environment_name(credential.get("username_env"), "credential.username_env")
        password_env = _environment_name(credential.get("password_env"), "credential.password_env")
        return CredentialValue(
            username=_required_text(os.environ.get(username_env), username_env),
            password=_required_text(os.environ.get(password_env), password_env),
        )
    return read_windows_generic_credential(credential.get("target"))
