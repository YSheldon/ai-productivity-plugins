from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import secrets
import sys
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any, Protocol


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_core import default_config_path
from release_gate_credentials import (
    CredentialProviderError,
    DEFAULT_AUDIT_CREDENTIAL_TARGET,
    DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET,
    read_windows_generic_credential,
)


_CRED_TYPE_GENERIC = 1
_ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CRED_PERSIST_LOCAL_MACHINE = 2


class ProvisioningError(RuntimeError):
    pass


class CredentialStore(Protocol):
    def read(self, target: str) -> str | None: ...

    def write(self, target: str, value: str) -> None: ...


class _CredentialW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", wintypes.LPVOID),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class WindowsCredentialStore:
    def read(self, target: str) -> str | None:
        return read_windows_generic_credential(target)

    def write(self, target: str, value: str) -> None:
        if os.name != "nt":
            raise ProvisioningError(
                "Windows Credential Manager is unavailable on this platform"
            )
        encoded = value.encode("utf-8")
        if not encoded:
            raise ProvisioningError("credential value cannot be empty")
        advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        cred_write = advapi32.CredWriteW
        cred_write.argtypes = [ctypes.POINTER(_CredentialW), wintypes.DWORD]
        cred_write.restype = wintypes.BOOL
        blob = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
        credential = _CredentialW()
        credential.Type = _CRED_TYPE_GENERIC
        credential.TargetName = target
        credential.Comment = "Product release gate managed credential"
        credential.CredentialBlobSize = len(encoded)
        credential.CredentialBlob = ctypes.cast(
            blob,
            ctypes.POINTER(ctypes.c_ubyte),
        )
        credential.Persist = _CRED_PERSIST_LOCAL_MACHINE
        credential.UserName = "product-release-gate"
        if not cred_write(ctypes.byref(credential), 0):
            error = ctypes.get_last_error()
            raise ProvisioningError(
                f"Windows Credential Manager write failed with error {error}"
            )


def _load_config(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ProvisioningError("release-gate configuration is missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvisioningError(
            "release-gate configuration is unreadable or invalid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise ProvisioningError("release-gate configuration must be one JSON object")
    return payload


def _write_config(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _credential_bindings(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    production = config.get("production")
    if not isinstance(production, dict):
        raise ProvisioningError("production configuration is required")
    authorization = production.setdefault("authorization", {})
    audit = production.setdefault("audit", {})
    if not isinstance(authorization, dict) or not isinstance(audit, dict):
        raise ProvisioningError("authorization and audit configuration must be objects")
    authorization.setdefault("key_env", "PRODUCT_RELEASE_GATE_AUTH_KEY")
    audit.setdefault("key_env", "PRODUCT_RELEASE_GATE_AUDIT_KEY")
    authorization.setdefault(
        "credential_target",
        DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET,
    )
    audit.setdefault("credential_target", DEFAULT_AUDIT_CREDENTIAL_TARGET)
    authorization_env = str(authorization.get("key_env") or "").strip()
    audit_env = str(audit.get("key_env") or "").strip()
    if not _ENV_NAME_PATTERN.fullmatch(authorization_env):
        raise ProvisioningError("authorization key_env is missing or invalid")
    if not _ENV_NAME_PATTERN.fullmatch(audit_env):
        raise ProvisioningError("audit key_env is missing or invalid")
    targets = (
        str(authorization.get("credential_target") or "").strip(),
        str(audit.get("credential_target") or "").strip(),
    )
    if any(
        not target
        or len(target) > 256
        or any(ord(character) < 32 for character in target)
        for target in targets
    ):
        raise ProvisioningError(
            "credential targets must contain 1-256 safe characters"
        )
    authorization["key_env"] = authorization_env
    audit["key_env"] = audit_env
    authorization["credential_target"] = targets[0]
    audit["credential_target"] = targets[1]
    if authorization["key_env"] == audit["key_env"]:
        raise ProvisioningError(
            "authorization and audit keys must use different environment variables"
        )
    if authorization["credential_target"] == audit["credential_target"]:
        raise ProvisioningError(
            "authorization and audit keys must use different credential targets"
        )
    return authorization, audit


def credential_status(
    config_path: str | Path,
    *,
    store: CredentialStore | None = None,
) -> dict[str, Any]:
    path = Path(config_path).expanduser().resolve(strict=False)
    config = _load_config(path)
    authorization, audit = _credential_bindings(config)
    provider = store or WindowsCredentialStore()
    authorization_value = provider.read(str(authorization["credential_target"]))
    audit_value = provider.read(str(audit["credential_target"]))
    ready = bool(
        authorization_value
        and audit_value
        and len(authorization_value.encode("utf-8")) >= 32
        and len(audit_value.encode("utf-8")) >= 32
        and not secrets.compare_digest(authorization_value, audit_value)
    )
    return {
        "status": "ready" if ready else "CAPABILITY_BLOCKED",
        "ready": ready,
        "authorization_credential_present": bool(authorization_value),
        "audit_credential_present": bool(audit_value),
        "credentials_distinct": bool(
            authorization_value
            and audit_value
            and not secrets.compare_digest(authorization_value, audit_value)
        ),
        "secret_values_returned": False,
        "config_path": str(path),
    }


def provision_credentials(
    config_path: str | Path,
    *,
    store: CredentialStore | None = None,
) -> dict[str, Any]:
    path = Path(config_path).expanduser().resolve(strict=False)
    config = _load_config(path)
    authorization, audit = _credential_bindings(config)
    provider = store or WindowsCredentialStore()
    targets = (
        str(authorization["credential_target"]),
        str(audit["credential_target"]),
    )
    values = [provider.read(target) for target in targets]
    created = 0
    for index, value in enumerate(values):
        if value:
            continue
        candidate = secrets.token_urlsafe(48)
        other = values[1 - index]
        while other and secrets.compare_digest(candidate, other):
            candidate = secrets.token_urlsafe(48)
        provider.write(targets[index], candidate)
        values[index] = candidate
        created += 1
    if not all(values) or any(len(value.encode("utf-8")) < 32 for value in values):
        raise ProvisioningError("managed credentials must each contain at least 32 bytes")
    if secrets.compare_digest(values[0], values[1]):
        raise ProvisioningError("authorization and audit credentials must be different")
    _write_config(path, config)
    result = credential_status(path, store=provider)
    result.update(
        {
            "credentials_created": created,
            "credentials_reused": 2 - created,
            "credential_values_printed": False,
            "rotation_supported_by_this_command": False,
        }
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Provision or check per-user Windows Credential Manager secrets "
            "for product-release-gate without printing their values."
        )
    )
    parser.add_argument("--config", default=str(default_config_path()))
    parser.add_argument("action", choices=("init", "status"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = (
            provision_credentials(args.config)
            if args.action == "init"
            else credential_status(args.config)
        )
    except (CredentialProviderError, ProvisioningError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "CAPABILITY_BLOCKED",
                    "ready": False,
                    "error_code": "CREDENTIAL_PROVISIONING_BLOCKED",
                    "error": str(exc),
                    "secret_values_returned": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 3
    print(json.dumps(result, indent=2))
    return 0 if result.get("ready") else 3


if __name__ == "__main__":
    raise SystemExit(main())
