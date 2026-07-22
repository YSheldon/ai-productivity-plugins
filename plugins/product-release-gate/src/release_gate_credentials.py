from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes
from typing import Callable, Mapping


DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET = (
    "ProductReleaseGate/authorization/v1"
)
DEFAULT_AUDIT_CREDENTIAL_TARGET = "ProductReleaseGate/audit/v1"

_ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CRED_TYPE_GENERIC = 1
_ERROR_NOT_FOUND = 1168


class CredentialProviderError(RuntimeError):
    pass


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


CredentialReader = Callable[[str], str | None]


def _wincred() -> tuple[object, object, object]:
    if os.name != "nt":
        raise CredentialProviderError(
            "Windows Credential Manager is unavailable on this platform"
        )
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    cred_read = advapi32.CredReadW
    cred_read.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(_CredentialW)),
    ]
    cred_read.restype = wintypes.BOOL
    cred_free = advapi32.CredFree
    cred_free.argtypes = [wintypes.LPVOID]
    cred_free.restype = None
    return advapi32, cred_read, cred_free


def read_windows_generic_credential(target: str) -> str | None:
    normalized = str(target or "").strip()
    if not normalized:
        raise CredentialProviderError("credential target is required")
    _advapi32, cred_read, cred_free = _wincred()
    credential = ctypes.POINTER(_CredentialW)()
    if not cred_read(
        normalized,
        _CRED_TYPE_GENERIC,
        0,
        ctypes.byref(credential),
    ):
        error = ctypes.get_last_error()
        if error == _ERROR_NOT_FOUND:
            return None
        raise CredentialProviderError(
            f"Windows Credential Manager read failed with error {error}"
        )
    try:
        record = credential.contents
        raw = ctypes.string_at(
            record.CredentialBlob,
            int(record.CredentialBlobSize),
        )
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CredentialProviderError(
                "credential value is not valid UTF-8"
            ) from exc
    finally:
        cred_free(credential)


def resolve_configured_secret(
    config: Mapping[str, object],
    *,
    environ: Mapping[str, str] | None = None,
    credential_reader: CredentialReader | None = None,
) -> tuple[str, str]:
    environment = os.environ if environ is None else environ
    key_env = str(config.get("key_env") or "").strip()
    if not _ENV_NAME_PATTERN.fullmatch(key_env):
        raise CredentialProviderError(
            "credential key_env is missing or invalid"
        )
    from_environment = str(environment.get(key_env) or "")
    if from_environment:
        return from_environment, "environment"

    target = str(config.get("credential_target") or "").strip()
    if not target:
        return "", "missing"
    reader = credential_reader or read_windows_generic_credential
    value = reader(target)
    return (str(value), "windows_credential_manager") if value else ("", "missing")
