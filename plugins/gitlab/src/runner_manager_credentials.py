from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes


RUNNER_MANAGER_CREDENTIAL_PREFIX = "CodexGitLab/runner-manager/v1/"
_POLICY_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168


class RunnerManagerCredentialError(RuntimeError):
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


def credential_target(policy_name: object) -> str:
    name = str(policy_name or "").strip()
    if not _POLICY_NAME_PATTERN.fullmatch(name):
        raise RunnerManagerCredentialError("policy_name is invalid")
    return f"{RUNNER_MANAGER_CREDENTIAL_PREFIX}{name}"


def validate_token(value: object) -> str:
    token = str(value or "")
    if not token or len(token.encode("utf-8")) > 8192:
        raise RunnerManagerCredentialError("GitLab Runner manager token is missing or invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in token):
        raise RunnerManagerCredentialError("GitLab Runner manager token is missing or invalid")
    return token


def _normalize_target(target: object) -> str:
    value = str(target or "")
    if not value.startswith(RUNNER_MANAGER_CREDENTIAL_PREFIX):
        raise RunnerManagerCredentialError("credential target is invalid")
    try:
        normalized = credential_target(value[len(RUNNER_MANAGER_CREDENTIAL_PREFIX) :])
    except RunnerManagerCredentialError as exc:
        raise RunnerManagerCredentialError("credential target is invalid") from exc
    if normalized != value:
        raise RunnerManagerCredentialError("credential target is invalid")
    return normalized


def _require_windows() -> None:
    if os.name != "nt":
        raise RunnerManagerCredentialError("Windows Credential Manager is unavailable on this platform")


class WindowsCredentialStore:
    """Per-user Windows Credential Manager storage for a short-lived manager token."""

    def read(self, target: str) -> str | None:
        _require_windows()
        normalized = _normalize_target(target)
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

        credential = ctypes.POINTER(_CredentialW)()
        if not cred_read(normalized, _CRED_TYPE_GENERIC, 0, ctypes.byref(credential)):
            error = ctypes.get_last_error()
            if error == _ERROR_NOT_FOUND:
                return None
            raise RunnerManagerCredentialError(
                f"Windows Credential Manager read failed with error {error}"
            )
        try:
            record = credential.contents
            raw = ctypes.string_at(record.CredentialBlob, int(record.CredentialBlobSize))
            try:
                return validate_token(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise RunnerManagerCredentialError("credential value is not valid UTF-8") from exc
        finally:
            cred_free(credential)

    def write(self, target: str, value: object) -> None:
        _require_windows()
        normalized = _normalize_target(target)
        token = validate_token(value)
        encoded = token.encode("utf-8")
        advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        cred_write = advapi32.CredWriteW
        cred_write.argtypes = [ctypes.POINTER(_CredentialW), wintypes.DWORD]
        cred_write.restype = wintypes.BOOL
        blob = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
        credential = _CredentialW()
        credential.Type = _CRED_TYPE_GENERIC
        credential.TargetName = normalized
        credential.Comment = "Codex GitLab Runner manager credential"
        credential.CredentialBlobSize = len(encoded)
        credential.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte))
        credential.Persist = _CRED_PERSIST_LOCAL_MACHINE
        credential.UserName = "codex-gitlab-runner"
        if not cred_write(ctypes.byref(credential), 0):
            error = ctypes.get_last_error()
            raise RunnerManagerCredentialError(
                f"Windows Credential Manager write failed with error {error}"
            )

    def delete(self, target: str) -> bool:
        _require_windows()
        normalized = _normalize_target(target)
        advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        cred_delete = advapi32.CredDeleteW
        cred_delete.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        cred_delete.restype = wintypes.BOOL
        if cred_delete(normalized, _CRED_TYPE_GENERIC, 0):
            return True
        error = ctypes.get_last_error()
        if error == _ERROR_NOT_FOUND:
            return False
        raise RunnerManagerCredentialError(
            f"Windows Credential Manager delete failed with error {error}"
        )
