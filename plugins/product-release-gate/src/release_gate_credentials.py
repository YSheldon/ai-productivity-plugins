from __future__ import annotations

import ctypes
import hashlib
import hmac
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


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("Sid", wintypes.LPVOID),
        ("Attributes", wintypes.DWORD),
    ]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


CredentialReader = Callable[[str], str | None]
RuntimePrincipalProvider = Callable[[], str]


def runtime_principal_sha256(principal: str) -> str:
    normalized = str(principal or "").strip()
    if (
        not normalized
        or len(normalized) > 512
        or any(ord(character) < 32 for character in normalized)
    ):
        raise CredentialProviderError("runtime principal is missing or invalid")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _windows_runtime_principal() -> str:
    token_query = 0x0008
    token_user_class = 1
    error_insufficient_buffer = 122
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)

    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = wintypes.HANDLE
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    open_process_token.restype = wintypes.BOOL
    get_token_information = advapi32.GetTokenInformation
    get_token_information.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_token_information.restype = wintypes.BOOL
    convert_sid = advapi32.ConvertSidToStringSidW
    convert_sid.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    convert_sid.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    token = wintypes.HANDLE()
    if not open_process_token(
        get_current_process(),
        token_query,
        ctypes.byref(token),
    ):
        error = ctypes.get_last_error()
        raise CredentialProviderError(
            f"Windows process token open failed with error {error}"
        )
    try:
        required = wintypes.DWORD()
        ctypes.set_last_error(0)
        get_token_information(
            token,
            token_user_class,
            None,
            0,
            ctypes.byref(required),
        )
        error = ctypes.get_last_error()
        if error != error_insufficient_buffer or required.value == 0:
            raise CredentialProviderError(
                f"Windows token identity sizing failed with error {error}"
            )
        buffer = ctypes.create_string_buffer(required.value)
        if not get_token_information(
            token,
            token_user_class,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            error = ctypes.get_last_error()
            raise CredentialProviderError(
                f"Windows token identity read failed with error {error}"
            )
        token_user = ctypes.cast(
            buffer,
            ctypes.POINTER(_TokenUser),
        ).contents
        sid_text = wintypes.LPWSTR()
        if not convert_sid(token_user.User.Sid, ctypes.byref(sid_text)):
            error = ctypes.get_last_error()
            raise CredentialProviderError(
                f"Windows SID conversion failed with error {error}"
            )
        try:
            sid = str(sid_text.value or "").strip()
        finally:
            local_free(ctypes.cast(sid_text, ctypes.c_void_p))
    finally:
        close_handle(token)
    if not sid:
        raise CredentialProviderError("Windows runtime SID is empty")
    return f"windows-sid:{sid}"


def current_runtime_principal() -> str:
    if os.name == "nt":
        return _windows_runtime_principal()
    if hasattr(os, "geteuid"):
        return f"posix-uid:{os.geteuid()}"
    raise CredentialProviderError("runtime identity is unavailable")


def runtime_identity_binding_status(
    binding: object | None,
    *,
    required: bool = False,
    principal_provider: RuntimePrincipalProvider | None = None,
) -> dict[str, object]:
    if binding is not None and not isinstance(binding, Mapping):
        return {
            "required": True,
            "ready": False,
            "identity_bound": False,
            "identity_matches": False,
            "principal_values_returned": False,
        }
    configured = binding if isinstance(binding, Mapping) else {}
    expected = str(configured.get("principal_sha256") or "").strip().lower()
    enforced = bool(required or configured.get("required") is True or expected)
    digest_valid = bool(re.fullmatch(r"[0-9a-f]{64}", expected))
    if not enforced:
        return {
            "required": False,
            "ready": True,
            "identity_bound": False,
            "identity_matches": False,
            "principal_values_returned": False,
        }
    if not digest_valid:
        return {
            "required": True,
            "ready": False,
            "identity_bound": False,
            "identity_matches": False,
            "principal_values_returned": False,
        }
    try:
        provider = principal_provider or current_runtime_principal
        current_digest = runtime_principal_sha256(provider())
    except (CredentialProviderError, OSError, ValueError):
        current_digest = ""
    matches = bool(
        current_digest and hmac.compare_digest(current_digest, expected)
    )
    return {
        "required": True,
        "ready": matches,
        "identity_bound": True,
        "identity_matches": matches,
        "principal_values_returned": False,
    }


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
