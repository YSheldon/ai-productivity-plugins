from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

import remotex_core as core
import secure_paths
import windows_credentials


CREDENTIAL_ALIAS_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$"
)
PUBLIC_KEY_FINGERPRINT_PATTERN = re.compile(
    r"^SHA256:[A-Za-z0-9+/]{43}$"
)
PROVIDER_FIELDS: dict[str, frozenset[str]] = {
    "identity-file": frozenset(
        {"source", "identity_file", "expected_public_key_sha256"}
    ),
    "ssh-agent": frozenset(
        {"source", "identity_file", "expected_public_key_sha256"}
    ),
    "windows-credential-manager": frozenset({"source", "target"}),
    "windows-integrated": frozenset({"source"}),
    "environment": frozenset({"source", "username_env", "password_env"}),
}
KIND_PROVIDERS: dict[str, frozenset[str]] = {
    "ssh": frozenset({"identity-file", "ssh-agent"}),
    "rdp": frozenset({"windows-credential-manager"}),
    "windows-guest": frozenset(
        {"windows-credential-manager", "windows-integrated"}
    ),
    "vsphere": frozenset({"windows-credential-manager", "environment"}),
    "vmware-workstation": frozenset(),
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _contains_credential_material(value: str) -> bool:
    return bool(
        core.TOKEN_PATTERN.search(value)
        or core.PEM_PATTERN.search(value)
        or core.URL_USERINFO_PATTERN.search(value)
        or core.SECRET_ASSIGNMENT_PATTERN.search(value)
    )


def _validate_record(record: Any, field: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise core.ToolError(f"{field} must be an object")
    source = str(record.get("source") or "").strip().lower()
    allowed = PROVIDER_FIELDS.get(source)
    if allowed is None:
        raise core.ToolError(f"{field}.source is unsupported")
    unknown = sorted(set(record) - allowed)
    missing = sorted(allowed - set(record))
    if source == "ssh-agent":
        missing = [name for name in missing if name not in {"identity_file", "expected_public_key_sha256"}]
    elif source == "identity-file":
        missing = [name for name in missing if name != "expected_public_key_sha256"]
    if unknown:
        raise core.ToolError(f"unknown credential field: {field}.{unknown[0]}")
    if missing:
        raise core.ToolError(f"missing credential field: {field}.{missing[0]}")

    normalized: dict[str, Any] = {"source": source}
    for key in allowed - {"source"}:
        raw = record.get(key)
        if raw in (None, ""):
            if key == "expected_public_key_sha256" and source in {
                "identity-file",
                "ssh-agent",
            }:
                continue
            if key == "identity_file" and source == "ssh-agent":
                continue
        value = core._required_text(raw, f"{field}.{key}")
        if _contains_credential_material(value):
            raise core.ToolError(f"{field} contains credential material")
        normalized[key] = value

    if source == "windows-credential-manager" and len(normalized["target"]) > 512:
        raise core.ToolError(f"{field}.target is too long")
    if source == "environment":
        normalized["username_env"] = core._environment_name(
            normalized["username_env"], f"{field}.username_env"
        )
        normalized["password_env"] = core._environment_name(
            normalized["password_env"], f"{field}.password_env"
        )
    fingerprint = normalized.get("expected_public_key_sha256")
    if fingerprint and PUBLIC_KEY_FINGERPRINT_PATTERN.fullmatch(fingerprint) is None:
        raise core.ToolError(
            f"{field}.expected_public_key_sha256 must be an OpenSSH SHA256 fingerprint"
        )
    return normalized


def validate_provider_for_kind(source: str, kind: str, field: str) -> None:
    supported = KIND_PROVIDERS.get(kind)
    if supported is None or source not in supported:
        raise core.ToolError(
            f"Credential provider {source or 'missing'} is incompatible with {field} kind {kind}"
        )


def validate_config_credentials(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    version = data.get("version", 1)
    if version == 1:
        if "credentials" in data:
            raise core.ToolError("RemoteX version 1 config must not contain credentials aliases")
        for name, profile in data.get("profiles", {}).items():
            if isinstance(profile, dict) and profile.get("credential_ref") not in (None, ""):
                raise core.ToolError(
                    f"RemoteX version 1 profile {name} must not use credential_ref"
                )
        return {}
    if version != 2:
        raise core.ToolError("RemoteX config version must be 1 or 2")
    unknown_top_level = sorted(set(data) - {"version", "credentials", "defaults", "profiles"})
    if unknown_top_level:
        raise core.ToolError(f"Unknown RemoteX version 2 field: {unknown_top_level[0]}")
    raw_credentials = data.get("credentials", {})
    if not isinstance(raw_credentials, dict):
        raise core.ToolError("RemoteX config field 'credentials' must be an object")
    normalized: dict[str, dict[str, Any]] = {}
    for alias, record in raw_credentials.items():
        if not isinstance(alias, str) or CREDENTIAL_ALIAS_PATTERN.fullmatch(alias) is None:
            raise core.ToolError("RemoteX credential aliases must use safe lowercase ASCII names")
        normalized[alias] = _validate_record(record, f"credentials.{alias}")

    for profile_name, profile in data.get("profiles", {}).items():
        if not isinstance(profile, dict):
            continue
        reference = profile.get("credential_ref")
        inline = profile.get("credential")
        if reference not in (None, "") and inline is not None:
            raise core.ToolError(
                f"Profile {profile_name} cannot use credential_ref and credential together"
            )
        kind = core.normalize_kind(profile.get("kind"))
        if reference not in (None, ""):
            alias = core._required_text(reference, f"profiles.{profile_name}.credential_ref")
            if CREDENTIAL_ALIAS_PATTERN.fullmatch(alias) is None:
                raise core.ToolError(f"Profile {profile_name} credential_ref is malformed")
            if alias not in normalized:
                raise core.ToolError(f"Profile {profile_name} credential_ref does not exist")
            validate_provider_for_kind(
                normalized[alias]["source"], kind, f"profile {profile_name}"
            )
        elif inline is not None:
            record = _validate_record(inline, f"profiles.{profile_name}.credential")
            validate_provider_for_kind(record["source"], kind, f"profile {profile_name}")
    return normalized


@dataclass(frozen=True)
class ResolvedCredential:
    profile_name: str
    kind: str
    source: str
    alias: str | None
    configuration_version: int
    _reference: Mapping[str, Any]

    @classmethod
    def create(
        cls,
        *,
        profile_name: str,
        kind: str,
        alias: str | None,
        configuration_version: int,
        reference: dict[str, Any],
    ) -> "ResolvedCredential":
        return cls(
            profile_name=profile_name,
            kind=kind,
            source=str(reference["source"]),
            alias=alias,
            configuration_version=configuration_version,
            _reference=MappingProxyType(dict(reference)),
        )

    def reference_dict(self) -> dict[str, Any]:
        return dict(self._reference)

    def public(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "alias": self.alias,
            "source": self.source,
            "configurationVersion": self.configuration_version,
            "ephemeral": self.source == "environment",
        }
        target = self._reference.get("target")
        identity_file = self._reference.get("identity_file")
        if isinstance(target, str):
            result["targetSha256"] = _digest(target)
        if isinstance(identity_file, str):
            result["identityFileSha256"] = _digest(identity_file)
        fingerprint = self._reference.get("expected_public_key_sha256")
        if isinstance(fingerprint, str):
            result["expectedPublicKeySha256"] = fingerprint
        return result

    def presence(self) -> dict[str, Any]:
        result = self.public()
        if self.source in {"windows-credential-manager", "environment"}:
            status = core.credential_status(self.reference_dict())
            present = bool(status.get("ready"))
            reason = None if present else (
                "environment-reference-missing"
                if self.source == "environment"
                else "windows-credential-reference-missing"
            )
            result.update({"present": present, "reason": reason})
            if self.source == "environment":
                result["missingEnvironmentVariableCount"] = len(
                    status.get("missing_environment_variables") or []
                )
            return result
        if self.source == "windows-integrated":
            present = os.name == "nt"
            result.update(
                {
                    "present": present,
                    "reason": None if present else "windows-integrated-unavailable",
                }
            )
            return result
        if self.source == "identity-file":
            path = core.expand_path(self._reference.get("identity_file"), "credential.identity_file")
            present = path.is_file()
            result.update(
                {
                    "present": present,
                    "reason": None if present else "identity-file-missing",
                }
            )
            return result
        result.update(
            {
                "present": None,
                "reason": "ssh-agent-runtime-check-required",
            }
        )
        return result


def _legacy_ssh_reference(profile: dict[str, Any]) -> dict[str, Any]:
    identity_file = profile.get("identity_file")
    if identity_file:
        return {"source": "identity-file", "identity_file": str(identity_file)}
    return {"source": "ssh-agent"}


def resolve_profile_reference(
    bundle: core.ConfigBundle,
    profile_name: str,
    profile: dict[str, Any],
    kind: str,
) -> ResolvedCredential:
    normalized_kind = core.normalize_kind(kind)
    version = int(bundle.data.get("version", 1))
    alias_value = profile.get("credential_ref")
    inline = profile.get("credential")
    if alias_value not in (None, "") and inline is not None:
        raise core.ToolError(
            f"Profile {profile_name} cannot use credential_ref and credential together"
        )
    alias: str | None = None
    if alias_value not in (None, ""):
        alias = core._required_text(
            alias_value, f"profiles.{profile_name}.credential_ref"
        )
        credentials = bundle.data.get("credentials", {})
        if not isinstance(credentials, dict) or alias not in credentials:
            raise core.ToolError(f"Profile {profile_name} credential_ref does not exist")
        reference = _validate_record(credentials[alias], f"credentials.{alias}")
    elif inline is not None:
        reference = _validate_record(
            inline, f"profiles.{profile_name}.credential"
        )
    elif normalized_kind == "ssh":
        reference = _validate_record(
            _legacy_ssh_reference(profile),
            f"profiles.{profile_name}.credential",
        )
    else:
        raise core.ToolError(f"Profile {profile_name} credential reference is missing")
    validate_provider_for_kind(reference["source"], normalized_kind, f"profile {profile_name}")
    return ResolvedCredential.create(
        profile_name=profile_name,
        kind=normalized_kind,
        alias=alias,
        configuration_version=version,
        reference=reference,
    )


def resolve_named_reference(
    bundle: core.ConfigBundle,
    alias: str,
) -> ResolvedCredential:
    name = core._required_text(alias, "credential_ref")
    credentials = bundle.data.get("credentials", {})
    if not isinstance(credentials, dict) or name not in credentials:
        raise core.ToolError(f"RemoteX credential_ref not found: {name}")
    reference = _validate_record(credentials[name], f"credentials.{name}")
    return ResolvedCredential.create(
        profile_name="",
        kind="credential",
        alias=name,
        configuration_version=int(bundle.data.get("version", 1)),
        reference=reference,
    )


def _setup_root() -> Path:
    configured = os.environ.get("REMOTEX_CREDENTIAL_SETUP_DIR")
    if configured:
        return core.expand_path(configured, "REMOTEX_CREDENTIAL_SETUP_DIR")
    if os.name == "nt":
        root = Path(
            os.environ.get("LOCALAPPDATA")
            or (core.DEFAULT_CONFIG_PATH.parents[2] / "AppData" / "Local")
        )
    else:
        root = Path(
            os.environ.get("XDG_STATE_HOME")
            or (core.DEFAULT_CONFIG_PATH.parents[2] / ".local" / "state")
        )
    return root / "RemoteX" / "credential-setup"


def _powershell_path() -> str:
    root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    return str(
        root
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )


def _setup_arguments(
    reference: ResolvedCredential,
    receipt_path: Path,
) -> list[str]:
    if reference.source != "windows-credential-manager":
        raise core.ToolError(
            "Secure setup supports Windows Credential Manager references only"
        )
    target = core._required_text(
        reference.reference_dict().get("target"),
        "credential.target",
    )
    helper = Path(__file__).resolve().parents[1] / "scripts" / "manage_windows_credential.ps1"
    if not helper.is_file():
        raise core.ToolError("RemoteX credential setup helper is unavailable")
    return [
        _powershell_path(),
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(helper),
        "-Operation",
        "Store",
        "-Target",
        target,
        "-ReceiptPath",
        str(receipt_path),
    ]


def _decode_setup_receipt(path: Path, expected_target_sha256: str) -> dict[str, Any]:
    secure_paths.ensure_private_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError("RemoteX credential setup receipt is invalid") from exc
    expected_fields = {
        "schema",
        "status",
        "existingBefore",
        "referencePresent",
        "targetSha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or value.get("schema") != "RemoteXCredentialSetupReceipt/v1"
        or value.get("status") not in {"stored", "cancelled", "failed"}
        or type(value.get("existingBefore")) is not bool
        or type(value.get("referencePresent")) is not bool
        or value.get("targetSha256") != expected_target_sha256
    ):
        raise core.ToolError("RemoteX credential setup receipt is invalid")
    return value


def launch_secure_setup(
    reference: ResolvedCredential,
    *,
    timeout: int,
) -> dict[str, Any]:
    if os.name != "nt":
        raise core.ToolError("Secure credential setup requires Windows")
    if reference.source != "windows-credential-manager":
        raise core.ToolError(
            "Secure setup supports Windows Credential Manager references only"
        )
    target = core._required_text(
        reference.reference_dict().get("target"),
        "credential.target",
    )
    target_sha256 = _digest(target)
    root = _setup_root()
    secure_paths.ensure_private_directory(root)
    receipt_path = root / f"{uuid.uuid4()}.json"
    arguments = _setup_arguments(reference, receipt_path)
    process: subprocess.Popen[Any] | None = None
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=(
                subprocess.CREATE_NEW_CONSOLE
                | subprocess.CREATE_NEW_PROCESS_GROUP
            ),
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=10)
            raise core.ToolError("RemoteX credential setup timed out") from exc
        if not receipt_path.is_file():
            raise core.ToolError("RemoteX credential setup did not produce a receipt")
        receipt = _decode_setup_receipt(receipt_path, target_sha256)
        expected_exit = 0 if receipt["status"] == "stored" else 2
        if process.returncode != expected_exit:
            raise core.ToolError(
                "RemoteX credential setup receipt and exit status differ"
            )
        if receipt["status"] == "failed":
            raise core.ToolError("RemoteX credential setup failed")
        present = windows_credentials.credential_exists(
            target,
            credential_types=(1, 2),
        )
        if receipt["status"] == "stored" and not present:
            raise core.ToolError("RemoteX credential setup presence readback failed")
        return {
            "status": receipt["status"],
            "existingBefore": receipt["existingBefore"],
            "referencePresent": present,
            "targetSha256": target_sha256,
        }
    except OSError as exc:
        raise core.ToolError("Unable to launch RemoteX credential setup securely") from exc
    finally:
        try:
            receipt_path.unlink(missing_ok=True)
        except OSError:
            pass


def _delete_windows_credential_type(target: str, credential_type: int) -> bool:
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    advapi32.CredDeleteW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    advapi32.CredDeleteW.restype = wintypes.BOOL
    if advapi32.CredDeleteW(target, credential_type, 0):
        return True
    error_code = ctypes.get_last_error()
    if error_code == 1168:
        return False
    raise core.ToolError(
        f"Unable to delete Windows credential (Win32 error {error_code})"
    )


def delete_windows_credential(reference: ResolvedCredential) -> dict[str, Any]:
    if os.name != "nt":
        raise core.ToolError("Windows credential deletion requires Windows")
    if reference.source != "windows-credential-manager":
        raise core.ToolError(
            "Credential deletion supports Windows Credential Manager references only"
        )
    target = core._required_text(
        reference.reference_dict().get("target"),
        "credential.target",
    )
    deleted = sum(
        1
        for credential_type in (1, 2)
        if _delete_windows_credential_type(target, credential_type)
    )
    present = windows_credentials.credential_exists(
        target,
        credential_types=(1, 2),
    )
    if present:
        raise core.ToolError("Windows credential deletion presence readback failed")
    return {
        "removed": deleted > 0,
        "deletedRecordCount": deleted,
        "referencePresent": False,
        "targetSha256": _digest(target),
    }
