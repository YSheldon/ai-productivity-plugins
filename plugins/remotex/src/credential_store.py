from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

import remotex_core as core


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
