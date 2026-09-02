from __future__ import annotations

import hashlib
import json
from typing import Any

import authentication_evidence
import credential_store
import remotex_core as core
import secure_paths


def _reference_key(resolved: credential_store.ResolvedCredential) -> str:
    if resolved.alias:
        return f"alias:{resolved.alias}"
    canonical = json.dumps(
        resolved.reference_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "inline:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _next_step(source: str, present: bool | None) -> str:
    if present is True:
        return {
            "identity-file": "run-remotex-ssh-test",
            "ssh-agent": "run-remotex-ssh-test",
            "windows-credential-manager": "run-protocol-authentication-test",
            "windows-integrated": "run-remotex-windows-guest-test",
            "environment": "run-remotex-vsphere-about",
        }.get(source, "run-protocol-authentication-test")
    if source == "windows-credential-manager":
        return "run-remotex-credential-setup"
    if source == "identity-file":
        return "configure-identity-file"
    if source == "ssh-agent":
        return "run-remotex-ssh-agent-list"
    if source == "environment":
        return "set-ephemeral-environment-references"
    if source == "windows-integrated":
        return "use-windows-host-identity"
    return "repair-credential-reference"


def _selected_profiles(
    bundle: core.ConfigBundle,
    args: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    requested_profile = core._text(args.get("profile")).strip()
    requested_alias = core._text(args.get("credential_ref")).strip()
    if requested_profile and requested_alias:
        raise core.ToolError("Pass profile or credential_ref, not both")
    profiles = bundle.data["profiles"]
    if requested_profile:
        profile = profiles.get(requested_profile)
        if not isinstance(profile, dict):
            raise core.ToolError(f"RemoteX profile not found: {requested_profile}")
        return [(requested_profile, profile)]
    if requested_alias:
        credentials = bundle.data.get("credentials", {})
        if not isinstance(credentials, dict) or requested_alias not in credentials:
            raise core.ToolError(f"RemoteX credential_ref not found: {requested_alias}")
        selected = [
            (name, profile)
            for name, profile in profiles.items()
            if isinstance(profile, dict)
            and core._text(profile.get("credential_ref")).strip() == requested_alias
        ]
        if not selected:
            raise core.ToolError(
                f"RemoteX credential_ref has no consuming profiles: {requested_alias}"
            )
        return selected
    return [
        (name, profile)
        for name, profile in profiles.items()
        if isinstance(profile, dict)
    ]


def doctor(args: dict[str, Any]) -> dict[str, Any]:
    bundle = core.load_config()
    config_protection = secure_paths.private_path_status(bundle.path)
    grouped: dict[str, dict[str, Any]] = {}
    incompatible_count = 0
    credential_profile_count = 0
    for profile_name, profile in _selected_profiles(bundle, args):
        kind = core.normalize_kind(profile.get("kind"))
        if kind == "vmware-workstation":
            continue
        credential_profile_count += 1
        try:
            resolved = credential_store.resolve_profile_reference(
                bundle,
                profile_name,
                profile,
                kind,
            )
            key = _reference_key(resolved)
            group = grouped.setdefault(
                key,
                {
                    "resolved": resolved,
                    "consumers": [],
                },
            )
            group["consumers"].append(profile_name)
        except core.ToolError:
            incompatible_count += 1

    references: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    present_count = 0
    missing_count = 0
    indeterminate_count = 0
    migration = bundle.data.get("version", 1) == 1
    for key in sorted(grouped):
        resolved = grouped[key]["resolved"]
        consumers = sorted(grouped[key]["consumers"])
        presence = resolved.presence()
        is_present = presence.get("present")
        if is_present is True:
            present_count += 1
        elif is_present is False:
            missing_count += 1
        else:
            indeterminate_count += 1
        evidence = [
            authentication_evidence.get_fresh(profile, resolved.source)
            for profile in consumers
        ]
        authentication_verified = (
            True if evidence and all(item is not None for item in evidence) else None
        )
        last_verified_at = (
            max(str(item["verifiedAt"]) for item in evidence if item is not None)
            if authentication_verified
            else None
        )
        item = {
            **resolved.public(),
            "credentialRef": resolved.alias,
            "consumerProfiles": consumers,
            "consumerCount": len(consumers),
            "referenceConfigured": True,
            "referencePresent": is_present,
            "providerCompatible": True,
            "localProtectionReady": bool(config_protection.get("ready")),
            "authenticationVerified": authentication_verified,
            "lastVerifiedAt": last_verified_at,
            "migrationRecommended": migration,
            "nextStep": _next_step(resolved.source, is_present),
        }
        if presence.get("reason"):
            item["presenceFailureCode"] = presence["reason"]
        if "missingEnvironmentVariableCount" in presence:
            item["missingEnvironmentVariableCount"] = presence[
                "missingEnvironmentVariableCount"
            ]
        references.append(item)
        if is_present is False:
            missing.append(
                {
                    **resolved.public(),
                    "credentialRef": resolved.alias,
                    "consumerCount": len(consumers),
                    "nextStep": _next_step(resolved.source, False),
                }
            )

    ok = (
        missing_count == 0
        and incompatible_count == 0
        and bool(config_protection.get("ready"))
    )
    return core.tool_result(
        {
            "ok": ok,
            "configurationVersion": bundle.data.get("version", 1),
            "migrationRecommended": migration,
            "configProtection": {
                "ready": bool(config_protection.get("ready")),
                "failureCode": config_protection.get("reason"),
            },
            "summary": {
                "credentialProfiles": credential_profile_count,
                "uniqueReferences": len(references),
                "present": present_count,
                "missing": missing_count,
                "indeterminate": indeterminate_count,
                "incompatibleProfiles": incompatible_count,
            },
            "uniqueMissing": missing,
            "references": references,
        }
    )


def _lifecycle_reference(
    args: dict[str, Any],
) -> tuple[
    core.ConfigBundle,
    credential_store.ResolvedCredential,
    list[str],
]:
    bundle = core.load_config()
    profile_name = core._text(args.get("profile")).strip()
    alias = core._text(args.get("credential_ref")).strip()
    if bool(profile_name) == bool(alias):
        raise core.ToolError("Pass exactly one of profile or credential_ref")
    if profile_name:
        profile = bundle.data["profiles"].get(profile_name)
        if not isinstance(profile, dict):
            raise core.ToolError(f"RemoteX profile not found: {profile_name}")
        kind = core.normalize_kind(profile.get("kind"))
        resolved = credential_store.resolve_profile_reference(
            bundle,
            profile_name,
            profile,
            kind,
        )
    else:
        resolved = credential_store.resolve_named_reference(bundle, alias)
    key = _reference_key(resolved)
    consumers: list[str] = []
    for name, profile in bundle.data["profiles"].items():
        if not isinstance(profile, dict):
            continue
        kind = core.normalize_kind(profile.get("kind"))
        if kind == "vmware-workstation":
            continue
        try:
            candidate = credential_store.resolve_profile_reference(
                bundle,
                name,
                profile,
                kind,
            )
        except core.ToolError:
            continue
        if _reference_key(candidate) == key:
            consumers.append(name)
    return bundle, resolved, sorted(consumers)


def setup(args: dict[str, Any]) -> dict[str, Any]:
    if not core.as_bool(args.get("confirm"), False):
        raise core.ToolError("confirm=true is required to open secure credential setup")
    _, resolved, consumers = _lifecycle_reference(args)
    if resolved.source != "windows-credential-manager":
        raise core.ToolError(
            "Secure setup supports Windows Credential Manager references only"
        )
    timeout = core.validate_timeout(args.get("timeout_seconds"), 300)
    lifecycle = credential_store.launch_secure_setup(resolved, timeout=timeout)
    stored = lifecycle.get("status") == "stored"
    cancelled = lifecycle.get("status") == "cancelled"
    return core.tool_result(
        {
            "ok": bool(stored and lifecycle.get("referencePresent")),
            "cancelled": cancelled,
            "status": lifecycle.get("status"),
            "credentialRef": resolved.alias,
            "source": resolved.source,
            "consumerCount": len(consumers),
            "rotated": bool(stored and lifecycle.get("existingBefore")),
            "referencePresent": bool(lifecycle.get("referencePresent")),
            "targetSha256": lifecycle.get("targetSha256"),
            "nextStep": (
                "run-protocol-authentication-test"
                if stored
                else "credential-setup-cancelled"
            ),
        }
    )


def delete(args: dict[str, Any]) -> dict[str, Any]:
    if not core.as_bool(args.get("confirm"), False):
        raise core.ToolError("confirm=true is required to delete a configured credential")
    _, resolved, consumers = _lifecycle_reference(args)
    if resolved.source != "windows-credential-manager":
        raise core.ToolError(
            "Credential deletion supports Windows Credential Manager references only"
        )
    lifecycle = credential_store.delete_windows_credential(resolved)
    return core.tool_result(
        {
            "ok": not lifecycle.get("referencePresent"),
            "credentialRef": resolved.alias,
            "source": resolved.source,
            "consumerCount": len(consumers),
            "removed": bool(lifecycle.get("removed")),
            "deletedRecordCount": int(lifecycle.get("deletedRecordCount") or 0),
            "referencePresent": bool(lifecycle.get("referencePresent")),
            "targetSha256": lifecycle.get("targetSha256"),
            "nextStep": "credential-reference-is-now-missing",
        }
    )


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_credential_doctor": {
        "description": (
            "Batch-check configured credential references, local protection, consumers, "
            "and separate authentication evidence without returning credential values."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string"},
                "credential_ref": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "handler": doctor,
    },
    "remotex_credential_setup": {
        "description": (
            "Open a visible local Windows secure prompt to store or rotate one configured "
            "Credential Manager reference without accepting credential values in MCP."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string"},
                "credential_ref": {"type": "string"},
                "confirm": {"type": "boolean"},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": core.MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["confirm"],
            "additionalProperties": False,
        },
        "handler": setup,
    },
    "remotex_credential_delete": {
        "description": (
            "Delete one configured Windows Credential Manager reference after explicit "
            "confirmation and absence readback."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string"},
                "credential_ref": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["confirm"],
            "additionalProperties": False,
        },
        "handler": delete,
    },
}
