from __future__ import annotations

import hashlib
from typing import Any

import config_store
import credential_store
import profile_config
import remotex_core as core


def _preview(prepared: profile_config.PreparedProfile) -> dict[str, Any]:
    profile = prepared.profile
    endpoint = (
        profile["url"]
        if profile["kind"] == "vsphere"
        else f"{profile['host']}:{profile['port']}"
    )
    return {
        "ok": True,
        "preview": True,
        "profile": prepared.profile_name,
        "kind": profile["kind"],
        "credentialRef": prepared.credential_ref,
        "credentialSource": prepared.record["source"],
        "queueResource": profile["queue_resource"],
        "endpointSha256": hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
        "configurationVersionBefore": int(
            prepared.bundle.data.get("version", 1)
        ),
        "configurationVersionAfter": 2,
        "migrationRequired": int(prepared.bundle.data.get("version", 1)) == 1,
        "configurationWriteRequired": not prepared.already_configured,
        "backupRequired": (
            not prepared.already_configured and prepared.bundle.exists
        ),
        "credentialPromptRequired": (
            prepared.record["source"] == "windows-credential-manager"
        ),
        "alreadyConfigured": prepared.already_configured,
        "nextStep": "rerun-with-confirm-true",
    }


def _next_step(kind: str) -> str:
    return {
        "ssh": "run-remotex-ssh-host-key-status",
        "rdp": "run-remotex-rdp-test",
        "windows-guest": "run-remotex-windows-guest-test",
        "vsphere": "run-remotex-vsphere-about",
    }[kind]


def _configured_reference(
    prepared: profile_config.PreparedProfile,
) -> credential_store.ResolvedCredential:
    configured = core.ConfigBundle(
        data=prepared.candidate,
        path=prepared.bundle.path,
        source="remotex",
        exists=True,
    )
    return credential_store.resolve_profile_reference(
        configured,
        prepared.profile_name,
        prepared.profile,
        prepared.profile["kind"],
    )


def _idempotent_result(
    prepared: profile_config.PreparedProfile,
    args: dict[str, Any],
) -> dict[str, Any]:
    lifecycle: dict[str, Any] | None = None
    reference_present: bool | None = None
    target_sha256: str | None = None
    if prepared.record["source"] == "windows-credential-manager":
        reference = _configured_reference(prepared)
        presence = reference.presence()
        if presence.get("present") is True:
            reference_present = True
            target_sha256 = presence.get("targetSha256")
        else:
            lifecycle = credential_store.launch_secure_setup(
                reference,
                timeout=core.validate_timeout(args.get("timeout_seconds"), 300),
            )
            reference_present = bool(lifecycle.get("referencePresent"))
            target_sha256 = lifecycle.get("targetSha256")
    stored = lifecycle is None or lifecycle.get("status") == "stored"
    return {
        **_preview(prepared),
        "ok": stored,
        "preview": False,
        "configurationStored": True,
        "backupCreated": False,
        "backupFileName": None,
        "configSha256": hashlib.sha256(
            prepared.bundle.path.read_bytes()
        ).hexdigest(),
        "backupSha256": None,
        "credentialPromptStatus": (
            lifecycle.get("status") if lifecycle is not None else "not-required"
        ),
        "referencePresent": reference_present,
        "rotated": bool(lifecycle is not None and lifecycle.get("existingBefore")),
        "targetSha256": target_sha256,
        "authenticationVerified": None,
        "cancelled": lifecycle is not None
        and lifecycle.get("status") == "cancelled",
        "nextStep": (
            _next_step(prepared.profile["kind"])
            if stored
            else "credential-setup-cancelled"
        ),
    }


def _cancelled_result(
    prepared: profile_config.PreparedProfile,
    lifecycle: dict[str, Any],
) -> dict[str, Any]:
    return {
        **_preview(prepared),
        "ok": False,
        "preview": False,
        "cancelled": lifecycle.get("status") == "cancelled",
        "configurationStored": False,
        "backupCreated": False,
        "credentialPromptStatus": lifecycle.get("status"),
        "referencePresent": bool(lifecycle.get("referencePresent")),
        "authenticationVerified": None,
        "nextStep": "credential-setup-cancelled",
    }


def _stored_result(
    prepared: profile_config.PreparedProfile,
    receipt: config_store.WriteReceipt,
    lifecycle: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        **_preview(prepared),
        "preview": False,
        "configurationStored": True,
        "backupCreated": receipt.backup_path is not None,
        "backupFileName": (
            receipt.backup_path.name if receipt.backup_path is not None else None
        ),
        "configSha256": receipt.config_sha256,
        "backupSha256": receipt.backup_sha256,
        "credentialPromptStatus": (
            lifecycle.get("status") if lifecycle is not None else "not-required"
        ),
        "referencePresent": (
            bool(lifecycle.get("referencePresent"))
            if lifecycle is not None
            else None
        ),
        "rotated": bool(
            lifecycle is not None
            and lifecycle.get("status") == "stored"
            and lifecycle.get("existingBefore")
        ),
        "targetSha256": (
            lifecycle.get("targetSha256") if lifecycle is not None else None
        ),
        "authenticationVerified": None,
        "nextStep": _next_step(prepared.profile["kind"]),
    }


def setup(args: dict[str, Any]) -> dict[str, Any]:
    prepared = profile_config.prepare(args)
    if not core.as_bool(args.get("confirm"), False):
        return core.tool_result(_preview(prepared))
    if prepared.already_configured:
        return core.tool_result(_idempotent_result(prepared, args))

    receipt = config_store.write_config(
        prepared.bundle.path,
        prepared.candidate,
        expected=prepared.bundle.data,
        expected_exists=prepared.bundle.exists,
    )
    lifecycle: dict[str, Any] | None = None
    if prepared.record["source"] == "windows-credential-manager":
        reference = _configured_reference(prepared)
        presence_before = reference.presence()
        if presence_before.get("present") is True:
            lifecycle = {
                "status": "not-required",
                "existingBefore": True,
                "referencePresent": True,
                "targetSha256": presence_before.get("targetSha256"),
            }
        else:
            try:
                lifecycle = credential_store.launch_secure_setup(
                    reference,
                    timeout=core.validate_timeout(
                        args.get("timeout_seconds"),
                        300,
                    ),
                )
            except Exception:
                cleanup_error: Exception | None = None
                try:
                    if reference.presence().get("present") is True:
                        credential_store.delete_windows_credential(reference)
                except Exception as cleanup_exc:
                    cleanup_error = cleanup_exc
                config_store.rollback(receipt, prepared.candidate)
                if cleanup_error is not None:
                    raise core.ToolError(
                        "RemoteX profile setup failed and the new credential could "
                        "not be removed"
                    ) from cleanup_error
                raise
        if lifecycle.get("status") not in {"stored", "not-required"}:
            cleanup_error: Exception | None = None
            if (
                presence_before.get("present") is not True
                and lifecycle.get("referencePresent")
            ):
                try:
                    credential_store.delete_windows_credential(reference)
                except Exception as cleanup_exc:
                    cleanup_error = cleanup_exc
            config_store.rollback(receipt, prepared.candidate)
            if cleanup_error is not None:
                raise core.ToolError(
                    "RemoteX profile setup failed and the new credential could "
                    "not be removed"
                ) from cleanup_error
            return core.tool_result(_cancelled_result(prepared, lifecycle))
    return core.tool_result(_stored_result(prepared, receipt, lifecycle))


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_profile_setup": {
        "description": (
            "Preview or create one credential-backed RemoteX profile and alias, then "
            "open a local secure prompt when Windows Credential Manager is required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": profile_config.PROFILE_SETUP_PROPERTIES,
            "required": [
                "profile",
                "kind",
                "credential_ref",
                "credential_source",
                "queue_resource",
                "confirm",
            ],
            "additionalProperties": False,
        },
        "handler": setup,
    }
}
