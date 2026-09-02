from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any
from urllib.parse import urlparse

import credential_store
import queue_leases
import remotex_core as core
import vm_identity
import vm_queue


PROFILE_SETUP_PROPERTIES: dict[str, dict[str, Any]] = {
    "profile": {"type": "string"},
    "kind": {
        "type": "string",
        "enum": ["ssh", "rdp", "windows-guest", "vsphere", "esxi"],
    },
    "host": {"type": "string"},
    "url": {"type": "string"},
    "user": {"type": "string"},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "platform": {
        "type": "string",
        "enum": ["auto", "windows", "posix"],
    },
    "credential_ref": {"type": "string"},
    "credential_source": {
        "type": "string",
        "enum": [
            "identity-file",
            "ssh-agent",
            "windows-credential-manager",
            "windows-integrated",
        ],
    },
    "identity_file": {"type": "string"},
    "expected_public_key_sha256": {"type": "string"},
    "queue_resource": {"type": "string"},
    "queue_lease_seconds": {
        "type": "integer",
        "minimum": 60,
        "maximum": 604800,
    },
    "vm_identity": {"type": "string"},
    "guest_machine_id": {"type": "string"},
    "staging_root": {"type": "string"},
    "authentication": {
        "type": "string",
        "enum": ["kerberos", "negotiate"],
    },
    "ca_file": {"type": "string"},
    "confirm": {"type": "boolean"},
    "timeout_seconds": {
        "type": "integer",
        "minimum": 1,
        "maximum": core.MAX_TIMEOUT_SECONDS,
    },
}
PROFILE_SETUP_FIELDS = frozenset(PROFILE_SETUP_PROPERTIES)
COMMON_PROFILE_SETUP_FIELDS = frozenset(
    {
        "profile",
        "kind",
        "credential_ref",
        "credential_source",
        "queue_resource",
        "queue_lease_seconds",
        "confirm",
        "timeout_seconds",
    }
)
KIND_PROFILE_SETUP_FIELDS: dict[str, frozenset[str]] = {
    "ssh": frozenset(
        {
            "host",
            "user",
            "port",
            "platform",
            "identity_file",
            "expected_public_key_sha256",
        }
    ),
    "rdp": frozenset({"host", "port"}),
    "windows-guest": frozenset(
        {
            "host",
            "port",
            "vm_identity",
            "guest_machine_id",
            "staging_root",
            "authentication",
        }
    ),
    "vsphere": frozenset({"url", "ca_file"}),
}


@dataclass(frozen=True)
class PreparedProfile:
    bundle: core.ConfigBundle
    candidate: dict[str, Any]
    profile_name: str
    credential_ref: str
    profile: dict[str, Any]
    record: dict[str, Any]
    already_configured: bool


def _safe_name(value: Any, field: str) -> str:
    raw = core._text(value)
    name = core._required_text(value, field)
    if raw != name or credential_store.CREDENTIAL_ALIAS_PATTERN.fullmatch(name) is None:
        raise core.ToolError(
            f"{field} must use 1-64 lowercase ASCII letters, digits, dots, "
            "underscores, or hyphens"
        )
    return name


def _host(value: Any) -> str:
    host = core.validate_host(value)
    if "://" in host or any(char in host for char in "@/\\?#"):
        raise core.ToolError("host must be only a hostname or address")
    return host


def validate_arguments(args: dict[str, Any]) -> str:
    unknown = sorted(set(args) - PROFILE_SETUP_FIELDS)
    if unknown:
        raise core.ToolError(f"unknown profile setup field: {unknown[0]}")
    for field, value in sorted(args.items()):
        if isinstance(value, str) and credential_store._contains_credential_material(
            value
        ):
            raise core.ToolError(f"{field} appears to contain credential material")
    kind = core.normalize_kind(args.get("kind"))
    irrelevant = sorted(
        set(args) - COMMON_PROFILE_SETUP_FIELDS - KIND_PROFILE_SETUP_FIELDS[kind]
    )
    if irrelevant:
        raise core.ToolError(f"field {irrelevant[0]} is not valid for kind {kind}")
    return kind


def _ssh_profile(args: dict[str, Any], credential_ref: str) -> dict[str, Any]:
    source = core._required_text(
        args.get("credential_source"),
        "credential_source",
    ).casefold()
    if source not in {"identity-file", "ssh-agent"}:
        raise core.ToolError(
            "SSH profile setup supports only identity-file or ssh-agent credentials"
        )
    platform = str(args.get("platform") or "auto").strip().casefold()
    if platform not in {"auto", "windows", "posix"}:
        raise core.ToolError("SSH platform must be auto, windows, or posix")
    return {
        "kind": "ssh",
        "host": _host(args.get("host")),
        "user": core.validate_user(args.get("user")),
        "port": core.validate_port(args.get("port"), 22),
        "platform": platform,
        "queue_resource": vm_queue._validate_resource(args.get("queue_resource")),
        "queue_lease_seconds": queue_leases._lease_seconds(
            args.get("queue_lease_seconds")
        ),
        "credential_ref": credential_ref,
        "known_hosts_file": "~/.ssh/known_hosts",
        "strict_host_key_checking": "yes",
        "host_key_policy": "managed",
        "connect_timeout_seconds": 10,
    }


def _rdp_profile(args: dict[str, Any], credential_ref: str) -> dict[str, Any]:
    if str(args.get("credential_source") or "").strip().casefold() != (
        "windows-credential-manager"
    ):
        raise core.ToolError("RDP profile setup requires Windows Credential Manager")
    return {
        "kind": "rdp",
        "host": _host(args.get("host")),
        "port": core.validate_port(args.get("port"), 3389),
        "queue_resource": vm_queue._validate_resource(args.get("queue_resource")),
        "queue_lease_seconds": queue_leases._lease_seconds(
            args.get("queue_lease_seconds")
        ),
        "credential_ref": credential_ref,
        "admin": False,
        "fullscreen": False,
    }


def _windows_guest_profile(
    args: dict[str, Any],
    credential_ref: str,
) -> dict[str, Any]:
    source = str(args.get("credential_source") or "").strip().casefold()
    if source not in {"windows-credential-manager", "windows-integrated"}:
        raise core.ToolError(
            "Windows guest profile setup requires Windows Credential Manager or "
            "Windows integrated authentication"
        )
    authentication = str(args.get("authentication") or "kerberos").strip().casefold()
    if authentication not in {"kerberos", "negotiate"}:
        raise core.ToolError(
            "Windows guest authentication must be kerberos or negotiate"
        )
    staging_root = core._required_text(args.get("staging_root"), "staging_root")
    staging_path = PureWindowsPath(staging_root)
    if not staging_path.is_absolute() or any(part == ".." for part in staging_path.parts):
        raise core.ToolError(
            "staging_root must be an absolute Windows path without traversal"
        )
    return {
        "kind": "windows-guest",
        "host": _host(args.get("host")),
        "port": core.validate_port(args.get("port"), 5985),
        "transport": "winrm",
        "authentication": authentication,
        "queue_resource": vm_queue._validate_resource(args.get("queue_resource")),
        "queue_lease_seconds": queue_leases._lease_seconds(
            args.get("queue_lease_seconds")
        ),
        "vm_identity": vm_identity._identity_id(args.get("vm_identity")),
        "guest_machine_id": vm_identity.normalize_machine_id(
            args.get("guest_machine_id")
        ),
        "staging_root": str(staging_path),
        "powershell_path": (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ),
        "credential_ref": credential_ref,
    }


def _vsphere_url(value: Any) -> str:
    url = core._required_text(value, "url")
    parsed = urlparse(url)
    if parsed.scheme.casefold() != "https" or not parsed.hostname:
        raise core.ToolError("vSphere/ESXi url must be an absolute https URL")
    if parsed.username or parsed.password:
        raise core.ToolError("vSphere/ESXi url must not contain credentials")
    return url.rstrip("/")


def _vsphere_profile(args: dict[str, Any], credential_ref: str) -> dict[str, Any]:
    if str(args.get("credential_source") or "").strip().casefold() != (
        "windows-credential-manager"
    ):
        raise core.ToolError(
            "vSphere profile setup requires Windows Credential Manager"
        )
    tls: dict[str, Any] = {"insecure": False}
    if args.get("ca_file") not in (None, ""):
        tls["ca_file"] = core._required_text(args.get("ca_file"), "ca_file")
    return {
        "kind": "vsphere",
        "url": _vsphere_url(args.get("url")),
        "queue_resource": vm_queue._validate_resource(args.get("queue_resource")),
        "queue_lease_seconds": queue_leases._lease_seconds(
            args.get("queue_lease_seconds")
        ),
        "credential_ref": credential_ref,
        "tls": tls,
    }


def _credential_record(args: dict[str, Any], kind: str) -> dict[str, Any]:
    source = core._required_text(
        args.get("credential_source"),
        "credential_source",
    ).casefold()
    if kind == "rdp":
        if source != "windows-credential-manager":
            raise core.ToolError("RDP profile setup requires Windows Credential Manager")
        host = _host(args.get("host"))
        return credential_store._validate_record(
            {"source": source, "target": f"TERMSRV/{host}"},
            "credential",
        )
    if kind == "windows-guest":
        if source == "windows-integrated":
            return credential_store._validate_record(
                {"source": source},
                "credential",
            )
        if source != "windows-credential-manager":
            raise core.ToolError(
                "Windows guest profile setup requires Windows Credential Manager or "
                "Windows integrated authentication"
            )
        alias = _safe_name(args.get("credential_ref"), "credential_ref")
        return credential_store._validate_record(
            {"source": source, "target": f"RemoteX/{alias}"},
            "credential",
        )
    if kind == "vsphere":
        if source != "windows-credential-manager":
            raise core.ToolError(
                "vSphere profile setup requires Windows Credential Manager"
            )
        alias = _safe_name(args.get("credential_ref"), "credential_ref")
        return credential_store._validate_record(
            {"source": source, "target": f"RemoteX/{alias}"},
            "credential",
        )
    record: dict[str, Any] = {"source": source}
    if args.get("identity_file") not in (None, ""):
        record["identity_file"] = core._required_text(
            args.get("identity_file"),
            "identity_file",
        )
    if args.get("expected_public_key_sha256") not in (None, ""):
        record["expected_public_key_sha256"] = core._required_text(
            args.get("expected_public_key_sha256"),
            "expected_public_key_sha256",
        )
    return credential_store._validate_record(record, "credential")


def prepare(args: dict[str, Any]) -> PreparedProfile:
    kind = validate_arguments(args)
    bundle = core.load_config()
    if bundle.source not in {"remotex", "missing"}:
        raise core.ToolError(
            "RemoteX profile setup requires the primary RemoteX config, not a legacy "
            "or environment-only source"
        )
    candidate = (
        credential_store.migrate_v1_config(bundle.data)
        if int(bundle.data.get("version", 1)) == 1
        else copy.deepcopy(bundle.data)
    )
    profile_name = _safe_name(args.get("profile"), "profile")
    credential_ref = _safe_name(args.get("credential_ref"), "credential_ref")
    record = _credential_record(args, kind)
    credential_store.validate_provider_for_kind(
        record["source"],
        kind,
        f"profile {profile_name}",
    )
    builders = {
        "ssh": _ssh_profile,
        "rdp": _rdp_profile,
        "windows-guest": _windows_guest_profile,
        "vsphere": _vsphere_profile,
    }
    profile = builders[kind](args, credential_ref)
    existing_profile = candidate["profiles"].get(profile_name)
    existing_record = candidate["credentials"].get(credential_ref)
    already_configured = existing_profile == profile and existing_record == record
    if existing_profile is not None and not already_configured:
        raise core.ToolError(
            f"RemoteX profile already exists with different configuration: {profile_name}"
        )
    if existing_record is not None and not already_configured:
        raise core.ToolError(
            f"RemoteX credential_ref already exists with different configuration: "
            f"{credential_ref}"
        )
    if not already_configured:
        candidate["credentials"][credential_ref] = record
        candidate["profiles"][profile_name] = profile
    candidate = core._validate_config(candidate)
    return PreparedProfile(
        bundle=bundle,
        candidate=candidate,
        profile_name=profile_name,
        credential_ref=credential_ref,
        profile=profile,
        record=record,
        already_configured=already_configured,
    )
