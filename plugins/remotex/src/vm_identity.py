from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import remotex_core as core


IDENTITY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MACHINE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
VMX_UUID_PATTERN = re.compile(r'^\s*(uuid\.(?:bios|location))\s*=\s*"([^"]+)"\s*$', re.IGNORECASE)


def _identity_id(value: Any) -> str:
    identity_id = core._required_text(value, "vm_identity")
    if not IDENTITY_ID_PATTERN.fullmatch(identity_id):
        raise core.ToolError(
            "vm_identity must use 1-128 ASCII letters, digits, dots, underscores, colons, or hyphens"
        )
    return identity_id


def normalize_machine_id(value: Any, field: str = "guest_machine_id") -> str:
    machine_id = core._required_text(value, field)
    if not MACHINE_ID_PATTERN.fullmatch(machine_id):
        raise core.ToolError(
            f"{field} must use 1-128 ASCII letters, digits, dots, underscores, or hyphens"
        )
    return machine_id.casefold()


def normalize_vmware_uuid(value: Any, field: str = "vmware_uuid") -> str:
    raw = core._required_text(value, field)
    compact = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if len(compact) != 32 or not re.fullmatch(r"[0-9A-Fa-f]{32}", compact):
        raise core.ToolError(
            f"{field} must contain a 128-bit VMware UUID in hexadecimal form"
        )
    return compact.casefold()


def vmx_uuid(vmx_path: Path) -> str:
    try:
        lines = vmx_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise core.ToolError(f"Unable to read VMX identity from {vmx_path}: {exc}") from exc
    values: dict[str, str] = {}
    for line in lines:
        match = VMX_UUID_PATTERN.match(line)
        if match:
            values[match.group(1).casefold()] = match.group(2)
    selected = values.get("uuid.bios") or values.get("uuid.location")
    if not selected:
        raise core.ToolError(
            f"VMX identity is missing uuid.bios or uuid.location: {vmx_path}"
        )
    return normalize_vmware_uuid(selected, "VMX UUID")


def _configured_resource(raw: dict[str, Any], profile: str) -> str:
    configured = raw.get("queue_resource")
    if configured in (None, ""):
        raise core.ToolError(
            f"Profile '{profile}' must configure queue_resource when vm_identity is used"
        )
    # Import lazily so this module stays usable while vm_queue imports core.
    import vm_queue

    return vm_queue._validate_resource(configured)


def binding_for_profile(
    profile: str,
    raw: dict[str, Any],
    *,
    require_identity: bool,
    require_guest_profile: bool = False,
) -> dict[str, Any] | None:
    configured_id = raw.get("vm_identity")
    if configured_id in (None, ""):
        if require_identity:
            raise core.ToolError(
                f"Profile '{profile}' must configure vm_identity for this mutating operation"
            )
        return None
    identity_id = _identity_id(configured_id)
    bundle = core.load_config()
    members: list[tuple[str, dict[str, Any], str]] = []
    for candidate_name, candidate_raw in bundle.data["profiles"].items():
        if not isinstance(candidate_raw, dict):
            continue
        if candidate_raw.get("vm_identity") in (None, ""):
            continue
        if _identity_id(candidate_raw.get("vm_identity")) != identity_id:
            continue
        members.append(
            (candidate_name, candidate_raw, core.normalize_kind(candidate_raw.get("kind")))
        )
    if not members:
        raise core.ToolError(f"vm_identity '{identity_id}' has no configured profiles")

    resources = {
        _configured_resource(member_raw, member_name)
        for member_name, member_raw, _ in members
    }
    if len(resources) != 1:
        raise core.ToolError(
            f"vm_identity '{identity_id}' profiles must share one exact queue_resource"
        )
    vmware_members = [item for item in members if item[2] == "vmware-workstation"]
    guest_members = [item for item in members if item[2] == "windows-guest"]
    rdp_members = [item for item in members if item[2] == "rdp"]
    if len(vmware_members) != 1:
        raise core.ToolError(
            f"vm_identity '{identity_id}' must bind exactly one VMware Workstation profile"
        )
    if len(rdp_members) != 1:
        raise core.ToolError(
            f"vm_identity '{identity_id}' must bind exactly one RDP profile"
        )
    if len(guest_members) != 1:
        raise core.ToolError(
            f"vm_identity '{identity_id}' must bind exactly one windows-guest profile"
        )
    vmware_name, vmware_raw, _ = vmware_members[0]
    expected_uuid = normalize_vmware_uuid(vmware_raw.get("vmware_uuid"))
    rdp_name, rdp_raw, _ = rdp_members[0]
    guest_name, guest_raw, _ = guest_members[0]

    guest_machine_ids = {
        normalize_machine_id(member_raw.get("guest_machine_id"))
        for _, member_raw, _ in guest_members
    }
    if len(guest_machine_ids) > 1:
        raise core.ToolError(
            f"vm_identity '{identity_id}' guest profiles disagree on guest_machine_id"
        )
    if not guest_machine_ids:
        raise core.ToolError(
            f"vm_identity '{identity_id}' guest profile must configure guest_machine_id"
        )

    return {
        "id": identity_id,
        "queueResource": next(iter(resources)),
        "vmwareProfile": vmware_name,
        "vmwareUuid": expected_uuid,
        "rdpProfile": rdp_name,
        "rdpEndpoint": {
            "host": core.validate_host(rdp_raw.get("host")),
            "port": core.validate_port(rdp_raw.get("port"), 3389),
        },
        "guestProfile": guest_name,
        "guestMachineId": next(iter(guest_machine_ids), None),
        "guestEndpoint": {
            "host": core.validate_host(guest_raw.get("host")),
            "port": core.validate_port(guest_raw.get("port"), 5985),
        },
        "members": [
            {"profile": member_name, "kind": kind}
            for member_name, _, kind in sorted(members)
        ],
    }


def verify_vmx(binding: dict[str, Any], vmx_path: Path) -> str:
    observed = vmx_uuid(vmx_path)
    if observed != binding["vmwareUuid"]:
        raise core.ToolError(
            "vm-identity-mismatch: configured VMware UUID does not match the selected VMX"
        )
    return observed


def verify_bound_vmx(binding: dict[str, Any], bundle: Any | None = None) -> Path:
    active_bundle = bundle or core.load_config()
    vmware_raw = active_bundle.data["profiles"].get(binding["vmwareProfile"])
    if not isinstance(vmware_raw, dict):
        raise core.ToolError("vm-identity-mismatch: bound VMware profile is unavailable")
    vmx_path = core.expand_path(vmware_raw.get("vmx_path"), "vmx_path")
    if vmx_path.suffix.lower() != ".vmx" or not vmx_path.is_file():
        raise core.ToolError(
            "vm-identity-mismatch: bound VMware VMX path is unavailable for this operation"
        )
    verify_vmx(binding, vmx_path)
    return vmx_path


def verify_guest_machine(binding: dict[str, Any], observed: Any) -> str:
    expected = binding.get("guestMachineId")
    if not expected:
        raise core.ToolError(
            f"vm_identity '{binding['id']}' has no configured guest_machine_id"
        )
    actual = normalize_machine_id(observed, "observed guest machine identifier")
    if actual != expected:
        raise core.ToolError(
            "guest-identity-mismatch: authenticated guest machine identifier does not match "
            "the VMX-bound logical VM"
        )
    return actual


def status_for_profile(profile: str, raw: dict[str, Any]) -> dict[str, Any]:
    try:
        binding = binding_for_profile(
            profile,
            raw,
            require_identity=False,
            require_guest_profile=False,
        )
    except core.ToolError as exc:
        return {"configured": True, "ready": False, "error": str(exc)}
    if binding is None:
        return {
            "configured": False,
            "ready": False,
            "error": "vm_identity is not configured",
        }
    return {"configured": True, "ready": True, **binding}
