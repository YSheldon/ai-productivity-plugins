from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import remotex_core as core
import vm_queue


SCHEMA = "RemoteXQueueLeases/v1"
DEFAULT_LEASE_SECONDS = 4 * 60 * 60
MIN_LEASE_SECONDS = 60
MAX_LEASE_SECONDS = 7 * 24 * 60 * 60
_ORIGINAL_REQUIRE_OWNER = vm_queue.require_owner
_HOOKS_INSTALLED = False


def lease_path() -> Path:
    configured = os.environ.get("REMOTEX_VM_QUEUE_LEASE_FILE")
    if configured:
        return core.expand_path(configured, "REMOTEX_VM_QUEUE_LEASE_FILE")
    queue = vm_queue.queue_path()
    return queue.with_name(f"{queue.stem}-leases.json")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _now()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, field: str) -> datetime:
    text = core._required_text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise core.ToolError(f"{field} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise core.ToolError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _empty() -> dict[str, Any]:
    return {"schema": SCHEMA, "leases": {}, "events": []}


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError(
            f"VM queue lease state at {path} is unreadable; refusing VM operations: {exc}"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != SCHEMA
        or not isinstance(payload.get("leases"), dict)
        or not isinstance(payload.get("events"), list)
    ):
        raise core.ToolError(
            f"VM queue lease state at {path} has an unsupported format; refusing VM operations"
        )
    for resource, record in payload["leases"].items():
        vm_queue._validate_resource(resource)
        if not isinstance(record, dict):
            raise core.ToolError(f"VM queue lease for {resource} is invalid")
        vm_queue.validate_requester(record.get("requester"))
        _parse_timestamp(record.get("issuedAt"), f"leases.{resource}.issuedAt")
        _parse_timestamp(record.get("expiresAt"), f"leases.{resource}.expiresAt")
        _lease_seconds(record.get("leaseSeconds"))
    return payload


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.tmp"
    )
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except OSError as exc:
        raise core.ToolError(
            f"Unable to persist VM queue lease state at {path}; refusing VM operations: {exc}"
        ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


@contextmanager
def _locked() -> Iterator[tuple[Path, dict[str, Any]]]:
    path = lease_path()
    lock = path.with_name(f"{path.name}.lock")
    with vm_queue._exclusive_lock(lock, "VM queue lease"):
        yield path, _load(path)


def _lease_seconds(value: Any) -> int:
    try:
        seconds = int(DEFAULT_LEASE_SECONDS if value in (None, "") else value)
    except (TypeError, ValueError) as exc:
        raise core.ToolError("lease_seconds must be an integer") from exc
    if not MIN_LEASE_SECONDS <= seconds <= MAX_LEASE_SECONDS:
        raise core.ToolError(
            f"lease_seconds must be between {MIN_LEASE_SECONDS} and {MAX_LEASE_SECONDS}"
        )
    return seconds


def _configured_lease(profile: str, requested: Any) -> int:
    if requested not in (None, ""):
        return _lease_seconds(requested)
    bundle = core.load_config()
    raw = bundle.data["profiles"].get(profile)
    if isinstance(raw, dict) and raw.get("queue_lease_seconds") not in (None, ""):
        return _lease_seconds(raw.get("queue_lease_seconds"))
    configured = os.environ.get("REMOTEX_VM_QUEUE_LEASE_SECONDS")
    return _lease_seconds(configured)


def _target(args: dict[str, Any]) -> dict[str, Any]:
    profile = core._required_text(args.get("profile"), "profile")
    bundle = core.load_config()
    raw = bundle.data["profiles"].get(profile)
    if not isinstance(raw, dict):
        raise core.ToolError(f"RemoteX profile not found: {profile}")
    kind = core.normalize_kind(raw.get("kind"))
    if kind == "ssh":
        resource = raw.get("queue_resource")
        if resource in (None, ""):
            raise core.ToolError(
                f"SSH profile '{profile}' requires queue_resource for VM queue participation"
            )
        if args.get("virtual_machine") not in (None, ""):
            raise core.ToolError("virtual_machine is not valid for an SSH profile")
        return {
            "profile": profile,
            "kind": kind,
            "resource": vm_queue._validate_resource(resource),
            "virtual_machine": None,
        }
    return vm_queue.resolve_profile_resource(profile, args.get("virtual_machine"))


def _event(
    state: dict[str, Any],
    event: str,
    resource: str,
    requester: str,
    **extra: Any,
) -> None:
    state["events"].append(
        {
            "event": event,
            "timestamp": _timestamp(),
            "resource": resource,
            "requester": requester,
            **extra,
        }
    )
    if len(state["events"]) > 1000:
        state["events"] = state["events"][-1000:]


def _lease_view(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not record:
        return None
    expires = _parse_timestamp(record["expiresAt"], "expiresAt")
    remaining = max(0, int((expires - _now()).total_seconds()))
    return {
        **record,
        "expired": remaining == 0,
        "remainingSeconds": remaining,
        "autoTransfer": False,
    }


def _legacy_lease_view() -> dict[str, Any]:
    return {
        "state": "legacy-unleased",
        "expired": False,
        "renewRequired": True,
        "autoTransfer": False,
        "prompt": (
            "This owner predates queue leases. Renew to migrate ownership into "
            "a bounded lease, or release it before session end."
        ),
    }


def _expire_locked(resource: str) -> dict[str, Any] | None:
    with _locked() as (lease_file, leases):
        record = leases["leases"].get(resource)
        if not record:
            return None
        expires = _parse_timestamp(record["expiresAt"], "expiresAt")
        if expires > _now():
            return record
        with vm_queue._locked_state() as (queue_file, queue_state):
            entry = queue_state["resources"].get(resource)
            owner = entry.get("owner") if isinstance(entry, dict) else None
            if owner and owner.get("requester") == record["requester"]:
                entry["owner"] = None
                if not entry.get("waiters"):
                    queue_state["resources"].pop(resource, None)
                vm_queue._write_state(queue_file, queue_state)
        leases["leases"].pop(resource, None)
        _event(
            leases,
            "lease-expired",
            resource,
            record["requester"],
            expiredAt=record["expiresAt"],
        )
        _write(lease_file, leases)
        return None


def _expire(resource: str) -> dict[str, Any] | None:
    with vm_queue._resource_operation_lock(resource):
        return _expire_locked(resource)


def _set_lease(
    resource: str,
    requester: str,
    seconds: int,
    event: str,
) -> dict[str, Any]:
    now = _now()
    record = {
        "requester": requester,
        "issuedAt": _timestamp(now),
        "expiresAt": _timestamp(now + timedelta(seconds=seconds)),
        "leaseSeconds": seconds,
    }
    with _locked() as (path, state):
        state["leases"][resource] = record
        _event(state, event, resource, requester, expiresAt=record["expiresAt"])
        _write(path, state)
    return record


def _clear_lease(resource: str, requester: str, event: str) -> None:
    with _locked() as (path, state):
        record = state["leases"].get(resource)
        if record and record.get("requester") == requester:
            state["leases"].pop(resource, None)
            _event(state, event, resource, requester)
            _write(path, state)


def inspect_resource(resource: str) -> dict[str, Any] | None:
    _expire(resource)
    with _locked() as (_, state):
        return _lease_view(state["leases"].get(resource))


def queue_status(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    lease = inspect_resource(target["resource"])
    result = vm_queue.inspect(target["resource"], args.get("requester"))
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["state_file"] = str(vm_queue.queue_path())
    result["lease"] = lease or (_legacy_lease_view() if result.get("owner") else None)
    result["lease_file"] = str(lease_path())
    return core.tool_result(result)


def queue_request(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    _expire(target["resource"])
    result = vm_queue.request(target["resource"], args.get("requester"))
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["lease"] = inspect_resource(target["resource"])
    return core.tool_result(result)


def queue_claim(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    requester = vm_queue.validate_requester(args.get("requester"))
    seconds = _configured_lease(target["profile"], args.get("lease_seconds"))
    with vm_queue._resource_operation_lock(target["resource"]):
        _expire_locked(target["resource"])
        result = vm_queue.claim(
            target["resource"],
            requester,
            args.get("confirm"),
        )
        if result.get("claimed"):
            lease = _set_lease(
                target["resource"],
                requester,
                seconds,
                "lease-issued",
            )
        else:
            lease = None
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["lease"] = _lease_view(lease)
    return core.tool_result(result)


def queue_renew(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    requester = vm_queue.validate_requester(args.get("requester"))
    seconds = _configured_lease(target["profile"], args.get("lease_seconds"))
    with vm_queue._resource_operation_lock(target["resource"]):
        active = _expire_locked(target["resource"])
        _ORIGINAL_REQUIRE_OWNER(target["resource"], requester)
        if active and active["requester"] != requester:
            raise core.ToolError(
                f"VM lease belongs to {active['requester']}; {requester} cannot renew it"
            )
        event = "lease-renewed" if active else "lease-migrated"
        lease = _set_lease(
            target["resource"],
            requester,
            seconds,
            event,
        )
    result = vm_queue.inspect(target["resource"], requester)
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["renew_status"] = (
        "renewed" if active else "migrated-legacy-owner"
    )
    result["lease"] = _lease_view(lease)
    return core.tool_result(result)


def queue_heartbeat(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    requester = vm_queue.validate_requester(args.get("requester"))
    seconds = _configured_lease(target["profile"], args.get("lease_seconds"))
    with vm_queue._resource_operation_lock(target["resource"]):
        active = _expire_locked(target["resource"])
        _ORIGINAL_REQUIRE_OWNER(target["resource"], requester)
        if active and active["requester"] != requester:
            raise core.ToolError(
                f"VM lease belongs to {active['requester']}; {requester} cannot heartbeat it"
            )
        event = "lease-heartbeat" if active else "lease-heartbeat-migrated"
        lease = _set_lease(target["resource"], requester, seconds, event)
    result = vm_queue.inspect(target["resource"], requester)
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["heartbeatStatus"] = "renewed" if active else "migrated-legacy-owner"
    result["heartbeatAt"] = lease["issuedAt"]
    result["lease"] = _lease_view(lease)
    return core.tool_result(result)


def queue_recover_stale(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    requester = vm_queue.validate_requester(args.get("requester"))
    if args.get("confirm") is not True:
        raise core.ToolError(
            "confirm=true is required to recover a stale VM lease; recovery never transfers ownership"
        )
    with vm_queue._resource_operation_lock(target["resource"]):
        with _locked() as (lease_file, leases):
            record = leases["leases"].get(target["resource"])
            if not isinstance(record, dict):
                raise core.ToolError(
                    "stale-owner-recovery-refused: no active lease exists for this VM resource"
                )
            expires = _parse_timestamp(record.get("expiresAt"), "expiresAt")
            if expires > _now():
                raise core.ToolError(
                    "stale-owner-recovery-refused: the current VM lease has not expired"
                )
            stale_owner = vm_queue.validate_requester(record.get("requester"))
            with vm_queue._locked_state() as (queue_file, queue_state):
                entry = queue_state["resources"].get(target["resource"])
                owner = entry.get("owner") if isinstance(entry, dict) else None
                if not isinstance(owner, dict) or owner.get("requester") != stale_owner:
                    raise core.ToolError(
                        "stale-owner-recovery-refused: queue owner does not match the expired lease"
                    )
                entry["owner"] = None
                if not entry.get("waiters"):
                    queue_state["resources"].pop(target["resource"], None)
                vm_queue._write_state(queue_file, queue_state)
            leases["leases"].pop(target["resource"], None)
            _event(
                leases,
                "stale-owner-recovered",
                target["resource"],
                requester,
                staleOwner=stale_owner,
                expiredAt=record["expiresAt"],
            )
            _write(lease_file, leases)
    result = vm_queue.inspect(target["resource"], requester)
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["recoveryStatus"] = "recovered-unowned"
    result["recoveredOwner"] = stale_owner
    result["lease"] = None
    result["nextAction"] = (
        "notify-first-waiter-to-confirm-claim"
        if result.get("next_waiter")
        else "request-and-confirm-claim"
    )
    return core.tool_result(result)


def queue_release(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    requester = vm_queue.validate_requester(args.get("requester"))
    _expire(target["resource"])
    result = vm_queue.release(target["resource"], requester)
    _clear_lease(target["resource"], requester, "lease-released")
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["lease"] = None
    return core.tool_result(result)


def queue_cancel(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    _expire(target["resource"])
    result = vm_queue.cancel(target["resource"], args.get("requester"))
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["lease"] = inspect_resource(target["resource"])
    return core.tool_result(result)


@contextmanager
def leased_owner_operation(resource: Any, requester: Any) -> Iterator[dict[str, Any]]:
    resource_name = vm_queue._validate_resource(resource)
    requester_name = vm_queue.validate_requester(requester)
    with vm_queue._resource_operation_lock(resource_name):
        lease = _expire_locked(resource_name)
        result = _ORIGINAL_REQUIRE_OWNER(resource_name, requester_name)
        if not lease:
            result["lease"] = _legacy_lease_view()
            yield result
            return
        if lease["requester"] != requester_name:
            raise core.ToolError(
                f"VM lease belongs to {lease['requester']}; {requester_name} cannot preempt it"
            )
        result["lease"] = _lease_view(lease)
        yield result


def install_hooks() -> None:
    global _HOOKS_INSTALLED
    if _HOOKS_INSTALLED:
        return
    vm_queue.owner_operation = leased_owner_operation
    _HOOKS_INSTALLED = True


def held_resources() -> list[dict[str, Any]]:
    with vm_queue._locked_state() as (_, state):
        resources = [
            (resource, entry)
            for resource, entry in state["resources"].items()
            if entry.get("owner")
        ]
    result: list[dict[str, Any]] = []
    for resource, _ in resources:
        lease = inspect_resource(resource)
        current = vm_queue.inspect(resource)
        if not current.get("owner"):
            continue
        effective_lease = lease or _legacy_lease_view()
        result.append(
            {
                "resource": resource,
                "owner": current["owner"],
                "lease": effective_lease,
                "actionRequired": "renew-or-release-before-session-end",
            }
        )
    return result


def health() -> dict[str, Any]:
    base = vm_queue.health()
    held = held_resources()
    leased_count = sum(
        1 for item in held if item["lease"].get("state") != "legacy-unleased"
    )
    base.update(
        {
            "lease_file": str(lease_path()),
            "default_lease_seconds": DEFAULT_LEASE_SECONDS,
            "held_owned_count": len(held),
            "leased_owned_count": leased_count,
            "legacy_unleased_count": len(held) - leased_count,
            "held_resources": held,
            "session_end_prompt_required": bool(held),
            "silent_auto_transfer": False,
        }
    )
    return base


PROFILE_PROPERTY = {
    "profile": {
        "type": "string",
        "description": (
            "Required SSH, RDP, Windows guest, vSphere/ESXi, or VMware Workstation "
            "profile name."
        ),
    },
    "virtual_machine": {
        "type": "string",
        "description": "Required vSphere inventory path; omit for other profile kinds.",
    },
}
REQUESTER_PROPERTY = {
    "requester": {
        "type": "string",
        "description": "Stable local requester identifier used for cooperative ownership.",
    }
}
LEASE_PROPERTY = {
    "lease_seconds": {
        "type": "integer",
        "minimum": MIN_LEASE_SECONDS,
        "maximum": MAX_LEASE_SECONDS,
        "description": "Explicit renewable lease duration; expiry never auto-assigns a waiter.",
    }
}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_vm_queue_status": {
        "description": "Inspect cooperative FIFO ownership and its renewable lease.",
        "inputSchema": {
            "type": "object",
            "properties": {**PROFILE_PROPERTY, **REQUESTER_PROPERTY},
            "required": ["profile"],
            "additionalProperties": False,
        },
        "handler": queue_status,
    },
    "remotex_vm_queue_request": {
        "description": "Join a FIFO queue without preempting the active lease owner.",
        "inputSchema": {
            "type": "object",
            "properties": {**PROFILE_PROPERTY, **REQUESTER_PROPERTY},
            "required": ["profile", "requester"],
            "additionalProperties": False,
        },
        "handler": queue_request,
    },
    "remotex_vm_queue_claim": {
        "description": (
            "Explicitly claim an unowned resource with a bounded lease and FIFO fairness."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **PROFILE_PROPERTY,
                **REQUESTER_PROPERTY,
                **LEASE_PROPERTY,
                "confirm": {"type": "boolean"},
            },
            "required": ["profile", "requester", "confirm"],
            "additionalProperties": False,
        },
        "handler": queue_claim,
    },
    "remotex_vm_queue_renew": {
        "description": "Renew the current requester's active lease without changing ownership.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **PROFILE_PROPERTY,
                **REQUESTER_PROPERTY,
                **LEASE_PROPERTY,
            },
            "required": ["profile", "requester"],
            "additionalProperties": False,
        },
        "handler": queue_renew,
    },
    "remotex_vm_queue_heartbeat": {
        "description": "Record an owner heartbeat and extend its bounded lease without transferring ownership.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **PROFILE_PROPERTY,
                **REQUESTER_PROPERTY,
                **LEASE_PROPERTY,
            },
            "required": ["profile", "requester"],
            "additionalProperties": False,
        },
        "handler": queue_heartbeat,
    },
    "remotex_vm_queue_recover_stale": {
        "description": "Explicitly recover an expired owner lease as unowned; it never assigns a waiter.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **PROFILE_PROPERTY,
                **REQUESTER_PROPERTY,
                "confirm": {"type": "boolean"},
            },
            "required": ["profile", "requester", "confirm"],
            "additionalProperties": False,
        },
        "handler": queue_recover_stale,
    },
    "remotex_vm_queue_release": {
        "description": "Release ownership and prompt, but never auto-assign, the first waiter.",
        "inputSchema": {
            "type": "object",
            "properties": {**PROFILE_PROPERTY, **REQUESTER_PROPERTY},
            "required": ["profile", "requester"],
            "additionalProperties": False,
        },
        "handler": queue_release,
    },
    "remotex_vm_queue_cancel": {
        "description": "Leave a wait queue without affecting the active owner or lease.",
        "inputSchema": {
            "type": "object",
            "properties": {**PROFILE_PROPERTY, **REQUESTER_PROPERTY},
            "required": ["profile", "requester"],
            "additionalProperties": False,
        },
        "handler": queue_cancel,
    },
}
