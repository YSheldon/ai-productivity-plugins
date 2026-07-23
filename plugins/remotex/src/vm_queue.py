from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, IO, Iterator
from urllib.parse import urlparse

import remotex_core as core


STATE_VERSION = 1
LOCK_TIMEOUT_SECONDS = 5.0
MAX_RESOURCE_LENGTH = 512
REQUESTER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
SUPPORTED_KINDS = {"rdp", "vsphere", "vmware-workstation"}
_PROCESS_LOCKS: set[str] = set()
_PROCESS_LOCKS_GUARD = threading.Lock()


def queue_path() -> Path:
    configured = os.environ.get("REMOTEX_VM_QUEUE_FILE")
    if configured:
        return core.expand_path(configured, "REMOTEX_VM_QUEUE_FILE")
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            root = Path(local_app_data)
        else:
            try:
                root = Path.home() / "AppData" / "Local"
            except RuntimeError as exc:
                raise core.ToolError(
                    "Cannot determine the local VM queue directory; set REMOTEX_VM_QUEUE_FILE"
                ) from exc
        return root / "RemoteX" / "vm-queue.json"
    state_home = os.environ.get("XDG_STATE_HOME")
    try:
        root = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    except RuntimeError as exc:
        raise core.ToolError(
            "Cannot determine the local VM queue directory; set REMOTEX_VM_QUEUE_FILE"
        ) from exc
    return root / "remotex" / "vm-queue.json"


def validate_requester(value: Any) -> str:
    requester = core._required_text(value, "requester")
    if not REQUESTER_PATTERN.fullmatch(requester):
        raise core.ToolError(
            "requester must use 1-128 ASCII letters, digits, dots, underscores, @, colons, or hyphens"
        )
    return requester


def _validate_resource(value: Any) -> str:
    resource = core._required_text(value, "queue resource")
    if len(resource) > MAX_RESOURCE_LENGTH:
        raise core.ToolError(f"queue resource exceeds {MAX_RESOURCE_LENGTH} characters")
    return resource


def _timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _empty_state() -> dict[str, Any]:
    return {"version": STATE_VERSION, "resources": {}}


def _validate_record(record: Any, label: str, time_field: str) -> dict[str, str]:
    if not isinstance(record, dict):
        raise core.ToolError(f"VM queue {label} record is invalid; refusing to discard ownership")
    requester = validate_requester(record.get("requester"))
    recorded_at = core._required_text(record.get(time_field), f"{label}.{time_field}")
    return {"requester": requester, time_field: recorded_at}


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError(
            f"VM queue state at {path} is unreadable; refusing VM operations: {exc}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("version") != STATE_VERSION:
        raise core.ToolError(
            f"VM queue state at {path} has an unsupported format; refusing VM operations"
        )
    resources = payload.get("resources")
    if not isinstance(resources, dict):
        raise core.ToolError(
            f"VM queue state at {path} has invalid resources; refusing VM operations"
        )
    validated: dict[str, Any] = {}
    for resource, entry in resources.items():
        resource_name = _validate_resource(resource)
        if not isinstance(entry, dict):
            raise core.ToolError(
                f"VM queue entry for {resource_name} is invalid; refusing VM operations"
            )
        owner = entry.get("owner")
        validated_owner = (
            None if owner is None else _validate_record(owner, "owner", "claimed_at")
        )
        waiters = entry.get("waiters", [])
        if not isinstance(waiters, list):
            raise core.ToolError(
                f"VM queue waiters for {resource_name} are invalid; refusing VM operations"
            )
        validated_waiters = [
            _validate_record(waiter, "waiter", "requested_at") for waiter in waiters
        ]
        requester_ids = [waiter["requester"] for waiter in validated_waiters]
        if len(requester_ids) != len(set(requester_ids)):
            raise core.ToolError(
                f"VM queue waiters for {resource_name} contain duplicates; refusing VM operations"
            )
        if validated_owner and validated_owner["requester"] in requester_ids:
            raise core.ToolError(
                f"VM queue owner for {resource_name} also appears as a waiter; refusing VM operations"
            )
        validated[resource_name] = {
            "owner": validated_owner,
            "waiters": validated_waiters,
        }
    return {"version": STATE_VERSION, "resources": validated}


def _write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    try:
        temporary.write_text(
            json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except OSError as exc:
        raise core.ToolError(
            f"Unable to persist VM queue state at {path}; refusing VM operations: {exc}"
        ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _ensure_lock_byte(handle: IO[bytes]) -> None:
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    handle.seek(0)


def _lock_nonblocking(handle: IO[bytes]) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(handle: IO[bytes]) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _exclusive_lock(lock_path: Path, label: str) -> Iterator[None]:
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
        _ensure_lock_byte(handle)
    except OSError as exc:
        raise core.ToolError(f"Unable to open {label} lock at {lock_path}: {exc}") from exc
    registry_key = str(lock_path.resolve(strict=False)).casefold()
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    acquired = False
    while time.monotonic() < deadline:
        with _PROCESS_LOCKS_GUARD:
            if registry_key not in _PROCESS_LOCKS:
                try:
                    _lock_nonblocking(handle)
                except (BlockingIOError, OSError):
                    pass
                else:
                    _PROCESS_LOCKS.add(registry_key)
                    acquired = True
        if acquired:
            break
        time.sleep(0.05)
    if not acquired:
        handle.close()
        raise core.ToolError(
            f"{label} lock at {lock_path} stayed busy; refusing VM operations"
        )
    try:
        yield
    finally:
        try:
            _unlock(handle)
        finally:
            handle.close()
            with _PROCESS_LOCKS_GUARD:
                _PROCESS_LOCKS.discard(registry_key)


@contextmanager
def _locked_state() -> Iterator[tuple[Path, dict[str, Any]]]:
    path = queue_path()
    lock_path = path.with_name(f"{path.name}.lock")
    with _exclusive_lock(lock_path, "VM queue"):
        yield path, _load_state(path)


@contextmanager
def _resource_operation_lock(resource: str) -> Iterator[None]:
    path = queue_path()
    digest = hashlib.sha256(resource.encode("utf-8")).hexdigest()
    lock_path = path.with_name(f"{path.name}.{digest}.operation.lock")
    with _exclusive_lock(lock_path, "VM operation"):
        yield


def _entry(state: dict[str, Any], resource: str) -> dict[str, Any]:
    resources = state["resources"]
    return resources.setdefault(resource, {"owner": None, "waiters": []})


def _view(
    resource: str,
    entry: dict[str, Any],
    *,
    requester: str | None = None,
) -> dict[str, Any]:
    owner = entry.get("owner")
    waiters = list(entry.get("waiters", []))
    requester_position = None
    if requester:
        for index, waiter in enumerate(waiters, start=1):
            if waiter["requester"] == requester:
                requester_position = index
                break
    result: dict[str, Any] = {
        "resource": resource,
        "state": "owned" if owner else "unowned",
        "owner": owner,
        "waiters": waiters,
        "queue_length": len(waiters),
        "requester": requester,
        "requester_position": requester_position,
        "preemption_allowed": False,
        "scope": "local-cooperative",
    }
    if owner:
        result["claim_available"] = owner["requester"] == requester
        result["prompt"] = (
            "This VM is already owned by this requester."
            if owner["requester"] == requester
            else "This VM is owned by another requester. Join the FIFO queue; do not preempt it."
        )
    elif waiters:
        first = waiters[0]["requester"]
        result["next_waiter"] = first
        result["claim_available"] = first == requester
        result["prompt"] = (
            "This VM is unowned and this requester is first in line. Ask for confirmation, then claim it."
            if first == requester
            else "This VM is unowned, but only the first queued requester may claim it."
        )
    else:
        result["claim_available"] = True
        result["prompt"] = (
            "This VM is unowned. Ask whether it should be claimed, then claim it explicitly."
        )
    return result


def inspect(resource: Any, requester: Any = None) -> dict[str, Any]:
    resource_name = _validate_resource(resource)
    requester_name = validate_requester(requester) if requester not in (None, "") else None
    with _locked_state() as (_, state):
        entry = state["resources"].get(resource_name, {"owner": None, "waiters": []})
        return _view(resource_name, entry, requester=requester_name)


def request(resource: Any, requester: Any) -> dict[str, Any]:
    resource_name = _validate_resource(resource)
    requester_name = validate_requester(requester)
    with _locked_state() as (path, state):
        entry = _entry(state, resource_name)
        owner = entry.get("owner")
        changed = False
        if owner and owner["requester"] == requester_name:
            status = "already-owned"
        else:
            waiters = entry["waiters"]
            if not any(waiter["requester"] == requester_name for waiter in waiters):
                waiters.append({"requester": requester_name, "requested_at": _timestamp()})
                changed = True
            status = "claim-available" if not owner and waiters[0]["requester"] == requester_name else "queued"
        if changed:
            _write_state(path, state)
        result = _view(resource_name, entry, requester=requester_name)
        result["request_status"] = status
        return result


def claim(resource: Any, requester: Any, confirm: Any) -> dict[str, Any]:
    resource_name = _validate_resource(resource)
    requester_name = validate_requester(requester)
    if not isinstance(confirm, bool) or not confirm:
        raise core.ToolError("confirm=true is required to claim an unowned VM")
    with _locked_state() as (path, state):
        entry = _entry(state, resource_name)
        owner = entry.get("owner")
        changed = False
        if owner:
            if owner["requester"] == requester_name:
                claim_status = "already-owned"
            else:
                waiters = entry["waiters"]
                if not any(waiter["requester"] == requester_name for waiter in waiters):
                    waiters.append({"requester": requester_name, "requested_at": _timestamp()})
                    changed = True
                claim_status = "queued-owner-active"
        else:
            waiters = entry["waiters"]
            if waiters and waiters[0]["requester"] != requester_name:
                if not any(waiter["requester"] == requester_name for waiter in waiters):
                    waiters.append({"requester": requester_name, "requested_at": _timestamp()})
                    changed = True
                claim_status = "queued-behind-first"
            else:
                entry["waiters"] = [
                    waiter for waiter in waiters if waiter["requester"] != requester_name
                ]
                entry["owner"] = {
                    "requester": requester_name,
                    "claimed_at": _timestamp(),
                }
                changed = True
                claim_status = "claimed"
        if changed:
            _write_state(path, state)
        result = _view(resource_name, entry, requester=requester_name)
        result["claim_status"] = claim_status
        result["claimed"] = bool(
            entry.get("owner") and entry["owner"]["requester"] == requester_name
        )
        return result


def release(resource: Any, requester: Any) -> dict[str, Any]:
    resource_name = _validate_resource(resource)
    requester_name = validate_requester(requester)
    with _resource_operation_lock(resource_name), _locked_state() as (path, state):
        entry = _entry(state, resource_name)
        owner = entry.get("owner")
        if owner and owner["requester"] != requester_name:
            raise core.ToolError(
                f"VM is owned by {owner['requester']}; {requester_name} cannot release or preempt it"
            )
        if not owner:
            result = _view(resource_name, entry, requester=requester_name)
            result["release_status"] = "already-unowned"
            return result
        entry["owner"] = None
        entry["waiters"] = [
            waiter for waiter in entry["waiters"] if waiter["requester"] != requester_name
        ]
        if not entry["waiters"]:
            state["resources"].pop(resource_name, None)
        _write_state(path, state)
        result = _view(resource_name, entry, requester=requester_name)
        result["release_status"] = "released"
        if entry["waiters"]:
            result["action_required"] = "notify-first-waiter-to-confirm-claim"
        return result


def cancel(resource: Any, requester: Any) -> dict[str, Any]:
    resource_name = _validate_resource(resource)
    requester_name = validate_requester(requester)
    with _locked_state() as (path, state):
        entry = _entry(state, resource_name)
        owner = entry.get("owner")
        if owner and owner["requester"] == requester_name:
            raise core.ToolError("The current owner must release the VM instead of cancelling")
        original = len(entry["waiters"])
        entry["waiters"] = [
            waiter for waiter in entry["waiters"] if waiter["requester"] != requester_name
        ]
        if len(entry["waiters"]) != original:
            if not owner and not entry["waiters"]:
                state["resources"].pop(resource_name, None)
            _write_state(path, state)
            cancel_status = "cancelled"
        else:
            cancel_status = "not-queued"
        result = _view(resource_name, entry, requester=requester_name)
        result["cancel_status"] = cancel_status
        return result


def require_owner(resource: Any, requester: Any) -> dict[str, Any]:
    resource_name = _validate_resource(resource)
    requester_name = validate_requester(requester)
    with _locked_state() as (_, state):
        entry = state["resources"].get(resource_name, {"owner": None, "waiters": []})
        owner = entry.get("owner")
        if not owner:
            raise core.ToolError(
                "VM is unowned. Request it first, ask for confirmation, then claim it before this operation."
            )
        if owner["requester"] != requester_name:
            raise core.ToolError(
                f"VM is owned by {owner['requester']}; {requester_name} must queue and cannot preempt it"
            )
        return _view(resource_name, entry, requester=requester_name)


@contextmanager
def owner_operation(resource: Any, requester: Any) -> Iterator[dict[str, Any]]:
    resource_name = _validate_resource(resource)
    requester_name = validate_requester(requester)
    with _resource_operation_lock(resource_name):
        yield require_owner(resource_name, requester_name)


def health() -> dict[str, Any]:
    with _locked_state() as (path, state):
        entries = list(state["resources"].values())
        return {
            "ok": True,
            "state_file": str(path),
            "resource_count": len(entries),
            "owned_count": sum(1 for entry in entries if entry.get("owner")),
            "waiter_count": sum(len(entry.get("waiters", [])) for entry in entries),
            "preemption_allowed": False,
            "scope": "local-cooperative",
        }


def _profile(profile: Any) -> tuple[str, dict[str, Any], str]:
    profile_name = core._required_text(profile, "profile")
    bundle = core.load_config()
    raw = bundle.data["profiles"].get(profile_name)
    if not isinstance(raw, dict):
        raise core.ToolError(f"RemoteX profile not found: {profile_name}")
    kind = core.normalize_kind(raw.get("kind"))
    if kind not in SUPPORTED_KINDS:
        raise core.ToolError(
            f"RemoteX profile '{profile_name}' is not a queue-managed VM profile"
        )
    return profile_name, raw, kind


def resolve_profile_resource(
    profile: Any,
    virtual_machine: Any = None,
) -> dict[str, Any]:
    profile_name, raw, kind = _profile(profile)
    configured = raw.get("queue_resource")
    configured_resource = (
        _validate_resource(configured) if configured not in (None, "") else None
    )
    selected_vm: str | None = None
    if kind == "rdp":
        if virtual_machine not in (None, ""):
            raise core.ToolError("virtual_machine is not valid for an RDP profile")
        host = core.validate_host(raw.get("host"))
        port = core.validate_port(raw.get("port"), 3389)
        resource = configured_resource or f"rdp:{host}:{port}"
    elif kind == "vmware-workstation":
        if virtual_machine not in (None, ""):
            raise core.ToolError("virtual_machine is not valid for a VMware Workstation profile")
        vmx_path = core.expand_path(raw.get("vmx_path"), "vmx_path")
        normalized = str(vmx_path.resolve(strict=False))
        if os.name == "nt":
            normalized = normalized.casefold()
        resource = configured_resource or f"vmware:{normalized}"
    else:
        selected_vm = core.validate_selector(virtual_machine, "virtual_machine")
        if configured_resource:
            if "{virtual_machine}" in configured_resource:
                resource = configured_resource.replace("{virtual_machine}", selected_vm)
            else:
                resource = f"{configured_resource}:{selected_vm}"
        else:
            url = core._required_text(raw.get("url"), "url").rstrip("/")
            parsed = urlparse(url)
            if parsed.scheme.lower() != "https" or not parsed.hostname:
                raise core.ToolError("vSphere/ESXi url must be an absolute https URL")
            if parsed.username or parsed.password:
                raise core.ToolError("vSphere/ESXi url must not contain credentials")
            resource = f"vsphere:{url}:{selected_vm}"
    return {
        "profile": profile_name,
        "kind": kind,
        "resource": _validate_resource(resource),
        "virtual_machine": selected_vm,
    }


def require_profile_owner(
    profile: Any,
    requester: Any,
    virtual_machine: Any = None,
) -> dict[str, Any]:
    target = resolve_profile_resource(profile, virtual_machine)
    result = require_owner(target["resource"], requester)
    result.update({key: value for key, value in target.items() if key != "resource"})
    return result


@contextmanager
def profile_owner_operation(
    profile: Any,
    requester: Any,
    virtual_machine: Any = None,
) -> Iterator[dict[str, Any]]:
    target = resolve_profile_resource(profile, virtual_machine)
    with owner_operation(target["resource"], requester) as result:
        result.update({key: value for key, value in target.items() if key != "resource"})
        yield result


def _target(args: dict[str, Any]) -> dict[str, Any]:
    return resolve_profile_resource(args.get("profile"), args.get("virtual_machine"))


def queue_status(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    result = inspect(target["resource"], args.get("requester"))
    result.update({key: value for key, value in target.items() if key != "resource"})
    result["state_file"] = str(queue_path())
    return core.tool_result(result)


def queue_request(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    result = request(target["resource"], args.get("requester"))
    result.update({key: value for key, value in target.items() if key != "resource"})
    return core.tool_result(result)


def queue_claim(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    result = claim(target["resource"], args.get("requester"), args.get("confirm"))
    result.update({key: value for key, value in target.items() if key != "resource"})
    return core.tool_result(result)


def queue_release(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    result = release(target["resource"], args.get("requester"))
    result.update({key: value for key, value in target.items() if key != "resource"})
    return core.tool_result(result)


def queue_cancel(args: dict[str, Any]) -> dict[str, Any]:
    target = _target(args)
    result = cancel(target["resource"], args.get("requester"))
    result.update({key: value for key, value in target.items() if key != "resource"})
    return core.tool_result(result)


PROFILE_PROPERTY = {
    "profile": {
        "type": "string",
        "description": "Required RDP, vSphere/ESXi, or VMware Workstation profile name.",
    },
    "virtual_machine": {
        "type": "string",
        "description": "Required vSphere inventory path; omit for RDP and VMware Workstation.",
    },
}

REQUESTER_PROPERTY = {
    "requester": {
        "type": "string",
        "description": "Stable local requester identifier used for cooperative ownership.",
    }
}

TOOLS: dict[str, dict[str, Any]] = {
    "remotex_vm_queue_status": {
        "description": "Inspect local cooperative VM ownership and FIFO waiters without changing the queue.",
        "inputSchema": {
            "type": "object",
            "properties": {**PROFILE_PROPERTY, **REQUESTER_PROPERTY},
            "required": ["profile"],
            "additionalProperties": False,
        },
        "handler": queue_status,
    },
    "remotex_vm_queue_request": {
        "description": "Join a VM FIFO queue; an unowned VM is only offered for explicit claim.",
        "inputSchema": {
            "type": "object",
            "properties": {**PROFILE_PROPERTY, **REQUESTER_PROPERTY},
            "required": ["profile", "requester"],
            "additionalProperties": False,
        },
        "handler": queue_request,
    },
    "remotex_vm_queue_claim": {
        "description": "Claim an unowned VM only with confirmation and without bypassing earlier waiters.",
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
        "handler": queue_claim,
    },
    "remotex_vm_queue_release": {
        "description": "Release a VM owned by this requester and prompt the first FIFO waiter.",
        "inputSchema": {
            "type": "object",
            "properties": {**PROFILE_PROPERTY, **REQUESTER_PROPERTY},
            "required": ["profile", "requester"],
            "additionalProperties": False,
        },
        "handler": queue_release,
    },
    "remotex_vm_queue_cancel": {
        "description": "Remove this requester from a VM wait queue without affecting its owner.",
        "inputSchema": {
            "type": "object",
            "properties": {**PROFILE_PROPERTY, **REQUESTER_PROPERTY},
            "required": ["profile", "requester"],
            "additionalProperties": False,
        },
        "handler": queue_cancel,
    },
}
