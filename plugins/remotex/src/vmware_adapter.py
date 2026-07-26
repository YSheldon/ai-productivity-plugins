from __future__ import annotations

import hashlib
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import remotex_core as core
import vm_identity
import vm_queue


WINDOWS_VMRUN_PATH = Path(
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
) / "VMware" / "VMware Workstation" / "vmrun.exe"
SNAPSHOT_STATE_SCHEMA = "RemoteXVmwareSnapshotState/v1"
SNAPSHOT_RECEIPT_SCHEMA = "RemoteXVmwareSnapshotReceipt/v1"
SNAPSHOT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,127}$")
IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _receipt_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _vmrun_path(configured: Any = None) -> str:
    if configured not in (None, ""):
        return core.find_executable("vmrun", configured)
    if os.name == "nt" and WINDOWS_VMRUN_PATH.is_file():
        return str(WINDOWS_VMRUN_PATH)
    return core.find_executable("vmrun")


def _vmrun_available(configured: Any = None) -> bool:
    try:
        _vmrun_path(configured)
    except core.ToolError:
        return False
    return True


def connection_config(profile: Any = None, *, require_vmx: bool) -> dict[str, Any]:
    name, raw, bundle = core.select_profile("vmware-workstation", profile)
    host_type = str(raw.get("host_type") or "ws").strip().lower()
    if host_type != "ws":
        raise core.ToolError("VMware Workstation host_type must be ws")
    vmx_path: Path | None = None
    if raw.get("vmx_path"):
        vmx_path = core.expand_path(raw.get("vmx_path"), "vmx_path")
        if vmx_path.suffix.lower() != ".vmx":
            raise core.ToolError("vmx_path must use the .vmx extension")
    if require_vmx and vmx_path is None:
        raise core.ToolError("vmx_path is required for this VMware operation")
    return {
        "profile": name,
        "raw": raw,
        "config_source": bundle.source,
        "host_type": host_type,
        "vmrun_path": raw.get("vmrun_path"),
        "vmx_path": vmx_path,
    }


def _canonical_vm(cfg: dict[str, Any]) -> dict[str, Any]:
    vmx = cfg["vmx_path"]
    if vmx is None or not vmx.is_file():
        raise core.ToolError(f"vmx_path does not exist: {vmx}")
    resolved = str(vmx.resolve(strict=False))
    if os.name == "nt":
        resolved = resolved.casefold()
    return {
        "profile": cfg["profile"],
        "vmxPath": resolved,
        "vmwareUuid": vm_identity.vmx_uuid(vmx),
    }


def _mutation_identity(cfg: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    binding = vm_identity.binding_for_profile(
        cfg["profile"],
        cfg["raw"],
        require_identity=True,
        require_guest_profile=False,
    )
    assert binding is not None
    observed_uuid = vm_identity.verify_vmx(binding, cfg["vmx_path"])
    canonical = _canonical_vm(cfg)
    if canonical["vmwareUuid"] != observed_uuid:
        raise core.ToolError("vm-identity-mismatch: VMX UUID readback changed during validation")
    return binding, canonical


def profile_status(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "profile": name,
        "kind": "vmware-workstation",
        "client_available": _vmrun_available(raw.get("vmrun_path")),
        "credential_source": "local-user-session",
    }
    errors: list[str] = []
    vmx_path: Path | None = None
    host_type = str(raw.get("host_type") or "ws").strip().lower()
    if host_type != "ws":
        errors.append("host_type must be ws")
    if raw.get("vmx_path"):
        try:
            vmx_path = core.expand_path(raw.get("vmx_path"), "vmx_path")
            result["vmx_file_exists"] = vmx_path.is_file()
            if not vmx_path.is_file():
                errors.append("vmx_path does not exist")
        except core.ToolError as exc:
            errors.append(str(exc))
    else:
        result["vmx_file_exists"] = None
    identity = vm_identity.status_for_profile(name, raw)
    result["vmIdentity"] = identity
    identity_validated = False
    if raw.get("vm_identity") not in (None, ""):
        if not identity.get("ready"):
            errors.append(str(identity.get("error") or "VM identity binding is invalid"))
        elif vmx_path is not None and vmx_path.is_file():
            try:
                vm_identity.verify_vmx(identity, vmx_path)
                identity_validated = True
            except core.ToolError as exc:
                errors.append(str(exc))
    if not result["client_available"]:
        errors.append("vmrun is unavailable")
    result["ready"] = not errors
    result["errors"] = errors
    snapshot_ready = bool(
        result["client_available"]
        and result.get("vmx_file_exists")
        and identity_validated
    )
    result["capabilities"] = {
        "power": {
            "available": snapshot_ready,
            "failureCode": None if snapshot_ready else "identity-or-client-unavailable",
        },
        "snapshot": {
            "available": snapshot_ready,
            "failureCode": None if snapshot_ready else "identity-or-client-unavailable",
        },
        "guest_exec": {
            "available": False,
            "failureCode": "use-bound-windows-guest-profile",
        },
        "guest_copy": {
            "available": False,
            "failureCode": "use-bound-windows-guest-profile",
        },
        "reboot_wait": {
            "available": False,
            "failureCode": "use-bound-windows-guest-profile",
        },
    }
    return result

def _run(cfg: dict[str, Any], arguments: list[str], timeout: int) -> dict[str, Any]:
    return core.run_process(
        [_vmrun_path(cfg.get("vmrun_path")), "-T", cfg["host_type"], *arguments],
        timeout=timeout,
    )


def _client_result(outcome: dict[str, Any]) -> dict[str, Any]:
    stdout = str(outcome.get("stdout") or "")
    stderr = str(outcome.get("stderr") or "")
    return {
        "clientReturnCode": outcome["returncode"],
        "timedOut": outcome["timed_out"],
        "stdoutSha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderrSha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "rawOutputExported": False,
    }


def _result(cfg: dict[str, Any], outcome: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "ok": outcome["returncode"] == 0 and not outcome["timed_out"],
        "profile": cfg["profile"],
        **_client_result(outcome),
        **extra,
    }


def _snapshot_state_path() -> Path:
    configured = os.environ.get("REMOTEX_VMWARE_SNAPSHOT_STATE_FILE")
    if configured:
        return core.expand_path(configured, "REMOTEX_VMWARE_SNAPSHOT_STATE_FILE")
    return vm_queue.queue_path().with_name("vmware-snapshot-state.json")


@contextmanager
def _locked_snapshot_state() -> Iterator[dict[str, Any]]:
    path = _snapshot_state_path()
    lock_path = path.with_name(f"{path.name}.lock")
    with vm_queue._exclusive_lock(lock_path, "VMware snapshot state"):
        yield _load_snapshot_state()


def _empty_snapshot_state() -> dict[str, Any]:
    return {"schema": SNAPSHOT_STATE_SCHEMA, "identities": {}}


def _load_snapshot_state() -> dict[str, Any]:
    path = _snapshot_state_path()
    if not path.exists():
        return _empty_snapshot_state()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError(f"VMware snapshot idempotency state is unreadable: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != SNAPSHOT_STATE_SCHEMA:
        raise core.ToolError(f"VMware snapshot idempotency state has an unsupported format: {path}")
    if not isinstance(value.get("identities"), dict):
        raise core.ToolError(f"VMware snapshot idempotency state has invalid identities: {path}")
    return value


def _write_snapshot_state(value: dict[str, Any]) -> None:
    path = _snapshot_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except OSError as exc:
        raise core.ToolError(f"Unable to persist VMware snapshot state at {path}: {exc}") from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _identity_key(binding: dict[str, Any]) -> str:
    return hashlib.sha256(
        (binding["id"] + "\x00" + binding["vmwareUuid"]).encode("utf-8")
    ).hexdigest()


def _snapshot_name(value: Any) -> str:
    name = core._required_text(value, "snapshot_name")
    if not SNAPSHOT_NAME_PATTERN.fullmatch(name) or name in {".", ".."} or "/" in name or "\\" in name:
        raise core.ToolError(
            "snapshot_name must be an unambiguous 1-128 character name without paths or control characters"
        )
    return name


def _idempotency_key(value: Any) -> str:
    key = core._required_text(value, "idempotency_key")
    if not IDEMPOTENCY_PATTERN.fullmatch(key):
        raise core.ToolError(
            "idempotency_key must use 1-128 ASCII letters, digits, dots, underscores, colons, or hyphens"
        )
    return key


def _snapshot_inventory(cfg: dict[str, Any], timeout: int) -> tuple[list[str], dict[str, Any]]:
    outcome = _run(cfg, ["listSnapshots", str(cfg["vmx_path"])], timeout)
    if outcome["returncode"] != 0 or outcome["timed_out"]:
        raise core.ToolError("snapshot-inventory-failed: vmrun listSnapshots did not complete")
    snapshots: list[str] = []
    for line in str(outcome.get("stdout") or "").splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.casefold().startswith("total snapshots"):
            continue
        normalized = re.sub(r"^[|`+\-\s]+", "", trimmed).strip()
        if normalized:
            snapshots.append(normalized)
    if len(snapshots) > 256:
        raise core.ToolError("snapshot-inventory-failed: vmrun returned more than 256 snapshots")
    if len(snapshots) != len(set(snapshots)):
        raise core.ToolError("snapshot-inventory-failed: vmrun returned ambiguous duplicate snapshot names")
    return snapshots, outcome


def _inventory_view(snapshots: list[str]) -> dict[str, Any]:
    return {
        "snapshots": snapshots,
        "count": len(snapshots),
        "sha256": hashlib.sha256("\n".join(snapshots).encode("utf-8")).hexdigest(),
    }


def _snapshot_receipt(
    operation: str,
    cfg: dict[str, Any],
    canonical: dict[str, Any],
    payload: dict[str, Any],
) -> dict[str, Any]:
    receipt = {
        "schema": SNAPSHOT_RECEIPT_SCHEMA,
        "createdAtUtc": _utc_now(),
        "profile": cfg["profile"],
        "canonicalVm": canonical,
        "operation": operation,
        "payload": payload,
        "rawOutputExported": False,
    }
    receipt["sha256"] = _receipt_hash(receipt)
    return receipt


def list_running(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"), require_vmx=False)
    timeout = core.validate_timeout(args.get("timeout_seconds"), 30)
    outcome = _run(cfg, ["list"], timeout)
    lines = [line.strip() for line in outcome["stdout"].splitlines() if line.strip()]
    running = lines[1:] if lines and lines[0].lower().startswith("total running") else lines
    result = _result(cfg, outcome, operation="list-running", runningVms=running)
    return core.tool_result(result)


def power(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"), require_vmx=True)
    action = str(args.get("action") or "").strip().lower()
    default_mode = "nogui" if action == "start" else "soft"
    mode = str(args.get("mode") or default_mode).strip().lower()
    if action not in {"start", "stop", "reset", "suspend", "pause", "unpause"}:
        raise core.ToolError("action must be start, stop, reset, suspend, pause, or unpause")
    if mode not in {"soft", "hard", "gui", "nogui"}:
        raise core.ToolError("mode must be soft, hard, gui, or nogui")
    if action == "start":
        if mode not in {"gui", "nogui"}:
            raise core.ToolError("start mode must be gui or nogui")
        arguments = [action, str(cfg["vmx_path"]), mode]
    elif action in {"stop", "reset", "suspend"}:
        if mode not in {"soft", "hard"}:
            raise core.ToolError(f"{action} mode must be soft or hard")
        arguments = [action, str(cfg["vmx_path"]), mode]
    else:
        arguments = [action, str(cfg["vmx_path"])]
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    with vm_queue.profile_owner_operation(cfg["profile"], args.get("requester")) as ownership:
        _, canonical = _mutation_identity(cfg)
        outcome = _run(cfg, arguments, timeout)
    return core.tool_result(
        _result(
            cfg,
            outcome,
            operation="power",
            canonicalVm=canonical,
            action=action,
            mode=None if action in {"pause", "unpause"} else mode,
            queueResource=ownership["resource"],
            queueOwner=ownership["owner"]["requester"],
        )
    )


def list_snapshots(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"), require_vmx=True)
    timeout = core.validate_timeout(args.get("timeout_seconds"), 30)
    binding, canonical = _mutation_identity(cfg)
    snapshots, outcome = _snapshot_inventory(cfg, timeout)
    return core.tool_result(
        {
            "ok": True,
            "profile": cfg["profile"],
            "vmIdentity": binding,
            "canonicalVm": canonical,
            "operation": "list-snapshots",
            "inventory": _inventory_view(snapshots),
            **_client_result(outcome),
        }
    )


def _record_for_name(state: dict[str, Any], binding: dict[str, Any], name: str) -> dict[str, Any] | None:
    identity = state["identities"].get(_identity_key(binding), {})
    records = identity.get("snapshots", {}) if isinstance(identity, dict) else {}
    record = records.get(name) if isinstance(records, dict) else None
    return record if isinstance(record, dict) else None


def _record_for_key(state: dict[str, Any], binding: dict[str, Any], key: str) -> tuple[str, dict[str, Any]] | None:
    identity = state["identities"].get(_identity_key(binding), {})
    records = identity.get("snapshots", {}) if isinstance(identity, dict) else {}
    if not isinstance(records, dict):
        return None
    for name, record in records.items():
        if isinstance(record, dict) and record.get("idempotencyKey") == key:
            return name, record
    return None


def _save_record(state: dict[str, Any], binding: dict[str, Any], name: str, record: dict[str, Any]) -> None:
    identities = state["identities"]
    identity = identities.setdefault(
        _identity_key(binding),
        {"id": binding["id"], "vmwareUuid": binding["vmwareUuid"], "snapshots": {}},
    )
    identity["snapshots"][name] = record


def _snapshot_failure_code(outcome: dict[str, Any], exact_match: bool) -> str | None:
    if outcome["timed_out"]:
        return "vmrun-timeout"
    if outcome["returncode"] != 0:
        return "vmrun-failed"
    if not exact_match:
        return "snapshot-readback-failed"
    return None


def snapshot_create(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"), require_vmx=True)
    requester = vm_queue.validate_requester(args.get("requester"))
    name = _snapshot_name(args.get("snapshot_name"))
    key = _idempotency_key(args.get("idempotency_key"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 180)
    requested_preflight_hash = core._required_text(
        args.get("preflight_receipt_sha256"), "preflight_receipt_sha256"
    )
    if not re.fullmatch(r"[0-9a-f]{64}", requested_preflight_hash):
        raise core.ToolError("preflight_receipt_sha256 must be a lowercase SHA-256 hex digest")
    with vm_queue.profile_owner_operation(cfg["profile"], requester) as ownership:
        binding, canonical = _mutation_identity(cfg)
        before, _ = _snapshot_inventory(cfg, timeout)
        state = _load_snapshot_state()
        same_name = _record_for_name(state, binding, name)
        same_key = _record_for_key(state, binding, key)
        if name in before:
            if same_name and same_name.get("idempotencyKey") == key:
                if same_name.get("preflightReceiptSha256") != requested_preflight_hash:
                    raise core.ToolError(
                        "idempotency-key-conflict: this key is already bound to a different preflight receipt"
                    )
                payload = {
                    "snapshotName": name,
                    "idempotencyKey": key,
                    "preflightReceiptSha256": same_name["preflightReceiptSha256"],
                    "requestAccepted": False,
                    "idempotent": True,
                    "clientReturnCode": None,
                    "beforeInventory": _inventory_view(before),
                    "afterInventory": _inventory_view(before),
                    "exactSnapshotMatch": True,
                    "targetStateReadback": True,
                    "failureCode": None,
                }
                receipt = _snapshot_receipt("snapshot-create", cfg, canonical, payload)
                response = {
                    "ok": True,
                    "profile": cfg["profile"],
                    "queueResource": ownership["resource"],
                    "queueOwner": ownership["owner"]["requester"],
                    **payload,
                    "receipt": receipt,
                    "receiptSha256": receipt["sha256"],
                }
            else:
                raise core.ToolError(
                    "snapshot-name-conflict: the exact snapshot name already exists with a different request"
                )
        else:
            if same_key:
                raise core.ToolError(
                    "idempotency-key-conflict: this key is already bound to a different snapshot name"
                )
            from windows_guest import require_preflight_receipt

            preflight = require_preflight_receipt(binding, requested_preflight_hash)
            outcome = _run(cfg, ["snapshot", str(cfg["vmx_path"]), name], timeout)
            after, _ = _snapshot_inventory(cfg, timeout)
            exact = name in after
            payload = {
                "snapshotName": name,
                "idempotencyKey": key,
                "preflightReceiptSha256": preflight["sha256"],
                "requestAccepted": True,
                "idempotent": False,
                **_client_result(outcome),
                "beforeInventory": _inventory_view(before),
                "afterInventory": _inventory_view(after),
                "exactSnapshotMatch": exact,
                "targetStateReadback": exact,
                "failureCode": _snapshot_failure_code(outcome, exact),
            }
            receipt = _snapshot_receipt("snapshot-create", cfg, canonical, payload)
            succeeded = outcome["returncode"] == 0 and not outcome["timed_out"] and exact
            if succeeded:
                with _locked_snapshot_state() as locked_state:
                    _save_record(
                        locked_state,
                        binding,
                        name,
                        {
                            "idempotencyKey": key,
                            "preflightReceiptSha256": preflight["sha256"],
                            "receiptSha256": receipt["sha256"],
                            "createdAtUtc": receipt["createdAtUtc"],
                        },
                    )
                    _write_snapshot_state(locked_state)
            response = {
                "ok": bool(succeeded),
                "profile": cfg["profile"],
                "queueResource": ownership["resource"],
                "queueOwner": ownership["owner"]["requester"],
                **payload,
                "receipt": receipt,
                "receiptSha256": receipt["sha256"],
            }
    return core.tool_result(response)

def _require_existing_snapshot(state: dict[str, Any], binding: dict[str, Any], name: str) -> dict[str, Any]:
    record = _record_for_name(state, binding, name)
    if not record:
        raise core.ToolError("snapshot-receipt-not-found: only snapshots created with a bound RemoteX receipt may be mutated")
    return record


def _confirmed(args: dict[str, Any], operation: str) -> None:
    if args.get("confirm") is not True:
        raise core.ToolError(f"confirm=true is required to {operation} a VMware snapshot")


def snapshot_revert(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"), require_vmx=True)
    requester = vm_queue.validate_requester(args.get("requester"))
    name = _snapshot_name(args.get("snapshot_name"))
    _confirmed(args, "revert")
    timeout = core.validate_timeout(args.get("timeout_seconds"), 180)
    with vm_queue.profile_owner_operation(cfg["profile"], requester) as ownership:
        binding, canonical = _mutation_identity(cfg)
        record = _require_existing_snapshot(_load_snapshot_state(), binding, name)
        before, _ = _snapshot_inventory(cfg, timeout)
        if name not in before:
            raise core.ToolError("snapshot-readback-failed: requested snapshot is absent before revert")
        outcome = _run(cfg, ["revertToSnapshot", str(cfg["vmx_path"]), name], timeout)
        after, _ = _snapshot_inventory(cfg, timeout)
    exact = name in after
    payload = {
        "snapshotName": name,
        "preflightReceiptSha256": record.get("preflightReceiptSha256"),
        "requestAccepted": True,
        **_client_result(outcome),
        "beforeInventory": _inventory_view(before),
        "afterInventory": _inventory_view(after),
        "exactSnapshotMatch": exact,
        "targetStateReadback": exact,
        "failureCode": _snapshot_failure_code(outcome, exact),
        "readbackScope": "snapshot-inventory",
    }
    receipt = _snapshot_receipt("snapshot-revert", cfg, canonical, payload)
    return core.tool_result({"ok": bool(outcome["returncode"] == 0 and not outcome["timed_out"] and exact), "profile": cfg["profile"], "queueResource": ownership["resource"], "queueOwner": ownership["owner"]["requester"], **payload, "receipt": receipt, "receiptSha256": receipt["sha256"]})


def snapshot_delete(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"), require_vmx=True)
    requester = vm_queue.validate_requester(args.get("requester"))
    name = _snapshot_name(args.get("snapshot_name"))
    _confirmed(args, "delete")
    timeout = core.validate_timeout(args.get("timeout_seconds"), 180)
    with vm_queue.profile_owner_operation(cfg["profile"], requester) as ownership:
        binding, canonical = _mutation_identity(cfg)
        record = _require_existing_snapshot(_load_snapshot_state(), binding, name)
        before, _ = _snapshot_inventory(cfg, timeout)
        if name not in before:
            raise core.ToolError("snapshot-readback-failed: requested snapshot is absent before delete")
        outcome = _run(cfg, ["deleteSnapshot", str(cfg["vmx_path"]), name], timeout)
        after, _ = _snapshot_inventory(cfg, timeout)
        exact = name not in after
        if outcome["returncode"] == 0 and not outcome["timed_out"] and exact:
            with _locked_snapshot_state() as locked_state:
                identity_state = locked_state["identities"].get(_identity_key(binding), {})
                if isinstance(identity_state, dict) and isinstance(identity_state.get("snapshots"), dict):
                    identity_state["snapshots"].pop(name, None)
                    _write_snapshot_state(locked_state)
    payload = {
        "snapshotName": name,
        "preflightReceiptSha256": record.get("preflightReceiptSha256"),
        "requestAccepted": True,
        **_client_result(outcome),
        "beforeInventory": _inventory_view(before),
        "afterInventory": _inventory_view(after),
        "exactSnapshotMatch": exact,
        "targetStateReadback": exact,
        "failureCode": _snapshot_failure_code(outcome, exact),
    }
    receipt = _snapshot_receipt("snapshot-delete", cfg, canonical, payload)
    return core.tool_result({"ok": bool(outcome["returncode"] == 0 and not outcome["timed_out"] and exact), "profile": cfg["profile"], "queueResource": ownership["resource"], "queueOwner": ownership["owner"]["requester"], **payload, "receipt": receipt, "receiptSha256": receipt["sha256"]})


COMMON_PROFILE = {"profile": {"type": "string", "description": "Optional VMware Workstation profile name from the RemoteX config."}}
COMMON_TIMEOUT = {"timeout_seconds": {"type": "integer", "minimum": 1, "maximum": core.MAX_TIMEOUT_SECONDS}}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_vmware_list_running": {
        "description": "List running local VMware Workstation virtual machines through vmrun.",
        "inputSchema": {"type": "object", "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT}, "additionalProperties": False},
        "handler": list_running,
    },
    "remotex_vmware_power": {
        "description": "Change a VM power state only after the requester owns its queue and the configured VMX identity matches.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, "action": {"type": "string", "enum": ["start", "stop", "reset", "suspend", "pause", "unpause"]}, "mode": {"type": "string", "enum": ["soft", "hard", "gui", "nogui"]}, "requester": {"type": "string"}},
            "required": ["action", "requester"],
            "additionalProperties": False,
        },
        "handler": power,
    },
    "remotex_vmware_list_snapshots": {
        "description": "List a configured VM's VMware Workstation snapshot inventory without mutating it.",
        "inputSchema": {"type": "object", "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT}, "additionalProperties": False},
        "handler": list_snapshots,
    },
    "remotex_vmware_snapshot_create": {
        "description": "Create a queue-owned VMware snapshot after a fresh, passing, VMX-bound guest preflight receipt; exact inventory readback is mandatory.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, "requester": {"type": "string"}, "snapshot_name": {"type": "string"}, "idempotency_key": {"type": "string"}, "preflight_receipt_sha256": {"type": "string"}},
            "required": ["requester", "snapshot_name", "idempotency_key", "preflight_receipt_sha256"],
            "additionalProperties": False,
        },
        "handler": snapshot_create,
    },
    "remotex_vmware_snapshot_revert": {
        "description": "Revert a receipt-bound VMware snapshot only after explicit confirmation and inventory readback.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, "requester": {"type": "string"}, "snapshot_name": {"type": "string"}, "confirm": {"type": "boolean"}},
            "required": ["requester", "snapshot_name", "confirm"],
            "additionalProperties": False,
        },
        "handler": snapshot_revert,
    },
    "remotex_vmware_snapshot_delete": {
        "description": "Delete a receipt-bound VMware snapshot only after explicit confirmation and absence readback.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, "requester": {"type": "string"}, "snapshot_name": {"type": "string"}, "confirm": {"type": "boolean"}},
            "required": ["requester", "snapshot_name", "confirm"],
            "additionalProperties": False,
        },
        "handler": snapshot_delete,
    },
}
