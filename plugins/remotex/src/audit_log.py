from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import remotex_core as core


SCHEMA = "RemoteXAudit/v1"
SESSION_ID = str(uuid.uuid4())
_PROCESS_LOCK = threading.Lock()


def audit_path() -> Path:
    configured = os.environ.get("REMOTEX_AUDIT_FILE")
    if configured:
        return core.expand_path(configured, "REMOTEX_AUDIT_FILE")
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    return root / "RemoteX" / "audit.jsonl"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@contextmanager
def _locked_file(path: Path) -> Iterator[Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_APPEND
        | getattr(os, "O_BINARY", 0)
    )
    handle = os.fdopen(os.open(path, flags, 0o600), "a+b")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    try:
        if os.name == "nt":
            import msvcrt

            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\x00")
                handle.flush()
                os.fsync(handle.fileno())
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield handle
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _records(handle: Any) -> list[dict[str, Any]]:
    handle.seek(0)
    raw = handle.read()
    if raw == b"\x00":
        return []
    raw = raw.lstrip(b"\x00")
    records: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise core.ToolError(
                f"RemoteX audit ledger is corrupt at line {number}: {audit_path()}"
            ) from exc
        if not isinstance(value, dict):
            raise core.ToolError(
                f"RemoteX audit ledger line {number} is not an object: {audit_path()}"
            )
        records.append(value)
    return records


def _verify_records(records: list[dict[str, Any]]) -> str | None:
    previous: str | None = None
    for number, record in enumerate(records, 1):
        expected_previous = record.get("previousHash")
        if expected_previous != previous:
            raise core.ToolError(
                f"RemoteX audit hash chain is broken at line {number}: {audit_path()}"
            )
        stored = record.get("entryHash")
        unsigned = dict(record)
        unsigned.pop("entryHash", None)
        calculated = hashlib.sha256(_canonical(unsigned)).hexdigest()
        if stored != calculated:
            raise core.ToolError(
                f"RemoteX audit entry hash is invalid at line {number}: {audit_path()}"
            )
        previous = stored
    return previous


def append(event: dict[str, Any]) -> dict[str, Any]:
    path = audit_path()
    with _PROCESS_LOCK, _locked_file(path) as handle:
        records = _records(handle)
        previous = _verify_records(records)
        record = {
            "schema": SCHEMA,
            "timestamp": _utc_now(),
            "sessionId": SESSION_ID,
            **event,
            "previousHash": previous,
        }
        record["entryHash"] = hashlib.sha256(_canonical(record)).hexdigest()
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 1:
            handle.seek(0)
            if handle.read(1) == b"\x00":
                handle.seek(0)
                handle.truncate()
        handle.seek(0, os.SEEK_END)
        handle.write(_canonical(record) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
        return record


def _reference_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for name, reference in value.items():
        if isinstance(reference, str):
            result[str(name)] = {"source": "environment", "reference": reference}
        elif isinstance(reference, dict):
            result[str(name)] = {
                key: reference.get(key)
                for key in ("source", "name", "target", "field", "secret")
                if key in reference
            }
    return result


def summarize_arguments(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        key: arguments[key]
        for key in (
            "profile",
            "requester",
            "action",
            "shell",
            "verify",
            "overwrite",
            "recursive",
            "virtual_machine",
            "resource",
            "task_id",
            "snapshot_name",
            "idempotency_key",
            "preflight_receipt_sha256",
            "run_id",
            "confirm",
        )
        if key in arguments
    }
    for key in ("command", "script"):
        if key in arguments:
            text = core._text(arguments.get(key))
            summary[f"{key}Sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
            summary[f"{key}Bytes"] = len(text.encode("utf-8"))
    for key in ("local_path", "remote_path", "relative_path"):
        if key in arguments:
            summary[key] = core.redact_text(arguments[key])
    if "environment_refs" in arguments:
        summary["environmentRefs"] = _reference_summary(arguments.get("environment_refs"))
    for key in (
        "timeout_seconds",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "memory_limit_mb",
        "cpu_time_seconds",
        "max_processes",
        "lease_seconds",
    ):
        if key in arguments:
            summary[key] = arguments[key]
    return summary


def summarize_result(result: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {"isError": bool(result.get("isError"))}
    try:
        content = result.get("content") or []
        text = content[0].get("text") if content and isinstance(content[0], dict) else None
        payload = json.loads(text) if text else {}
    except (AttributeError, json.JSONDecodeError, TypeError):
        payload = {}
    if isinstance(payload, dict):
        for key in (
            "ok",
            "exitCode",
            "returncode",
            "timedOut",
            "timed_out",
            "durationMs",
            "terminationReason",
            "integrityMatched",
            "protocol",
            "taskId",
            "state",
            "claim_status",
            "release_status",
            "renew_status",
            "heartbeatStatus",
            "recoveryStatus",
            "requestAccepted",
            "clientReturnCode",
            "targetStateReadback",
            "exactSnapshotMatch",
            "receiptSha256",
            "failureCode",
            "integrityMatched",
            "newAuthenticatedSessionReady",
            "oldBootIdentityDisappeared",
        ):
            if key in payload:
                summary[key] = payload[key]
        for key in ("actualLocalPath", "actualRemotePath"):
            if key in payload:
                summary[key] = core.redact_text(payload[key])
    return summary


def begin(tool: str, arguments: dict[str, Any], version: str) -> str:
    operation_id = str(uuid.uuid4())
    append(
        {
            "event": "operation-start",
            "operationId": operation_id,
            "tool": tool,
            "toolVersion": version,
            "request": summarize_arguments(tool, arguments),
        }
    )
    return operation_id


def finish(
    operation_id: str,
    tool: str,
    result: dict[str, Any],
    version: str,
    started_monotonic: float,
) -> None:
    append(
        {
            "event": "operation-finish",
            "operationId": operation_id,
            "tool": tool,
            "toolVersion": version,
            "durationMs": int((time_monotonic() - started_monotonic) * 1000),
            "result": summarize_result(result),
        }
    )


def time_monotonic() -> float:
    return time.monotonic()


def attach_metadata(result: dict[str, Any], operation_id: str) -> dict[str, Any]:
    metadata = {
        "sessionId": SESSION_ID,
        "operationId": operation_id,
    }
    result["_meta"] = {
        **(result.get("_meta") if isinstance(result.get("_meta"), dict) else {}),
        "remotex": metadata,
    }
    try:
        content = result.get("content") or []
        if not content or not isinstance(content[0], dict):
            return result
        payload = json.loads(content[0].get("text") or "")
        if not isinstance(payload, dict):
            return result
        payload.update(metadata)
        content[0]["text"] = json.dumps(payload, ensure_ascii=False, indent=2)
    except (AttributeError, json.JSONDecodeError, TypeError):
        pass
    return result


def export(_: dict[str, Any]) -> dict[str, Any]:
    path = audit_path()
    if not path.exists():
        return core.tool_result(
            {
                "ok": True,
                "path": str(path),
                "entryCount": 0,
                "chainValid": True,
                "sha256": None,
                "lastEntryHash": None,
            }
        )
    with _PROCESS_LOCK, _locked_file(path) as handle:
        records = _records(handle)
        last_hash = _verify_records(records)
        handle.seek(0)
        raw = handle.read().lstrip(b"\x00")
    return core.tool_result(
        {
            "ok": True,
            "path": str(path),
            "entryCount": len(records),
            "chainValid": True,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "lastEntryHash": last_hash,
            "sessionId": SESSION_ID,
        }
    )


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_audit_export": {
        "description": (
            "Verify and export metadata for the hash-linked local RemoteX JSONL audit ledger."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "handler": export,
    }
}
