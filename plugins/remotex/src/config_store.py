from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import remotex_core as core
import secure_paths
import vm_queue


def _serialized(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        secure_paths.ensure_private_file(temporary)
        os.replace(temporary, path)
        secure_paths.ensure_private_file(path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _read_validated(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise core.ToolError("RemoteX config must be a regular local file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError("RemoteX config readback is invalid") from exc
    if not isinstance(value, dict):
        raise core.ToolError("RemoteX config readback is invalid")
    return core._validate_config(value)


def _backup_path(path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return path.with_name(
        f"{path.name}.profile-setup-backup-{timestamp}-{uuid.uuid4().hex[:8]}.json"
    )


@dataclass(frozen=True)
class WriteReceipt:
    path: Path
    original: bytes | None
    backup_path: Path | None
    config_sha256: str
    backup_sha256: str | None


def write_config(
    path: Path,
    candidate: dict[str, Any],
    *,
    expected: dict[str, Any],
    expected_exists: bool,
) -> WriteReceipt:
    target = path.expanduser().absolute()
    candidate = core._validate_config(candidate)
    secure_paths.ensure_private_directory(target.parent)
    lock_path = target.with_name(f".{target.name}.profile-setup.lock")
    with vm_queue._exclusive_lock(lock_path, "RemoteX config"):
        secure_paths.ensure_private_file(lock_path)
        return _write_config_locked(
            target,
            candidate,
            expected=expected,
            expected_exists=expected_exists,
        )


def _write_config_locked(
    target: Path,
    candidate: dict[str, Any],
    *,
    expected: dict[str, Any],
    expected_exists: bool,
) -> WriteReceipt:
    if target.exists() and (not target.is_file() or target.is_symlink()):
        raise core.ToolError("RemoteX config must be a regular local file")
    if target.exists() != expected_exists:
        raise core.ToolError("RemoteX config changed before setup; rerun the preview")
    if expected_exists and _read_validated(target) != expected:
        raise core.ToolError("RemoteX config changed before setup; rerun the preview")
    original = target.read_bytes() if expected_exists else None
    backup_path: Path | None = None
    backup_sha256: str | None = None
    if original is not None:
        backup_path = _backup_path(target)
        try:
            with backup_path.open("xb") as handle:
                handle.write(original)
                handle.flush()
                os.fsync(handle.fileno())
            secure_paths.ensure_private_file(backup_path)
        except Exception as exc:
            try:
                backup_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise core.ToolError(
                "RemoteX profile setup failed before replacement"
            ) from exc
        backup_sha256 = hashlib.sha256(original).hexdigest()

    candidate_bytes = _serialized(candidate)
    try:
        _atomic_write(target, candidate_bytes)
        if _read_validated(target) != candidate:
            raise core.ToolError("RemoteX config semantic readback differs")
    except Exception as exc:
        try:
            if original is None:
                target.unlink(missing_ok=True)
            else:
                _atomic_write(target, original)
            if target.exists() != expected_exists:
                raise core.ToolError("RemoteX config rollback state differs")
            if expected_exists and _read_validated(target) != expected:
                raise core.ToolError("RemoteX config rollback readback differs")
            if backup_path is not None:
                backup_path.unlink(missing_ok=True)
        except Exception as restore_exc:
            raise core.ToolError(
                "RemoteX profile setup failed and rollback could not be verified"
            ) from restore_exc
        if isinstance(exc, core.ToolError):
            raise
        raise core.ToolError("RemoteX profile setup failed and was rolled back") from exc

    return WriteReceipt(
        path=target,
        original=original,
        backup_path=backup_path,
        config_sha256=hashlib.sha256(candidate_bytes).hexdigest(),
        backup_sha256=backup_sha256,
    )


def rollback(receipt: WriteReceipt, expected: dict[str, Any]) -> None:
    secure_paths.ensure_private_directory(receipt.path.parent)
    lock_path = receipt.path.with_name(
        f".{receipt.path.name}.profile-setup.lock"
    )
    with vm_queue._exclusive_lock(lock_path, "RemoteX config"):
        secure_paths.ensure_private_file(lock_path)
        _rollback_locked(receipt, expected)


def _rollback_locked(receipt: WriteReceipt, expected: dict[str, Any]) -> None:
    if _read_validated(receipt.path) != expected:
        raise core.ToolError("RemoteX config changed after setup; refusing rollback")
    if receipt.original is None:
        receipt.path.unlink(missing_ok=True)
        if receipt.path.exists():
            raise core.ToolError("RemoteX config rollback absence readback failed")
    else:
        _atomic_write(receipt.path, receipt.original)
        if hashlib.sha256(receipt.path.read_bytes()).hexdigest() != hashlib.sha256(
            receipt.original
        ).hexdigest():
            raise core.ToolError("RemoteX config rollback byte readback differs")
    if receipt.backup_path is not None:
        receipt.backup_path.unlink(missing_ok=True)
