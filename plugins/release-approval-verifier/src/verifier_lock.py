from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, IO, Mapping


_OWNER_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_PROCESS_LOCKS: set[str] = set()
_PROCESS_LOCKS_GUARD = threading.Lock()


class RunLockError(RuntimeError):
    """Raised when the run-once lock cannot be managed safely."""


class RunOnceLock:
    """Non-expiring, process-safe lock for unattended run-once operations."""

    def __init__(
        self,
        path: str | Path,
        *,
        owner: str,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        if not _OWNER_PATTERN.fullmatch(owner):
            raise RunLockError("lock owner must use 1-128 safe identifier characters.")
        self.path = Path(path)
        self.metadata_path = self.path.with_name(f"{self.path.name}.json")
        self.owner = owner
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._handle: IO[bytes] | None = None
        self._registry_key = str(self.path.resolve(strict=False)).casefold()

    def acquire(self) -> dict[str, Any]:
        if self._handle is not None:
            return {"status": "acquired", "recovered_owner": None}

        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        self._ensure_lock_byte(handle)

        with _PROCESS_LOCKS_GUARD:
            if self._registry_key in _PROCESS_LOCKS:
                handle.close()
                return {"status": "active", "owner": self._active_owner()}
            try:
                self._lock_nonblocking(handle)
            except (BlockingIOError, OSError):
                handle.close()
                return {"status": "active", "owner": self._active_owner()}
            _PROCESS_LOCKS.add(self._registry_key)

        recovered_owner: str | None = None
        prior = self._read_metadata()
        if prior.get("status") == "active":
            prior_owner = str(prior.get("owner") or "").strip()
            if prior_owner and prior_owner != self.owner:
                recovered_owner = prior_owner

        self._handle = handle
        try:
            self._write_metadata(
                {
                    "status": "active",
                    "owner": self.owner,
                    "acquired_at": self._isoformat(self.now_fn()),
                }
            )
        except Exception:
            self._release_handle()
            raise
        return {"status": "acquired", "recovered_owner": recovered_owner}

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            self._write_metadata(
                {
                    "status": "released",
                    "owner": self.owner,
                    "released_at": self._isoformat(self.now_fn()),
                }
            )
        finally:
            self._release_handle()

    def __enter__(self) -> RunOnceLock:
        result = self.acquire()
        if result["status"] != "acquired":
            raise RunLockError(f"run-once lock is held by {result.get('owner', 'unknown')}.")
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.release()

    def _active_owner(self) -> str:
        metadata = self._read_metadata()
        owner = str(metadata.get("owner") or "").strip()
        return owner if metadata.get("status") == "active" and owner else "unknown"

    def _read_metadata(self) -> Mapping[str, Any]:
        if not self.metadata_path.is_file():
            return {}
        try:
            payload = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, Mapping) else {}

    def _write_metadata(self, payload: Mapping[str, Any]) -> None:
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.metadata_path.with_name(
            f".{self.metadata_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        temporary.write_text(
            json.dumps(dict(payload), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.metadata_path)

    def _release_handle(self) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            self._unlock(handle)
        finally:
            handle.close()
            with _PROCESS_LOCKS_GUARD:
                _PROCESS_LOCKS.discard(self._registry_key)

    @staticmethod
    def _ensure_lock_byte(handle: IO[bytes]) -> None:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
            os.fsync(handle.fileno())
        handle.seek(0)

    @staticmethod
    def _lock_nonblocking(handle: IO[bytes]) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _unlock(handle: IO[bytes]) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _isoformat(value: datetime) -> str:
        return (
            value.astimezone(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
