from __future__ import annotations

import contextlib
import json
import os
import socket
import time
import threading
from pathlib import Path
from typing import Any

with contextlib.suppress(ImportError):
    import msvcrt  # noqa: F401

with contextlib.suppress(ImportError):
    import fcntl  # noqa: F401


_LOCAL_LOCK_GUARD = threading.Lock()
_LOCAL_LOCK_PATHS: set[str] = set()


class RunOnceLock:
    def __init__(self, path: str | Path, *, owner: str | None = None) -> None:
        self.path = Path(path).resolve(strict=False)
        self.metadata_path = self.path.with_name(f"{self.path.name}.json")
        self.owner = owner or f"{socket.gethostname()}:{os.getpid()}"
        self._handle: int | None = None

    def acquire(self) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        local_key = self._local_key()
        with _LOCAL_LOCK_GUARD:
            if local_key in _LOCAL_LOCK_PATHS:
                return {"status": "active", "owner": self._active_owner()}

        handle = self._open_and_lock()
        if handle is None:
            return {"status": "active", "owner": self._active_owner()}

        with _LOCAL_LOCK_GUARD:
            if local_key in _LOCAL_LOCK_PATHS:
                self._unlock_and_close(handle)
                return {"status": "active", "owner": self._active_owner()}
            _LOCAL_LOCK_PATHS.add(local_key)
        self._handle = handle

        orphan_metadata = self._metadata()
        orphan_owner = (
            str(orphan_metadata.get("owner") or "").strip()
            or self._lock_owner()
        )
        try:
            self._write_owner()
            self.metadata_path.write_text(
                json.dumps(
                    {
                        "status": "active",
                        "owner": self.owner,
                        "acquired_at": time.time(),
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
        except Exception:
            self.release(force=True)
            raise
        return {"status": "acquired", "recovered_owner": orphan_owner or None}

    def release(self, *, force: bool = False) -> None:
        handle = self._handle
        if handle is None:
            return
        try:
            current = self._metadata().get("owner")
            if force or current in {None, self.owner}:
                with contextlib.suppress(OSError):
                    self.metadata_path.unlink()
                with contextlib.suppress(OSError):
                    os.ftruncate(handle, 0)
        finally:
            self._handle = None
            self._unlock_and_close(handle)
            with _LOCAL_LOCK_GUARD:
                _LOCAL_LOCK_PATHS.discard(self._local_key())

    def _local_key(self) -> str:
        return os.path.normcase(str(self.path))

    def _active_owner(self) -> str | None:
        return (
            str(self._metadata().get("owner") or "").strip()
            or self._lock_owner()
        )

    def _lock_owner(self) -> str | None:
        try:
            return self.path.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def _open_and_lock(self) -> int | None:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        handle: int | None = None
        try:
            handle = os.open(str(self.path), flags, 0o600)
            if os.fstat(handle).st_size == 0:
                os.write(handle, b" ")
            os.lseek(handle, 0, os.SEEK_SET)
            if os.name == "nt":
                msvcrt.locking(handle, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except OSError:
            if handle is not None:
                with contextlib.suppress(OSError):
                    os.close(handle)
            return None

    def _write_owner(self) -> None:
        if self._handle is None:
            raise RuntimeError("lock handle is unavailable")
        os.ftruncate(self._handle, 0)
        os.lseek(self._handle, 0, os.SEEK_SET)
        os.write(self._handle, self.owner.encode("utf-8"))

    @staticmethod
    def _unlock_and_close(handle: int) -> None:
        try:
            os.lseek(handle, 0, os.SEEK_SET)
            if os.name == "nt":
                msvcrt.locking(handle, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)

    def _metadata(self) -> dict[str, Any]:
        if not self.metadata_path.exists():
            return {}
        try:
            payload = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}
