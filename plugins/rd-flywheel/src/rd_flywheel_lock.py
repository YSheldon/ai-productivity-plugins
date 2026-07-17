from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO


_PROCESS_LOCKS: set[str] = set()
_PROCESS_LOCKS_GUARD = threading.Lock()


class KernelRunLock:
    """Non-expiring process lock backed by the operating-system kernel."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._file: BinaryIO | None = None
        self._registry_key = str(self.path.resolve(strict=False)).casefold()
        self.orphan_metadata: dict[str, Any] | None = None

    @property
    def acquired(self) -> bool:
        return self._file is not None

    def acquire(self) -> bool:
        with _PROCESS_LOCKS_GUARD:
            if self._registry_key in _PROCESS_LOCKS:
                return False
            _PROCESS_LOCKS.add(self._registry_key)

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.path.open("a+b")
            self._ensure_lock_byte(handle)
            if not self._try_kernel_lock(handle):
                handle.close()
                self._release_registry()
                return False
            self._file = handle
            self.orphan_metadata = self._read_existing_metadata(handle)
            self._write_owner_metadata(handle)
            return True
        except Exception:
            if self._file is not None:
                try:
                    self._unlock_kernel(self._file)
                finally:
                    self._file.close()
                    self._file = None
            self._release_registry()
            raise

    def release(self) -> None:
        handle = self._file
        if handle is None:
            return
        try:
            self._unlock_kernel(handle)
        finally:
            handle.close()
            self._file = None
            self._release_registry()

    def __enter__(self) -> "KernelRunLock":
        if not self.acquire():
            raise BlockingIOError("rd-flywheel run lock is already active.")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.release()

    @staticmethod
    def _ensure_lock_byte(handle: BinaryIO) -> None:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b" ")
            handle.flush()
            os.fsync(handle.fileno())
        handle.seek(0)

    @staticmethod
    def _try_kernel_lock(handle: BinaryIO) -> bool:
        if os.name == "nt":
            import msvcrt

            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                return False
        import fcntl

        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (BlockingIOError, OSError):
            return False

    @staticmethod
    def _unlock_kernel(handle: BinaryIO) -> None:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _read_existing_metadata(handle: BinaryIO) -> dict[str, Any] | None:
        handle.seek(0)
        raw = handle.read().decode("utf-8", errors="replace").strip(" \x00\r\n\t")
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return {"unparseable_metadata_sha256": __import__("hashlib").sha256(raw.encode()).hexdigest()}
        return dict(payload) if isinstance(payload, dict) else {"invalid_metadata_type": type(payload).__name__}

    @staticmethod
    def _write_owner_metadata(handle: BinaryIO) -> None:
        payload = {
            "pid": os.getpid(),
            "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        handle.seek(0)
        handle.truncate()
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)

    def _release_registry(self) -> None:
        with _PROCESS_LOCKS_GUARD:
            _PROCESS_LOCKS.discard(self._registry_key)
