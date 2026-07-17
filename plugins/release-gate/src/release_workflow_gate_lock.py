from __future__ import annotations

import contextlib
import json
import os
import socket
import time
from pathlib import Path
from typing import Any

with contextlib.suppress(ImportError):
    import msvcrt  # noqa: F401

with contextlib.suppress(ImportError):
    import fcntl  # noqa: F401


class RunOnceLock:
    def __init__(self, path: str | Path, *, owner: str | None = None) -> None:
        self.path = Path(path).resolve(strict=False)
        self.metadata_path = self.path.with_name(f"{self.path.name}.json")
        self.owner = owner or f"{socket.gethostname()}:{os.getpid()}"

    def acquire(self) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        orphan_metadata = self._metadata()
        orphan_owner = str(orphan_metadata.get("owner") or "").strip() or None
        recovered_owner = None
        if orphan_owner and (not self.path.exists() or not self._pid_alive()):
            recovered_owner = orphan_owner
            self.release(force=True)
        try:
            handle = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return {"status": "active", "owner": self._metadata().get("owner")}
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(self.owner)
        self.metadata_path.write_text(
            json.dumps({"status": "active", "owner": self.owner, "acquired_at": time.time()}, sort_keys=True),
            encoding="utf-8",
        )
        return {"status": "acquired", "recovered_owner": recovered_owner}

    def release(self, *, force: bool = False) -> None:
        current = self._metadata().get("owner")
        if not force and current not in {None, self.owner}:
            return
        if self.path.exists():
            self.path.unlink()
        if self.metadata_path.exists():
            self.metadata_path.unlink()

    def _pid_alive(self) -> bool:
        try:
            owner = str(self._metadata().get("owner") or "")
            pid = int(owner.rsplit(":", 1)[-1])
        except (ValueError, TypeError):
            return False
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def _metadata(self) -> dict[str, Any]:
        if not self.metadata_path.exists():
            return {}
        try:
            payload = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}
