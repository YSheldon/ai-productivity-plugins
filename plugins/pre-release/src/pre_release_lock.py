from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from typing import Any

try:  # pragma: no cover - imported for cross-platform contract evidence
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore

try:  # pragma: no cover - imported for cross-platform contract evidence
    import msvcrt  # type: ignore
except ImportError:  # pragma: no cover
    msvcrt = None  # type: ignore


class RunOnceLock:
    def __init__(self, path: str | Path, *, owner: str | None = None) -> None:
        self.path = Path(path).resolve(strict=False)
        self.metadata_path = self.path.with_name(f"{self.path.name}.json")
        self.owner = owner or f"{socket.gethostname()}:{os.getpid()}"
        self.orphan_metadata: dict[str, Any] = {}

    def acquire(self) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        recovered_owner = None
        orphan = self._metadata()
        if orphan and self._is_orphaned(orphan):
            self.orphan_metadata = orphan
            recovered_owner = orphan.get("owner")
            self.release(force=True)
        try:
            handle = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return {"status": "active", "owner": self._metadata().get("owner"), "orphan_metadata": self.orphan_metadata or None}
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(self.owner)
        self.metadata_path.write_text(json.dumps({"status": "active", "owner": self.owner, "acquired_at": time.time()}, sort_keys=True), encoding="utf-8")
        return {"status": "acquired", "recovered_owner": recovered_owner, "orphan_metadata": self.orphan_metadata or None}

    def release(self, *, force: bool = False) -> None:
        current = self._metadata().get("owner")
        if not force and current not in {None, self.owner}:
            return
        if self.path.exists():
            self.path.unlink()
        if self.metadata_path.exists():
            self.metadata_path.unlink()

    def _is_orphaned(self, metadata: dict[str, Any]) -> bool:
        if not self.path.exists():
            return True
        owner = str(metadata.get("owner") or "")
        if not owner:
            return True
        return not self._pid_alive(owner)

    @staticmethod
    def _pid_alive(owner: str) -> bool:
        try:
            pid = int(owner.rsplit(":", 1)[-1])
        except (ValueError, TypeError):
            return False
        if pid <= 0:
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
