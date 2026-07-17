from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class DependencyLockError(RuntimeError):
    """Raised when a dependency lock or its pinned runtime entrypoint drifts."""


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def resolve_locked_entrypoint(
    dependency_lock: str | Path,
    *,
    dependency_lock_sha256: str,
    plugin_name: str,
    plugin_root: str | Path,
    entrypoint_path: str | Path,
) -> Path:
    lock_path = Path(dependency_lock).expanduser().resolve(strict=True)
    expected_lock_digest = str(dependency_lock_sha256 or "").strip().lower()
    if not _SHA256_PATTERN.fullmatch(expected_lock_digest):
        raise DependencyLockError("dependency lock SHA-256 is missing or invalid.")
    if sha256_file(lock_path) != expected_lock_digest:
        raise DependencyLockError("dependency lock drift was detected.")

    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DependencyLockError("dependency lock is invalid JSON.") from exc
    plugins = payload.get("plugins") if isinstance(payload, Mapping) else None
    if not isinstance(plugins, list):
        raise DependencyLockError("dependency lock must contain a plugins array.")

    expected_root = Path(plugin_root)
    expected_entrypoint = Path(entrypoint_path)
    if expected_root.is_absolute() or expected_entrypoint.is_absolute():
        raise DependencyLockError("locked plugin paths must be repository-relative.")
    try:
        expected_entrypoint.relative_to(expected_root)
    except ValueError as exc:
        raise DependencyLockError(
            "locked runtime entrypoint must be under the expected plugin root."
        ) from exc

    for plugin in plugins:
        if not isinstance(plugin, Mapping) or plugin.get("name") != plugin_name:
            continue
        locked_root = Path(str(plugin.get("plugin_root") or ""))
        if locked_root.as_posix() != expected_root.as_posix():
            raise DependencyLockError(f"dependency lock {plugin_name} root is invalid.")
        entrypoints = plugin.get("entrypoints")
        if not isinstance(entrypoints, list):
            raise DependencyLockError(
                f"dependency lock does not pin {plugin_name} runtime entrypoints."
            )
        for entrypoint in entrypoints:
            if not isinstance(entrypoint, Mapping):
                continue
            locked_path = Path(str(entrypoint.get("path") or ""))
            if locked_path.as_posix() != expected_entrypoint.as_posix():
                continue
            expected_digest = str(entrypoint.get("sha256") or "").strip().lower()
            if not _SHA256_PATTERN.fullmatch(expected_digest):
                raise DependencyLockError("locked runtime entrypoint SHA-256 is invalid.")
            resolved = (lock_path.parent / locked_path).resolve(strict=True)
            try:
                resolved.relative_to((lock_path.parent / expected_root).resolve(strict=True))
            except ValueError as exc:
                raise DependencyLockError(
                    "locked runtime entrypoint escapes the plugin root."
                ) from exc
            if sha256_file(resolved) != expected_digest:
                raise DependencyLockError("locked runtime entrypoint drift was detected.")
            return resolved
        raise DependencyLockError(
            f"dependency lock does not pin runtime entrypoint {expected_entrypoint.as_posix()}."
        )
    raise DependencyLockError(f"dependency lock does not include {plugin_name}.")
