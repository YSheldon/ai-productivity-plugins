from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlparse


ADAPTER_VERSION = "1.0.0"
STATE_DIRECTORY = ".product-release-gate"
VALID_STAGES = frozenset(
    {"preproduction", "production_canary", "production_full"}
)
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


class AdapterError(RuntimeError):
    pass


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def object_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_replace(source: Path, destination: Path) -> None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file = kernel32.MoveFileExW
        move_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
        ]
        move_file.restype = wintypes.BOOL
        replace_existing = 0x00000001
        write_through = 0x00000008
        if not move_file(
            str(source),
            str(destination),
            replace_existing | write_through,
        ):
            error = ctypes.get_last_error()
            raise OSError(
                error,
                ctypes.FormatError(error),
                str(destination),
            )
        return
    os.replace(source, destination)
    _fsync_directory(destination.parent)


def durable_copy(source: Path, destination: Path) -> None:
    shutil.copyfile(source, destination)
    with destination.open("rb+") as handle:
        handle.flush()
        os.fsync(handle.fileno())
    shutil.copystat(source, destination, follow_symlinks=False)


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdapterError(f"{label} is missing") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterError(f"{label} is unreadable or invalid JSON") from exc
    if not isinstance(value, dict):
        raise AdapterError(f"{label} must be one JSON object")
    return value


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    payload = (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode(
        "utf-8"
    )
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        durable_replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def safe_logical_name(value: Any) -> str:
    raw = str(value or "")
    name = raw.strip()
    stem = name.split(".", 1)[0].casefold()
    if (
        not name
        or raw != name
        or name in {".", ".."}
        or name.endswith(".")
        or "/" in name
        or "\\" in name
        or ":" in name
        or any(ord(character) < 32 for character in name)
        or stem in _WINDOWS_RESERVED_NAMES
    ):
        raise AdapterError(
            "Manifest-R logical_name must be one portable file name"
        )
    return name


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _paths_overlap(left: Path, right: Path) -> bool:
    return _is_relative_to(left, right) or _is_relative_to(right, left)


def resolve_target_ref(target_ref: str) -> Path:
    raw = str(target_ref or "").strip()
    if not raw:
        raise AdapterError("target is required")
    if raw.casefold().startswith("file:"):
        parsed = urlparse(raw)
        if parsed.scheme.casefold() != "file" or parsed.query or parsed.fragment:
            raise AdapterError("target file URI is invalid")
        path_text = unquote(parsed.path)
        if os.name == "nt" and re.match(r"^/[A-Za-z]:/", path_text):
            path_text = path_text[1:]
        if parsed.netloc and parsed.netloc.casefold() != "localhost":
            path_text = f"//{parsed.netloc}{path_text}"
        candidate = Path(path_text)
    else:
        candidate = Path(os.path.expandvars(raw)).expanduser()
    if not candidate.is_absolute():
        raise AdapterError("target must be an absolute path or file URI")
    # Keep the lexical path so TargetLayout can detect symlinks, junctions,
    # and redirected parents before any target state is written.
    normalized = Path(os.path.abspath(os.path.normpath(os.fspath(candidate))))
    if normalized == Path(normalized.anchor):
        raise AdapterError("target cannot be a filesystem root")
    return normalized


def _resolve_state_path(root: Path, relative: str, label: str) -> Path:
    candidate = Path(str(relative or ""))
    if candidate.is_absolute():
        raise AdapterError(f"{label} must be relative to the target state root")
    try:
        resolved_root = root.resolve(strict=False)
        resolved = (resolved_root / candidate).resolve(strict=False)
    except OSError as exc:
        raise AdapterError(f"{label} cannot be resolved safely") from exc
    if not _is_relative_to(resolved, resolved_root):
        raise AdapterError(f"{label} escapes the target state root")
    return resolved


class TargetLock:
    def __init__(self, path: Path, timeout_seconds: int) -> None:
        if timeout_seconds < 1 or timeout_seconds > 300:
            raise AdapterError("lock timeout must be between 1 and 300 seconds")
        self.path = path
        self.timeout_seconds = timeout_seconds
        self._handle: Any = None

    def __enter__(self) -> "TargetLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a+b")
        self._handle.seek(0, os.SEEK_END)
        if self._handle.tell() == 0:
            self._handle.write(b"\0")
            self._handle.flush()
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                self._handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(
                        self._handle.fileno(),
                        msvcrt.LK_NBLCK,
                        1,
                    )
                else:
                    import fcntl

                    fcntl.flock(
                        self._handle.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                return self
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    self._handle.close()
                    self._handle = None
                    raise AdapterError("target operation lock timed out")
                time.sleep(0.1)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._handle is None:
            return
        try:
            self._handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(
                    self._handle.fileno(),
                    msvcrt.LK_UNLCK,
                    1,
                )
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None


@dataclass(frozen=True)
class TargetLayout:
    target_root: Path
    control_root: Path
    releases: Path
    staging: Path
    deployments: Path
    verifications: Path
    rollbacks: Path
    readbacks: Path
    current: Path
    lock: Path

    @classmethod
    def for_target(cls, target_root: Path) -> "TargetLayout":
        control_root = target_root / STATE_DIRECTORY
        directories = {
            "releases": control_root / "releases",
            "staging": control_root / "staging",
            "deployments": control_root / "deployments",
            "verifications": control_root / "verifications",
            "rollbacks": control_root / "rollbacks",
            "readbacks": control_root / "readbacks",
        }
        return cls(
            target_root=target_root,
            control_root=control_root,
            current=control_root / "current.json",
            lock=control_root / "operation.lock",
            **directories,
        )

    def _named_directories(self) -> dict[str, Path]:
        return {
            "releases": self.releases,
            "staging": self.staging,
            "deployments": self.deployments,
            "verifications": self.verifications,
            "rollbacks": self.rollbacks,
            "readbacks": self.readbacks,
        }

    @staticmethod
    def _reject_redirect(path: Path, label: str) -> None:
        current = path
        while True:
            try:
                metadata = current.stat(follow_symlinks=False)
            except FileNotFoundError:
                metadata = None
            except OSError as exc:
                raise AdapterError(
                    f"{label} path cannot be resolved safely"
                ) from exc
            if metadata is not None:
                file_attributes = getattr(metadata, "st_file_attributes", 0)
                reparse_flag = getattr(
                    stat,
                    "FILE_ATTRIBUTE_REPARSE_POINT",
                    0x400,
                )
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or file_attributes & reparse_flag
                ):
                    raise AdapterError(
                        f"{label} cannot be a symlink or redirected path"
                    )
            parent = current.parent
            if parent == current:
                break
            current = parent

    def prepare_for_deploy(self) -> None:
        self._reject_redirect(self.target_root, "target directory")
        if self.target_root.exists() and not self.target_root.is_dir():
            raise AdapterError("target exists but is not a directory")
        self.target_root.mkdir(parents=True, exist_ok=True)
        self._reject_redirect(self.target_root, "target directory")
        self._reject_redirect(self.control_root, "target control directory")
        self.control_root.mkdir(parents=True, exist_ok=True)
        self._reject_redirect(self.control_root, "target control directory")
        for label, path in self._named_directories().items():
            self._reject_redirect(path, f"target {label} directory")
            path.mkdir(parents=True, exist_ok=True)
            self._reject_redirect(path, f"target {label} directory")

    def require_existing(self) -> None:
        self._reject_redirect(self.target_root, "target directory")
        if not self.target_root.is_dir():
            raise AdapterError("target directory is missing")
        self._reject_redirect(self.control_root, "target control directory")
        if not self.control_root.is_dir():
            raise AdapterError("target control directory is missing or unsafe")
        for label, path in self._named_directories().items():
            self._reject_redirect(path, f"target {label} directory")
            if not path.is_dir():
                raise AdapterError(
                    f"target {label} directory is missing or unsafe"
                )


@dataclass(frozen=True)
class ManifestBundle:
    payload: dict[str, Any]
    digest: str
    event_id: str
    output_dir: Path
    source_files: dict[str, Path]
    inventory: list[dict[str, Any]]
    inventory_digest: str


def load_manifest_bundle(
    manifest_path: Path,
    expected_digest: str,
) -> ManifestBundle:
    if not _DIGEST_PATTERN.fullmatch(str(expected_digest or "")):
        raise AdapterError("expected Manifest-R digest is invalid")
    if manifest_path.is_symlink():
        raise AdapterError("Manifest-R path cannot be a symlink")
    manifest = read_json_object(manifest_path, "Manifest-R")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise AdapterError("Manifest-R contains no artifacts")
    source_manifest_digest = str(manifest.get("source_manifest_s_digest") or "")
    computed_digest = object_digest(
        {
            "source_manifest_s_digest": source_manifest_digest,
            "artifacts": artifacts,
        }
    )
    if (
        computed_digest != expected_digest
        or computed_digest != str(manifest.get("digest") or "")
    ):
        raise AdapterError("Manifest-R digest does not match the expected release")
    event_id = str(manifest.get("event_id") or "")
    if not _EVENT_ID_PATTERN.fullmatch(event_id):
        raise AdapterError("Manifest-R event_id is invalid")
    output_text = str(manifest.get("output_dir") or "").strip()
    if not output_text:
        raise AdapterError("Manifest-R output_dir is missing")
    output_path = Path(os.path.expandvars(output_text)).expanduser()
    if output_path.is_symlink():
        raise AdapterError("Manifest-R output_dir cannot be a symlink")
    try:
        output_dir = output_path.resolve(strict=True)
    except OSError as exc:
        raise AdapterError("Manifest-R output_dir is missing") from exc
    if not output_dir.is_dir():
        raise AdapterError("Manifest-R output_dir is not a directory")

    source_files: dict[str, Path] = {}
    source_names_casefold: set[str] = set()
    inventory: list[dict[str, Any]] = []
    for item in artifacts:
        if not isinstance(item, dict):
            raise AdapterError("Manifest-R artifact must be one JSON object")
        logical_name = safe_logical_name(item.get("logical_name"))
        normalized_name = logical_name.casefold()
        if normalized_name in source_names_casefold:
            raise AdapterError("Manifest-R contains duplicate logical names")
        source_names_casefold.add(normalized_name)
        raw_path = Path(str(item.get("file_path") or ""))
        if raw_path.is_symlink():
            raise AdapterError(f"Manifest-R artifact cannot be a symlink: {logical_name}")
        try:
            file_path = raw_path.resolve(strict=True)
        except OSError as exc:
            raise AdapterError(
                f"Manifest-R artifact is missing: {logical_name}"
            ) from exc
        expected_path = (output_dir / logical_name).resolve(strict=True)
        if file_path != expected_path or not _is_relative_to(file_path, output_dir):
            raise AdapterError(
                f"Manifest-R artifact path is not bound to output_dir: {logical_name}"
            )
        if not file_path.is_file():
            raise AdapterError(f"Manifest-R artifact is not a file: {logical_name}")
        expected_size = item.get("size")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool):
            raise AdapterError(f"Manifest-R artifact size is invalid: {logical_name}")
        if file_path.stat().st_size != expected_size:
            raise AdapterError(f"Manifest-R artifact size drifted: {logical_name}")
        expected_sha1 = str(item.get("sha1") or "").lower()
        if not _SHA1_PATTERN.fullmatch(expected_sha1):
            raise AdapterError(f"Manifest-R artifact SHA1 is invalid: {logical_name}")
        actual_sha1 = file_digest(file_path, "sha1")
        if actual_sha1 != expected_sha1:
            raise AdapterError(f"Manifest-R artifact SHA1 drifted: {logical_name}")
        expected_sha256 = str(item.get("sha256") or "").lower()
        if not _SHA256_PATTERN.fullmatch(expected_sha256):
            raise AdapterError(
                f"Manifest-R artifact SHA256 is invalid: {logical_name}"
            )
        actual_sha256 = file_digest(file_path, "sha256")
        if actual_sha256 != expected_sha256:
            raise AdapterError(
                f"Manifest-R artifact SHA256 drifted: {logical_name}"
            )
        source_files[logical_name] = file_path
        inventory.append(
            {
                "logical_name": logical_name,
                "size": expected_size,
                "sha1": actual_sha1,
                "sha256": actual_sha256,
            }
        )
    actual_names = {
        path.relative_to(output_dir).as_posix()
        for path in output_dir.rglob("*")
        if path.is_file()
    }
    if actual_names != set(source_files):
        raise AdapterError("Manifest-R output_dir file set drifted")
    inventory_digest = object_digest(
        {
            "manifest_r_digest": expected_digest,
            "artifacts": inventory,
        }
    )
    return ManifestBundle(
        payload=manifest,
        digest=expected_digest,
        event_id=event_id,
        output_dir=output_dir,
        source_files=source_files,
        inventory=inventory,
        inventory_digest=inventory_digest,
    )


def verify_authorization(
    authorization_path: Path,
    *,
    expected_manifest_digest: str,
    event_id: str,
    stage: str,
    key_env: str,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    if authorization_path.is_symlink():
        raise AdapterError("release authorization path cannot be a symlink")
    credential = read_json_object(
        authorization_path,
        "release authorization credential",
    )
    claims = credential.get("claims")
    if (
        credential.get("algorithm") != "HMAC-SHA256"
        or not isinstance(claims, dict)
    ):
        raise AdapterError("release authorization credential is invalid")
    env_name = str(key_env or "").strip()
    if not env_name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
        raise AdapterError("authorization key environment variable name is invalid")
    key_text = str(environ.get(env_name) or "")
    key = key_text.encode("utf-8")
    if len(key) < 32:
        raise AdapterError("authorization key is missing or shorter than 32 bytes")
    expected_signature = hmac.new(
        key,
        canonical_json(claims).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(
        str(credential.get("signature") or ""),
        expected_signature,
    ):
        raise AdapterError("release authorization credential signature is invalid")
    if claims.get("event_id") != event_id:
        raise AdapterError("release authorization event binding is invalid")
    if claims.get("manifest_r_digest") != expected_manifest_digest:
        raise AdapterError("release authorization Manifest-R binding is invalid")
    allowed_stages = {
        value.strip()
        for value in str(claims.get("target_scope") or "").split(",")
        if value.strip()
    }
    if stage not in allowed_stages:
        raise AdapterError("release authorization does not permit this stage")
    expires_text = str(claims.get("expires_at") or "").replace("Z", "+00:00")
    try:
        expires = datetime.fromisoformat(expires_text)
    except ValueError as exc:
        raise AdapterError("release authorization expiry is invalid") from exc
    if expires.tzinfo is None or datetime.now(timezone.utc) >= expires:
        raise AdapterError("release authorization credential has expired")
    return credential


class FilesystemReleaseAdapter:
    def __init__(
        self,
        target_ref: str,
        *,
        lock_timeout_seconds: int = 30,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.target_ref = str(target_ref or "").strip()
        self.target_root = resolve_target_ref(self.target_ref)
        self.layout = TargetLayout.for_target(self.target_root)
        self.lock_timeout_seconds = lock_timeout_seconds
        self.environ = os.environ if environ is None else environ

    @staticmethod
    def _reference_path(directory: Path, reference: str) -> Path:
        if not str(reference or "").strip():
            raise AdapterError("operation reference is missing")
        return directory / f"{object_digest(str(reference))}.json"

    def _read_current(self) -> dict[str, Any] | None:
        if not self.layout.current.exists():
            return None
        current = read_json_object(self.layout.current, "target current pointer")
        if current.get("schema_version") != 1:
            raise AdapterError("target current pointer schema is invalid")
        if current.get("target_ref") != self.target_ref:
            raise AdapterError("target current pointer identity differs")
        return current

    def _verify_release(
        self,
        release_ref: str,
        expected_manifest_digest: str,
    ) -> str:
        release_dir = _resolve_state_path(
            self.layout.control_root,
            release_ref,
            "release_ref",
        )
        if release_dir.is_symlink() or not release_dir.is_dir():
            raise AdapterError("deployed release directory is missing or unsafe")
        manifest = read_json_object(
            release_dir / "manifest-r.json",
            "deployed Manifest-R",
        )
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise AdapterError("deployed Manifest-R contains no artifacts")
        manifest_digest = object_digest(
            {
                "source_manifest_s_digest": manifest.get(
                    "source_manifest_s_digest"
                ),
                "artifacts": artifacts,
            }
        )
        if (
            manifest_digest != expected_manifest_digest
            or manifest.get("digest") != expected_manifest_digest
        ):
            raise AdapterError("deployed Manifest-R digest differs")
        manifest_inventory: dict[str, dict[str, Any]] = {}
        manifest_names_casefold: set[str] = set()
        for item in artifacts:
            if not isinstance(item, dict):
                raise AdapterError("deployed Manifest-R artifact is invalid")
            name = safe_logical_name(item.get("logical_name"))
            normalized_name = name.casefold()
            if normalized_name in manifest_names_casefold:
                raise AdapterError(
                    "deployed Manifest-R contains duplicate names"
                )
            manifest_names_casefold.add(normalized_name)
            size = item.get("size")
            sha1 = str(item.get("sha1") or "").lower()
            sha256 = str(item.get("sha256") or "").lower()
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or not _SHA1_PATTERN.fullmatch(sha1)
                or not _SHA256_PATTERN.fullmatch(sha256)
            ):
                raise AdapterError(
                    f"deployed Manifest-R artifact hashes are invalid: {name}"
                )
            manifest_inventory[name] = {
                "size": size,
                "sha1": sha1,
                "sha256": sha256,
            }
        inventory = read_json_object(
            release_dir / "inventory.json",
            "deployed inventory",
        )
        inventory_items = inventory.get("artifacts")
        if not isinstance(inventory_items, list) or not inventory_items:
            raise AdapterError("deployed inventory contains no artifacts")
        inventory_digest = object_digest(
            {
                "manifest_r_digest": expected_manifest_digest,
                "artifacts": inventory_items,
            }
        )
        if inventory.get("inventory_sha256") != inventory_digest:
            raise AdapterError("deployed inventory digest differs")
        release_metadata = read_json_object(
            release_dir / "release.json",
            "deployed release metadata",
        )
        if (
            release_metadata.get("release_ref") != release_ref
            or release_metadata.get("manifest_r_digest")
            != expected_manifest_digest
            or release_metadata.get("inventory_sha256") != inventory_digest
        ):
            raise AdapterError("deployed release metadata differs")
        files_root = release_dir / "files"
        if files_root.is_symlink() or not files_root.is_dir():
            raise AdapterError("deployed release file directory is unsafe")
        expected_names: set[str] = set()
        expected_names_casefold: set[str] = set()
        for item in inventory_items:
            if not isinstance(item, dict):
                raise AdapterError("deployed inventory artifact is invalid")
            name = safe_logical_name(item.get("logical_name"))
            normalized_name = name.casefold()
            if normalized_name in expected_names_casefold:
                raise AdapterError("deployed inventory contains duplicate names")
            expected_names.add(name)
            expected_names_casefold.add(normalized_name)
            manifest_item = manifest_inventory.get(name)
            if (
                manifest_item is None
                or item.get("size") != manifest_item["size"]
                or item.get("sha1") != manifest_item["sha1"]
                or item.get("sha256") != manifest_item["sha256"]
            ):
                raise AdapterError(
                    f"deployed inventory artifact differs from Manifest-R: {name}"
                )
            path = files_root / name
            if path.is_symlink() or not path.is_file():
                raise AdapterError(f"deployed artifact is missing or unsafe: {name}")
            size = item.get("size")
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or path.stat().st_size != size
            ):
                raise AdapterError(f"deployed artifact size differs: {name}")
            if file_digest(path, "sha1") != item.get("sha1"):
                raise AdapterError(f"deployed artifact SHA1 differs: {name}")
            if file_digest(path, "sha256") != item.get("sha256"):
                raise AdapterError(f"deployed artifact SHA256 differs: {name}")
        actual_names = {
            path.relative_to(files_root).as_posix()
            for path in files_root.rglob("*")
            if path.is_file()
        }
        if (
            actual_names != expected_names
            or expected_names != set(manifest_inventory)
        ):
            raise AdapterError("deployed release file set differs")
        return inventory_digest

    def _install_release(self, bundle: ManifestBundle) -> str:
        if _paths_overlap(self.target_root, bundle.output_dir):
            raise AdapterError("target and Manifest-R output_dir must not overlap")
        release_ref = f"releases/{bundle.digest}"
        release_dir = self.layout.releases / bundle.digest
        if release_dir.exists():
            observed = self._verify_release(release_ref, bundle.digest)
            if observed != bundle.inventory_digest:
                raise AdapterError("existing content-addressed release differs")
            return release_ref
        staging = self.layout.staging / f"{bundle.digest}.{uuid.uuid4().hex}"
        files_root = staging / "files"
        files_root.mkdir(parents=True, exist_ok=False)
        try:
            for item in bundle.inventory:
                name = item["logical_name"]
                destination = files_root / name
                durable_copy(bundle.source_files[name], destination)
                if (
                    destination.stat().st_size != item["size"]
                    or file_digest(destination, "sha1") != item["sha1"]
                    or file_digest(destination, "sha256") != item["sha256"]
                ):
                    raise AdapterError(
                        f"copied artifact integrity differs: {name}"
                    )
            atomic_write_json(staging / "manifest-r.json", bundle.payload)
            atomic_write_json(
                staging / "inventory.json",
                {
                    "schema_version": 1,
                    "manifest_r_digest": bundle.digest,
                    "inventory_sha256": bundle.inventory_digest,
                    "artifacts": bundle.inventory,
                },
            )
            atomic_write_json(
                staging / "release.json",
                {
                    "schema_version": 1,
                    "adapter_version": ADAPTER_VERSION,
                    "event_id": bundle.event_id,
                    "release_ref": release_ref,
                    "manifest_r_digest": bundle.digest,
                    "inventory_sha256": bundle.inventory_digest,
                    "created_at": utc_now(),
                },
            )
            durable_replace(staging, release_dir)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
        observed = self._verify_release(release_ref, bundle.digest)
        if observed != bundle.inventory_digest:
            raise AdapterError("installed content-addressed release differs")
        return release_ref

    def _verify_active_pointer(
        self,
        *,
        expected_digest: str,
        deployment_ref: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        current = self._read_current()
        if not current or current.get("active") is not True:
            raise AdapterError("target has no active release")
        if current.get("manifest_r_digest") != expected_digest:
            raise AdapterError("target active Manifest-R digest differs")
        if deployment_ref and current.get("deployment_ref") != deployment_ref:
            raise AdapterError("target active deployment reference differs")
        inventory_digest = self._verify_release(
            str(current.get("release_ref") or ""),
            expected_digest,
        )
        if current.get("inventory_sha256") != inventory_digest:
            raise AdapterError("target active inventory digest differs")
        return current, inventory_digest

    def _active_pointer_from_record(
        self,
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "active": True,
            "adapter_version": ADAPTER_VERSION,
            "target_ref": self.target_ref,
            "event_id": record.get("event_id"),
            "stage": record.get("stage"),
            "manifest_r_digest": record.get("manifest_r_digest"),
            "inventory_sha256": record.get("inventory_sha256"),
            "release_ref": record.get("release_ref"),
            "deployment_ref": record.get("deployment_ref"),
            "activated_at": str(record.get("activated_at") or utc_now()),
        }

    @staticmethod
    def _pointer_matches_deployment(
        current: Mapping[str, Any] | None,
        record: Mapping[str, Any],
    ) -> bool:
        return bool(
            current
            and current.get("active") is True
            and all(
                current.get(key) == record.get(key)
                for key in (
                    "target_ref",
                    "event_id",
                    "stage",
                    "manifest_r_digest",
                    "inventory_sha256",
                    "release_ref",
                    "deployment_ref",
                )
            )
        )

    def deploy(
        self,
        *,
        stage: str,
        manifest_path: Path,
        authorization_path: Path,
        idempotency_key: str,
        expected_digest: str,
        authorization_key_env: str,
    ) -> dict[str, Any]:
        if stage not in VALID_STAGES:
            raise AdapterError("deployment stage is invalid")
        if not _DIGEST_PATTERN.fullmatch(str(idempotency_key or "")):
            raise AdapterError("deployment idempotency key is invalid")
        bundle = load_manifest_bundle(manifest_path, expected_digest)
        credential = verify_authorization(
            authorization_path,
            expected_manifest_digest=expected_digest,
            event_id=bundle.event_id,
            stage=stage,
            key_env=authorization_key_env,
            environ=self.environ,
        )
        if _paths_overlap(self.target_root, bundle.output_dir):
            raise AdapterError(
                "target and Manifest-R output_dir must not overlap"
            )
        self.layout.prepare_for_deploy()
        deployment_ref = (
            f"fs-deploy:{stage}:{expected_digest[:12]}:{idempotency_key[:12]}"
        )
        rollback_ref = (
            f"fs-rollback:{stage}:{object_digest(deployment_ref)[:20]}"
        )
        record_path = self._reference_path(
            self.layout.deployments,
            deployment_ref,
        )
        with TargetLock(self.layout.lock, self.lock_timeout_seconds):
            release_ref = self._install_release(bundle)
            if record_path.exists():
                record = read_json_object(record_path, "deployment record")
                valid = (
                    record.get("deployment_ref") == deployment_ref
                    and record.get("rollback_ref") == rollback_ref
                    and record.get("stage") == stage
                    and record.get("target_ref") == self.target_ref
                    and record.get("manifest_r_digest") == expected_digest
                    and record.get("idempotency_key") == idempotency_key
                    and record.get("release_ref") == release_ref
                )
                if not valid:
                    raise AdapterError("existing deployment record differs")
                status = str(record.get("status") or "")
                if status not in {"PREPARED", "ACTIVE"}:
                    raise AdapterError("existing deployment state is invalid")
                current = self._read_current()
                if status == "PREPARED":
                    previous = record.get("previous_current")
                    if previous is not None and not isinstance(previous, dict):
                        raise AdapterError(
                            "deployment previous target state is invalid"
                        )
                    if self._pointer_matches_deployment(current, record):
                        pass
                    elif object_digest(current) == object_digest(previous):
                        current = self._active_pointer_from_record(record)
                        atomic_write_json(self.layout.current, current)
                    else:
                        raise AdapterError(
                            "prepared deployment target state cannot be reconciled"
                        )
                current, inventory_digest = self._verify_active_pointer(
                    expected_digest=expected_digest,
                    deployment_ref=deployment_ref,
                )
                if status == "PREPARED":
                    record = {
                        **record,
                        "status": "ACTIVE",
                        "current_pointer_digest": object_digest(current),
                        "activated_at": current["activated_at"],
                        "reconciled_at": utc_now(),
                    }
                    atomic_write_json(record_path, record)
                elif record.get("current_pointer_digest") != object_digest(
                    current
                ):
                    raise AdapterError(
                        "active deployment pointer digest differs"
                    )
                return {
                    "result": "PASS",
                    "target_ref": self.target_ref,
                    "deployment_ref": deployment_ref,
                    "rollback_ref": rollback_ref,
                    "deployed_manifest_r_digest": expected_digest,
                    "inventory_sha256": inventory_digest,
                    "release_ref": release_ref,
                    "idempotent": True,
                }
            previous_current = self._read_current()
            record = {
                "schema_version": 1,
                "adapter_version": ADAPTER_VERSION,
                "status": "PREPARED",
                "event_id": bundle.event_id,
                "stage": stage,
                "target_ref": self.target_ref,
                "manifest_r_digest": expected_digest,
                "inventory_sha256": bundle.inventory_digest,
                "release_ref": release_ref,
                "deployment_ref": deployment_ref,
                "rollback_ref": rollback_ref,
                "idempotency_key": idempotency_key,
                "authorization_credential_digest": object_digest(credential),
                "previous_current": previous_current,
                "prepared_at": utc_now(),
            }
            atomic_write_json(record_path, record)
            current = self._active_pointer_from_record(record)
            atomic_write_json(self.layout.current, current)
            record = {
                **record,
                "status": "ACTIVE",
                "current_pointer_digest": object_digest(current),
                "activated_at": current["activated_at"],
            }
            atomic_write_json(record_path, record)
            return {
                "result": "PASS",
                "target_ref": self.target_ref,
                "deployment_ref": deployment_ref,
                "rollback_ref": rollback_ref,
                "deployed_manifest_r_digest": expected_digest,
                "inventory_sha256": bundle.inventory_digest,
                "release_ref": release_ref,
                "idempotent": False,
            }

    def verify(
        self,
        *,
        stage: str,
        deployment_ref: str,
        rollback_ref: str,
        expected_digest: str,
    ) -> dict[str, Any]:
        if stage not in VALID_STAGES:
            raise AdapterError("verification stage is invalid")
        self.layout.require_existing()
        record_path = self._reference_path(
            self.layout.deployments,
            deployment_ref,
        )
        with TargetLock(self.layout.lock, self.lock_timeout_seconds):
            record = read_json_object(record_path, "deployment record")
            if (
                record.get("stage") != stage
                or record.get("target_ref") != self.target_ref
                or record.get("rollback_ref") != rollback_ref
                or record.get("manifest_r_digest") != expected_digest
            ):
                raise AdapterError("deployment record binding differs")
            _, inventory_digest = self._verify_active_pointer(
                expected_digest=expected_digest,
                deployment_ref=deployment_ref,
            )
            verification_ref = (
                "fs-verify:"
                + object_digest(
                    {
                        "deployment_ref": deployment_ref,
                        "manifest_r_digest": expected_digest,
                    }
                )[:24]
            )
            receipt = {
                "schema_version": 1,
                "result": "PASS",
                "target_ref": self.target_ref,
                "stage": stage,
                "deployment_ref": deployment_ref,
                "verification_ref": verification_ref,
                "observed_manifest_r_digest": expected_digest,
                "inventory_sha256": inventory_digest,
                "verified_at": utc_now(),
            }
            atomic_write_json(
                self._reference_path(
                    self.layout.verifications,
                    verification_ref,
                ),
                receipt,
            )
            return receipt

    def rollback(
        self,
        *,
        stage: str,
        deployment_ref: str,
        rollback_ref: str,
    ) -> dict[str, Any]:
        if stage not in VALID_STAGES:
            raise AdapterError("rollback stage is invalid")
        self.layout.require_existing()
        deployment_path = self._reference_path(
            self.layout.deployments,
            deployment_ref,
        )
        rollback_receipt_ref = (
            "fs-rollback-receipt:"
            + object_digest(
                {
                    "deployment_ref": deployment_ref,
                    "rollback_ref": rollback_ref,
                }
            )[:24]
        )
        rollback_path = self._reference_path(
            self.layout.rollbacks,
            rollback_receipt_ref,
        )
        with TargetLock(self.layout.lock, self.lock_timeout_seconds):
            deployment = read_json_object(
                deployment_path,
                "deployment record",
            )
            if (
                deployment.get("stage") != stage
                or deployment.get("target_ref") != self.target_ref
                or deployment.get("rollback_ref") != rollback_ref
            ):
                raise AdapterError("rollback deployment binding differs")
            current = self._read_current()
            previous = deployment.get("previous_current")
            if previous is not None and not isinstance(previous, dict):
                raise AdapterError("deployment previous target state is invalid")
            if previous and previous.get("active") is True:
                if previous.get("target_ref") != self.target_ref:
                    raise AdapterError("previous target identity differs")
                self._verify_release(
                    str(previous.get("release_ref") or ""),
                    str(previous.get("manifest_r_digest") or ""),
                )
                restored_current = previous
                restored_ref = str(previous.get("deployment_ref") or "")
                if not restored_ref:
                    raise AdapterError("previous deployment reference is missing")
            else:
                restored_current = {
                    "schema_version": 1,
                    "active": False,
                    "target_ref": self.target_ref,
                }
                restored_ref = (
                    "fs-empty:" + object_digest(deployment_ref)[:24]
                )
            restored_current_digest = object_digest(restored_current)
            receipt_base = {
                "schema_version": 1,
                "adapter_version": ADAPTER_VERSION,
                "stage": stage,
                "target_ref": self.target_ref,
                "deployment_ref": deployment_ref,
                "rollback_ref": rollback_ref,
                "restored_ref": restored_ref,
                "rollback_receipt_ref": rollback_receipt_ref,
                "restored_current_digest": restored_current_digest,
            }
            if rollback_path.exists():
                receipt = read_json_object(rollback_path, "rollback record")
                if any(
                    receipt.get(key) != value
                    for key, value in receipt_base.items()
                ):
                    raise AdapterError("existing rollback record differs")
                status = str(receipt.get("status") or "")
                if status not in {"PREPARED", "COMPLETE"}:
                    raise AdapterError("existing rollback state is invalid")
                if status == "PREPARED":
                    if object_digest(current) == restored_current_digest:
                        pass
                    elif (
                        current
                        and current.get("deployment_ref") == deployment_ref
                    ):
                        atomic_write_json(
                            self.layout.current,
                            restored_current,
                        )
                        current = restored_current
                    else:
                        raise AdapterError(
                            "prepared rollback target state cannot be reconciled"
                        )
                    receipt = {
                        **receipt_base,
                        "status": "COMPLETE",
                        "result": "PASS",
                        "prepared_at": receipt.get("prepared_at"),
                        "rolled_back_at": utc_now(),
                        "reconciled_at": utc_now(),
                    }
                    atomic_write_json(rollback_path, receipt)
                if object_digest(self._read_current()) != restored_current_digest:
                    raise AdapterError(
                        "existing rollback target state differs"
                    )
                return {
                    "result": "PASS",
                    "target_ref": self.target_ref,
                    "deployment_ref": deployment_ref,
                    "rollback_ref": rollback_ref,
                    "restored_ref": restored_ref,
                    "rollback_receipt_ref": rollback_receipt_ref,
                    "idempotent": True,
                }
            if not current or current.get("deployment_ref") != deployment_ref:
                raise AdapterError(
                    "rollback target is not the active deployment"
                )
            prepared_receipt = {
                **receipt_base,
                "status": "PREPARED",
                "result": "PENDING",
                "prepared_at": utc_now(),
            }
            atomic_write_json(rollback_path, prepared_receipt)
            atomic_write_json(self.layout.current, restored_current)
            receipt = {
                **receipt_base,
                "status": "COMPLETE",
                "result": "PASS",
                "prepared_at": prepared_receipt["prepared_at"],
                "rolled_back_at": utc_now(),
            }
            atomic_write_json(rollback_path, receipt)
            return {
                "result": "PASS",
                "target_ref": self.target_ref,
                "deployment_ref": deployment_ref,
                "rollback_ref": rollback_ref,
                "restored_ref": restored_ref,
                "rollback_receipt_ref": rollback_receipt_ref,
                "idempotent": False,
            }

    def verify_rollback(
        self,
        *,
        stage: str,
        deployment_ref: str,
        rollback_ref: str,
        restored_ref: str,
        rollback_receipt_ref: str,
    ) -> dict[str, Any]:
        if stage not in VALID_STAGES:
            raise AdapterError("rollback verification stage is invalid")
        self.layout.require_existing()
        rollback_path = self._reference_path(
            self.layout.rollbacks,
            rollback_receipt_ref,
        )
        with TargetLock(self.layout.lock, self.lock_timeout_seconds):
            receipt = read_json_object(rollback_path, "rollback record")
            if (
                receipt.get("stage") != stage
                or receipt.get("target_ref") != self.target_ref
                or receipt.get("deployment_ref") != deployment_ref
                or receipt.get("rollback_ref") != rollback_ref
                or receipt.get("restored_ref") != restored_ref
                or receipt.get("rollback_receipt_ref")
                != rollback_receipt_ref
                or receipt.get("status") != "COMPLETE"
                or receipt.get("result") != "PASS"
            ):
                raise AdapterError("rollback verification binding differs")
            current = self._read_current()
            if object_digest(current) != receipt.get("restored_current_digest"):
                raise AdapterError("rollback target state differs")
            inventory_digest = ""
            if current and current.get("active") is True:
                inventory_digest = self._verify_release(
                    str(current.get("release_ref") or ""),
                    str(current.get("manifest_r_digest") or ""),
                )
            verification_ref = (
                "fs-rollback-verify:"
                + object_digest(rollback_receipt_ref)[:24]
            )
            return {
                "result": "PASS",
                "target_ref": self.target_ref,
                "deployment_ref": deployment_ref,
                "rollback_ref": rollback_ref,
                "restored_ref": restored_ref,
                "rollback_receipt_ref": rollback_receipt_ref,
                "verification_ref": verification_ref,
                "restored_inventory_sha256": inventory_digest,
            }

    def readback(self, *, expected_digest: str) -> dict[str, Any]:
        if not _DIGEST_PATTERN.fullmatch(str(expected_digest or "")):
            raise AdapterError("readback expected digest is invalid")
        self.layout.require_existing()
        with TargetLock(self.layout.lock, self.lock_timeout_seconds):
            current, inventory_digest = self._verify_active_pointer(
                expected_digest=expected_digest,
            )
            readback_ref = (
                "fs-readback:"
                + object_digest(
                    {
                        "target_ref": self.target_ref,
                        "manifest_r_digest": expected_digest,
                        "deployment_ref": current.get("deployment_ref"),
                    }
                )[:24]
            )
            receipt = {
                "schema_version": 1,
                "result": "PASS",
                "target_ref": self.target_ref,
                "readback_ref": readback_ref,
                "deployment_ref": current.get("deployment_ref"),
                "observed_manifest_r_digest": expected_digest,
                "inventory_sha256": inventory_digest,
                "read_at": utc_now(),
            }
            atomic_write_json(
                self._reference_path(self.layout.readbacks, readback_ref),
                receipt,
            )
            return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="filesystem-release-adapter")
    parser.add_argument("--version", action="version", version=ADAPTER_VERSION)
    commands = parser.add_subparsers(dest="operation", required=True)

    deploy = commands.add_parser("deploy")
    deploy.add_argument("--stage", required=True, choices=sorted(VALID_STAGES))
    deploy.add_argument("--target", required=True)
    deploy.add_argument("--manifest-r", required=True)
    deploy.add_argument("--authorization", required=True)
    deploy.add_argument("--idempotency-key", required=True)
    deploy.add_argument("--expected-digest", required=True)
    deploy.add_argument(
        "--authorization-key-env",
        default="PRODUCT_RELEASE_GATE_AUTH_KEY",
    )

    verify = commands.add_parser("verify")
    verify.add_argument("--stage", required=True, choices=sorted(VALID_STAGES))
    verify.add_argument("--target", required=True)
    verify.add_argument("--deployment-ref", required=True)
    verify.add_argument("--rollback-ref", required=True)
    verify.add_argument("--expected-digest", required=True)

    rollback = commands.add_parser("rollback")
    rollback.add_argument("--stage", required=True, choices=sorted(VALID_STAGES))
    rollback.add_argument("--target", required=True)
    rollback.add_argument("--deployment-ref", required=True)
    rollback.add_argument("--rollback-ref", required=True)

    rollback_verify = commands.add_parser("verify-rollback")
    rollback_verify.add_argument(
        "--stage", required=True, choices=sorted(VALID_STAGES)
    )
    rollback_verify.add_argument("--target", required=True)
    rollback_verify.add_argument("--deployment-ref", required=True)
    rollback_verify.add_argument("--rollback-ref", required=True)
    rollback_verify.add_argument("--restored-ref", required=True)
    rollback_verify.add_argument("--rollback-receipt-ref", required=True)

    readback = commands.add_parser("readback")
    readback.add_argument("--target", required=True)
    readback.add_argument("--expected-digest", required=True)

    for command in (
        deploy,
        verify,
        rollback,
        rollback_verify,
        readback,
    ):
        command.add_argument(
            "--lock-timeout-seconds",
            type=int,
            default=30,
        )
        command.add_argument("--json", action="store_true")
    return parser


def run_operation(args: argparse.Namespace) -> dict[str, Any]:
    adapter = FilesystemReleaseAdapter(
        args.target,
        lock_timeout_seconds=args.lock_timeout_seconds,
    )
    if args.operation == "deploy":
        return adapter.deploy(
            stage=args.stage,
            manifest_path=Path(args.manifest_r),
            authorization_path=Path(args.authorization),
            idempotency_key=args.idempotency_key,
            expected_digest=args.expected_digest,
            authorization_key_env=args.authorization_key_env,
        )
    if args.operation == "verify":
        return adapter.verify(
            stage=args.stage,
            deployment_ref=args.deployment_ref,
            rollback_ref=args.rollback_ref,
            expected_digest=args.expected_digest,
        )
    if args.operation == "rollback":
        return adapter.rollback(
            stage=args.stage,
            deployment_ref=args.deployment_ref,
            rollback_ref=args.rollback_ref,
        )
    if args.operation == "verify-rollback":
        return adapter.verify_rollback(
            stage=args.stage,
            deployment_ref=args.deployment_ref,
            rollback_ref=args.rollback_ref,
            restored_ref=args.restored_ref,
            rollback_receipt_ref=args.rollback_receipt_ref,
        )
    if args.operation == "readback":
        return adapter.readback(expected_digest=args.expected_digest)
    raise AdapterError("unsupported adapter operation")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = run_operation(args)
    except (AdapterError, OSError) as exc:
        print(
            json.dumps(
                {
                    "result": "FAIL",
                    "error_code": "FILESYSTEM_ADAPTER_BLOCKED",
                    "error": str(exc),
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(
        json.dumps(
            result,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
