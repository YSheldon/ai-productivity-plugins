from __future__ import annotations

import hashlib
import os
import secrets
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import remotex_core as core
import secure_paths
import ssh_vnext


SERVICE_NAME = "lite-cloudquery"
TARGET_DIRECTORY = "/opt/KSF/kingsoft/x86_64/config/lite-cloudquery"
_TARGET_COMPONENTS = (
    "/opt",
    "/opt/KSF",
    "/opt/KSF/kingsoft",
    "/opt/KSF/kingsoft/x86_64",
    "/opt/KSF/kingsoft/x86_64/config",
)
_KEY_ENTRIES = {
    "tls-client-key.pem": "private/management-center/tls-client-key.pem",
    "response-key.pem": "private/management-center/response-key.pem",
}
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
_MAX_KEY_BYTES = 4 * 1024 * 1024
_STAGING_PREFIX = "/opt/KSF/kingsoft/x86_64/config/lite-cloudquery/.remotex-service-key-"
_LOCK_PATH = "/opt/KSF/kingsoft/x86_64/config/lite-cloudquery/.remotex-service-key.lock"
ARCHIVE_ROOTS = (Path(r"C:/Work/AI/CloudQuery"),)


@dataclass(frozen=True)
class ExtractedKey:
    path: Path
    bytes: int
    sha256: str


def _archive_path(value: Any) -> Path:
    path = core.expand_path(value, "archive_path")
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise core.ToolError("archive_path must be an existing regular file, not a symlink")
    if path.suffix.casefold() != ".zip":
        raise core.ToolError("archive_path must be a .zip file")
    if secure_paths._network_path(path):
        raise core.ToolError("archive_path must be on an approved local path")
    resolved = path.resolve()
    if not _approved_archive_path(resolved):
        raise core.ToolError("archive_path is outside the approved service-key archive root")
    for parent in (resolved, *resolved.parents):
        if parent.exists() and secure_paths._reparse_point(parent):
            raise core.ToolError("archive_path must not use a reparse point or symlink")
    if path.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise core.ToolError("archive_path exceeds the supported size limit")
    return resolved


def _approved_archive_path(resolved: Path) -> bool:
    approved = False
    for root in ARCHIVE_ROOTS:
        try:
            resolved.relative_to(root.resolve())
            approved = True
            break
        except ValueError:
            continue
    return approved


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK


def _matching_zip_entries(
    infos: list[zipfile.ZipInfo], expected: str
) -> list[zipfile.ZipInfo]:
    matches: list[zipfile.ZipInfo] = []
    for info in infos:
        name = info.filename.replace("\\", "/")
        if name == expected:
            matches.append(info)
            continue
        suffix = "/" + expected
        if name.endswith(suffix):
            prefix = name[: -len(suffix)].strip("/")
            if prefix and "/" not in prefix and prefix not in {".", ".."}:
                matches.append(info)
    return matches


def _write_extracted(
    info: zipfile.ZipInfo,
    archive: zipfile.ZipFile,
    destination: Path,
) -> ExtractedKey:
    if info.is_dir() or _is_zip_symlink(info):
        raise core.ToolError(
            f"service-key archive entry is a symbolic link or directory: {info.filename}"
        )
    if info.file_size > _MAX_KEY_BYTES:
        raise core.ToolError(f"service-key archive entry is too large: {info.filename}")
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(info, "r") as source, destination.open("xb") as target:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > _MAX_KEY_BYTES:
                    raise core.ToolError(
                        f"service-key archive entry is too large: {info.filename}"
                    )
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
    except core.ToolError:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    os.chmod(destination, 0o600)
    secure_paths.ensure_private_file(destination)
    return ExtractedKey(destination, size, digest.hexdigest())


def _open_archive_handle(path: Path):
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.GetFinalPathNameByHandleW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD

        class FileAttributeTagInfo(ctypes.Structure):
            _fields_ = [
                ("FileAttributes", wintypes.DWORD),
                ("ReparseTag", wintypes.DWORD),
            ]

        kernel32.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,
            0x00000001,
            None,
            3,
            0x00000080 | 0x00200000,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in (None, invalid):
            raise core.ToolError("unable to open the approved service-key archive")
        try:
            info = FileAttributeTagInfo()
            if not kernel32.GetFileInformationByHandleEx(
                handle, 9, ctypes.byref(info), ctypes.sizeof(info)
            ):
                raise core.ToolError("unable to inspect the service-key archive handle")
            if info.FileAttributes & 0x400:
                raise core.ToolError("service-key archive handle is a reparse point")
            buffer = ctypes.create_unicode_buffer(32768)
            length = kernel32.GetFinalPathNameByHandleW(
                handle, buffer, len(buffer), 0
            )
            if not length or length >= len(buffer):
                raise core.ToolError("unable to resolve the service-key archive handle")
            final_value = buffer.value
            if final_value.startswith("\\\\?\\"):
                final_value = final_value[4:]
            if not _approved_archive_path(Path(final_value)):
                raise core.ToolError("service-key archive handle escaped the approved root")
            handle_value = handle.value if hasattr(handle, "value") else int(handle)
            descriptor = msvcrt.open_osfhandle(
                handle_value, os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            handle = None
            return os.fdopen(descriptor, "rb", closefd=True)
        finally:
            if handle not in (None, invalid):
                kernel32.CloseHandle(handle)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise core.ToolError("unable to open the approved service-key archive") from exc
    try:
        opened = os.fstat(descriptor)
        current = path.stat()
        if opened.st_ino and current.st_ino and (
            opened.st_dev != current.st_dev or opened.st_ino != current.st_ino
        ):
            raise core.ToolError("service-key archive changed while opening")
        if not stat.S_ISREG(opened.st_mode):
            raise core.ToolError("service-key archive handle is not a regular file")
        return os.fdopen(descriptor, "rb", closefd=True)
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def _snapshot_archive(archive_path: Path) -> Iterator[tuple[Path, str]]:
    path = _archive_path(archive_path)
    with tempfile.TemporaryDirectory(prefix="remotex-service-key-archive-") as temporary:
        root = Path(temporary)
        secure_paths.ensure_private_directory(root)
        snapshot = root / "source.zip"
        digest = hashlib.sha256()
        size = 0
        with _open_archive_handle(path) as source, snapshot.open("xb") as target:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > _MAX_ARCHIVE_BYTES:
                    raise core.ToolError("archive_path exceeds the supported size limit")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        secure_paths.ensure_private_file(snapshot)
        yield snapshot, digest.hexdigest()


@contextmanager
def _extract_snapshot(snapshot: Path) -> Iterator[dict[str, ExtractedKey]]:
    try:
        archive = zipfile.ZipFile(snapshot, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise core.ToolError("archive_path is not a readable ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        for entry in _KEY_ENTRIES.values():
            if len(_matching_zip_entries(infos, entry)) != 1:
                raise core.ToolError(
                    f"service-key archive entry is missing or duplicated: {entry}"
                )
        with tempfile.TemporaryDirectory(prefix="remotex-service-key-") as temporary:
            root = Path(temporary)
            secure_paths.ensure_private_directory(root)
            result: dict[str, ExtractedKey] = {}
            for name, entry in _KEY_ENTRIES.items():
                result[name] = _write_extracted(
                    _matching_zip_entries(infos, entry)[0], archive, root / name
                )
            yield result


@contextmanager
def _extracted_keys(archive_path: Path) -> Iterator[dict[str, ExtractedKey]]:
    with _snapshot_archive(archive_path) as (snapshot, _):
        with _extract_snapshot(snapshot) as extracted:
            yield extracted


def _run_remote_script(cfg: dict[str, Any], script: str, timeout: int) -> dict[str, Any]:
    return ssh_vnext._execute_script_unqueued(
        {
            "profile": cfg["profile"],
            "shell": "sh",
            "script": script,
            "timeout_seconds": timeout,
            "max_stdout_bytes": 1024 * 1024,
            "max_stderr_bytes": 1024 * 1024,
        }
    )


def _run_sftp(cfg: dict[str, Any], timeout: int, batch: str) -> dict[str, Any]:
    return ssh_vnext._run_sftp(cfg, timeout, batch)


def _require_remote_success(result: dict[str, Any], phase: str) -> str:
    if result.get("ok"):
        return str(result.get("stdout") or "")
    diagnostic = str(
        result.get("stderr") or result.get("stdout") or "remote operation failed"
    )
    raise core.ToolError(f"service-key {phase} failed: {diagnostic}")


def _inspect_script() -> str:
    components = " ".join(_TARGET_COMPONENTS)
    names = " ".join(_KEY_ENTRIES)
    return f"""set -eu
if [ \"$(id -u)\" != 0 ]; then printf '%s\\n' 'service-key deployment requires root' >&2; exit 41; fi
for component in {components}; do
  if [ -L \"$component\" ]; then printf '%s\\n' 'service-key target component is a symbolic link' >&2; exit 42; fi
done
target={TARGET_DIRECTORY!r}
if [ -L \"$target\" ]; then printf '%s\\n' 'service-key target directory is a symbolic link' >&2; exit 43; fi
if [ -e \"$target\" ] && [ ! -d \"$target\" ]; then printf '%s\\n' 'service-key target is not a directory' >&2; exit 44; fi
lock={_LOCK_PATH!r}
if [ -e \"$lock\" ] || [ -L \"$lock\" ]; then printf '%s\\n' 'service-key target is busy' >&2; exit 56; fi
printf '%s\\n' 'REMOTE_X_SERVICE_KEY_INSPECT v1'
if [ -d \"$target\" ]; then printf '%s\\n' 'TARGET_PRESENT'; else printf '%s\\n' 'TARGET_MISSING'; fi
for name in {names}; do
  if [ -L \"$target/$name\" ]; then printf 'KEY\\t%s\\tSYMLINK\\n' \"$name\"; elif [ -e \"$target/$name\" ]; then printf 'KEY\\t%s\\tPRESENT\\n' \"$name\"; else printf 'KEY\\t%s\\tMISSING\\n' \"$name\"; fi
done
""".strip()


def _create_staging_script(staging: str) -> str:
    suffix = staging[len(_STAGING_PREFIX) :] if staging.startswith(_STAGING_PREFIX) else ""
    if not suffix.isalnum():
        raise core.ToolError("invalid service-key staging path")
    components = " ".join(_TARGET_COMPONENTS)
    return f"""set -eu
if [ \"$(id -u)\" != 0 ]; then printf '%s\\n' 'service-key deployment requires root' >&2; exit 41; fi
for component in {components}; do
  if [ -L \"$component\" ]; then printf '%s\\n' 'service-key target component is a symbolic link' >&2; exit 42; fi
done
target={TARGET_DIRECTORY!r}
if [ -L \"$target\" ]; then printf '%s\\n' 'service-key target directory is a symbolic link' >&2; exit 43; fi
install -d -o root -g root -m 700 \"$target\"
if [ \"$(stat -c '%u:%g:%a' \"$target\")\" != '0:0:700' ]; then printf '%s\\n' 'service-key target directory protection mismatch' >&2; exit 45; fi
staging={staging!r}
if [ -e \"$staging\" ] || [ -L \"$staging\" ]; then printf '%s\\n' 'service-key staging collision' >&2; exit 46; fi
lock={_LOCK_PATH!r}
if [ -e \"$lock\" ] || [ -L \"$lock\" ]; then printf '%s\\n' 'service-key target is busy' >&2; exit 56; fi
mkdir \"$lock\"
marker=\"$lock/staging\"
setup_cleanup() {{
  status=$?
  if [ \"$status\" -ne 0 ]; then rm -rf -- \"$staging\" || true; rm -f -- \"$marker\" || true; rmdir \"$lock\" 2>/dev/null || true; fi
  exit \"$status\"
}}
trap setup_cleanup EXIT HUP INT TERM
chown root:root \"$lock\"; chmod 700 \"$lock\"
if [ \"$(stat -c '%u:%g:%a' \"$lock\")\" != '0:0:700' ]; then printf '%s\\n' 'service-key lock protection mismatch' >&2; exit 57; fi
printf '%s\\n' \"$staging\" > \"$marker\"
chown root:root \"$marker\"; chmod 600 \"$marker\"
if [ \"$(cat \"$marker\")\" != \"$staging\" ]; then printf '%s\\n' 'service-key lock marker mismatch' >&2; exit 62; fi
(umask 077; mkdir \"$staging\")
chown root:root \"$staging\"
chmod 700 \"$staging\"
if [ \"$(stat -c '%u:%g:%a' \"$staging\")\" != '0:0:700' ]; then printf '%s\\n' 'service-key staging protection mismatch' >&2; exit 47; fi
printf '%s\\n' 'REMOTE_X_SERVICE_KEY_STAGING_READY v1'
trap - EXIT HUP INT TERM
""".strip()


def _cleanup_script(staging: str) -> str:
    suffix = staging[len(_STAGING_PREFIX) :] if staging.startswith(_STAGING_PREFIX) else ""
    if not suffix.isalnum():
        raise core.ToolError("invalid service-key staging path")
    return f"""set -eu
staging={staging!r}
lock={_LOCK_PATH!r}
case \"$staging\" in
  {_STAGING_PREFIX}*) ;;
  *) printf '%s\\n' 'refusing to clean an unrecognized service-key path' >&2; exit 55 ;;
esac
if [ -L \"$lock\" ]; then printf '%s\\n' 'refusing to remove a symbolic-link lock' >&2; exit 60; fi
if [ -d \"$lock\" ]; then
  marker=\"$lock/staging\"
  if [ -L \"$marker\" ] || [ ! -f \"$marker\" ]; then printf '%s\\n' 'service-key lock has no ownership marker' >&2; exit 61; fi
  owner=$(cat \"$marker\") || exit 61
  if [ \"$owner\" != \"$staging\" ]; then printf '%s\\n' 'service-key lock belongs to another deployment' >&2; exit 0; fi
  rm -rf -- \"$staging\"
  rm -f -- \"$marker\"
  rmdir \"$lock\"
elif [ -e \"$lock\" ]; then
  printf '%s\\n' 'service-key lock is not a directory' >&2; exit 61
elif [ -e \"$staging\" ] || [ -L \"$staging\" ]; then
  printf '%s\\n' 'service-key staging has no ownership marker' >&2; exit 61
fi
""".strip()


def _finalize_script(
    staging: str,
    expected: dict[str, ExtractedKey],
) -> str:
    suffix = staging[len(_STAGING_PREFIX) :] if staging.startswith(_STAGING_PREFIX) else ""
    if not suffix.isalnum():
        raise core.ToolError("invalid service-key staging path")
    components = " ".join(_TARGET_COMPONENTS)
    expected_lines = "\n".join(
        f"expected_{name.replace('-', '_').replace('.', '_')}={info.sha256!r}"
        for name, info in expected.items()
    )
    checks = "\n".join(
        f"check_key \"{name}\" \"$expected_{name.replace('-', '_').replace('.', '_')}\""
        for name in expected
    )
    moves = "\n".join(f"move_key \"{name}\"" for name in expected)
    names = " ".join(expected)
    return f"""set -eu
if [ \"$(id -u)\" != 0 ]; then printf '%s\\n' 'service-key deployment requires root' >&2; exit 41; fi
for component in {components}; do
  if [ -L \"$component\" ]; then printf '%s\\n' 'service-key target component is a symbolic link' >&2; exit 42; fi
done
target={TARGET_DIRECTORY!r}
staging={staging!r}
lock={_LOCK_PATH!r}
if [ -L \"$lock\" ] || [ ! -d \"$lock\" ]; then printf '%s\\n' 'service-key lock is invalid' >&2; exit 58; fi
if [ \"$(stat -c '%u:%g:%a' \"$lock\")\" != '0:0:700' ]; then printf '%s\\n' 'service-key lock protection mismatch' >&2; exit 59; fi
marker=\"$lock/staging\"
if [ -L \"$marker\" ] || [ ! -f \"$marker\" ]; then printf '%s\\n' 'service-key lock marker is invalid' >&2; exit 62; fi
if [ \"$(cat \"$marker\")\" != \"$staging\" ]; then printf '%s\\n' 'service-key lock ownership mismatch' >&2; exit 63; fi
if [ -L \"$staging\" ] || [ ! -d \"$staging\" ]; then printf '%s\\n' 'service-key staging directory is invalid' >&2; exit 48; fi
if [ \"$(stat -c '%u:%g:%a' \"$staging\")\" != '0:0:700' ]; then printf '%s\\n' 'service-key staging protection mismatch' >&2; exit 49; fi
{expected_lines}
check_key() {{
  name=\"$1\"; expected_hash=\"$2\"; path=\"$staging/$name\"
  if [ -L \"$path\" ] || [ ! -f \"$path\" ]; then printf '%s\\n' 'service-key staging file is not a regular file' >&2; exit 50; fi
  chown root:root \"$path\"; chmod 600 \"$path\"
  hash_line=$(sha256sum \"$path\") || exit 51
  actual_hash=${{hash_line%% *}}
  if [ -z \"$actual_hash\" ] || [ \"$actual_hash\" != \"$expected_hash\" ]; then printf '%s\\n' 'service-key staging hash mismatch' >&2; exit 51; fi
}}
{checks}
if [ -L \"$target\" ] || [ ! -d \"$target\" ]; then printf '%s\\n' 'service-key target directory changed' >&2; exit 45; fi
install -d -o root -g root -m 700 \"$target\"
if [ \"$(stat -c '%u:%g:%a' \"$target\")\" != '0:0:700' ]; then printf '%s\\n' 'service-key target directory protection mismatch' >&2; exit 45; fi
linked_names=
rollback() {{
  status=$?
  if [ \"$status\" -ne 0 ]; then
    for linked in $linked_names; do rm -f -- \"$target/$linked\" || true; done
    rm -rf -- \"$staging\" || true
    rm -f -- \"$marker\" || true
    rmdir \"$lock\" 2>/dev/null || true
  fi
  exit \"$status\"
}}
trap rollback EXIT HUP INT TERM
move_key() {{
  name=\"$1\"; destination=\"$target/$name\"
  if [ -L \"$destination\" ]; then printf '%s\\n' 'service-key destination is a symbolic link' >&2; exit 52; fi
  if [ -e \"$destination\" ]; then printf '%s\\n' 'service-key destination already exists' >&2; exit 53; fi
  ln \"$staging/$name\" \"$destination\"
  linked_names=\"$linked_names $name\"
  chown root:root \"$destination\"; chmod 600 \"$destination\"
  rm -f -- \"$staging/$name\"
}}
{moves}
rmdir \"$staging\"
printf '%s\\n' 'REMOTE_X_SERVICE_KEY_RESULT v1'
dir_symlink=0; if [ -L \"$target\" ]; then dir_symlink=1; fi
if [ \"$dir_symlink\" != 0 ]; then printf '%s\\n' 'service-key postflight directory symlink' >&2; exit 54; fi
dir_owner=$(stat -c '%U:%G' \"$target\") || exit 62
dir_mode=$(stat -c '%a' \"$target\") || exit 62
printf 'DIRECTORY\\t%s\\t%s\\t%s\\n' \"$dir_owner\" \"$dir_mode\" \"$dir_symlink\"
for name in {names}; do
  path=\"$target/$name\"
  file_symlink=0; if [ -L \"$path\" ]; then file_symlink=1; fi
  if [ \"$file_symlink\" != 0 ] || [ ! -f \"$path\" ]; then printf '%s\\n' 'service-key postflight file invalid' >&2; exit 54; fi
  file_owner=$(stat -c '%U:%G' \"$path\") || exit 63
  file_mode=$(stat -c '%a' \"$path\") || exit 63
  file_bytes=$(stat -c '%s' \"$path\") || exit 63
  hash_line=$(sha256sum \"$path\") || exit 63
  file_hash=${{hash_line%% *}}
  if [ -z \"$file_hash\" ]; then exit 63; fi
  printf 'FILE\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$name\" \"$file_owner\" \"$file_mode\" \"$file_hash\" \"$file_bytes\" \"$file_symlink\"
done
rm -f -- \"$marker\"
rmdir \"$lock\"
trap - EXIT HUP INT TERM
""".strip()


def _parse_finalize(stdout: str, expected: dict[str, ExtractedKey]) -> dict[str, Any]:
    directory: dict[str, Any] | None = None
    files: dict[str, dict[str, Any]] = {}
    for line in stdout.splitlines():
        parts = line.split("\t")
        if parts[0] == "DIRECTORY" and len(parts) == 4:
            directory = {
                "owner": parts[1],
                "mode": f"{int(parts[2], 8):04o}",
                "symlink": parts[3] == "1",
            }
        elif parts[0] == "FILE" and len(parts) == 7:
            files[parts[1]] = {
                "owner": parts[2],
                "mode": f"{int(parts[3], 8):04o}",
                "sha256": parts[4],
                "bytes": int(parts[5]),
                "symlink": parts[6] == "1",
            }
    if directory is None or set(files) != set(expected):
        raise core.ToolError("service-key postflight returned incomplete metadata")
    if directory != {"owner": "root:root", "mode": "0700", "symlink": False}:
        raise core.ToolError("service-key target directory protection verification failed")
    for name, info in expected.items():
        observed = files[name]
        if (
            observed["owner"] != "root:root"
            or observed["mode"] != "0600"
            or observed["symlink"]
            or observed["sha256"] != info.sha256
            or observed["bytes"] != info.bytes
        ):
            raise core.ToolError(f"service-key postflight verification failed: {name}")
    return {"directory": directory, "files": files}


def deploy(args: dict[str, Any]) -> dict[str, Any]:
    if args.get("confirm") is not True:
        raise core.ToolError("confirm=true is required for service-key deployment")
    requester = core._required_text(args.get("requester"), "requester")
    if any(char.isspace() for char in requester):
        raise core.ToolError("requester must not contain whitespace")
    archive = _archive_path(args.get("archive_path"))
    cfg = ssh_vnext.connection_config(args.get("profile"))
    if cfg.get("host_key_policy") != "managed" or cfg.get("strict_host_key_checking") != "yes":
        raise core.ToolError(
            "service-key deployment requires strict_host_key_checking=yes with "
            "host_key_policy=managed"
        )
    if not cfg.get("queue_resource"):
        raise core.ToolError("service-key deployment requires a configured queue_resource")
    timeout = core.validate_timeout(
        args.get("timeout_seconds"),
        cfg.get("connect_timeout_seconds", core.DEFAULT_COMMAND_TIMEOUT_SECONDS),
    )
    staging = f"{_STAGING_PREFIX}{secrets.token_hex(16)}"
    with _snapshot_archive(archive) as (snapshot, archive_sha256):
        with _extract_snapshot(snapshot) as extracted:
            with ssh_vnext.queue_owner_operation(cfg, {**args, "requester": requester}):
                ssh_vnext._enforce_host_key(cfg, timeout)
                inspect = _require_remote_success(
                    _run_remote_script(cfg, _inspect_script(), timeout),
                    "inspect",
                )
                if "TARGET_PRESENT" in inspect:
                    existing = [
                        name
                        for name in _KEY_ENTRIES
                        if f"KEY\t{name}\tPRESENT" in inspect
                    ]
                    if existing:
                        raise core.ToolError(
                            "service-key destination already exists: "
                            + ", ".join(existing)
                        )
                try:
                    _require_remote_success(
                        _run_remote_script(cfg, _create_staging_script(staging), timeout),
                        "staging",
                    )
                    for name, info in extracted.items():
                        outcome = _run_sftp(
                            cfg,
                            timeout,
                            "put "
                            + ssh_vnext._sftp_path(str(info.path))
                            + " "
                            + ssh_vnext._sftp_path(f"{staging}/{name}"),
                        )
                        if outcome.get("returncode") != 0:
                            raise core.ToolError(
                                f"service-key SFTP upload failed: {name}"
                            )
                    finalize = _require_remote_success(
                        _run_remote_script(
                            cfg,
                            _finalize_script(staging, extracted),
                            timeout,
                        ),
                        "finalize",
                    )
                    postflight = _parse_finalize(finalize, extracted)
                except Exception as exc:
                    try:
                        cleanup = _run_remote_script(
                            cfg, _cleanup_script(staging), timeout
                        )
                    except Exception:
                        cleanup = None
                    if not cleanup or not cleanup.get("ok"):
                        raise core.ToolError(
                            "service-key deployment failed and remote staging cleanup "
                            f"failed; inspect {staging} without exposing its contents"
                        ) from exc
                    raise
    return core.tool_result(
        {
            "ok": True,
            "service": SERVICE_NAME,
            "profile": cfg["profile"],
            "targetDirectory": TARGET_DIRECTORY,
            "archiveSha256": archive_sha256,
            "files": {
                name: {
                    "bytes": info.bytes,
                    "sha256": info.sha256,
                    "remote": postflight["files"][name],
                }
                for name, info in extracted.items()
            },
            "directory": postflight["directory"],
            "protocol": "sftp",
            "integrityMatched": True,
        }
    )


TOOLS = {
    "remotex_ssh_service_key_deploy": {
        "description": (
            "Extract only the fixed lite-cloudquery service keys from a local ZIP, "
            "upload them through SFTP, and verify root-owned 0700/0600 remote state. "
            "On Windows the archive must be under C:/Work/AI/CloudQuery. "
            "Private-key contents are never accepted as tool arguments or returned."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string"},
                "archive_path": {"type": "string"},
                "requester": {"type": "string"},
                "confirm": {"type": "boolean"},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": core.MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["archive_path", "requester", "confirm"],
            "additionalProperties": False,
        },
        "handler": deploy,
    }
}
