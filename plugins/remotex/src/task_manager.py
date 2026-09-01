from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import remotex_core as core
import secure_paths
import ssh_vnext


TASK_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
WORKER_PAYLOAD_MAGIC = b"REMOTEX_TASK_PAYLOAD_V2\n"
MAX_WORKER_PAYLOAD_BYTES = 4 * 1024 * 1024
TASK_START_ACK_SECONDS = 5
LEGACY_SENSITIVE_FILENAMES = ("stdin.bin", "secrets.json")


def task_root() -> Path:
    configured = os.environ.get("REMOTEX_TASK_DIR")
    if configured:
        return core.expand_path(configured, "REMOTEX_TASK_DIR")
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    return root / "RemoteX" / "tasks"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _task_id(value: Any) -> str:
    task_id = core._required_text(value, "task_id").lower()
    if not TASK_ID_PATTERN.fullmatch(task_id):
        raise core.ToolError("task_id must be a RemoteX UUID")
    return task_id


def _directory(task_id: str) -> Path:
    root = task_root().resolve(strict=False)
    directory = (root / task_id).resolve(strict=False)
    if directory.parent != root:
        raise core.ToolError("task_id escaped the RemoteX task directory")
    return directory


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise core.ToolError(f"{label} does not exist: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError(f"Unable to read {label} at {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise core.ToolError(f"{label} at {path} is not an object")
    return value


def _pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        process_query_limited_information = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _kill_pid_tree(pid: int) -> bool:
    if not _pid_running(pid):
        return False
    if os.name == "nt":
        subprocess.run(
            ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            check=False,
            timeout=15,
        )
        return True
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
    return True


def _reap_worker(process: subprocess.Popen[Any]) -> None:
    try:
        process.wait()
    except (OSError, subprocess.SubprocessError):
        pass


def _encode_worker_payload(input_bytes: bytes, secrets: list[str]) -> bytes:
    if not isinstance(input_bytes, bytes):
        raise core.ToolError("RemoteX task input must be bytes")
    if not isinstance(secrets, list) or any(not isinstance(value, str) for value in secrets):
        raise core.ToolError("RemoteX task redaction values are invalid")
    document = json.dumps(
        {
            "schema": "RemoteXTaskPayload/v2",
            "inputBase64": base64.b64encode(input_bytes).decode("ascii"),
            "secrets": secrets,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if not document or len(document) > MAX_WORKER_PAYLOAD_BYTES:
        raise core.ToolError("RemoteX task payload exceeds the safe size limit")
    return WORKER_PAYLOAD_MAGIC + len(document).to_bytes(8, "big") + document


def _wait_for_worker_ack(
    directory: Path,
    process: subprocess.Popen[Any],
) -> dict[str, Any]:
    deadline = time.monotonic() + TASK_START_ACK_SECONDS
    while time.monotonic() < deadline:
        try:
            state = _read_json(directory / "state.json", "task state")
        except core.ToolError:
            state = {}
        if state.get("state") in {"running", "completed", "failed", "cancelled"}:
            return state
        if process.poll() is not None:
            raise core.ToolError("RemoteX task worker exited before secret-pipe acknowledgment")
        time.sleep(0.02)
    raise core.ToolError("RemoteX task worker secret-pipe acknowledgment timed out")


def _terminate_failed_start(process: subprocess.Popen[Any] | None, directory: Path) -> None:
    if process is not None:
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        try:
            _kill_pid_tree(int(process.pid))
        except (OSError, TypeError, ValueError):
            try:
                process.kill()
            except (OSError, subprocess.SubprocessError):
                pass
    shutil.rmtree(directory, ignore_errors=True)


def start(args: dict[str, Any]) -> dict[str, Any]:
    prepared = ssh_vnext.prepare_script(args)
    with ssh_vnext.queue_owner_operation(prepared["cfg"], args):
        return _start_owned(args, prepared)


def _start_owned(
    args: dict[str, Any],
    prepared: dict[str, Any],
) -> dict[str, Any]:
    task_id = str(uuid.uuid4())
    directory = _directory(task_id)
    if directory.exists():
        raise core.ToolError("RemoteX task directory already exists")
    secure_paths.ensure_private_directory(directory)
    script = core._text(args.get("script"))
    spec = {
        "schema": "RemoteXTaskSpec/v2",
        "taskId": task_id,
        "profile": prepared["cfg"]["profile"],
        "host": prepared["cfg"]["host"],
        "port": prepared["cfg"]["port"],
        "shell": prepared["shell"],
        "scriptSha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
        "environmentInjections": [
            item.public() for item in prepared["injections"]
        ],
        "argv": prepared["argv"],
        "timeout": prepared["timeout"],
        "maxStdoutBytes": prepared["max_stdout_bytes"],
        "maxStderrBytes": prepared["max_stderr_bytes"],
        "outputEncoding": prepared["output_encoding"],
        "limits": prepared["limits"],
        "createdAt": _now(),
        "queueResource": prepared["cfg"].get("queue_resource"),
        "requester": core._text(args.get("requester")).strip() or None,
    }
    _write_json(directory / "spec.json", spec)
    _write_json(
        directory / "state.json",
        {
            "schema": "RemoteXTask/v2",
            "taskId": task_id,
            "state": "starting",
            "profile": prepared["cfg"]["profile"],
            "shell": prepared["shell"],
            "createdAt": spec["createdAt"],
        },
    )
    worker = Path(__file__).with_name("task_worker.py")
    kwargs: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "cwd": str(worker.parent),
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        )
    else:
        kwargs["start_new_session"] = True
    process: subprocess.Popen[Any] | None = None
    try:
        process = subprocess.Popen(
            [sys.executable, str(worker), str(directory)],
            **kwargs,
        )
        (directory / "worker.pid").write_text(str(process.pid), encoding="ascii")
        if process.stdin is None:
            raise core.ToolError("RemoteX task worker secret pipe is unavailable")
        process.stdin.write(
            _encode_worker_payload(prepared["input_bytes"], prepared["secrets"])
        )
        process.stdin.flush()
        process.stdin.close()
        acknowledged = _wait_for_worker_ack(directory, process)
    except (OSError, BrokenPipeError, subprocess.SubprocessError, core.ToolError) as exc:
        _terminate_failed_start(process, directory)
        if isinstance(exc, core.ToolError):
            raise
        raise core.ToolError("Unable to start RemoteX task worker securely") from exc
    threading.Thread(
        target=_reap_worker,
        args=(process,),
        name=f"remotex-task-reaper-{task_id}",
        daemon=True,
    ).start()
    return core.tool_result(
        {
            "ok": True,
            "taskId": task_id,
            "state": acknowledged.get("state", "running"),
            "workerPid": process.pid,
            "profile": prepared["cfg"]["profile"],
            "requestedShell": prepared["shell"],
            "scriptSha256": spec["scriptSha256"],
            "environmentInjections": spec["environmentInjections"],
            "taskDirectory": str(directory),
            "resumeSupported": True,
            "nextStep": "Call remotex_ssh_task_status, then collect or cancel by task_id.",
        }
    )


def _worker_pid(directory: Path) -> int | None:
    try:
        value = int((directory / "worker.pid").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None
    return value if value > 0 else None


def status(args: dict[str, Any]) -> dict[str, Any]:
    task_id = _task_id(args.get("task_id"))
    directory = _directory(task_id)
    state = _read_json(directory / "state.json", "task state")
    result_path = directory / "result.json"
    legacy_sensitive_count = sum(
        1 for name in LEGACY_SENSITIVE_FILENAMES if (directory / name).is_file()
    )
    if result_path.exists():
        result = _read_json(result_path, "task result")
        return core.tool_result(
            {
                "ok": True,
                "taskId": task_id,
                "state": result.get("state", state.get("state")),
                "finished": True,
                "resultReady": True,
                "workerRunning": False,
                "profile": result.get("profile") or state.get("profile"),
                "exitCode": result.get("exitCode"),
                "timedOut": result.get("timedOut"),
                "terminationReason": result.get("terminationReason"),
                "completedAt": result.get("completedAt"),
                "legacySensitiveArtifactCount": legacy_sensitive_count,
            }
        )
    pid = _worker_pid(directory)
    running = bool(pid and _pid_running(pid))
    effective_state = state.get("state")
    if not running and effective_state in {"starting", "running"}:
        effective_state = "orphaned"
    return core.tool_result(
        {
            "ok": running,
            "taskId": task_id,
            "state": effective_state,
            "finished": False,
            "resultReady": False,
            "workerPid": pid,
            "workerRunning": running,
            "profile": state.get("profile"),
            "startedAt": state.get("startedAt"),
            "legacySensitiveArtifactCount": legacy_sensitive_count,
        }
    )


def cleanup_sensitive_artifacts(args: dict[str, Any]) -> dict[str, Any]:
    task_id = _task_id(args.get("task_id"))
    if not core.as_bool(args.get("confirm"), False):
        raise core.ToolError("confirm=true is required to remove legacy sensitive artifacts")
    directory = _directory(task_id)
    if not directory.is_dir():
        raise core.ToolError("RemoteX task directory is unavailable")
    pid = _worker_pid(directory)
    if pid and _pid_running(pid):
        raise core.ToolError("Legacy sensitive artifacts cannot be removed for an active worker")
    removed = 0
    for name in LEGACY_SENSITIVE_FILENAMES:
        candidate = directory / name
        if candidate.is_file():
            try:
                candidate.unlink()
            except OSError as exc:
                raise core.ToolError("Unable to remove legacy sensitive artifacts") from exc
            removed += 1
    remaining = sum(
        1 for name in LEGACY_SENSITIVE_FILENAMES if (directory / name).is_file()
    )
    return core.tool_result(
        {
            "ok": remaining == 0,
            "taskId": task_id,
            "removedCount": removed,
            "remainingSensitiveArtifactCount": remaining,
            "taskDirectorySha256": hashlib.sha256(
                str(directory.resolve()).encode("utf-8")
            ).hexdigest(),
        }
    )


def cancel(args: dict[str, Any]) -> dict[str, Any]:
    task_id = _task_id(args.get("task_id"))
    directory = _directory(task_id)
    result_path = directory / "result.json"
    if result_path.exists():
        result = _read_json(result_path, "task result")
        return core.tool_result(
            {
                "ok": True,
                "taskId": task_id,
                "cancelStatus": "already-finished",
                "state": result.get("state"),
                "idempotent": True,
            }
        )
    pid = _worker_pid(directory)
    terminated = bool(pid and _kill_pid_tree(pid))
    cancelled_at = _now()
    result = {
        "schema": "RemoteXTaskResult/v1",
        "taskId": task_id,
        "state": "cancelled",
        "ok": False,
        "cancelled": True,
        "workerPid": pid,
        "processTreeTerminated": terminated,
        "terminationReason": "explicit-cancel",
        "completedAt": cancelled_at,
    }
    _write_json(result_path, result)
    _write_json(
        directory / "state.json",
        {
            "schema": "RemoteXTask/v1",
            "taskId": task_id,
            "state": "cancelled",
            "workerPid": pid,
            "completedAt": cancelled_at,
        },
    )
    return core.tool_result(
        {
            "ok": True,
            "taskId": task_id,
            "cancelStatus": "cancelled" if terminated else "already-stopped",
            "state": "cancelled",
            "processTreeTerminated": terminated,
            "idempotent": True,
        }
    )


def collect(args: dict[str, Any]) -> dict[str, Any]:
    task_id = _task_id(args.get("task_id"))
    directory = _directory(task_id)
    result_path = directory / "result.json"
    if not result_path.exists():
        raise core.ToolError("Task result is not ready; call status or cancel first")
    result = _read_json(result_path, "task result")
    cleanup = core.as_bool(args.get("cleanup"), False)
    result["collected"] = True
    result["cleanupRequested"] = cleanup
    if cleanup:
        shutil.rmtree(directory)
        result["taskArtifactsRemoved"] = True
    else:
        result["taskArtifactsRemoved"] = False
        result["taskDirectory"] = str(directory)
    return core.tool_result(result)


TASK_ID_PROPERTY = {
    "task_id": {
        "type": "string",
        "description": "RemoteX task UUID returned by remotex_ssh_task_start.",
    }
}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_ssh_task_start": {
        "description": (
            "Start a resumable bounded SSH script task in an independent local worker."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **ssh_vnext.COMMON_PROFILE,
                **ssh_vnext.COMMON_TIMEOUT,
                **ssh_vnext.OUTPUT_PROPERTIES,
                **ssh_vnext.RESOURCE_PROPERTIES,
                **ssh_vnext.ENVIRONMENT_REFS,
                **ssh_vnext.REQUESTER_PROPERTY,
                "shell": {
                    "type": "string",
                    "enum": sorted(ssh_vnext.SUPPORTED_SHELLS),
                },
                "script": {"type": "string"},
            },
            "required": ["script"],
            "additionalProperties": False,
        },
        "handler": start,
    },
    "remotex_ssh_task_status": {
        "description": "Read persisted state for a resumable SSH task.",
        "inputSchema": {
            "type": "object",
            "properties": TASK_ID_PROPERTY,
            "required": ["task_id"],
            "additionalProperties": False,
        },
        "handler": status,
    },
    "remotex_ssh_task_cancel": {
        "description": "Idempotently terminate the task worker and its SSH process tree.",
        "inputSchema": {
            "type": "object",
            "properties": TASK_ID_PROPERTY,
            "required": ["task_id"],
            "additionalProperties": False,
        },
        "handler": cancel,
    },
    "remotex_ssh_task_collect": {
        "description": "Collect a completed task result and optionally remove local artifacts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **TASK_ID_PROPERTY,
                "cleanup": {"type": "boolean"},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
        "handler": collect,
    },
    "remotex_ssh_task_cleanup_sensitive_artifacts": {
        "description": (
            "Explicitly remove legacy stdin.bin or secrets.json artifacts from one "
            "inactive RemoteX task directory without reading their contents."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **TASK_ID_PROPERTY,
                "confirm": {"type": "boolean"},
            },
            "required": ["task_id", "confirm"],
            "additionalProperties": False,
        },
        "handler": cleanup_sensitive_artifacts,
    },
}
