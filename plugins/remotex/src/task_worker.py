from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import execution
import queue_leases
import remotex_core as core
import ssh_vnext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
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
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _remove(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _queue_operation(spec: dict[str, Any]):
    resource = spec.get("queueResource")
    if not resource:
        return nullcontext(None)
    requester = core._required_text(spec.get("requester"), "requester")
    return queue_leases.leased_owner_operation(resource, requester)


def run(task_directory: Path) -> int:
    spec_path = task_directory / "spec.json"
    input_path = task_directory / "stdin.bin"
    secrets_path = task_directory / "secrets.json"
    state_path = task_directory / "state.json"
    result_path = task_directory / "result.json"
    spec = _read_json(spec_path)
    input_bytes = input_path.read_bytes()
    secrets_value = _read_json(secrets_path)
    secrets = [str(value) for value in secrets_value] if isinstance(secrets_value, list) else []
    _remove(input_path)
    _remove(secrets_path)
    _write_json(
        state_path,
        {
            "schema": "RemoteXTask/v1",
            "taskId": spec["taskId"],
            "state": "running",
            "workerPid": os.getpid(),
            "profile": spec["profile"],
            "shell": spec["shell"],
            "startedAt": _now(),
        },
    )
    try:
        with _queue_operation(spec):
            outcome = execution.run_process(
                list(spec["argv"]),
                timeout=int(spec["timeout"]),
                input_bytes=input_bytes,
                max_stdout_bytes=int(spec["maxStdoutBytes"]),
                max_stderr_bytes=int(spec["maxStderrBytes"]),
                output_encoding=str(spec["outputEncoding"]),
                secrets=secrets,
                memory_limit_mb=spec["limits"].get("memoryMb"),
                cpu_time_seconds=spec["limits"].get("cpuSeconds"),
                max_processes=spec["limits"].get("maxProcesses"),
                terminate_on_output_limit=True,
            )
        clean_stderr, metadata = ssh_vnext._extract_metadata(outcome["stderr"])
        result = {
            "schema": "RemoteXTaskResult/v1",
            "taskId": spec["taskId"],
            "state": "completed",
            "ok": outcome["returncode"] == 0 and not outcome["timed_out"],
            "profile": spec["profile"],
            "host": spec["host"],
            "port": spec["port"],
            "requestedShell": spec["shell"],
            "interpreter": metadata.get("interpreter") or spec["shell"],
            "scriptSha256": spec["scriptSha256"],
            "environmentInjections": spec["environmentInjections"],
            "queueResource": spec.get("queueResource"),
            "requester": spec.get("requester"),
            "exitCode": outcome["returncode"],
            "timedOut": outcome["timed_out"],
            "durationMs": outcome["duration_ms"],
            "remotePid": metadata.get("remotePid"),
            "localPid": outcome["process_id"],
            "stdout": outcome["stdout"],
            "stderr": clean_stderr,
            "stdoutBytes": outcome["stdout_bytes"],
            "stderrBytes": outcome["stderr_bytes"],
            "stdoutTruncated": outcome["stdout_truncated"],
            "stderrTruncated": outcome["stderr_truncated"],
            "stdoutEncoding": outcome["stdout_encoding"],
            "stderrEncoding": outcome["stderr_encoding"],
            "processTreeTerminated": outcome["process_tree_terminated"],
            "terminatedProcessIds": outcome["terminated_process_ids"],
            "terminationReason": outcome["termination_reason"],
            "peakMemoryBytes": outcome["peak_memory_bytes"],
            "resourceLimits": outcome["resource_limits"],
            "completedAt": _now(),
        }
        _write_json(result_path, result)
        _write_json(
            state_path,
            {
                "schema": "RemoteXTask/v1",
                "taskId": spec["taskId"],
                "state": "completed",
                "workerPid": os.getpid(),
                "profile": spec["profile"],
                "shell": spec["shell"],
                "completedAt": result["completedAt"],
            },
        )
        return 0
    except Exception as exc:
        error = core.redact_text(f"{type(exc).__name__}: {exc}")
        _write_json(
            result_path,
            {
                "schema": "RemoteXTaskResult/v1",
                "taskId": spec.get("taskId"),
                "state": "failed",
                "ok": False,
                "error": error,
                "completedAt": _now(),
            },
        )
        _write_json(
            state_path,
            {
                "schema": "RemoteXTask/v1",
                "taskId": spec.get("taskId"),
                "state": "failed",
                "workerPid": os.getpid(),
                "error": error,
                "completedAt": _now(),
            },
        )
        sys.stderr.write(core.redact_text(traceback.format_exc()) + "\n")
        return 1
    finally:
        for index in range(len(secrets)):
            secrets[index] = ""


def main() -> int:
    if len(sys.argv) != 2:
        sys.stderr.write("usage: task_worker.py TASK_DIRECTORY\n")
        return 2
    return run(Path(sys.argv[1]).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
