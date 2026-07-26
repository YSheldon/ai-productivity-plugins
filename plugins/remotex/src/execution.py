from __future__ import annotations

import ctypes
import locale
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any

import remotex_core as core


DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_MEMORY_MB = 16 * 1024
MAX_PROCESS_COUNT = 256


def byte_limit(value: Any, default: int, field: str) -> int:
    try:
        limit = int(default if value in (None, "") else value)
    except (TypeError, ValueError) as exc:
        raise core.ToolError(f"{field} must be an integer number of bytes") from exc
    if not 1 <= limit <= MAX_OUTPUT_BYTES:
        raise core.ToolError(f"{field} must be between 1 and {MAX_OUTPUT_BYTES} bytes")
    return limit


def optional_limit(
    value: Any,
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    if value in (None, ""):
        return None
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise core.ToolError(f"{field} must be an integer") from exc
    if not minimum <= limit <= maximum:
        raise core.ToolError(f"{field} must be between {minimum} and {maximum}")
    return limit


def decode_output(data: bytes, encoding: str = "auto") -> tuple[str, str]:
    requested = str(encoding or "auto").strip().lower()
    requested = {
        "utf8": "utf-8",
        "utf-8-bom": "utf-8-sig",
        "utf16le": "utf-16-le",
        "utf-16le": "utf-16-le",
    }.get(requested, requested)
    if requested != "auto":
        if requested == "oem":
            requested = "mbcs" if os.name == "nt" else locale.getpreferredencoding(False)
        try:
            return data.decode(requested, errors="replace"), requested
        except LookupError as exc:
            raise core.ToolError(f"Unsupported output encoding: {encoding}") from exc

    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace"), "utf-8-sig"
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le", errors="replace").lstrip("\ufeff"), "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be", errors="replace").lstrip("\ufeff"), "utf-16-be"
    if data and data.count(b"\x00") > len(data) // 4:
        try:
            return data.decode("utf-16-le"), "utf-16-le"
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    candidates = [locale.getpreferredencoding(False)]
    if os.name == "nt":
        candidates.extend(["mbcs", "cp936", "cp437"])
    for candidate in candidates:
        try:
            return data.decode(candidate), candidate
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace"), "utf-8-replacement"


def redact(value: str, secrets: list[str] | None = None) -> str:
    text = value
    for secret in secrets or []:
        if secret:
            text = text.replace(secret, "[REDACTED SECRET]")
    return core.redact_text(text)


class _Collector(threading.Thread):
    def __init__(self, stream: Any, limit: int):
        super().__init__(daemon=True)
        self.stream = stream
        self.limit = limit
        self.total = 0
        self._kept = 0
        self._chunks: list[bytes] = []

    def run(self) -> None:
        while True:
            chunk = self.stream.read(64 * 1024)
            if not chunk:
                return
            self.total += len(chunk)
            remaining = self.limit - self._kept
            if remaining > 0:
                kept = chunk[:remaining]
                self._chunks.append(kept)
                self._kept += len(kept)

    @property
    def data(self) -> bytes:
        return b"".join(self._chunks)

    @property
    def truncated(self) -> bool:
        return self.total > self._kept


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _WindowsJob:
    _PROCESS_TIME = 0x00000002
    _ACTIVE_PROCESS = 0x00000008
    _PROCESS_MEMORY = 0x00000100
    _KILL_ON_CLOSE = 0x00002000
    _INFO_CLASS = 9

    def __init__(
        self,
        process: subprocess.Popen,
        *,
        memory_limit_mb: int | None,
        cpu_time_seconds: int | None,
        max_processes: int | None,
    ):
        self.handle: int | None = None
        self.assigned = False
        self.error: int | None = None
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        kernel32.SetInformationJobObject.restype = ctypes.c_int
        kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            self.error = ctypes.get_last_error()
            return
        self.handle = int(handle)
        info = _ExtendedLimitInformation()
        flags = self._KILL_ON_CLOSE
        if memory_limit_mb is not None:
            info.ProcessMemoryLimit = memory_limit_mb * 1024 * 1024
            flags |= self._PROCESS_MEMORY
        if cpu_time_seconds is not None:
            info.BasicLimitInformation.PerProcessUserTimeLimit = cpu_time_seconds * 10_000_000
            flags |= self._PROCESS_TIME
        if max_processes is not None:
            info.BasicLimitInformation.ActiveProcessLimit = max_processes
            flags |= self._ACTIVE_PROCESS
        info.BasicLimitInformation.LimitFlags = flags
        if not kernel32.SetInformationJobObject(
            ctypes.c_void_p(self.handle),
            self._INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            self.error = ctypes.get_last_error()
            self.close()
            return
        if not kernel32.AssignProcessToJobObject(
            ctypes.c_void_p(self.handle),
            ctypes.c_void_p(int(process._handle)),  # type: ignore[attr-defined]
        ):
            self.error = ctypes.get_last_error()
            self.close()
            return
        self.assigned = True

    def terminate(self) -> bool:
        if not self.handle or not self.assigned:
            return False
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.TerminateJobObject.restype = ctypes.c_int
        return bool(kernel32.TerminateJobObject(ctypes.c_void_p(self.handle), 1))

    def peak_memory_bytes(self) -> int | None:
        if not self.handle:
            return None
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.QueryInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.QueryInformationJobObject.restype = ctypes.c_int
        info = _ExtendedLimitInformation()
        if not kernel32.QueryInformationJobObject(
            ctypes.c_void_p(self.handle),
            self._INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
            None,
        ):
            return None
        return int(info.PeakJobMemoryUsed)

    def close(self) -> None:
        if self.handle:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            kernel32.CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = None


def _posix_limiter(memory_limit_mb: int | None, cpu_time_seconds: int | None) -> Any:
    if os.name == "nt" or (memory_limit_mb is None and cpu_time_seconds is None):
        return None

    def apply() -> None:
        import resource

        if memory_limit_mb is not None:
            value = memory_limit_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (value, value))
        if cpu_time_seconds is not None:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_time_seconds, cpu_time_seconds))

    return apply


def terminate_tree(process: subprocess.Popen, job: _WindowsJob | None = None) -> bool:
    if process.poll() is not None:
        return False
    if os.name == "nt":
        if job and job.terminate():
            return True
        try:
            subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            process.kill()
        return True
    try:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        process.kill()
    return True


def run_process(
    argv: list[str],
    *,
    timeout: int,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
    max_stdout_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    output_encoding: str = "auto",
    secrets: list[str] | None = None,
    memory_limit_mb: int | None = None,
    cpu_time_seconds: int | None = None,
    max_processes: int | None = None,
    terminate_on_output_limit: bool = False,
) -> dict[str, Any]:
    timeout = core.validate_timeout(timeout, core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    max_stdout_bytes = byte_limit(max_stdout_bytes, DEFAULT_MAX_OUTPUT_BYTES, "max_stdout_bytes")
    max_stderr_bytes = byte_limit(max_stderr_bytes, DEFAULT_MAX_OUTPUT_BYTES, "max_stderr_bytes")
    memory_limit_mb = optional_limit(
        memory_limit_mb,
        "memory_limit_mb",
        minimum=16,
        maximum=MAX_MEMORY_MB,
    )
    cpu_time_seconds = optional_limit(
        cpu_time_seconds,
        "cpu_time_seconds",
        minimum=1,
        maximum=core.MAX_TIMEOUT_SECONDS,
    )
    max_processes = optional_limit(
        max_processes,
        "max_processes",
        minimum=1,
        maximum=MAX_PROCESS_COUNT,
    )
    kwargs: dict[str, Any] = {
        "stdin": subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": environment,
        "text": False,
        "close_fds": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
        limiter = _posix_limiter(memory_limit_mb, cpu_time_seconds)
        if limiter:
            kwargs["preexec_fn"] = limiter
    started = time.monotonic()
    try:
        process = subprocess.Popen(argv, **kwargs)
    except FileNotFoundError as exc:
        raise core.ToolError(f"Executable not found: {argv[0]}") from exc
    except OSError as exc:
        raise core.ToolError(f"Unable to start {argv[0]}: {exc}") from exc

    job = (
        _WindowsJob(
            process,
            memory_limit_mb=memory_limit_mb,
            cpu_time_seconds=cpu_time_seconds,
            max_processes=max_processes,
        )
        if os.name == "nt"
        else None
    )
    if job and not job.assigned:
        error = job.error
        terminate_tree(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        job.close()
        raise core.ToolError(
            "Unable to assign the local process to a Windows Job Object "
            f"(Win32 error {error}); refusing unmanaged execution"
        )
    stdout = _Collector(process.stdout, max_stdout_bytes)
    stderr = _Collector(process.stderr, max_stderr_bytes)
    stdout.start()
    stderr.start()
    if input_bytes is not None and process.stdin is not None:
        try:
            process.stdin.write(input_bytes)
            process.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()

    reason: str | None = None
    tree_terminated = False
    deadline = started + timeout
    while process.poll() is None:
        if time.monotonic() >= deadline:
            reason = "wall-time-limit"
        elif terminate_on_output_limit and (
            stdout.total > max_stdout_bytes or stderr.total > max_stderr_bytes
        ):
            reason = "output-byte-limit"
        if reason:
            tree_terminated = terminate_tree(process, job)
            break
        time.sleep(0.02)
    try:
        returncode = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        tree_terminated = terminate_tree(process, job)
        returncode = process.wait(timeout=5)
    stdout.join(timeout=5)
    stderr.join(timeout=5)
    if process.stdout is not None:
        process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()
    stdout_text, stdout_encoding = decode_output(stdout.data, output_encoding)
    stderr_text, stderr_encoding = decode_output(stderr.data, output_encoding)
    peak_memory = job.peak_memory_bytes() if job else None
    job_assigned = bool(job and job.assigned)
    job_error = job.error if job else None
    if job:
        job.close()
    return {
        "returncode": returncode,
        "timed_out": reason == "wall-time-limit",
        "stdout": redact(stdout_text, secrets),
        "stderr": redact(stderr_text, secrets),
        "stdout_bytes": stdout.total,
        "stderr_bytes": stderr.total,
        "stdout_truncated": stdout.truncated,
        "stderr_truncated": stderr.truncated,
        "stdout_encoding": stdout_encoding,
        "stderr_encoding": stderr_encoding,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "process_id": process.pid,
        "process_tree_terminated": tree_terminated,
        "terminated_process_ids": [process.pid] if tree_terminated else [],
        "termination_reason": reason,
        "peak_memory_bytes": peak_memory,
        "resource_limits": {
            "wall_time_seconds": timeout,
            "memory_limit_mb": memory_limit_mb,
            "cpu_time_seconds": cpu_time_seconds,
            "max_processes": max_processes,
            "output_limit_terminates": terminate_on_output_limit,
            "windows_job_object_assigned": job_assigned,
            "windows_job_object_error": job_error,
            "linux_process_group": os.name != "nt",
        },
    }


@dataclass(frozen=True)
class EnvironmentInjection:
    remote_name: str
    value: str
    source: str
    reference: str
    secret: bool

    def public(self) -> dict[str, Any]:
        return {
            "name": self.remote_name,
            "source": self.source,
            "reference": self.reference,
            "secret": self.secret,
            "injected": True,
        }


def resolve_environment_refs(value: Any) -> list[EnvironmentInjection]:
    if value in (None, {}):
        return []
    if not isinstance(value, dict):
        raise core.ToolError("environment_refs must be an object")
    injections: list[EnvironmentInjection] = []
    for remote_name, raw in value.items():
        name = core._environment_name(remote_name, f"environment_refs.{remote_name}")
        if isinstance(raw, str):
            source = "environment"
            reference = core._environment_name(raw, f"environment_refs.{name}")
            secret = True
            resolved = os.environ.get(reference)
            if resolved is None:
                raise core.ToolError(f"Environment reference is not set: {reference}")
        elif isinstance(raw, dict):
            source = str(raw.get("source") or "environment").strip().lower()
            secret = core.as_bool(raw.get("secret"), True)
            if source == "environment":
                reference = core._environment_name(
                    raw.get("name"),
                    f"environment_refs.{name}.name",
                )
                resolved = os.environ.get(reference)
                if resolved is None:
                    raise core.ToolError(f"Environment reference is not set: {reference}")
            elif source == "windows-credential-manager":
                reference = core._required_text(
                    raw.get("target"),
                    f"environment_refs.{name}.target",
                )
                field = str(raw.get("field") or "password").strip().lower()
                if field not in {"username", "password"}:
                    raise core.ToolError(
                        f"environment_refs.{name}.field must be username or password"
                    )
                credential = core.read_windows_generic_credential(reference)
                resolved = credential.username if field == "username" else credential.password
            else:
                raise core.ToolError(
                    f"environment_refs.{name}.source must be environment or "
                    "windows-credential-manager"
                )
        else:
            raise core.ToolError(f"environment_refs.{name} must be a string or object")
        if "\x00" in resolved:
            raise core.ToolError(f"environment_refs.{name} contains an unsupported NUL")
        injections.append(
            EnvironmentInjection(
                remote_name=name,
                value=resolved,
                source=source,
                reference=reference,
                secret=secret,
            )
        )
    return injections
