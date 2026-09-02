from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shlex
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import authentication_evidence
import execution
import remotex_core as core
import ssh_adapter as legacy


DEFAULT_PORT = 22
SUPPORTED_SHELLS = {"auto", "powershell", "pwsh", "cmd", "sh", "bash"}
SUPPORTED_PLATFORMS = {"auto", "windows", "posix"}
HOST_KEY_POLICIES = {"known-hosts", "managed"}
META_PREFIX = "__REMOTEX_META__"
WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
SAFE_SCP_PATH = re.compile(r"^[A-Za-z0-9_./:\\-]+$")
SAFE_AUTH_METHOD = re.compile(r"^[A-Za-z0-9@._+-]{1,128}$")
AUTHENTICATION_DENIED = re.compile(
    r"permission denied(?:\s*\((?P<methods>[^)]*)\))?",
    re.IGNORECASE,
)


WINDOWS_WRAPPER = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Text.UTF8Encoding]::new($false)
$job = $null
$temp = $null
try {
    $encoded = [Console]::In.ReadToEnd().Trim()
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
    $request = $json | ConvertFrom-Json
    if ($null -ne $request.environment) {
        foreach ($property in $request.environment.PSObject.Properties) {
            [Environment]::SetEnvironmentVariable(
                [string]$property.Name,
                [string]$property.Value,
                [EnvironmentVariableTarget]::Process
            )
        }
    }
    if (-not ('RemoteXNativeJob' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

public sealed class RemoteXNativeJob : IDisposable {
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits {
        public BasicLimits BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private IntPtr handle;
    public bool Assigned { get; private set; }
    public int LastError { get; private set; }

    public RemoteXNativeJob(long memoryBytes, long cpuSeconds, int processCount) {
        handle = CreateJobObject(IntPtr.Zero, null);
        if (handle == IntPtr.Zero) {
            LastError = Marshal.GetLastWin32Error();
            return;
        }
        ExtendedLimits limits = new ExtendedLimits();
        const uint KillOnClose = 0x00002000;
        const uint ProcessMemory = 0x00000100;
        const uint ProcessTime = 0x00000002;
        const uint ActiveProcess = 0x00000008;
        limits.BasicLimitInformation.LimitFlags = KillOnClose;
        if (memoryBytes > 0) {
            limits.ProcessMemoryLimit = (UIntPtr)(ulong)memoryBytes;
            limits.BasicLimitInformation.LimitFlags |= ProcessMemory;
        }
        if (cpuSeconds > 0) {
            limits.BasicLimitInformation.PerProcessUserTimeLimit = cpuSeconds * 10000000L;
            limits.BasicLimitInformation.LimitFlags |= ProcessTime;
        }
        if (processCount > 0) {
            limits.BasicLimitInformation.ActiveProcessLimit = (uint)processCount;
            limits.BasicLimitInformation.LimitFlags |= ActiveProcess;
        }
        int size = Marshal.SizeOf(typeof(ExtendedLimits));
        IntPtr pointer = Marshal.AllocHGlobal(size);
        try {
            Marshal.StructureToPtr(limits, pointer, false);
            if (!SetInformationJobObject(handle, 9, pointer, (uint)size)) {
                LastError = Marshal.GetLastWin32Error();
                Dispose();
                return;
            }
        } finally {
            Marshal.FreeHGlobal(pointer);
        }
        using (Process current = Process.GetCurrentProcess()) {
            Assigned = AssignProcessToJobObject(handle, current.Handle);
        }
        if (!Assigned) {
            LastError = Marshal.GetLastWin32Error();
            Dispose();
        }
    }
    public void Kill() {
        if (handle != IntPtr.Zero) {
            TerminateJobObject(handle, 1);
        }
    }
    public void Dispose() {
        if (handle != IntPtr.Zero) {
            CloseHandle(handle);
            handle = IntPtr.Zero;
        }
    }
}
'@
    }
    $memoryBytes = if ($null -ne $request.limits.memoryMb) {
        [long]$request.limits.memoryMb * 1MB
    } else { 0 }
    $cpuSeconds = if ($null -ne $request.limits.cpuSeconds) {
        [long]$request.limits.cpuSeconds
    } else { 0 }
    $processCount = if ($null -ne $request.limits.maxProcesses) {
        [int]$request.limits.maxProcesses
    } else { 0 }
    $job = [RemoteXNativeJob]::new($memoryBytes, $cpuSeconds, $processCount)
    if (-not $job.Assigned) {
        throw "Unable to assign the RemoteX PowerShell process to a Windows Job Object. " +
            "Win32 error: $($job.LastError)"
    }
    $requestedShell = [string]$request.shell
    $actual = $requestedShell
    if ($requestedShell -eq 'auto') {
        $actual = if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) {
            'pwsh'
        } else {
            'powershell'
        }
    }
    $metadata = [ordered]@{
        remotePid = $PID
        interpreter = $actual
        jobObjectAssigned = [bool]$job.Assigned
        jobObjectError = [int]$job.LastError
    }
    [Console]::Error.WriteLine('__REMOTEX_META__' + ($metadata | ConvertTo-Json -Compress))
    if ($actual -eq 'powershell') {
        & ([ScriptBlock]::Create([string]$request.script))
        if ($null -ne $LASTEXITCODE) {
            exit [int]$LASTEXITCODE
        }
        exit 0
    }
    $extension = if ($actual -eq 'cmd') { '.cmd' } else { '.ps1' }
    $temp = Join-Path ([IO.Path]::GetTempPath()) (
        'remotex-' + [Guid]::NewGuid().ToString('N') + $extension
    )
    if ($actual -eq 'cmd') {
        $content = "@chcp 65001>nul`r`n" + [string]$request.script
        [IO.File]::WriteAllText($temp, $content, [Text.UTF8Encoding]::new($false))
        & cmd.exe /d /q /c $temp
    } else {
        $content = @'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Text.UTF8Encoding]::new($false)
'@ + "`r`n" + [string]$request.script
        [IO.File]::WriteAllText($temp, $content, [Text.UTF8Encoding]::new($true))
        & pwsh.exe -NoLogo -NoProfile -NonInteractive -File $temp
    }
    exit [int]$LASTEXITCODE
}
catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 1
}
finally {
    if ($null -ne $temp) {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $job) {
        $job.Dispose()
    }
}
""".strip()


def _strict_mode(value: Any) -> str:
    mode = legacy._strict_host_key_mode(value)
    if mode == "no":
        raise core.ToolError(
            "strict_host_key_checking=no is not supported; register or approve the host key"
        )
    return mode


def _host_key_policy(value: Any, strict_mode: str) -> str:
    policy = str(value or "known-hosts").strip().lower()
    if policy not in HOST_KEY_POLICIES:
        raise core.ToolError("host_key_policy must be known-hosts or managed")
    if policy == "managed" and strict_mode != "yes":
        raise core.ToolError(
            "host_key_policy=managed requires strict_host_key_checking=yes"
        )
    return policy


def connection_config(profile: Any = None) -> dict[str, Any]:
    cfg = legacy.connection_config(profile)
    name, raw, _ = core.select_profile("ssh", profile)
    strict_mode = _strict_mode(raw.get("strict_host_key_checking"))
    cfg["strict_host_key_checking"] = strict_mode
    cfg["host_key_policy"] = _host_key_policy(
        raw.get("host_key_policy"),
        strict_mode,
    )
    platform = str(raw.get("platform") or "auto").strip().lower()
    if platform not in SUPPORTED_PLATFORMS:
        raise core.ToolError("SSH platform must be auto, windows, or posix")
    cfg["platform"] = platform
    cfg["profile"] = name
    queue_resource = core._text(raw.get("queue_resource")).strip()
    if queue_resource:
        import vm_queue

        cfg["queue_resource"] = vm_queue._validate_resource(queue_resource)
    else:
        cfg["queue_resource"] = None
    return cfg


def _enforce_host_key(cfg: dict[str, Any], timeout: int) -> dict[str, Any]:
    _enforce_expected_public_key(cfg)
    import host_keys

    return host_keys.enforce(cfg, timeout)


@contextmanager
def queue_owner_operation(
    cfg: dict[str, Any],
    args: dict[str, Any],
):
    resource = cfg.get("queue_resource")
    if not resource:
        yield None
        return
    import queue_leases

    requester = core._required_text(args.get("requester"), "requester")
    with queue_leases.leased_owner_operation(resource, requester) as ownership:
        yield ownership


def profile_status(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    result = legacy.profile_status(name, raw)
    clients = {
        binary: core.executable_available(binary)
        for binary in ("ssh", "sftp", "scp", "ssh-add", "ssh-keygen", "ssh-keyscan")
    }
    result["clients"] = clients
    result["transfer_ready"] = clients["sftp"] or clients["scp"]
    result["host_key_scan_ready"] = clients["ssh-keyscan"] and clients["ssh-keygen"]
    platform = str(raw.get("platform") or "auto").strip().lower()
    result["platform"] = platform
    errors = [
        error
        for error in (result.get("errors") or [])
        if error != "one or more OpenSSH clients are unavailable"
    ]
    try:
        strict_mode = _strict_mode(raw.get("strict_host_key_checking"))
        result["host_key_policy"] = _host_key_policy(
            raw.get("host_key_policy"),
            strict_mode,
        )
        if platform not in SUPPORTED_PLATFORMS:
            raise core.ToolError("SSH platform must be auto, windows, or posix")
        queue_resource = core._text(raw.get("queue_resource")).strip()
        if queue_resource:
            import vm_queue

            result["queue_resource"] = vm_queue._validate_resource(
                queue_resource
            )
    except core.ToolError as exc:
        errors.append(str(exc))
    source = result.get("credential_source")
    if not clients["ssh"]:
        errors.append("ssh client is unavailable")
    if not result["transfer_ready"]:
        errors.append("neither sftp nor scp is available")
    if (
        result.get("host_key_policy") == "managed"
        and not result["host_key_scan_ready"]
    ):
        errors.append("managed host-key policy requires ssh-keyscan and ssh-keygen")
    if source == "ssh-agent":
        if not clients["ssh-add"]:
            errors.append("ssh-add client is unavailable for ssh-agent credentials")
        elif "ssh_agent_has_identities" not in result:
            outcome = core.run_process(
                [core.find_executable("ssh-add"), "-l"],
                timeout=15,
            )
            result["ssh_agent_has_identities"] = outcome["returncode"] == 0
            if not result["ssh_agent_has_identities"]:
                errors.append("ssh-agent has no available identities")
    result["client_available"] = (
        clients["ssh"]
        and result["transfer_ready"]
        and (source != "ssh-agent" or clients["ssh-add"])
    )
    result["ready"] = not errors
    result["errors"] = errors
    return result


def _public_key_evidence(cfg: dict[str, Any]) -> dict[str, Any] | None:
    if cfg["credential_source"] not in {"identity-file", "ssh-agent"}:
        return None
    identity_file = cfg.get("identity_file")
    if not identity_file:
        return {"state": "unavailable"}
    public_key_file = Path(f"{identity_file}.pub")
    try:
        lines = public_key_file.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {"state": "missing"}
    except (OSError, UnicodeError):
        return {"state": "unavailable"}
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        fields = value.split()
        if len(fields) < 2 or not SAFE_AUTH_METHOD.fullmatch(fields[0]):
            return {"state": "invalid"}
        try:
            public_key_blob = base64.b64decode(fields[1], validate=True)
        except (ValueError, binascii.Error):
            return {"state": "invalid"}
        if not public_key_blob:
            return {"state": "invalid"}
        fingerprint = base64.b64encode(
            hashlib.sha256(public_key_blob).digest()
        ).decode("ascii").rstrip("=")
        result = {
            "state": "available",
            "algorithm": fields[0],
            "fingerprint": f"SHA256:{fingerprint}",
        }
        expected = cfg.get("expected_public_key_sha256")
        if expected:
            result["expectedFingerprint"] = expected
            result["matchesExpected"] = result["fingerprint"] == expected
            if not result["matchesExpected"]:
                result["state"] = "mismatch"
        return result
    return {"state": "missing"}


def _enforce_expected_public_key(cfg: dict[str, Any]) -> None:
    expected = cfg.get("expected_public_key_sha256")
    if not expected:
        return
    evidence = _public_key_evidence(cfg)
    if not evidence or evidence.get("state") != "available":
        raise core.ToolError(
            "Configured SSH public-key fingerprint does not match the local identity"
        )


def _server_advertised_methods(stderr: str) -> list[str]:
    match = AUTHENTICATION_DENIED.search(stderr)
    methods = match.group("methods") if match else None
    if not methods:
        return []
    result: list[str] = []
    for raw_method in methods.split(","):
        method = raw_method.strip().lower()
        if method and SAFE_AUTH_METHOD.fullmatch(method) and method not in result:
            result.append(method)
    return result


def _authentication_evidence(cfg: dict[str, Any], outcome: dict[str, Any]) -> dict[str, Any]:
    authenticated = outcome["returncode"] == 0 and not outcome["timed_out"]
    result: dict[str, Any] = {
        "state": "authenticated" if authenticated else "not-verified",
        "verified": authenticated,
        "credentialSource": cfg["credential_source"],
        "passwordFallbackAllowed": False,
    }
    public_key = _public_key_evidence(cfg)
    if public_key is not None:
        result["publicKey"] = public_key
    if authenticated:
        return result
    if outcome["timed_out"]:
        result.update(
            {
                "failureCode": "connection-timeout",
                "nextStep": (
                    "Verify network reachability and host-key policy, then rerun "
                    "remotex_ssh_test."
                ),
            }
        )
        return result
    stderr = str(outcome.get("stderr") or "")
    if AUTHENTICATION_DENIED.search(stderr):
        if cfg["credential_source"] == "identity-file":
            failure_code = "configured-public-key-rejected"
            next_step = (
                "Authorize the configured public key on the target through an approved "
                "out-of-band channel, then rerun remotex_ssh_test. RemoteX does not fall "
                "back to password authentication."
            )
        else:
            failure_code = "ssh-agent-identity-rejected"
            next_step = (
                "Confirm the intended public key is loaded in the SSH agent and authorized "
                "on the target, then rerun remotex_ssh_test. RemoteX does not fall back to "
                "password authentication."
            )
        result.update(
            {
                "state": "rejected",
                "failureCode": failure_code,
                "serverAdvertisedMethods": _server_advertised_methods(stderr),
                "nextStep": next_step,
            }
        )
        return result
    result.update(
        {
            "failureCode": "ssh-connection-not-verified",
            "nextStep": (
                "Review the sanitized SSH stderr, verify the endpoint and host-key policy, "
                "then rerun remotex_ssh_test."
            ),
        }
    )
    return result


def _connection_result(
    cfg: dict[str, Any],
    outcome: dict[str, Any],
    *,
    authentication_attempt: bool = False,
) -> dict[str, Any]:
    result = {
        "ok": outcome["returncode"] == 0 and not outcome["timed_out"],
        "profile": cfg["profile"],
        "host": cfg["host"],
        "user": cfg["user"],
        "port": cfg["port"],
        "credentialSource": cfg["credential_source"],
        "exitCode": outcome["returncode"],
        "returncode": outcome["returncode"],
        "timedOut": outcome["timed_out"],
        "timed_out": outcome["timed_out"],
        "durationMs": outcome.get("duration_ms"),
        "localPid": outcome.get("process_id"),
        "stdout": outcome["stdout"],
        "stderr": outcome["stderr"],
        "stdoutBytes": outcome.get("stdout_bytes"),
        "stderrBytes": outcome.get("stderr_bytes"),
        "stdoutTruncated": outcome.get("stdout_truncated", False),
        "stderrTruncated": outcome.get("stderr_truncated", False),
        "stdoutEncoding": outcome.get("stdout_encoding"),
        "stderrEncoding": outcome.get("stderr_encoding"),
        "processTreeTerminated": outcome.get("process_tree_terminated", False),
        "terminatedProcessIds": outcome.get("terminated_process_ids", []),
        "terminationReason": outcome.get("termination_reason"),
        "peakMemoryBytes": outcome.get("peak_memory_bytes"),
        "resourceLimits": outcome.get("resource_limits"),
    }
    if authentication_attempt:
        result["authentication"] = _authentication_evidence(cfg, outcome)
    return result


def _limits(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "memoryMb": execution.optional_limit(
            args.get("memory_limit_mb"),
            "memory_limit_mb",
            minimum=16,
            maximum=execution.MAX_MEMORY_MB,
        ),
        "cpuSeconds": execution.optional_limit(
            args.get("cpu_time_seconds"),
            "cpu_time_seconds",
            minimum=1,
            maximum=core.MAX_TIMEOUT_SECONDS,
        ),
        "maxProcesses": execution.optional_limit(
            args.get("max_processes"),
            "max_processes",
            minimum=1,
            maximum=execution.MAX_PROCESS_COUNT,
        ),
    }


def _shell_for(args: dict[str, Any], cfg: dict[str, Any]) -> str:
    supplied = args.get("shell")
    shell = str(supplied or ("auto" if cfg["platform"] == "windows" else "sh")).strip().lower()
    if shell not in SUPPORTED_SHELLS:
        raise core.ToolError("shell must be auto, powershell, pwsh, cmd, sh, or bash")
    if shell in {"powershell", "pwsh", "cmd"} and cfg["platform"] == "posix":
        raise core.ToolError(f"shell={shell} conflicts with profile platform=posix")
    if shell in {"sh", "bash"} and cfg["platform"] == "windows":
        raise core.ToolError(f"shell={shell} conflicts with profile platform=windows")
    if shell == "auto" and cfg["platform"] == "posix":
        return "sh"
    return shell


def _encoded_powershell_command() -> str:
    return base64.b64encode(WINDOWS_WRAPPER.encode("utf-16-le")).decode("ascii")


def _shell_payload(
    shell: str,
    script: str,
    injections: list[execution.EnvironmentInjection],
    limits: dict[str, Any],
    timeout: int,
) -> bytes:
    lines = [str(len(injections))]
    for item in injections:
        value = base64.b64encode(item.value.encode("utf-8")).decode("ascii")
        lines.append(f"{item.remote_name}\t{value}")
    lines.extend(
        [
            base64.b64encode(script.encode("utf-8")).decode("ascii"),
            str(timeout),
            str(limits["memoryMb"] or 0),
            str(limits["cpuSeconds"] or 0),
            str(limits["maxProcesses"] or 0),
        ]
    )
    payload = "\n".join(lines)
    marker = "REMOTEX_PAYLOAD_8A4B5D74"
    wrapper = f"""set -eu
payload_file=$(mktemp "${{TMPDIR:-/tmp}}/remotex-payload.XXXXXX")
script_file=$(mktemp "${{TMPDIR:-/tmp}}/remotex-script.XXXXXX")
child_pid=
cleanup() {{
  if [ -n "${{child_pid:-}}" ] && kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "-$child_pid" 2>/dev/null || kill -TERM "$child_pid" 2>/dev/null || true
  fi
  rm -f "$payload_file" "$script_file"
}}
trap cleanup EXIT HUP INT TERM
cat >"$payload_file" <<'{marker}'
{payload}
{marker}
exec 3<"$payload_file"
IFS= read -r env_count <&3
i=0
while [ "$i" -lt "$env_count" ]; do
  IFS="$(printf '\\t')" read -r env_name env_value <&3
  decoded=$(printf '%s' "$env_value" | base64 -d)
  export "$env_name=$decoded"
  i=$((i + 1))
done
IFS= read -r script_b64 <&3
IFS= read -r wall_seconds <&3
IFS= read -r memory_mb <&3
IFS= read -r cpu_seconds <&3
IFS= read -r max_processes <&3
printf '%s' "$script_b64" | base64 -d >"$script_file"
chmod 700 "$script_file"
if [ "$memory_mb" -gt 0 ]; then ulimit -v $((memory_mb * 1024)); fi
if [ "$cpu_seconds" -gt 0 ]; then ulimit -t "$cpu_seconds"; fi
if [ "$max_processes" -gt 0 ]; then
  ulimit -u "$max_processes" 2>/dev/null || {{ printf '%s\n' 'max-process limit is unsupported' >&2; exit 125; }}
fi
interpreter={shlex.quote(shell)}
if ! command -v setsid >/dev/null 2>&1; then
  printf '%s\n' 'setsid is required for RemoteX process-tree isolation' >&2
  exit 125
fi
setsid "$interpreter" "$script_file" &
child_pid=$!
printf '{META_PREFIX}{{"remotePid":%s,"interpreter":"%s","processGroup":true}}\\n' "$child_pid" "$interpreter" >&2
(
  sleep "$wall_seconds"
  if kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "-$child_pid" 2>/dev/null || kill -TERM "$child_pid" 2>/dev/null || true
    sleep 2
    kill -KILL "-$child_pid" 2>/dev/null || kill -KILL "$child_pid" 2>/dev/null || true
  fi
) &
watcher=$!
set +e
wait "$child_pid"
status=$?
set -e
child_pid=
kill "$watcher" 2>/dev/null || true
wait "$watcher" 2>/dev/null || true
exit "$status"
"""
    return wrapper.encode("utf-8")


def prepare_script(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    script = core._text(args.get("script"))
    if not script.strip():
        raise core.ToolError("script is required")
    if "\x00" in script:
        raise core.ToolError("script must not contain NUL characters")
    if len(script) > core.MAX_SCRIPT_LENGTH:
        raise core.ToolError(f"script exceeds {core.MAX_SCRIPT_LENGTH} characters")
    shell = _shell_for(args, cfg)
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    _enforce_host_key(cfg, timeout)
    injections = execution.resolve_environment_refs(args.get("environment_refs"))
    limits = _limits(args)
    if shell in {"auto", "powershell", "pwsh", "cmd"}:
        envelope = {
            "shell": shell,
            "script": script,
            "environment": {item.remote_name: item.value for item in injections},
            "limits": limits,
        }
        input_bytes = base64.b64encode(
            json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        remote_command = (
            "powershell.exe -NoLogo -NoProfile -NonInteractive "
            f"-EncodedCommand {_encoded_powershell_command()}"
        )
    else:
        input_bytes = _shell_payload(shell, script, injections, limits, timeout)
        remote_command = "sh -s"
    return {
        "cfg": cfg,
        "shell": shell,
        "timeout": timeout,
        "argv": legacy.ssh_arguments(cfg, timeout, remote_command),
        "input_bytes": input_bytes,
        "injections": injections,
        "secrets": [item.value for item in injections if item.secret],
        "limits": limits,
        "max_stdout_bytes": execution.byte_limit(
            args.get("max_stdout_bytes"),
            execution.DEFAULT_MAX_OUTPUT_BYTES,
            "max_stdout_bytes",
        ),
        "max_stderr_bytes": execution.byte_limit(
            args.get("max_stderr_bytes"),
            execution.DEFAULT_MAX_OUTPUT_BYTES,
            "max_stderr_bytes",
        ),
        "output_encoding": str(args.get("output_encoding") or "utf-8"),
    }


def _extract_metadata(stderr: str) -> tuple[str, dict[str, Any]]:
    metadata: dict[str, Any] = {}
    kept: list[str] = []
    for line in stderr.splitlines(keepends=True):
        plain = line.rstrip("\r\n")
        if plain.startswith(META_PREFIX):
            try:
                value = json.loads(plain[len(META_PREFIX) :])
                if isinstance(value, dict):
                    metadata.update(value)
                    continue
            except json.JSONDecodeError:
                pass
        kept.append(line)
    return "".join(kept), metadata


def finalize_script(
    prepared: dict[str, Any],
    outcome: dict[str, Any],
) -> dict[str, Any]:
    result = _connection_result(prepared["cfg"], outcome)
    clean_stderr, metadata = _extract_metadata(result["stderr"])
    result["stderr"] = clean_stderr
    result["requestedShell"] = prepared["shell"]
    result["interpreter"] = metadata.get("interpreter") or prepared["shell"]
    result["remotePid"] = metadata.get("remotePid")
    result["remoteProcessGroup"] = metadata.get("processGroup")
    result["remoteJobObjectAssigned"] = metadata.get("jobObjectAssigned")
    result["remoteJobObjectError"] = metadata.get("jobObjectError")
    result["environmentInjections"] = [
        item.public() for item in prepared["injections"]
    ]
    result["scriptSha256"] = hashlib.sha256(
        core._text(prepared.get("script_for_hash", "")).encode("utf-8")
    ).hexdigest() if "script_for_hash" in prepared else None
    return result


def _run_prepared_script(prepared: dict[str, Any]) -> dict[str, Any]:
    outcome = execution.run_process(
        prepared["argv"],
        timeout=prepared["timeout"],
        input_bytes=prepared["input_bytes"],
        max_stdout_bytes=prepared["max_stdout_bytes"],
        max_stderr_bytes=prepared["max_stderr_bytes"],
        output_encoding=prepared["output_encoding"],
        secrets=prepared["secrets"],
        memory_limit_mb=prepared["limits"]["memoryMb"],
        cpu_time_seconds=prepared["limits"]["cpuSeconds"],
        max_processes=prepared["limits"]["maxProcesses"],
        terminate_on_output_limit=True,
    )
    return finalize_script(prepared, outcome)


def _execute_script_unqueued(args: dict[str, Any]) -> dict[str, Any]:
    prepared = prepare_script(args)
    prepared["script_for_hash"] = core._text(args.get("script"))
    return _run_prepared_script(prepared)


def execute_script(args: dict[str, Any]) -> dict[str, Any]:
    prepared = prepare_script(args)
    prepared["script_for_hash"] = core._text(args.get("script"))
    with queue_owner_operation(prepared["cfg"], args):
        return _run_prepared_script(prepared)


def test_connection(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), cfg["connect_timeout_seconds"])
    _enforce_host_key(cfg, timeout)
    outcome = execution.run_process(
        legacy.ssh_arguments(cfg, timeout, "hostname"),
        timeout=timeout,
    )
    result = _connection_result(cfg, outcome, authentication_attempt=True)
    if result["authentication"].get("verified"):
        try:
            authentication_evidence.record_verified(
                cfg["profile"],
                cfg["credential_source"],
                f"{cfg['host']}:{cfg['port']}",
            )
            result["authenticationEvidenceRecorded"] = True
        except core.ToolError:
            result["authenticationEvidenceRecorded"] = False
            result["authenticationEvidenceFailureCode"] = (
                "local-authentication-evidence-unavailable"
            )
    return core.tool_result(result)


def run_command(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    command = core._required_text(args.get("command"), "command")
    if len(command) > core.MAX_COMMAND_LENGTH:
        raise core.ToolError(
            f"command exceeds {core.MAX_COMMAND_LENGTH} characters; use remotex_ssh_run_script"
        )
    if "\r" in command or "\n" in command:
        raise core.ToolError("command must be one line; use remotex_ssh_run_script")
    if args.get("environment_refs"):
        raise core.ToolError("environment_refs require remotex_ssh_run_script")
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    _enforce_host_key(cfg, timeout)
    with queue_owner_operation(cfg, args):
        outcome = execution.run_process(
            legacy.ssh_arguments(cfg, timeout, command),
            timeout=timeout,
            max_stdout_bytes=execution.byte_limit(
                args.get("max_stdout_bytes"),
                execution.DEFAULT_MAX_OUTPUT_BYTES,
                "max_stdout_bytes",
            ),
            max_stderr_bytes=execution.byte_limit(
                args.get("max_stderr_bytes"),
                execution.DEFAULT_MAX_OUTPUT_BYTES,
                "max_stderr_bytes",
            ),
            output_encoding=str(args.get("output_encoding") or "auto"),
        )
    return core.tool_result(_connection_result(cfg, outcome))


def run_script(args: dict[str, Any]) -> dict[str, Any]:
    return core.tool_result(execute_script(args))


def _local_source(value: Any) -> Path:
    path = core.expand_path(value, "local_path")
    if not path.exists():
        raise core.ToolError(f"local_path does not exist: {path}")
    if path.is_symlink():
        raise core.ToolError(f"local_path must not be a symlink: {path}")
    return path


def _local_destination(value: Any) -> Path:
    path = core.expand_path(value, "local_path")
    if path.exists() and path.is_symlink():
        raise core.ToolError(f"local_path must not be a symlink: {path}")
    if not path.parent.is_dir():
        raise core.ToolError(f"local_path parent directory does not exist: {path.parent}")
    return path


def _sftp_path(path: str) -> str:
    if "\x00" in path or "\r" in path or "\n" in path:
        raise core.ToolError("transfer paths must not contain NUL or newline characters")
    normalized = path.replace("\\", "/")
    if '"' in normalized:
        normalized = normalized.replace('"', '\\"')
    return f'"{normalized}"'


def sftp_arguments(cfg: dict[str, Any], timeout: int) -> list[str]:
    args = [core.find_executable("sftp"), "-q", "-b", "-"]
    args.extend(legacy._common_options(cfg, timeout))
    args.extend(["-P", str(cfg["port"]), f"{cfg['user']}@{cfg['host']}"])
    return args


def _scp_spec(cfg: dict[str, Any], path: str) -> str:
    if not SAFE_SCP_PATH.fullmatch(path):
        raise core.ToolError(
            "sftp is unavailable and this path cannot be transferred safely with scp fallback"
        )
    host = cfg["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{cfg['user']}@{host}:{path}"


def _local_integrity(path: Path) -> dict[str, Any]:
    if path.is_file():
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
        return {
            "exists": True,
            "kind": "file",
            "bytes": size,
            "sha256": digest.hexdigest(),
            "entryCount": 1,
            "actualPath": str(path.resolve()),
        }
    lines: list[str] = []
    total = 0
    count = 0
    for item in path.rglob("*"):
        relative = item.relative_to(path).as_posix()
        if item.is_dir():
            lines.append(f"D\x00{relative}\n")
            count += 1
        elif item.is_file():
            info = _local_integrity(item)
            total += int(info["bytes"])
            count += 1
            lines.append(
                f"F\x00{relative}\x00{info['bytes']}\x00{info['sha256']}\n"
            )
    lines.sort()
    manifest = "".join(lines).encode("utf-8")
    return {
        "exists": True,
        "kind": "directory",
        "bytes": total,
        "sha256": hashlib.sha256(manifest).hexdigest(),
        "entryCount": count,
        "actualPath": str(path.resolve()),
    }


def _platform_for(cfg: dict[str, Any], remote_path: str) -> str:
    if cfg["platform"] in {"windows", "posix"}:
        return cfg["platform"]
    return "windows" if WINDOWS_DRIVE_PATH.match(remote_path) else "posix"


def _remote_integrity(cfg: dict[str, Any], remote_path: str, timeout: int) -> dict[str, Any]:
    encoded_path = base64.b64encode(remote_path.encode("utf-8")).decode("ascii")
    platform = _platform_for(cfg, remote_path)
    if platform == "windows":
        script = rf"""
$ErrorActionPreference = 'Stop'
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_path}'))
if (-not (Test-Path -LiteralPath $p)) {{
    [pscustomobject]@{{ exists = $false; requestedPath = $p }} | ConvertTo-Json -Compress
    exit 0
}}
$item = Get-Item -LiteralPath $p -Force
if (-not $item.PSIsContainer) {{
    [pscustomobject]@{{
        exists = $true
        kind = 'file'
        bytes = [long]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        entryCount = 1
        actualPath = $item.FullName
    }} | ConvertTo-Json -Compress
    exit 0
}}
$root = $item.FullName.TrimEnd('\')
$lines = [Collections.Generic.List[string]]::new()
$total = [long]0
$count = 0
foreach ($child in @(Get-ChildItem -LiteralPath $root -Force -Recurse)) {{
    $relative = $child.FullName.Substring($root.Length).TrimStart('\').Replace('\', '/')
    if ($child.PSIsContainer) {{
        $lines.Add("D`0$relative`n")
    }} else {{
        $hash = (Get-FileHash -LiteralPath $child.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines.Add("F`0$relative`0$($child.Length)`0$hash`n")
        $total += [long]$child.Length
    }}
    $count++
}}
$ordered = $lines.ToArray()
[Array]::Sort($ordered, [StringComparer]::Ordinal)
$manifest = [Text.Encoding]::UTF8.GetBytes(($ordered -join ''))
$algorithm = [Security.Cryptography.SHA256]::Create()
try {{ $digest = $algorithm.ComputeHash($manifest) }} finally {{ $algorithm.Dispose() }}
$sha = ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
[pscustomobject]@{{
    exists = $true
    kind = 'directory'
    bytes = $total
    sha256 = $sha
    entryCount = $count
    actualPath = $root
}} | ConvertTo-Json -Compress
""".strip()
        result = _execute_script_unqueued(
            {
                "profile": cfg["profile"],
                "shell": "powershell",
                "script": script,
                "timeout_seconds": timeout,
                "max_stdout_bytes": 1024 * 1024,
            }
        )
    else:
        python = rf"""
import base64, hashlib, json, os
p = base64.b64decode("{encoded_path}").decode("utf-8")
if not os.path.exists(p):
    print(json.dumps({{"exists": False, "requestedPath": p}}))
elif os.path.isfile(p):
    h = hashlib.sha256()
    size = 0
    with open(p, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    print(json.dumps({{
        "exists": True, "kind": "file", "bytes": size,
        "sha256": h.hexdigest(), "entryCount": 1,
        "actualPath": os.path.realpath(p)
    }}))
else:
    lines = []
    total = 0
    count = 0
    for root, dirs, files in os.walk(p):
        dirs.sort()
        files.sort()
        for name in dirs:
            rel = os.path.relpath(os.path.join(root, name), p).replace(os.sep, "/")
            lines.append("D\\0" + rel + "\\n")
            count += 1
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, p).replace(os.sep, "/")
            h = hashlib.sha256()
            size = 0
            with open(full, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    h.update(chunk)
            lines.append("F\\0%s\\0%d\\0%s\\n" % (rel, size, h.hexdigest()))
            total += size
            count += 1
    manifest = "".join(sorted(lines)).encode("utf-8")
    print(json.dumps({{
        "exists": True, "kind": "directory", "bytes": total,
        "sha256": hashlib.sha256(manifest).hexdigest(),
        "entryCount": count, "actualPath": os.path.realpath(p)
    }}))
""".strip()
        shell_script = (
            "python3 - <<'REMOTEX_PY'\n"
            + python
            + "\nREMOTEX_PY"
        )
        result = _execute_script_unqueued(
            {
                "profile": cfg["profile"],
                "shell": "sh",
                "script": shell_script,
                "timeout_seconds": timeout,
                "max_stdout_bytes": 1024 * 1024,
            }
        )
    if not result["ok"]:
        raise core.ToolError(
            f"Unable to inspect remote path: {result['stderr'] or result['stdout']}"
        )
    candidates = [line for line in result["stdout"].splitlines() if line.strip()]
    if not candidates:
        raise core.ToolError("Remote path inspection returned no JSON")
    try:
        payload = json.loads(candidates[-1])
    except json.JSONDecodeError as exc:
        raise core.ToolError("Remote path inspection returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise core.ToolError("Remote path inspection returned a non-object")
    return payload


def _verify_integrity(
    verify: str,
    local: dict[str, Any],
    remote: dict[str, Any],
) -> bool | None:
    if verify == "none":
        return None
    if not remote.get("exists"):
        return False
    if verify == "size":
        return (
            local.get("kind") == remote.get("kind")
            and int(local.get("bytes", -1)) == int(remote.get("bytes", -2))
            and int(local.get("entryCount", -1)) == int(remote.get("entryCount", -2))
        )
    return (
        local.get("kind") == remote.get("kind")
        and local.get("sha256") == remote.get("sha256")
        and int(local.get("entryCount", -1)) == int(remote.get("entryCount", -2))
    )


def _transfer_options(args: dict[str, Any]) -> tuple[str, str]:
    verify = str(args.get("verify") or "sha256").strip().lower()
    overwrite = str(args.get("overwrite") or "replace").strip().lower()
    if verify not in {"none", "size", "sha256"}:
        raise core.ToolError("verify must be none, size, or sha256")
    if overwrite not in {"fail", "replace", "resume"}:
        raise core.ToolError("overwrite must be fail, replace, or resume")
    return verify, overwrite


def _run_sftp(
    cfg: dict[str, Any],
    timeout: int,
    batch: str,
) -> dict[str, Any]:
    return execution.run_process(
        sftp_arguments(cfg, timeout),
        timeout=timeout,
        input_bytes=(batch + "\n").encode("utf-8"),
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=1024 * 1024,
        output_encoding="utf-8",
    )


def copy_to(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    with queue_owner_operation(cfg, args):
        return _copy_to_owned(args, cfg)


def _copy_to_owned(
    args: dict[str, Any],
    cfg: dict[str, Any],
) -> dict[str, Any]:
    local_path = _local_source(args.get("local_path"))
    recursive = core.as_bool(args.get("recursive"), False)
    if local_path.is_dir() and not recursive:
        raise core.ToolError("local_path is a directory; set recursive=true to copy it")
    remote_path = core.validate_selector(args.get("remote_path"), "remote_path")
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    verify, overwrite = _transfer_options(args)
    _enforce_host_key(cfg, timeout)
    before = _remote_integrity(cfg, remote_path, timeout)
    if overwrite == "fail" and before.get("exists"):
        raise core.ToolError(f"remote_path already exists: {remote_path}")
    if overwrite == "resume" and local_path.is_dir():
        raise core.ToolError("overwrite=resume supports files only")
    local_info = _local_integrity(local_path)
    protocol = "sftp"
    if core.executable_available("sftp"):
        flags = []
        if recursive:
            flags.append("-r")
        if overwrite == "resume":
            flags.append("-a")
        command = "put"
        batch = " ".join(
            [command, *flags, _sftp_path(str(local_path)), _sftp_path(remote_path)]
        )
        outcome = _run_sftp(cfg, timeout, batch)
    else:
        protocol = "scp"
        argv = legacy.scp_arguments(cfg, timeout)
        if recursive:
            argv.append("-r")
        argv.extend([str(local_path), _scp_spec(cfg, remote_path)])
        outcome = execution.run_process(argv, timeout=timeout)
    result = _connection_result(cfg, outcome)
    if not result["ok"]:
        return core.tool_result({**result, "protocol": protocol})
    remote_info = _remote_integrity(cfg, remote_path, timeout)
    matched = _verify_integrity(verify, local_info, remote_info)
    if matched is False:
        raise core.ToolError("transfer completed but requested integrity verification failed")
    return core.tool_result(
        {
            **result,
            "direction": "local-to-remote",
            "protocol": protocol,
            "requestedLocalPath": str(local_path),
            "actualLocalPath": local_info["actualPath"],
            "requestedRemotePath": remote_path,
            "actualRemotePath": remote_info.get("actualPath"),
            "localBytes": local_info["bytes"],
            "remoteBytes": remote_info.get("bytes"),
            "localSha256": local_info["sha256"],
            "remoteSha256": remote_info.get("sha256"),
            "integrityMode": verify,
            "integrityMatched": matched,
            "overwrite": overwrite,
            "bytesTransferred": local_info["bytes"],
            "retryCount": 0,
        }
    )


def copy_from(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    with queue_owner_operation(cfg, args):
        return _copy_from_owned(args, cfg)


def _copy_from_owned(
    args: dict[str, Any],
    cfg: dict[str, Any],
) -> dict[str, Any]:
    remote_path = core.validate_selector(args.get("remote_path"), "remote_path")
    local_path = _local_destination(args.get("local_path"))
    recursive = core.as_bool(args.get("recursive"), False)
    timeout = core.validate_timeout(args.get("timeout_seconds"), core.DEFAULT_COMMAND_TIMEOUT_SECONDS)
    verify, overwrite = _transfer_options(args)
    _enforce_host_key(cfg, timeout)
    remote_info = _remote_integrity(cfg, remote_path, timeout)
    if not remote_info.get("exists"):
        raise core.ToolError(f"remote_path does not exist: {remote_path}")
    if remote_info.get("kind") == "directory" and not recursive:
        raise core.ToolError("remote_path is a directory; set recursive=true to copy it")
    if overwrite == "fail" and local_path.exists():
        raise core.ToolError(f"local_path already exists: {local_path}")
    if overwrite == "resume" and remote_info.get("kind") != "file":
        raise core.ToolError("overwrite=resume supports files only")
    protocol = "sftp"
    if core.executable_available("sftp"):
        flags = []
        if recursive:
            flags.append("-r")
        if overwrite == "resume":
            flags.append("-a")
        batch = " ".join(
            ["get", *flags, _sftp_path(remote_path), _sftp_path(str(local_path))]
        )
        outcome = _run_sftp(cfg, timeout, batch)
    else:
        protocol = "scp"
        argv = legacy.scp_arguments(cfg, timeout)
        if recursive:
            argv.append("-r")
        argv.extend([_scp_spec(cfg, remote_path), str(local_path)])
        outcome = execution.run_process(argv, timeout=timeout)
    result = _connection_result(cfg, outcome)
    if not result["ok"]:
        return core.tool_result({**result, "protocol": protocol})
    if not local_path.exists():
        raise core.ToolError("transfer reported success but local_path was not created")
    local_info = _local_integrity(local_path)
    matched = _verify_integrity(verify, local_info, remote_info)
    if matched is False:
        raise core.ToolError("transfer completed but requested integrity verification failed")
    return core.tool_result(
        {
            **result,
            "direction": "remote-to-local",
            "protocol": protocol,
            "requestedRemotePath": remote_path,
            "actualRemotePath": remote_info.get("actualPath"),
            "requestedLocalPath": str(local_path),
            "actualLocalPath": local_info["actualPath"],
            "remoteBytes": remote_info.get("bytes"),
            "localBytes": local_info["bytes"],
            "remoteSha256": remote_info.get("sha256"),
            "localSha256": local_info["sha256"],
            "integrityMode": verify,
            "integrityMatched": matched,
            "overwrite": overwrite,
            "bytesTransferred": local_info["bytes"],
            "retryCount": 0,
        }
    )


COMMON_PROFILE = {
    "profile": {
        "type": "string",
        "description": "Optional SSH profile name from the RemoteX config.",
    }
}
COMMON_TIMEOUT = {
    "timeout_seconds": {
        "type": "integer",
        "minimum": 1,
        "maximum": core.MAX_TIMEOUT_SECONDS,
    }
}
OUTPUT_PROPERTIES = {
    "max_stdout_bytes": {
        "type": "integer",
        "minimum": 1,
        "maximum": execution.MAX_OUTPUT_BYTES,
    },
    "max_stderr_bytes": {
        "type": "integer",
        "minimum": 1,
        "maximum": execution.MAX_OUTPUT_BYTES,
    },
    "output_encoding": {"type": "string"},
}
RESOURCE_PROPERTIES = {
    "memory_limit_mb": {
        "type": "integer",
        "minimum": 16,
        "maximum": execution.MAX_MEMORY_MB,
    },
    "cpu_time_seconds": {
        "type": "integer",
        "minimum": 1,
        "maximum": core.MAX_TIMEOUT_SECONDS,
    },
    "max_processes": {
        "type": "integer",
        "minimum": 1,
        "maximum": execution.MAX_PROCESS_COUNT,
    },
}
ENVIRONMENT_REFS = {
    "environment_refs": {
        "type": "object",
        "description": (
            "Map remote environment names to local environment-variable or "
            "Windows Credential Manager references. Values are injected over SSH stdin."
        ),
        "additionalProperties": {
            "anyOf": [
                {"type": "string"},
                {
                    "type": "object",
                    "properties": {
                        "source": {
                            "type": "string",
                            "enum": ["environment", "windows-credential-manager"],
                        },
                        "name": {"type": "string"},
                        "target": {"type": "string"},
                        "field": {"type": "string", "enum": ["username", "password"]},
                        "secret": {"type": "boolean"},
                    },
                    "additionalProperties": False,
                },
            ]
        },
    }
}
TRANSFER_PROPERTIES = {
    "recursive": {"type": "boolean"},
    "verify": {"type": "string", "enum": ["none", "size", "sha256"]},
    "overwrite": {"type": "string", "enum": ["fail", "replace", "resume"]},
}
REQUESTER_PROPERTY = {
    "requester": {
        "type": "string",
        "description": (
            "Required queue owner when the SSH profile declares queue_resource."
        ),
    }
}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_ssh_test": {
        "description": (
            "Test a configured SSH profile with strict host-key and public-key-only defaults, "
            "returning server-side authentication evidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT},
            "additionalProperties": False,
        },
        "handler": test_connection,
    },
    "remotex_ssh_run_command": {
        "description": "Run one explicit command with bounded byte-safe output capture.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                **OUTPUT_PROPERTIES,
                **REQUESTER_PROPERTY,
                "command": {"type": "string"},
            },
            "required": ["command"],
            "additionalProperties": False,
        },
        "handler": run_command,
    },
    "remotex_ssh_run_script": {
        "description": (
            "Run PowerShell, pwsh, cmd, sh, or bash through SSH stdin with structured "
            "exit, encoding, truncation, PID, and resource-limit results."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                **OUTPUT_PROPERTIES,
                **RESOURCE_PROPERTIES,
                **ENVIRONMENT_REFS,
                **REQUESTER_PROPERTY,
                "shell": {"type": "string", "enum": sorted(SUPPORTED_SHELLS)},
                "script": {"type": "string"},
            },
            "required": ["script"],
            "additionalProperties": False,
        },
        "handler": run_script,
    },
    "remotex_ssh_copy_to": {
        "description": (
            "Copy to an SSH host with SFTP-first path-safe transfer and optional "
            "size or SHA-256 verification."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                **TRANSFER_PROPERTIES,
                **REQUESTER_PROPERTY,
                "local_path": {"type": "string"},
                "remote_path": {"type": "string"},
            },
            "required": ["local_path", "remote_path"],
            "additionalProperties": False,
        },
        "handler": copy_to,
    },
    "remotex_ssh_copy_from": {
        "description": (
            "Copy from an SSH host with SFTP-first path-safe transfer and optional "
            "size or SHA-256 verification."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_PROFILE,
                **COMMON_TIMEOUT,
                **TRANSFER_PROPERTIES,
                **REQUESTER_PROPERTY,
                "remote_path": {"type": "string"},
                "local_path": {"type": "string"},
            },
            "required": ["remote_path", "local_path"],
            "additionalProperties": False,
        },
        "handler": copy_from,
    },
    "remotex_ssh_agent_list": legacy.TOOLS["remotex_ssh_agent_list"],
    "remotex_ssh_agent_add": legacy.TOOLS["remotex_ssh_agent_add"],
    "remotex_ssh_agent_remove": legacy.TOOLS["remotex_ssh_agent_remove"],
    "remotex_ssh_key_fingerprint": legacy.TOOLS["remotex_ssh_key_fingerprint"],
}
