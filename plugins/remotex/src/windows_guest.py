from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Iterator

import credential_store
import execution
import remotex_core as core
import vm_identity
import vm_queue


RECEIPT_SCHEMA = "RemoteXWindowsGuestPreflight/v1"
OPERATION_SCHEMA = "RemoteXWindowsGuestOperation/v1"
RECEIPT_STATE_SCHEMA = "RemoteXWindowsGuestReceiptState/v1"
DEFAULT_PORT = 5985
DEFAULT_RECEIPT_AGE_SECONDS = 900
MAX_RECEIPT_AGE_SECONDS = 86_400
MAX_GUEST_COPY_BYTES = 8 * 1024 * 1024
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
KB_PATTERN = re.compile(r"^KB[0-9]{4,12}$", re.IGNORECASE)
ITEM_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


LOCAL_WINRM_WRAPPER = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function ConvertFrom-RemoteXBase64([string]$Value) {
  return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Value))
}
$inputText = [Console]::In.ReadToEnd().TrimEnd([char[]]"`r`n")
$parts = $inputText -split "`r?`n"
if ($parts.Count -ne 5) { throw 'RemoteX WinRM input envelope is invalid' }
$remoteComputer = ConvertFrom-RemoteXBase64 $parts[0]
$remotePort = [int](ConvertFrom-RemoteXBase64 $parts[1])
$authMode = ConvertFrom-RemoteXBase64 $parts[2]
$username = ConvertFrom-RemoteXBase64 $parts[3]
$passwordAndScript = ConvertFrom-RemoteXBase64 $parts[4]
$separator = [char]0
$separatorIndex = $passwordAndScript.IndexOf($separator)
if ($separatorIndex -lt 0) { throw 'RemoteX WinRM credential envelope is invalid' }
$password = $passwordAndScript.Substring(0, $separatorIndex)
$remoteScript = $passwordAndScript.Substring($separatorIndex + 1)
$sessionArgs = @{ ComputerName = $remoteComputer; Port = $remotePort; Authentication = $authMode; ErrorAction = 'Stop' }
if ($username.Length -gt 0) {
  $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
  $sessionArgs['Credential'] = New-Object System.Management.Automation.PSCredential($username, $securePassword)
}
$session = $null
try {
  $session = New-PSSession @sessionArgs
  $scriptBlock = [ScriptBlock]::Create($remoteScript)
  $records = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ErrorAction Stop
  foreach ($record in @($records)) {
    if ($null -ne $record) { [Console]::Out.WriteLine([string]$record) }
  }
}
finally {
  if ($null -ne $session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
}
""".strip()

IDENTITY_SCRIPT = r"""
$os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
if ([string]::IsNullOrEmpty($env:COMPUTERNAME)) { throw 'Guest machine identifier is unavailable' }
Write-Output ('REMOTEX_IDENTITY|' + $env:COMPUTERNAME + '|' + $os.LastBootUpTime)
""".strip()

REBOOT_SCRIPT = r"""
Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r', '/t', '0', '/f' -WindowStyle Hidden
Write-Output 'REMOTEX_REBOOT_ACCEPTED|1'
""".strip()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_receipt(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _from_b64(value: str, field: str) -> str:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise core.ToolError(f"Invalid base64 guest receipt field: {field}") from exc


def _encoded_wrapper() -> str:
    return base64.b64encode(LOCAL_WINRM_WRAPPER.encode("utf-16-le")).decode("ascii")


def _receipt_path() -> Path:
    configured = os.environ.get("REMOTEX_GUEST_RECEIPT_FILE")
    if configured:
        return core.expand_path(configured, "REMOTEX_GUEST_RECEIPT_FILE")
    return vm_queue.queue_path().with_name("windows-guest-receipts.json")


@contextmanager
def _locked_receipts() -> Iterator[dict[str, Any]]:
    path = _receipt_path()
    lock_path = path.with_name(f"{path.name}.lock")
    with vm_queue._exclusive_lock(lock_path, "Windows guest receipt"):
        yield _load_receipts()


def _empty_receipts() -> dict[str, Any]:
    return {"schema": RECEIPT_STATE_SCHEMA, "receipts": {}}


def _load_receipts() -> dict[str, Any]:
    path = _receipt_path()
    if not path.exists():
        return _empty_receipts()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError(f"Guest receipt state is unreadable: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != RECEIPT_STATE_SCHEMA:
        raise core.ToolError(f"Guest receipt state has an unsupported format: {path}")
    if not isinstance(value.get("receipts"), dict):
        raise core.ToolError(f"Guest receipt state has invalid receipts: {path}")
    return value


def _write_receipts(value: dict[str, Any]) -> None:
    path = _receipt_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except OSError as exc:
        raise core.ToolError(f"Unable to persist guest receipt state at {path}: {exc}") from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _run_id(value: Any) -> str:
    run_id = core._required_text(value, "run_id")
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise core.ToolError(
            "run_id must use 1-128 ASCII letters, digits, dots, underscores, colons, or hyphens"
        )
    return run_id


def _safe_item(value: Any, field: str) -> str:
    item = core._required_text(value, field)
    if not ITEM_PATTERN.fullmatch(item):
        raise core.ToolError(f"{field} must use 1-128 ASCII letters, digits, dots, underscores, or hyphens")
    return item


def _item_list(value: Any, field: str) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list):
        raise core.ToolError(f"{field} must be an array")
    if len(value) > 64:
        raise core.ToolError(f"{field} may contain at most 64 items")
    return [_safe_item(item, f"{field} item") for item in value]


def _version(value: Any, field: str, *, default: str | None = None) -> str | None:
    if value in (None, ""):
        return default
    text = core._required_text(value, field)
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", text):
        raise core.ToolError(f"{field} must be a dotted numeric version")
    return text


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _policy(value: Any) -> dict[str, Any]:
    if value in (None, {}):
        value = {}
    if not isinstance(value, dict):
        raise core.ToolError("policy must be an object")
    required_kbs = _item_list(value.get("required_kbs"), "policy.required_kbs")
    for kb in required_kbs:
        if not KB_PATTERN.fullmatch(kb):
            raise core.ToolError("policy.required_kbs must use KB followed by digits")
    try:
        minimum_dotnet = int(value.get("minimum_dotnet_release", 0))
        minimum_free = int(value.get("minimum_free_system_drive_bytes", 0))
        max_age = int(value.get("max_receipt_age_seconds", DEFAULT_RECEIPT_AGE_SECONDS))
    except (TypeError, ValueError) as exc:
        raise core.ToolError("policy numeric values must be integers") from exc
    if minimum_dotnet < 0 or minimum_free < 0:
        raise core.ToolError("policy numeric minimums must not be negative")
    if not 60 <= max_age <= MAX_RECEIPT_AGE_SECONDS:
        raise core.ToolError(
            f"policy.max_receipt_age_seconds must be between 60 and {MAX_RECEIPT_AGE_SECONDS}"
        )
    architecture = value.get("required_architecture")
    if architecture not in (None, "", "x86", "x64"):
        raise core.ToolError("policy.required_architecture must be x86 or x64")
    return {
        "minimumOsVersion": _version(value.get("minimum_os_version"), "policy.minimum_os_version"),
        "minimumPowerShellVersion": _version(
            value.get("minimum_powershell_version"),
            "policy.minimum_powershell_version",
        ),
        "minimumDotNetRelease": minimum_dotnet,
        "requiredKbs": [kb.upper() for kb in required_kbs],
        "requiredCmdlets": _item_list(value.get("required_cmdlets"), "policy.required_cmdlets"),
        "requiredArchitecture": architecture or None,
        "minimumFreeSystemDriveBytes": minimum_free,
        "inactiveProcesses": _item_list(value.get("inactive_processes"), "policy.inactive_processes"),
        "inactiveServices": _item_list(value.get("inactive_services"), "policy.inactive_services"),
        "inactiveDrivers": _item_list(value.get("inactive_drivers"), "policy.inactive_drivers"),
        "inactiveEtwSessions": _item_list(value.get("inactive_etw_sessions"), "policy.inactive_etw_sessions"),
        "maxReceiptAgeSeconds": max_age,
    }


def _credential_status(credential: Any) -> dict[str, Any]:
    if not isinstance(credential, dict):
        return {"source": None, "ready": False, "reason": "credential reference is missing"}
    source = str(credential.get("source") or "").strip().lower()
    if source == "windows-integrated":
        return {
            "source": source,
            "ready": os.name == "nt",
            "reason": None if os.name == "nt" else "Windows integrated authentication requires Windows",
        }
    if source != "windows-credential-manager":
        return {
            "source": source or None,
            "ready": False,
            "reason": "Windows guest credentials must use windows-integrated or windows-credential-manager",
        }
    status = core.credential_status(credential)
    return {
        "source": source,
        "target": status.get("target"),
        "ready": bool(status.get("ready")),
        "reason": status.get("reason"),
    }


def _staging_root(value: Any) -> str:
    root = core._required_text(value, "staging_root")
    path = PureWindowsPath(root)
    if not path.is_absolute() or any(part == ".." for part in path.parts):
        raise core.ToolError("staging_root must be an absolute Windows path without traversal")
    return str(path)


def _verify_bound_vmx(bundle: core.ConfigBundle, identity: dict[str, Any]) -> Path:
    return vm_identity.verify_bound_vmx(identity, bundle)


def connection_config(profile: Any = None) -> dict[str, Any]:
    name, raw, bundle = core.select_profile("windows-guest", profile)
    transport = str(raw.get("transport") or "winrm").strip().lower()
    if transport != "winrm":
        raise core.ToolError("Windows guest transport must be winrm")
    authentication = str(raw.get("authentication") or "kerberos").strip().lower()
    if authentication not in {"kerberos", "negotiate"}:
        raise core.ToolError("Windows guest authentication must be kerberos or negotiate")
    resolved_credential = credential_store.resolve_profile_reference(
        bundle,
        name,
        raw,
        "windows-guest",
    )
    credential = resolved_credential.reference_dict()
    credential_state = _credential_status(credential)
    if not credential_state.get("ready"):
        raise core.ToolError(str(credential_state.get("reason") or "guest credential reference is unavailable"))
    identity = vm_identity.binding_for_profile(
        name,
        raw,
        require_identity=True,
        require_guest_profile=True,
    )
    bound_vmx_path = _verify_bound_vmx(bundle, identity)
    return {
        "profile": name,
        "configSource": bundle.source,
        "host": core.validate_host(raw.get("host")),
        "port": core.validate_port(raw.get("port"), DEFAULT_PORT),
        "transport": transport,
        "authentication": authentication,
        "credential": credential,
        "credentialState": credential_state,
        "credentialAlias": resolved_credential.alias,
        "configurationVersion": resolved_credential.configuration_version,
        "stagingRoot": _staging_root(raw.get("staging_root")),
        "powershellPath": raw.get("powershell_path"),
        "identity": identity,
        "boundVmxPath": bound_vmx_path,
    }


def _powershell_path(cfg: dict[str, Any]) -> str:
    return core.find_executable("powershell", cfg.get("powershellPath"))


def _credential_values(cfg: dict[str, Any]) -> tuple[str, str, list[str]]:
    credential = cfg["credential"]
    source = str(credential.get("source") or "").strip().lower()
    if source == "windows-integrated":
        return "", "", []
    value = core.read_windows_generic_credential(credential.get("target"))
    return value.username, value.password, [value.username, value.password]


def _invoke(
    cfg: dict[str, Any],
    script: str,
    *,
    timeout: int,
    max_stdout_bytes: int = execution.DEFAULT_MAX_OUTPUT_BYTES,
) -> dict[str, Any]:
    username, password, secrets = _credential_values(cfg)
    envelope = "\n".join(
        [
            _b64(cfg["host"]),
            _b64(str(cfg["port"])),
            _b64(cfg["authentication"].capitalize()),
            _b64(username),
            _b64(password + "\x00" + script),
        ]
    ).encode("utf-8")
    return execution.run_process(
        [
            _powershell_path(cfg),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            _encoded_wrapper(),
        ],
        timeout=timeout,
        input_bytes=envelope,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=execution.DEFAULT_MAX_OUTPUT_BYTES,
        output_encoding="utf-8",
        secrets=secrets,
        memory_limit_mb=512,
        max_processes=16,
        terminate_on_output_limit=True,
    )


def _failure_code(outcome: dict[str, Any]) -> str:
    if outcome.get("timed_out"):
        return "transport-timeout"
    text = (str(outcome.get("stdout") or "") + "\n" + str(outcome.get("stderr") or "")).casefold()
    if any(fragment in text for fragment in ("access is denied", "authentication", "logon failure", "kerberos")):
        return "authentication-failed"
    if any(fragment in text for fragment in ("winrm cannot complete", "connection refused", "network path", "unreachable", "timed out")):
        return "transport-unreachable"
    return "target-readback-failed"


def _identity_from_outcome(cfg: dict[str, Any], outcome: dict[str, Any]) -> dict[str, Any]:
    if outcome.get("returncode") != 0 or outcome.get("timed_out"):
        raise core.ToolError(f"{_failure_code(outcome)}: authenticated guest identity probe failed")
    marker = next(
        (line for line in str(outcome.get("stdout") or "").splitlines() if line.startswith("REMOTEX_IDENTITY|")),
        None,
    )
    if marker is None:
        raise core.ToolError("target-readback-failed: guest identity probe returned no identity marker")
    pieces = marker.split("|", 2)
    if len(pieces) != 3 or not pieces[1] or not pieces[2]:
        raise core.ToolError("target-readback-failed: guest identity probe marker is malformed")
    observed = vm_identity.verify_guest_machine(cfg["identity"], pieces[1])
    return {
        "machineId": observed,
        "bootIdentity": core._required_text(pieces[2], "guest boot identity"),
        "vmIdentity": cfg["identity"],
    }


def _probe_identity(cfg: dict[str, Any], timeout: int) -> dict[str, Any]:
    return _identity_from_outcome(cfg, _invoke(cfg, IDENTITY_SCRIPT, timeout=timeout))


def _capability(available: bool, failure_code: str | None = None) -> dict[str, Any]:
    return {"available": available, "failureCode": None if available else failure_code}


def profile_status(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    result: dict[str, Any] = {
        "profile": name,
        "kind": "windows-guest",
        "client_available": core.executable_available("powershell", raw.get("powershell_path")),
    }
    transport = str(raw.get("transport") or "winrm").strip().lower()
    authentication = str(raw.get("authentication") or "kerberos").strip().lower()
    result["transport"] = transport
    result["authentication"] = authentication
    if transport != "winrm":
        errors.append("Windows guest transport must be winrm")
    if authentication not in {"kerberos", "negotiate"}:
        errors.append("Windows guest authentication must be kerberos or negotiate")
    try:
        bundle = core.load_config()
        resolved_credential = credential_store.resolve_profile_reference(
            bundle,
            name,
            raw,
            "windows-guest",
        )
        credential_state = _credential_status(
            resolved_credential.reference_dict()
        )
        result["credential_alias"] = resolved_credential.alias
        result["configuration_version"] = resolved_credential.configuration_version
    except core.ToolError as exc:
        credential_state = {"source": None, "ready": False, "reason": str(exc)}
    result["credential_source"] = credential_state.get("source")
    result["credential_reference_ready"] = credential_state.get("ready")
    if not credential_state.get("ready"):
        errors.append(str(credential_state.get("reason") or "guest credential reference is unavailable"))
    try:
        result["host"] = core.validate_host(raw.get("host"))
        result["port"] = core.validate_port(raw.get("port"), DEFAULT_PORT)
        result["staging_root"] = _staging_root(raw.get("staging_root"))
        identity = vm_identity.status_for_profile(name, raw)
        result["vmIdentity"] = identity
        if not identity.get("ready"):
            errors.append(str(identity.get("error")))
        else:
            bundle = core.load_config()
            result["bound_vmx_path"] = str(_verify_bound_vmx(bundle, identity))
    except core.ToolError as exc:
        errors.append(str(exc))
    if not result["client_available"]:
        errors.append("local PowerShell client is unavailable")
    ready = not errors
    result["ready"] = ready
    result["errors"] = errors
    unavailable = "client-unavailable" if not result["client_available"] else "configuration-invalid"
    result["capabilities"] = {
        "power": _capability(False, "use-bound-vmware-profile"),
        "snapshot": _capability(False, "use-bound-vmware-profile"),
        "guest_exec": _capability(ready, unavailable),
        "guest_copy": _capability(ready, unavailable),
        "reboot_wait": _capability(ready, unavailable),
    }
    return result


def test_connection(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 15)
    try:
        identity = _probe_identity(cfg, timeout)
    except core.ToolError as exc:
        code = str(exc).split(":", 1)[0]
        return core.tool_result(
            {
                "ok": False,
                "profile": cfg["profile"],
                "transport": "winrm",
                "credentialSource": cfg["credentialState"]["source"],
                "failureCode": code,
                "error": str(exc),
            }
        )
    return core.tool_result(
        {
            "ok": True,
            "profile": cfg["profile"],
            "transport": "winrm",
            "credentialSource": cfg["credentialState"]["source"],
            "authenticatedReadback": True,
            "machineId": identity["machineId"],
            "bootIdentity": identity["bootIdentity"],
            "vmIdentity": identity["vmIdentity"],
        }
    )


def _ps_decode(value: str) -> str:
    return "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" + _b64(value) + "'))"


def _ps_array(values: list[str]) -> str:
    return "@(" + ",".join(_ps_decode(value) for value in values) + ")"


def _preflight_script(run_id: str, policy: dict[str, Any]) -> str:
    return f"""
function Emit-RemoteX([string]$Name, [object]$Value) {{
  $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$Value))
  Write-Output ('REMOTEX_PREFLIGHT|' + $Name + '|' + $encoded)
}}
$requiredKbs = {_ps_array(policy['requiredKbs'])}
$requiredCmdlets = {_ps_array(policy['requiredCmdlets'])}
$inactiveProcesses = {_ps_array(policy['inactiveProcesses'])}
$inactiveServices = {_ps_array(policy['inactiveServices'])}
$inactiveDrivers = {_ps_array(policy['inactiveDrivers'])}
$inactiveEtwSessions = {_ps_array(policy['inactiveEtwSessions'])}
$os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
$computer = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
$release = 0
try {{ $release = [int](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full' -ErrorAction Stop).Release }} catch {{ $release = 0 }}
$pending = $false
$pendingPaths = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'
)
foreach ($pendingPath in $pendingPaths) {{ if (Test-Path $pendingPath) {{ $pending = $true }} }}
try {{ if ((Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -ErrorAction Stop).PendingFileRenameOperations) {{ $pending = $true }} }} catch {{}}
$drive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction Stop
Emit-RemoteX 'run_id' {_ps_decode(run_id)}
Emit-RemoteX 'machine_id' $env:COMPUTERNAME
Emit-RemoteX 'boot_identity' $os.LastBootUpTime
Emit-RemoteX 'os_version' $os.Version
Emit-RemoteX 'architecture' $os.OSArchitecture
Emit-RemoteX 'powershell_version' $PSVersionTable.PSVersion.ToString()
Emit-RemoteX 'dotnet_release' $release
Emit-RemoteX 'pending_reboot' $pending
Emit-RemoteX 'free_system_drive_bytes' $drive.FreeSpace
Emit-RemoteX 'utc' ([DateTime]::UtcNow.ToString('o'))
foreach ($kb in $requiredKbs) {{
  $present = $false
  try {{ $present = $null -ne (Get-HotFix -Id $kb -ErrorAction SilentlyContinue) }} catch {{ $present = $false }}
  Emit-RemoteX ('kb:' + $kb) $present
}}
foreach ($cmdlet in $requiredCmdlets) {{ Emit-RemoteX ('cmdlet:' + $cmdlet) ($null -ne (Get-Command $cmdlet -ErrorAction SilentlyContinue)) }}
foreach ($processName in $inactiveProcesses) {{ Emit-RemoteX ('process:' + $processName) ($null -ne (Get-Process -Name $processName -ErrorAction SilentlyContinue)) }}
foreach ($serviceName in $inactiveServices) {{
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  Emit-RemoteX ('service:' + $serviceName) ($null -ne $service -and $service.Status -ne 'Stopped')
}}
foreach ($driverName in $inactiveDrivers) {{
  $driver = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -eq $driverName -and $_.State -eq 'Running' }}
  Emit-RemoteX ('driver:' + $driverName) ($null -ne $driver)
}}
foreach ($sessionName in $inactiveEtwSessions) {{
  & logman query $sessionName -ets 2>$null | Out-Null
  Emit-RemoteX ('etw:' + $sessionName) ($LASTEXITCODE -eq 0)
}}
""".strip()


def _marker_values(output: str, prefix: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith(prefix):
            continue
        pieces = line.split("|", 2)
        if len(pieces) != 3 or not pieces[1] or pieces[1] in values:
            raise core.ToolError("target-readback-failed: guest receipt marker is malformed")
        values[pieces[1]] = _from_b64(pieces[2], pieces[1])
    return values


def _as_bool(value: str, field: str) -> bool:
    lowered = value.strip().casefold()
    if lowered in {"true", "1"}:
        return True
    if lowered in {"false", "0"}:
        return False
    raise core.ToolError(f"target-readback-failed: guest receipt field {field} is not boolean")


def _as_int(value: str, field: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise core.ToolError(f"target-readback-failed: guest receipt field {field} is not numeric") from exc


def _architecture(value: Any) -> str:
    raw = core._required_text(value, "guest architecture").casefold()
    normalized = raw.replace(" ", "").replace("-", "")
    if normalized in {"x64", "amd64", "64bit"}:
        return "x64"
    if normalized in {"x86", "i386", "i686", "32bit"}:
        return "x86"
    raise core.ToolError(
        "target-readback-failed: guest architecture is not a recognized x86 or x64 value"
    )


def _preflight_evidence(
    cfg: dict[str, Any],
    run_id: str,
    policy: dict[str, Any],
    outcome: dict[str, Any],
) -> dict[str, Any]:
    if outcome.get("returncode") != 0 or outcome.get("timed_out"):
        raise core.ToolError(f"{_failure_code(outcome)}: Windows guest preflight did not complete")
    values = _marker_values(str(outcome.get("stdout") or ""), "REMOTEX_PREFLIGHT|")
    required = {
        "run_id",
        "machine_id",
        "boot_identity",
        "os_version",
        "architecture",
        "powershell_version",
        "dotnet_release",
        "pending_reboot",
        "free_system_drive_bytes",
        "utc",
    }
    missing = sorted(required - set(values))
    if missing:
        raise core.ToolError(
            "target-readback-failed: guest preflight omitted required fields " + ", ".join(missing)
        )
    if values["run_id"] != run_id:
        raise core.ToolError("target-readback-failed: guest preflight run_id does not match request")
    machine_id = vm_identity.verify_guest_machine(cfg["identity"], values["machine_id"])
    os_version = _version(values["os_version"], "guest OS version")
    powershell_version = _version(values["powershell_version"], "guest PowerShell version")
    if os_version is None or powershell_version is None:
        raise core.ToolError(
            "target-readback-failed: guest preflight version fields must be present"
        )
    evidence = {
        "machineId": machine_id,
        "bootIdentity": core._required_text(values["boot_identity"], "guest boot identity"),
        "osVersion": os_version,
        "architecture": _architecture(values["architecture"]),
        "powershellVersion": powershell_version,
        "dotnetRelease": _as_int(values["dotnet_release"], "dotnet_release"),
        "pendingReboot": _as_bool(values["pending_reboot"], "pending_reboot"),
        "freeSystemDriveBytes": _as_int(values["free_system_drive_bytes"], "free_system_drive_bytes"),
        "guestUtc": core._required_text(values["utc"], "guest UTC"),
        "requiredKbs": {kb: _as_bool(values.get("kb:" + kb, "false"), "kb:" + kb) for kb in policy["requiredKbs"]},
        "cmdletSmoke": {name: _as_bool(values.get("cmdlet:" + name, "false"), "cmdlet:" + name) for name in policy["requiredCmdlets"]},
        "inactiveRuntime": {
            "processes": {name: _as_bool(values.get("process:" + name, "false"), "process:" + name) for name in policy["inactiveProcesses"]},
            "services": {name: _as_bool(values.get("service:" + name, "false"), "service:" + name) for name in policy["inactiveServices"]},
            "drivers": {name: _as_bool(values.get("driver:" + name, "false"), "driver:" + name) for name in policy["inactiveDrivers"]},
            "etwSessions": {name: _as_bool(values.get("etw:" + name, "false"), "etw:" + name) for name in policy["inactiveEtwSessions"]},
        },
    }
    return evidence


def _preflight_failures(evidence: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if policy["minimumOsVersion"] and _version_tuple(evidence["osVersion"]) < _version_tuple(policy["minimumOsVersion"]):
        failures.append("os-version-below-minimum")
    if policy["requiredArchitecture"] and evidence["architecture"] != policy["requiredArchitecture"]:
        failures.append("architecture-mismatch")
    if policy["minimumPowerShellVersion"] and _version_tuple(evidence["powershellVersion"]) < _version_tuple(policy["minimumPowerShellVersion"]):
        failures.append("powershell-version-below-minimum")
    if evidence["dotnetRelease"] < policy["minimumDotNetRelease"]:
        failures.append("dotnet-release-below-minimum")
    if any(not present for present in evidence["requiredKbs"].values()):
        failures.append("required-kb-missing")
    if any(not present for present in evidence["cmdletSmoke"].values()):
        failures.append("cmdlet-smoke-failed")
    if evidence["pendingReboot"]:
        failures.append("pending-reboot")
    if evidence["freeSystemDriveBytes"] < policy["minimumFreeSystemDriveBytes"]:
        failures.append("system-drive-space-low")
    runtime_values = evidence["inactiveRuntime"]
    if any(any(active for active in group.values()) for group in runtime_values.values()):
        failures.append("runtime-not-inert")
    return failures


def _persist_preflight(receipt: dict[str, Any]) -> None:
    with _locked_receipts() as state:
        state["receipts"][receipt["sha256"]] = receipt
        _write_receipts(state)


def require_preflight_receipt(identity: dict[str, Any], receipt_hash: Any) -> dict[str, Any]:
    requested = core._required_text(receipt_hash, "preflight_receipt_sha256").casefold()
    if not SHA256_PATTERN.fullmatch(requested):
        raise core.ToolError("preflight_receipt_sha256 must be a lowercase SHA-256 hex digest")
    with _locked_receipts() as state:
        receipt = state["receipts"].get(requested)
        if not isinstance(receipt, dict):
            raise core.ToolError(
                "preflight-receipt-not-found: no local guest preflight receipt matches the supplied hash"
            )
        unsigned = dict(receipt)
        stored_hash = unsigned.pop("sha256", None)
        if (
            receipt.get("schema") != RECEIPT_SCHEMA
            or stored_hash != requested
            or _hash_receipt(unsigned) != requested
        ):
            raise core.ToolError(
                "preflight-receipt-invalid: persisted guest preflight receipt is malformed"
            )
        if not receipt.get("pass"):
            raise core.ToolError(
                "preflight-receipt-failed: snapshot operations require a passing guest preflight"
            )
        receipt_identity = receipt.get("vmIdentity")
        if (
            not isinstance(receipt_identity, dict)
            or receipt_identity.get("id") != identity["id"]
            or receipt_identity.get("vmwareUuid") != identity["vmwareUuid"]
            or receipt_identity.get("guestMachineId") != identity.get("guestMachineId")
            or receipt_identity.get("queueResource") != identity.get("queueResource")
        ):
            raise core.ToolError(
                "preflight-receipt-identity-mismatch: receipt is not bound to the selected VMX identity"
            )
        try:
            created = datetime.fromisoformat(
                str(receipt["createdAtUtc"]).replace("Z", "+00:00")
            )
            policy = receipt.get("policy")
            if not isinstance(policy, dict):
                raise ValueError("policy")
            max_age = int(policy.get("maxReceiptAgeSeconds", 0))
        except (KeyError, TypeError, ValueError) as exc:
            raise core.ToolError(
                "preflight-receipt-invalid: receipt timestamp or policy is unavailable"
            ) from exc
    age = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).total_seconds()
    if age < 0 or max_age < 60 or age > max_age:
        raise core.ToolError(
            "preflight-receipt-stale: guest preflight receipt is no longer fresh"
        )
    return receipt

def preflight(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    requester = vm_queue.validate_requester(args.get("requester"))
    run_id = _run_id(args.get("run_id"))
    policy = _policy(args.get("policy"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 120)
    with vm_queue.profile_owner_operation(cfg["profile"], requester) as ownership:
        _probe_identity(cfg, min(timeout, 30))
        outcome = _invoke(
            cfg,
            _preflight_script(run_id, policy),
            timeout=timeout,
        )
        evidence = _preflight_evidence(cfg, run_id, policy, outcome)
    failures = _preflight_failures(evidence, policy)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "createdAtUtc": _utc_now(),
        "runId": run_id,
        "profile": cfg["profile"],
        "vmIdentity": cfg["identity"],
        "policy": policy,
        "evidence": evidence,
        "pass": not failures,
        "failureCodes": failures,
        "rawOutputExported": False,
    }
    receipt["sha256"] = _hash_receipt(receipt)
    _persist_preflight(receipt)
    return core.tool_result(
        {
            "ok": receipt["pass"],
            "profile": cfg["profile"],
            "queueResource": ownership["resource"],
            "queueOwner": ownership["owner"]["requester"],
            "receipt": receipt,
            "receiptSha256": receipt["sha256"],
        }
    )


def _script(value: Any) -> str:
    script = core._required_text(value, "script")
    if "\x00" in script:
        raise core.ToolError("script must not contain NUL characters")
    if len(script) > core.MAX_SCRIPT_LENGTH:
        raise core.ToolError(f"script exceeds {core.MAX_SCRIPT_LENGTH} characters")
    return script


def _safe_allowlist(value: Any) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > 32:
        raise core.ToolError("output_allowlist must contain at most 32 field names")
    return [_safe_item(item, "output_allowlist item") for item in value]


def _safe_output(outcome: dict[str, Any], allowlist: list[str]) -> dict[str, Any]:
    stdout = str(outcome.get("stdout") or "")
    stderr = str(outcome.get("stderr") or "")
    result: dict[str, Any] = {
        "stdoutSha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderrSha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "stdoutBytes": outcome.get("stdout_bytes"),
        "stderrBytes": outcome.get("stderr_bytes"),
        "outputScrubbed": not bool(allowlist),
    }
    if not allowlist:
        return result
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise core.ToolError("guest-output-schema-invalid: allowlisted output must be one JSON object") from exc
    if not isinstance(payload, dict):
        raise core.ToolError("guest-output-schema-invalid: allowlisted output must be one JSON object")
    approved: dict[str, Any] = {}
    for name in allowlist:
        if name not in payload:
            continue
        candidate = payload[name]
        if isinstance(candidate, str):
            if len(candidate) > 256:
                raise core.ToolError("guest-output-schema-invalid: allowlisted string exceeds 256 characters")
        elif not isinstance(candidate, (bool, int, float)) and candidate is not None:
            raise core.ToolError("guest-output-schema-invalid: allowlisted values must be scalar")
        approved[name] = candidate
    result["outputFields"] = approved
    result["outputScrubbed"] = False
    return result


def _receipt_payload(payload: dict[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {}
    for key, value in payload.items():
        if key in {"actualRemotePath", "localPath", "requestedRelativePath"}:
            scrubbed[key + "Sha256"] = hashlib.sha256(str(value).encode("utf-8")).hexdigest()
        elif key == "result" and isinstance(value, dict):
            result = {name: item for name, item in value.items() if name != "outputFields"}
            if "outputFields" in value:
                result["outputFieldsExported"] = False
            scrubbed[key] = result
        else:
            scrubbed[key] = value
    return scrubbed


def _operation_receipt(operation: str, cfg: dict[str, Any], run_id: str | None, payload: dict[str, Any]) -> dict[str, Any]:
    receipt = {
        "schema": OPERATION_SCHEMA,
        "operation": operation,
        "createdAtUtc": _utc_now(),
        "profile": cfg["profile"],
        "vmIdentity": cfg["identity"],
        "runId": run_id,
        "payload": _receipt_payload(payload),
        "rawOutputExported": False,
    }
    receipt["sha256"] = _hash_receipt(receipt)
    return receipt


def run_script(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    requester = vm_queue.validate_requester(args.get("requester"))
    script = _script(args.get("script"))
    allowlist = _safe_allowlist(args.get("output_allowlist"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 120)
    with vm_queue.profile_owner_operation(cfg["profile"], requester) as ownership:
        identity = _probe_identity(cfg, min(timeout, 30))
        outcome = _invoke(cfg, script, timeout=timeout)
    payload = {
        "requestAccepted": True,
        "clientReturnCode": outcome.get("returncode"),
        "timedOut": outcome.get("timed_out"),
        "targetIdentityReadback": identity,
        "targetStateReadback": outcome.get("returncode") == 0 and not outcome.get("timed_out"),
        "result": _safe_output(outcome, allowlist),
    }
    receipt = _operation_receipt("guest-exec", cfg, None, payload)
    return core.tool_result(
        {
            "ok": bool(payload["targetStateReadback"]),
            "profile": cfg["profile"],
            "queueResource": ownership["resource"],
            "queueOwner": ownership["owner"]["requester"],
            **payload,
            "receipt": receipt,
            "receiptSha256": receipt["sha256"],
        }
    )


def _relative_path(value: Any) -> str:
    relative = core._required_text(value, "relative_path")
    path = PureWindowsPath(relative)
    if path.is_absolute() or path.drive or any(part in {".", ".."} for part in path.parts):
        raise core.ToolError("relative_path must stay below the declared staging_root")
    return str(path)


def _overwrite(value: Any) -> str:
    choice = str(value or "fail").strip().lower()
    if choice not in {"fail", "replace"}:
        raise core.ToolError("overwrite must be fail or replace")
    return choice


def _local_file(value: Any, *, must_exist: bool) -> Path:
    path = core.expand_path(value, "local_path")
    if path.is_symlink():
        raise core.ToolError("local_path must not be a symlink")
    if must_exist and (not path.exists() or not path.is_file()):
        raise core.ToolError("local_path must name an existing regular file")
    if not must_exist and path.parent and not path.parent.exists():
        raise core.ToolError("local_path parent directory does not exist")
    return path


def _copy_script(staging_root: str, relative: str, *, direction: str, content: bytes | None, replace: bool) -> str:
    root = _ps_decode(staging_root)
    rel = _ps_decode(relative)
    common = f"""
$root = {root}
$relative = {rel}
if ([System.IO.Path]::IsPathRooted($relative) -or $relative.Split('\\') -contains '..') {{ throw 'RemoteX staging path is invalid' }}
$rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\\') + '\\'
$target = [System.IO.Path]::GetFullPath((Join-Path $root $relative))
if (-not $target.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {{ throw 'RemoteX staging path escapes its root' }}
""".strip()
    if direction == "to":
        assert content is not None
        encoded = base64.b64encode(content).decode("ascii")
        return common + f"""

$bytes = [System.Convert]::FromBase64String('{encoded}')
if ((Test-Path $target) -and -not ${str(replace).lower()}) {{ throw 'RemoteX staging target already exists' }}
$parent = Split-Path -Parent $target
if (-not (Test-Path $parent)) {{ New-Item -ItemType Directory -Path $parent -Force | Out-Null }}
[System.IO.File]::WriteAllBytes($target, $bytes)
$readback = [System.IO.File]::ReadAllBytes($target)
$hash = ([System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash($readback))).Replace('-', '').ToLowerInvariant()
$path64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($target))
Write-Output ('REMOTEX_COPY|to|' + $path64 + '|' + $readback.Length + '|' + $hash)
"""
    return common + """

if (-not (Test-Path $target -PathType Leaf)) { throw 'RemoteX staging source does not exist' }
$bytes = [System.IO.File]::ReadAllBytes($target)
$hash = ([System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
$path64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($target))
Write-Output ('REMOTEX_COPY_DATA|' + [System.Convert]::ToBase64String($bytes))
Write-Output ('REMOTEX_COPY|from|' + $path64 + '|' + $bytes.Length + '|' + $hash)
"""


def _copy_marker(outcome: dict[str, Any], direction: str) -> tuple[str, int, str]:
    marker = next(
        (line for line in str(outcome.get("stdout") or "").splitlines() if line.startswith("REMOTEX_COPY|")),
        None,
    )
    if marker is None:
        raise core.ToolError("target-readback-failed: guest copy returned no bounded receipt")
    pieces = marker.split("|", 4)
    if len(pieces) != 5 or pieces[1] != direction:
        raise core.ToolError("target-readback-failed: guest copy receipt is malformed")
    remote_path = _from_b64(pieces[2], "copy path")
    try:
        byte_count = int(pieces[3])
    except ValueError as exc:
        raise core.ToolError("target-readback-failed: guest copy byte count is invalid") from exc
    digest = pieces[4].casefold()
    if byte_count < 0 or not SHA256_PATTERN.fullmatch(digest):
        raise core.ToolError("target-readback-failed: guest copy receipt is invalid")
    return remote_path, byte_count, digest


def copy_to(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    requester = vm_queue.validate_requester(args.get("requester"))
    local = _local_file(args.get("local_path"), must_exist=True)
    if local.stat().st_size > MAX_GUEST_COPY_BYTES:
        raise core.ToolError(f"guest copy is limited to {MAX_GUEST_COPY_BYTES} bytes")
    relative = _relative_path(args.get("relative_path"))
    overwrite = _overwrite(args.get("overwrite"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 180)
    content = local.read_bytes()
    local_hash = hashlib.sha256(content).hexdigest()
    with vm_queue.profile_owner_operation(cfg["profile"], requester) as ownership:
        identity = _probe_identity(cfg, min(timeout, 30))
        outcome = _invoke(
            cfg,
            _copy_script(cfg["stagingRoot"], relative, direction="to", content=content, replace=overwrite == "replace"),
            timeout=timeout,
        )
    if outcome.get("returncode") != 0 or outcome.get("timed_out"):
        raise core.ToolError(f"{_failure_code(outcome)}: guest copy-to did not complete")
    remote_path, bytes_written, remote_hash = _copy_marker(outcome, "to")
    matched = bytes_written == len(content) and remote_hash == local_hash
    payload = {
        "requestAccepted": True,
        "clientReturnCode": outcome.get("returncode"),
        "targetIdentityReadback": identity,
        "targetStateReadback": matched,
        "requestedRelativePath": relative,
        "actualRemotePath": remote_path,
        "localBytes": len(content),
        "remoteBytes": bytes_written,
        "localSha256": local_hash,
        "remoteSha256": remote_hash,
        "integrityMatched": matched,
    }
    receipt = _operation_receipt("guest-copy-to", cfg, None, payload)
    return core.tool_result(
        {
            "ok": matched,
            "profile": cfg["profile"],
            "queueResource": ownership["resource"],
            "queueOwner": ownership["owner"]["requester"],
            **payload,
            "receipt": receipt,
            "receiptSha256": receipt["sha256"],
        }
    )


def copy_from(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    requester = vm_queue.validate_requester(args.get("requester"))
    local = _local_file(args.get("local_path"), must_exist=False)
    overwrite = _overwrite(args.get("overwrite"))
    if local.exists() and overwrite != "replace":
        raise core.ToolError("local_path already exists; set overwrite=replace to replace it")
    relative = _relative_path(args.get("relative_path"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), 180)
    with vm_queue.profile_owner_operation(cfg["profile"], requester) as ownership:
        identity = _probe_identity(cfg, min(timeout, 30))
        outcome = _invoke(
            cfg,
            _copy_script(cfg["stagingRoot"], relative, direction="from", content=None, replace=False),
            timeout=timeout,
            max_stdout_bytes=execution.MAX_OUTPUT_BYTES,
        )
    if outcome.get("returncode") != 0 or outcome.get("timed_out"):
        raise core.ToolError(f"{_failure_code(outcome)}: guest copy-from did not complete")
    remote_path, remote_bytes, remote_hash = _copy_marker(outcome, "from")
    encoded = next(
        (line[len("REMOTEX_COPY_DATA|"):] for line in str(outcome.get("stdout") or "").splitlines() if line.startswith("REMOTEX_COPY_DATA|")),
        None,
    )
    if encoded is None:
        raise core.ToolError("target-readback-failed: guest copy returned no file payload")
    try:
        content = base64.b64decode(encoded.encode("ascii"), validate=True)
    except ValueError as exc:
        raise core.ToolError("target-readback-failed: guest copy payload is invalid") from exc
    if len(content) > MAX_GUEST_COPY_BYTES:
        raise core.ToolError(f"guest copy exceeds {MAX_GUEST_COPY_BYTES} bytes")
    local_hash = hashlib.sha256(content).hexdigest()
    matched = len(content) == remote_bytes and local_hash == remote_hash
    if matched:
        local.write_bytes(content)
    payload = {
        "requestAccepted": True,
        "clientReturnCode": outcome.get("returncode"),
        "targetIdentityReadback": identity,
        "targetStateReadback": matched,
        "requestedRelativePath": relative,
        "actualRemotePath": remote_path,
        "localPath": str(local),
        "localBytes": len(content),
        "remoteBytes": remote_bytes,
        "localSha256": local_hash,
        "remoteSha256": remote_hash,
        "integrityMatched": matched,
        "localWritten": matched,
    }
    receipt = _operation_receipt("guest-copy-from", cfg, None, payload)
    return core.tool_result(
        {
            "ok": matched,
            "profile": cfg["profile"],
            "queueResource": ownership["resource"],
            "queueOwner": ownership["owner"]["requester"],
            **payload,
            "receipt": receipt,
            "receiptSha256": receipt["sha256"],
        }
    )


def reboot(args: dict[str, Any]) -> dict[str, Any]:
    cfg = connection_config(args.get("profile"))
    requester = vm_queue.validate_requester(args.get("requester"))
    run_id = _run_id(args.get("run_id"))
    if args.get("confirm") is not True:
        raise core.ToolError("confirm=true is required to reboot a Windows guest")
    timeout = core.validate_timeout(args.get("timeout_seconds"), 300)
    with vm_queue.profile_owner_operation(cfg["profile"], requester) as ownership:
        before = _probe_identity(cfg, min(timeout, 30))
        accepted_outcome = _invoke(cfg, REBOOT_SCRIPT, timeout=min(timeout, 30))
        accepted = "REMOTEX_REBOOT_ACCEPTED|1" in str(accepted_outcome.get("stdout") or "")
        old_boot_disappeared = False
        after: dict[str, Any] | None = None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                candidate = _probe_identity(cfg, min(20, max(1, int(deadline - time.monotonic()))))
            except core.ToolError:
                old_boot_disappeared = True
            else:
                if candidate["bootIdentity"] != before["bootIdentity"]:
                    old_boot_disappeared = True
                    after = candidate
                    break
            time.sleep(0.5)
    ready = after is not None
    payload = {
        "requestAccepted": accepted,
        "clientReturnCode": accepted_outcome.get("returncode"),
        "oldBootIdentity": before["bootIdentity"],
        "oldBootIdentityDisappeared": old_boot_disappeared,
        "newAuthenticatedSessionReady": ready,
        "newBootIdentity": after["bootIdentity"] if after else None,
        "targetStateReadback": ready,
        "failureCode": None if ready else "reboot-readback-timeout",
    }
    receipt = _operation_receipt("guest-reboot", cfg, run_id, payload)
    return core.tool_result(
        {
            "ok": ready,
            "profile": cfg["profile"],
            "queueResource": ownership["resource"],
            "queueOwner": ownership["owner"]["requester"],
            **payload,
            "receipt": receipt,
            "receiptSha256": receipt["sha256"],
        }
    )


COMMON_PROFILE = {
    "profile": {"type": "string", "description": "Windows guest profile from RemoteX config."},
}
COMMON_TIMEOUT = {
    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": core.MAX_TIMEOUT_SECONDS},
}
REQUESTER = {"requester": {"type": "string"}}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_windows_guest_test": {
        "description": "Use authenticated WinRM to read the configured Windows guest identity without exposing credentials.",
        "inputSchema": {"type": "object", "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT}, "additionalProperties": False},
        "handler": test_connection,
    },
    "remotex_windows_guest_preflight": {
        "description": "Collect a PowerShell 2.0-compatible, hash-bound Windows upgrade/test readiness receipt under the VM queue owner.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, **REQUESTER, "run_id": {"type": "string"}, "policy": {"type": "object"}},
            "required": ["requester", "run_id"],
            "additionalProperties": False,
        },
        "handler": preflight,
    },
    "remotex_windows_guest_run_script": {
        "description": "Run a bounded PowerShell script after authenticated VM identity verification; output is scrubbed unless fields are allowlisted.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, **REQUESTER, "script": {"type": "string"}, "output_allowlist": {"type": "array", "items": {"type": "string"}}},
            "required": ["requester", "script"],
            "additionalProperties": False,
        },
        "handler": run_script,
    },
    "remotex_windows_guest_copy_to": {
        "description": "Copy one local file to the configured guest staging root and verify size and SHA-256 through guest readback.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, **REQUESTER, "local_path": {"type": "string"}, "relative_path": {"type": "string"}, "overwrite": {"type": "string", "enum": ["fail", "replace"]}},
            "required": ["requester", "local_path", "relative_path"],
            "additionalProperties": False,
        },
        "handler": copy_to,
    },
    "remotex_windows_guest_copy_from": {
        "description": "Copy one file from the configured guest staging root and verify size and SHA-256 without returning its contents.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, **REQUESTER, "local_path": {"type": "string"}, "relative_path": {"type": "string"}, "overwrite": {"type": "string", "enum": ["fail", "replace"]}},
            "required": ["requester", "local_path", "relative_path"],
            "additionalProperties": False,
        },
        "handler": copy_from,
    },
    "remotex_windows_guest_reboot": {
        "description": "Restart a Windows guest only after confirmation and verify a new authenticated boot identity before returning success.",
        "inputSchema": {
            "type": "object",
            "properties": {**COMMON_PROFILE, **COMMON_TIMEOUT, **REQUESTER, "run_id": {"type": "string"}, "confirm": {"type": "boolean"}},
            "required": ["requester", "run_id", "confirm"],
            "additionalProperties": False,
        },
        "handler": reboot,
    },
}
