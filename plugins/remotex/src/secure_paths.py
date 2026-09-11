from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import remotex_core as core


WINDOWS_SYSTEM_SID = "S-1-5-18"
WINDOWS_ADMINISTRATORS_SID = "S-1-5-32-544"
WINDOWS_LOCAL_ADMINISTRATOR_ALIAS = "LA"
_ACE_PATTERN = re.compile(r"\(([^()]*)\)")


def _network_path(path: Path) -> bool:
    value = str(path)
    return value.startswith(("\\\\", "//"))


def _reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse)


def _powershell_path() -> str:
    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    candidate = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(candidate)


def _run_windows_powershell(script: str, *arguments: str) -> str:
    encoded_arguments = [
        base64.b64encode(value.encode("utf-8")).decode("ascii")
        for value in arguments
    ]
    argument_expression = ",".join(
        "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
        + value
        + "'))"
        for value in encoded_arguments
    )
    command = (
        "$ErrorActionPreference='Stop';"
        "$OutputEncoding=[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);"
        f"$args=@({argument_expression});"
        + script
    )
    encoded_command = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    try:
        completed = subprocess.run(
            [
                _powershell_path(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded_command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise core.ToolError("Unable to inspect Windows path protection") from exc
    if completed.returncode != 0:
        raise core.ToolError("Unable to inspect Windows path protection")
    return completed.stdout.strip()


def _windows_identity() -> tuple[str, str]:
    raw = _run_windows_powershell(
        "$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); "
        "[pscustomobject]@{Sid=$identity.User.Value;Name=$identity.Name}|"
        "ConvertTo-Json -Compress"
    )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise core.ToolError("Unable to inspect Windows identity") from exc
    sid = str(value.get("Sid") or "").strip()
    name = str(value.get("Name") or "").strip()
    if not sid.startswith("S-1-") or not name:
        raise core.ToolError("Unable to inspect Windows identity")
    return sid, name


def _windows_acl(path: Path) -> dict[str, str]:
    raw = _run_windows_powershell(
        "$path=$args[0];"
        "if([IO.Directory]::Exists($path)){$acl=[IO.Directory]::GetAccessControl($path)}"
        "elseif([IO.File]::Exists($path)){$acl=[IO.File]::GetAccessControl($path)}"
        "else{throw 'path is unavailable'};"
        "$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;"
        "$sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All);"
        "[pscustomobject]@{Owner=$owner;Sddl=$sddl}|ConvertTo-Json -Compress",
        str(path),
    )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise core.ToolError("Unable to inspect Windows path protection") from exc
    owner = str(value.get("Owner") or "").strip()
    sddl = str(value.get("Sddl") or "").strip()
    if not owner or not sddl:
        raise core.ToolError("Unable to inspect Windows path protection")
    return {"owner": owner, "sddl": sddl}


def _allow_trustees(sddl: str) -> set[str]:
    trustees: set[str] = set()
    for raw_ace in _ACE_PATTERN.findall(sddl):
        fields = raw_ace.split(";")
        if len(fields) >= 6 and fields[0] in {"A", "OA"}:
            trustees.add(fields[-1].upper())
    return trustees


def private_path_status(path: Path) -> dict[str, Any]:
    candidate = Path(path)
    if not candidate.exists():
        return {"ready": False, "reason": "path-missing", "pathType": None}
    if _network_path(candidate):
        return {"ready": False, "reason": "network-path", "pathType": None}
    if _reparse_point(candidate):
        return {"ready": False, "reason": "reparse-point", "pathType": None}
    path_type = "directory" if candidate.is_dir() else "file" if candidate.is_file() else None
    if path_type is None:
        return {"ready": False, "reason": "unsupported-path-type", "pathType": None}

    if os.name != "nt":
        mode = stat.S_IMODE(candidate.stat().st_mode)
        expected = 0o700 if path_type == "directory" else 0o600
        return {
            "ready": mode == expected,
            "reason": None if mode == expected else "posix-mode-too-broad",
            "pathType": path_type,
            "mode": f"{mode:04o}",
        }

    sid, identity_name = _windows_identity()
    acl = _windows_acl(candidate)
    allowed = {
        sid.upper(),
        WINDOWS_SYSTEM_SID,
        WINDOWS_ADMINISTRATORS_SID,
        "SY",
        "BA",
        WINDOWS_LOCAL_ADMINISTRATOR_ALIAS,
    }
    unexpected = sorted(_allow_trustees(acl["sddl"]) - allowed)
    protected = "D:P" in acl["sddl"]
    owner_matches = acl["owner"].casefold() in {
        sid.casefold(),
        identity_name.casefold(),
    }
    owner_trusted = owner_matches or acl["owner"].casefold() in {
        WINDOWS_ADMINISTRATORS_SID.casefold(),
        "ba",
        WINDOWS_LOCAL_ADMINISTRATOR_ALIAS.casefold(),
        "builtin\\administrators",
    }
    ready = protected and owner_trusted and not unexpected
    reason = None
    if not protected:
        reason = "windows-acl-inheritance-enabled"
    elif not owner_trusted:
        reason = "windows-owner-mismatch"
    elif unexpected:
        reason = "windows-acl-too-broad"
    return {
        "ready": ready,
        "reason": reason,
        "pathType": path_type,
        "ownerMatchesCurrentUser": owner_matches,
        "ownerTrusted": owner_trusted,
        "inheritanceProtected": protected,
        "unexpectedAllowPrincipalCount": len(unexpected),
        "unexpectedAllowTrustees": unexpected[:8],
    }


def _protect_windows(path: Path, *, directory: bool) -> None:
    sid, _ = _windows_identity()
    flags = "OICI" if directory else ""
    sddl = (
        f"O:{sid}G:{sid}D:P"
        f"(A;{flags};FA;;;SY)"
        f"(A;{flags};FA;;;BA)"
        f"(A;{flags};FA;;;{sid})"
    )
    _run_windows_powershell(
        "$path=$args[0];$sddl=$args[1];"
        "$sections=([Security.AccessControl.AccessControlSections]::Owner -bor "
        "[Security.AccessControl.AccessControlSections]::Group -bor "
        "[Security.AccessControl.AccessControlSections]::Access);"
        "if([IO.Directory]::Exists($path)){"
        "$acl=New-Object Security.AccessControl.DirectorySecurity;"
        "$acl.SetSecurityDescriptorSddlForm($sddl,$sections);"
        "[IO.Directory]::SetAccessControl($path,$acl)"
        "}elseif([IO.File]::Exists($path)){"
        "$acl=New-Object Security.AccessControl.FileSecurity;"
        "$acl.SetSecurityDescriptorSddlForm($sddl,$sections);"
        "[IO.File]::SetAccessControl($path,$acl)"
        "}else{throw 'path is unavailable'}",
        str(path),
        sddl,
    )


def ensure_private_directory(path: Path) -> dict[str, Any]:
    candidate = Path(path)
    if _network_path(candidate) or _reparse_point(candidate):
        raise core.ToolError("Private RemoteX directory must be local and not a reparse point")
    candidate.mkdir(parents=True, exist_ok=True)
    if not candidate.is_dir() or _reparse_point(candidate):
        raise core.ToolError("Private RemoteX directory is invalid")
    if os.name == "nt":
        _protect_windows(candidate, directory=True)
    else:
        os.chmod(candidate, 0o700)
    status = private_path_status(candidate)
    if not status.get("ready"):
        details = ",".join(status.get("unexpectedAllowTrustees") or [])
        raise core.ToolError(
            "Private RemoteX directory protection verification failed: "
            + str(status.get("reason") or "unknown")
            + (f":{details}" if details else "")
        )
    return status


def ensure_private_file(path: Path) -> dict[str, Any]:
    candidate = Path(path)
    if not candidate.is_file() or _network_path(candidate) or _reparse_point(candidate):
        raise core.ToolError("Private RemoteX file is invalid")
    if os.name == "nt":
        _protect_windows(candidate, directory=False)
    else:
        os.chmod(candidate, 0o600)
    status = private_path_status(candidate)
    if not status.get("ready"):
        details = ",".join(status.get("unexpectedAllowTrustees") or [])
        raise core.ToolError(
            "Private RemoteX file protection verification failed: "
            + str(status.get("reason") or "unknown")
            + (f":{details}" if details else "")
        )
    return status
