from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import execution
import remotex_core as core
import ssh_vnext


SCHEMA = "RemoteXHostKeys/v1"
COMPATIBILITY_KEY_TYPES = "rsa,ecdsa,ed25519"
_ALGORITHM_SCAN_ERROR = re.compile(
    r"(?:no matching .*host key|host key algorithm|(?:unknown|unsupported) key type)",
    re.IGNORECASE,
)


def registry_path() -> Path:
    configured = os.environ.get("REMOTEX_HOSTKEY_FILE")
    if configured:
        return core.expand_path(configured, "REMOTEX_HOSTKEY_FILE")
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    return root / "RemoteX" / "host-keys.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load() -> dict[str, Any]:
    path = registry_path()
    if not path.exists():
        return {"schema": SCHEMA, "profiles": {}, "events": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError(f"Unable to read RemoteX host-key registry at {path}: {exc}") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != SCHEMA
        or not isinstance(payload.get("profiles"), dict)
        or not isinstance(payload.get("events"), list)
    ):
        raise core.ToolError(f"RemoteX host-key registry has an unsupported format: {path}")
    return payload


def _write(payload: dict[str, Any]) -> None:
    path = registry_path()
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


def _fingerprint(key_blob: str) -> str:
    try:
        raw = base64.b64decode(key_blob.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise core.ToolError("ssh-keyscan returned an invalid public-key blob") from exc
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _scan_argv(executable: str, cfg: dict[str, Any], timeout: int, key_types: str | None) -> list[str]:
    argv = [
        executable,
        "-T",
        str(timeout),
        "-p",
        str(cfg["port"]),
    ]
    if key_types:
        argv.extend(["-t", key_types])
    argv.append(cfg["host"])
    return argv


def _parse_scan_output(stdout: str) -> tuple[list[dict[str, str]], list[str]]:
    keys: list[dict[str, str]] = []
    lines: list[str] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            raise core.ToolError("ssh-keyscan returned an unsupported line")
        keys.append(
            {
                "algorithm": parts[1],
                "fingerprint": _fingerprint(parts[2]),
                "hostField": parts[0],
            }
        )
        lines.append(line)
    keys.sort(key=lambda item: (item["algorithm"], item["fingerprint"]))
    return keys, lines


def _git_keyscan() -> str | None:
    if os.name != "nt":
        return None
    candidate = Path("C:/Program Files/Git/usr/bin/ssh-keyscan.exe")
    return str(candidate) if candidate.is_file() else None


def _scan(cfg: dict[str, Any], timeout: int) -> tuple[list[dict[str, str]], list[str]]:
    executable = core.find_executable("ssh-keyscan")

    def run(key_types: str | None) -> dict[str, Any]:
        return execution.run_process(
            _scan_argv(executable, cfg, timeout, key_types),
            timeout=timeout + 2,
            max_stdout_bytes=1024 * 1024,
            max_stderr_bytes=1024 * 1024,
            output_encoding="utf-8",
        )

    outcome = run(None)
    stdout = str(outcome.get("stdout") or "")
    keys, lines = _parse_scan_output(stdout)

    # ssh-keyscan may return usable lines while reporting that another advertised
    # server key type had no compatible local implementation. Keep complete keys;
    # only retry with modern, non-DSA types when the first scan returned no key.
    if keys and not outcome.get("timed_out"):
        return keys, lines

    diagnostic = str(outcome.get("stderr") or stdout)
    # Host key types (-t) cannot repair a broken local KEX implementation.
    if not keys and not outcome.get("timed_out") and "unsupported KEX method" in diagnostic:
        fallback = _git_keyscan()
        if fallback and os.path.normcase(fallback) != os.path.normcase(executable):
            executable = fallback
            compatibility = run(COMPATIBILITY_KEY_TYPES)
            compatibility_stdout = str(compatibility.get("stdout") or "")
            compatibility_keys, compatibility_lines = _parse_scan_output(compatibility_stdout)
            if compatibility_keys and not compatibility.get("timed_out"):
                return compatibility_keys, compatibility_lines
            raise core.ToolError("Unable to scan SSH host keys with compatible local scanner")
    if not keys and _ALGORITHM_SCAN_ERROR.search(diagnostic):
        compatibility = run(COMPATIBILITY_KEY_TYPES)
        compatibility_stdout = str(compatibility.get("stdout") or "")
        compatibility_keys, compatibility_lines = _parse_scan_output(
            compatibility_stdout
        )
        if compatibility_keys and not compatibility.get("timed_out"):
            return compatibility_keys, compatibility_lines
        diagnostic = str(
            compatibility.get("stderr")
            or compatibility_stdout
            or diagnostic
        )

    if outcome.get("timed_out"):
        diagnostic = diagnostic or "scan timed out"
    raise core.ToolError(f"Unable to scan SSH host keys: {diagnostic}")


def enforce(cfg: dict[str, Any], timeout: int) -> dict[str, Any]:
    policy = str(cfg.get("host_key_policy") or "known-hosts")
    if policy == "known-hosts":
        return {
            "policy": policy,
            "state": "delegated",
            "matchSource": "openssh-known-hosts",
        }
    if policy != "managed":
        raise core.ToolError("host_key_policy must be known-hosts or managed")
    if cfg.get("strict_host_key_checking") != "yes":
        raise core.ToolError(
            "host_key_policy=managed requires strict_host_key_checking=yes"
        )
    keys, _ = _scan(cfg, timeout)
    registry = _load()
    record = registry["profiles"].get(cfg["profile"])
    if not isinstance(record, dict):
        raise core.ToolError(
            "SSH host key is not registered in the RemoteX registry; "
            "inspect and explicitly approve a fingerprint first"
        )
    if record.get("host") != cfg["host"] or int(record.get("port", -1)) != cfg["port"]:
        raise core.ToolError(
            "The registered SSH host-key endpoint does not match this profile; "
            "inspect and explicitly approve the intended endpoint"
        )
    current = sorted(item["fingerprint"] for item in keys)
    registered = sorted(str(item) for item in record.get("fingerprints", []))
    if not registered or not set(registered).issubset(set(current)):
        raise core.ToolError(
            "The approved SSH host key is absent; the connection is blocked "
            "until an explicit rotation approval"
        )
    return {
        "policy": policy,
        "state": "matched",
        "matchSource": "remotex-registry",
        "fingerprints": current,
        "registeredAt": record.get("approvedAt"),
    }


def profile_summary(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    registry = _load()
    record = registry["profiles"].get(name)
    known_hosts = raw.get("known_hosts_file")
    strict_mode = ssh_vnext._strict_mode(raw.get("strict_host_key_checking"))
    policy = ssh_vnext._host_key_policy(raw.get("host_key_policy"), strict_mode)
    host = core.validate_host(raw.get("host"))
    port = core.validate_port(raw.get("port"), ssh_vnext.DEFAULT_PORT)
    endpoint_matches = bool(
        isinstance(record, dict)
        and record.get("host") == host
        and int(record.get("port", -1)) == port
    )
    governance_state = (
        "registered"
        if endpoint_matches
        else ("endpoint-mismatch" if record else "unregistered")
    )
    return {
        "governanceState": governance_state,
        "policy": policy,
        "matchSource": (
            "remotex-registry" if policy == "managed" else "openssh-known-hosts"
        ),
        "endpointMatched": endpoint_matches if record else None,
        "registeredAt": record.get("approvedAt") if isinstance(record, dict) else None,
        "fingerprints": record.get("fingerprints", []) if isinstance(record, dict) else [],
        "knownHostsFileConfigured": bool(known_hosts),
        "knownHostsFileExists": bool(
            known_hosts and core.expand_path(known_hosts, "known_hosts_file").is_file()
        ),
        "changePolicy": "block-until-explicit-approval",
    }


def status(args: dict[str, Any]) -> dict[str, Any]:
    cfg = ssh_vnext.connection_config(args.get("profile"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), cfg["connect_timeout_seconds"])
    keys, _ = _scan(cfg, timeout)
    registry = _load()
    record = registry["profiles"].get(cfg["profile"])
    current = [item["fingerprint"] for item in keys]
    registered = record.get("fingerprints", []) if isinstance(record, dict) else []
    endpoint_matches = bool(
        isinstance(record, dict)
        and record.get("host") == cfg["host"]
        and int(record.get("port", -1)) == cfg["port"]
    )
    if not record:
        state = "unregistered"
        match = None
        blocked = True
    elif not endpoint_matches:
        state = "endpoint-mismatch"
        match = False
        blocked = True
    elif registered and set(registered).issubset(set(current)):
        state = "matched"
        match = True
        blocked = False
    else:
        state = "changed"
        match = False
        blocked = True
    return core.tool_result(
        {
            "ok": not blocked,
            "profile": cfg["profile"],
            "host": cfg["host"],
            "port": cfg["port"],
            "state": state,
            "blocked": blocked,
            "fingerprintMatched": match,
            "currentKeys": keys,
            "registeredFingerprints": registered,
            "registeredAt": record.get("approvedAt") if isinstance(record, dict) else None,
            "registryPath": str(registry_path()),
            "prompt": (
                "Approve one displayed fingerprint explicitly before trusting this host."
                if state == "unregistered"
                else (
                    "Host key changed. Verify the target out of band, then approve rotation explicitly."
                    if state == "changed"
                    else (
                        "The registered host-key endpoint does not match this profile."
                        if state == "endpoint-mismatch"
                        else "Registered SSH host keys match the current scan."
                    )
                )
            ),
        }
    )


def _remove_known_host(cfg: dict[str, Any], known_hosts: Path, timeout: int) -> None:
    targets = [cfg["host"]]
    if cfg["port"] != 22:
        targets.insert(0, f"[{cfg['host']}]:{cfg['port']}")
    for target in targets:
        outcome = execution.run_process(
            [
                core.find_executable("ssh-keygen"),
                "-R",
                target,
                "-f",
                str(known_hosts),
            ],
            timeout=timeout,
            output_encoding="utf-8",
        )
        if outcome["returncode"] not in {0, 1}:
            raise core.ToolError(f"Unable to update known_hosts: {outcome['stderr']}")


def approve(args: dict[str, Any]) -> dict[str, Any]:
    if not core.as_bool(args.get("confirm"), False):
        raise core.ToolError("confirm=true is required to approve an SSH host key")
    expected = core._required_text(args.get("fingerprint"), "fingerprint")
    rotation = core.as_bool(args.get("rotation"), False)
    cfg = ssh_vnext.connection_config(args.get("profile"))
    timeout = core.validate_timeout(args.get("timeout_seconds"), cfg["connect_timeout_seconds"])
    keys, lines = _scan(cfg, timeout)
    observed = [item["fingerprint"] for item in keys]
    if expected not in observed:
        raise core.ToolError("The approved fingerprint is not present in the current host-key scan")
    approved_keys = [
        item for item in keys if item["fingerprint"] == expected
    ]
    approved_lines = [
        line
        for line in lines
        if len(line.split()) >= 3
        and _fingerprint(line.split()[2]) == expected
    ]
    if not approved_keys or not approved_lines:
        raise core.ToolError(
            "The approved fingerprint could not be mapped to a scanned host-key line"
        )
    if not cfg.get("known_hosts_file"):
        raise core.ToolError("known_hosts_file is required for host-key approval")
    known_hosts = Path(cfg["known_hosts_file"])
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    registry = _load()
    previous = registry["profiles"].get(cfg["profile"])
    previous_fingerprints = (
        previous.get("fingerprints", []) if isinstance(previous, dict) else []
    )
    changed = bool(
        previous
        and (
            expected not in previous_fingerprints
            or previous.get("host") != cfg["host"]
            or int(previous.get("port", -1)) != cfg["port"]
        )
    )
    if changed and not rotation:
        raise core.ToolError("Host key changed; rotation=true is required for explicit rotation")
    if rotation and not previous:
        raise core.ToolError("rotation=true is only valid for an already registered profile")
    if known_hosts.exists():
        _remove_known_host(cfg, known_hosts, timeout)
    with known_hosts.open("a", encoding="utf-8", newline="\n") as handle:
        for line in approved_lines:
            handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    event_type = "host-key-rotation-approved" if changed else (
        "host-key-registration-approved" if not previous else "host-key-reapproved"
    )
    approved_at = _now()
    registry["profiles"][cfg["profile"]] = {
        "host": cfg["host"],
        "port": cfg["port"],
        "fingerprints": [expected],
        "algorithms": [item["algorithm"] for item in approved_keys],
        "approvedAt": approved_at,
        "knownHostsFile": str(known_hosts),
    }
    registry["events"].append(
        {
            "event": event_type,
            "timestamp": approved_at,
            "profile": cfg["profile"],
            "previousFingerprints": previous_fingerprints,
            "fingerprints": [expected],
            "observedFingerprints": observed,
        }
    )
    _write(registry)
    return core.tool_result(
        {
            "ok": True,
            "profile": cfg["profile"],
            "event": event_type,
            "fingerprints": [expected],
            "algorithms": [item["algorithm"] for item in approved_keys],
            "knownHostsFile": str(known_hosts),
            "registeredAt": approved_at,
            "rotation": changed,
        }
    )


COMMON = {
    "profile": {"type": "string"},
    "timeout_seconds": {
        "type": "integer",
        "minimum": 1,
        "maximum": core.MAX_TIMEOUT_SECONDS,
    },
}


TOOLS: dict[str, dict[str, Any]] = {
    "remotex_ssh_host_key_status": {
        "description": (
            "Scan and compare SSH host fingerprints; unregistered or changed keys are blocked."
        ),
        "inputSchema": {
            "type": "object",
            "properties": COMMON,
            "additionalProperties": False,
        },
        "handler": status,
    },
    "remotex_ssh_host_key_approve": {
        "description": (
            "Explicitly register or rotate a scanned SSH host key and update known_hosts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON,
                "fingerprint": {"type": "string"},
                "confirm": {"type": "boolean"},
                "rotation": {"type": "boolean"},
            },
            "required": ["fingerprint", "confirm"],
            "additionalProperties": False,
        },
        "handler": approve,
    },
}
