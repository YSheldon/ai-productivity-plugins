from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import credential_store
import remotex_core as core
import secure_paths


EVIDENCE_SCHEMA = "RemoteXCredentialEvidence/v1"
DEFAULT_MAX_AGE_SECONDS = 86_400


def evidence_path() -> Path:
    configured = os.environ.get("REMOTEX_CREDENTIAL_EVIDENCE_FILE")
    if configured:
        return core.expand_path(
            configured,
            "REMOTEX_CREDENTIAL_EVIDENCE_FILE",
        )
    if os.name == "nt":
        root = Path(
            os.environ.get("LOCALAPPDATA")
            or (core.DEFAULT_CONFIG_PATH.parents[2] / "AppData" / "Local")
        )
    else:
        root = Path(
            os.environ.get("XDG_STATE_HOME")
            or (core.DEFAULT_CONFIG_PATH.parents[2] / ".local" / "state")
        )
    return root / "RemoteX" / "credential-auth-evidence.json"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read() -> dict[str, Any]:
    path = evidence_path()
    if not path.exists():
        return {"schema": EVIDENCE_SCHEMA, "profiles": {}}
    status = secure_paths.private_path_status(path)
    if not status.get("ready"):
        raise core.ToolError("Credential authentication evidence protection is invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise core.ToolError("Credential authentication evidence is invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "profiles"}
        or value.get("schema") != EVIDENCE_SCHEMA
        or not isinstance(value.get("profiles"), dict)
    ):
        raise core.ToolError("Credential authentication evidence is invalid")
    return value


def _write(value: dict[str, Any]) -> None:
    path = evidence_path()
    secure_paths.ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        secure_paths.ensure_private_file(temporary)
        os.replace(temporary, path)
        secure_paths.ensure_private_file(path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def record_verified(profile: str, provider: str, endpoint_identity: str) -> dict[str, Any]:
    profile_name = core._required_text(profile, "profile")
    if len(profile_name) > 128:
        raise core.ToolError("profile is too long")
    source = str(provider or "").strip().lower()
    if source not in credential_store.PROVIDER_FIELDS:
        raise core.ToolError("credential evidence provider is unsupported")
    endpoint = core._required_text(endpoint_identity, "endpoint_identity")
    value = _read()
    verified_at = _timestamp(_now())
    entry = {
        "provider": source,
        "endpointSha256": hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
        "verified": True,
        "verifiedAt": verified_at,
    }
    value["profiles"][profile_name] = entry
    _write(value)
    return dict(entry)


def get_fresh(
    profile: str,
    provider: str,
    *,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any] | None:
    value = _read()
    entry = value["profiles"].get(profile)
    if not isinstance(entry, dict) or entry.get("provider") != provider:
        return None
    if (
        set(entry) != {"provider", "endpointSha256", "verified", "verifiedAt"}
        or entry.get("verified") is not True
        or not isinstance(entry.get("endpointSha256"), str)
    ):
        return None
    raw_timestamp = entry.get("verifiedAt")
    if not isinstance(raw_timestamp, str) or not raw_timestamp.endswith("Z"):
        return None
    try:
        verified_at = datetime.fromisoformat(raw_timestamp[:-1] + "+00:00")
    except ValueError:
        return None
    if _now() - verified_at > timedelta(seconds=max_age_seconds):
        return None
    return {
        "verified": True,
        "verifiedAt": raw_timestamp,
        "provider": provider,
        "endpointSha256": entry["endpointSha256"],
    }
