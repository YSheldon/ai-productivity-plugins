"""Build the explicit ProductMaterialWorkflow/v1 handoff for GitLab live gate."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

HANDOFF_SCHEMA = "ProductMaterialWorkflow/v1"
HANDOFF_STAGE = "RELEASE_GATE_REQUESTED"
DIGEST_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
MATERIAL_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class HandoffError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise HandoffError(f"{label} must be sha256:<64 hex characters>")
    return value.lower()


def _safe_relative(value: Any, label: str) -> str:
    path = str(value or "")
    if not path or path.startswith(("/", "\\")) or ":" in path or "\\" in path:
        raise HandoffError(f"{label} must be a relative forward-slash path")
    segments = path.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise HandoffError(f"{label} must not contain empty or dot segments")
    return path


def validate_request(request: Mapping[str, Any]) -> dict[str, Any]:
    required = {"request_id", "pipeline_nonce", "product", "svn", "release_materials"}
    if set(request) != required:
        raise HandoffError("request fields must match ProductMaterialWorkflow/v1 request schema")
    request_id = str(request["request_id"])
    nonce = str(request["pipeline_nonce"])
    if ID_RE.fullmatch(request_id) is None or ID_RE.fullmatch(nonce) is None:
        raise HandoffError("request_id and pipeline_nonce contain unsafe characters")
    product = request["product"]
    if not isinstance(product, Mapping) or set(product) != {"name", "version"}:
        raise HandoffError("product must contain only name and version")
    if not str(product["name"]).strip() or not str(product["version"]).strip():
        raise HandoffError("product name and version are required")
    svn = request["svn"]
    if not isinstance(svn, Mapping) or set(svn) != {"repository_root", "fixed_revision"}:
        raise HandoffError("svn must contain repository_root and fixed_revision")
    repository_root = str(svn["repository_root"])
    parsed = urlparse(repository_root)
    if parsed.scheme.casefold() != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise HandoffError("svn.repository_root must be an HTTPS URL without credentials")
    try:
        revision = int(svn["fixed_revision"])
    except (TypeError, ValueError) as exc:
        raise HandoffError("svn.fixed_revision must be a positive integer") from exc
    if revision < 1:
        raise HandoffError("svn.fixed_revision must be a positive integer")
    materials = request["release_materials"]
    if not isinstance(materials, list) or not materials:
        raise HandoffError("release_materials must contain at least one item")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(materials):
        if not isinstance(raw, Mapping) or set(raw) != {"id", "path", "svn_path"}:
            raise HandoffError(f"release_materials[{index}] fields are invalid")
        material_id = str(raw["id"])
        if MATERIAL_ID_RE.fullmatch(material_id) is None or material_id in seen:
            raise HandoffError(f"release_materials[{index}].id is invalid or duplicated")
        seen.add(material_id)
        normalized.append(
            {
                "id": material_id,
                "path": _safe_relative(raw["path"], f"release_materials[{index}].path"),
                "svn_path": _safe_relative(raw["svn_path"], f"release_materials[{index}].svn_path"),
            }
        )
    return {
        "request_id": request_id,
        "pipeline_nonce": nonce,
        "product": {"name": str(product["name"]), "version": str(product["version"])},
        "svn": {"repository_root": repository_root, "fixed_revision": revision},
        "release_materials": normalized,
    }


def build_handoff(
    *,
    event: Mapping[str, Any],
    manifest_r: Mapping[str, Any],
    request: Mapping[str, Any],
    pre_release_report_sha256: str,
    source_message_id: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    if str(event.get("status")) != "RELEASE_READY":
        raise HandoffError("live handoff requires event status RELEASE_READY")
    event_manifest = str(event.get("manifest_r_digest") or "")
    manifest_digest = str(manifest_r.get("digest") or "")
    if not event_manifest or event_manifest != manifest_digest:
        raise HandoffError("Manifest-R digest is missing or does not match the event")
    if not source_message_id or any(ch in source_message_id for ch in "\r\n"):
        raise HandoffError("source_message_id must be a single non-empty line")
    report_digest = _digest(pre_release_report_sha256, "pre_release_report_sha256")
    normalized_request = validate_request(request)
    timestamp = created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HandoffError("created_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise HandoffError("created_at must include a timezone")
    event_id = str(event.get("event_id") or "")
    if ID_RE.fullmatch(event_id) is None:
        raise HandoffError("event_id contains unsafe characters")
    return {
        "schema": HANDOFF_SCHEMA,
        "stage": HANDOFF_STAGE,
        "event_id": event_id,
        "request": normalized_request,
        "request_sha256": sha256_json(normalized_request),
        "source": {
            "pre_release_status": "PASS",
            "pre_release_report_sha256": report_digest,
            "manifest_sha256": "sha256:" + event_manifest.lower(),
            "source_message_id": source_message_id,
        },
        "created_at": timestamp,
    }


def write_handoff(path: str | os.PathLike[str], handoff: Mapping[str, Any]) -> str:
    destination = Path(os.path.expandvars(str(path))).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".pmg-handoff-", suffix=".tmp", dir=destination.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(canonical_json(handoff) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
    return str(destination)
