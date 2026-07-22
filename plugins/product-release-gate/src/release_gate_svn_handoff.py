from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse


WORKFLOW_SCHEMA = "ProductMaterialWorkflow/v1"
WORKFLOW_STAGE = "RELEASE_GATE_REQUESTED"
MANIFEST_R_SCHEMA = "ProductReleaseGateManifestR/v1"
VERIFIED_RECEIPT_SCHEMA = "ProductMaterialGateVerifiedReceipt/v1"

_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
_SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class SvnGateContractError(RuntimeError):
    """A deterministic, fail-closed SVN release-gate contract error."""


def _canonical_bytes(value: Any, *, ensure_ascii: bool) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def manifest_r_digest(manifest_r: Mapping[str, Any]) -> str:
    payload = {
        "source_manifest_s_digest": manifest_r.get("source_manifest_s_digest"),
        "artifacts": manifest_r.get("artifacts"),
    }
    return hashlib.sha256(_canonical_bytes(payload, ensure_ascii=True)).hexdigest()


def workflow_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical_bytes(value, ensure_ascii=False)
    ).hexdigest()


def _nonempty_line(value: Any, label: str) -> str:
    normalized = str(value or "").strip()
    if not normalized or any(character in normalized for character in "\r\n"):
        raise SvnGateContractError(f"{label} must be one non-empty line")
    return normalized


def _identifier(value: Any, label: str) -> str:
    normalized = _nonempty_line(value, label)
    if _ID_PATTERN.fullmatch(normalized) is None:
        raise SvnGateContractError(f"{label} contains unsafe characters")
    return normalized


def _digest(value: Any, label: str) -> str:
    normalized = str(value or "").strip().lower()
    if _DIGEST_PATTERN.fullmatch(normalized) is None:
        raise SvnGateContractError(
            f"{label} must be sha256:<64 lowercase hex characters>"
        )
    return normalized


def _timestamp(value: Any, label: str) -> str:
    normalized = _nonempty_line(value, label)
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SvnGateContractError(
            f"{label} must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise SvnGateContractError(f"{label} must include a timezone")
    return normalized


def _relative_path(value: Any, label: str) -> str:
    normalized = _nonempty_line(value, label).replace("\\", "/")
    if (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
    ):
        raise SvnGateContractError(f"{label} must be a safe relative path")
    return normalized


def _manifest_artifacts(
    manifest_r: Mapping[str, Any],
    *,
    event_id: str,
) -> dict[str, Mapping[str, Any]]:
    if manifest_r.get("schema") != MANIFEST_R_SCHEMA:
        raise SvnGateContractError(
            f"Manifest-R schema must be {MANIFEST_R_SCHEMA}"
        )
    if manifest_r.get("phase") != "Manifest-R":
        raise SvnGateContractError("Manifest-R phase is invalid")
    if manifest_r.get("event_id") != event_id:
        raise SvnGateContractError("Manifest-R event_id does not match the event")
    source_digest = manifest_r.get("source_manifest_s_digest")
    if not isinstance(source_digest, str) or _SHA256_PATTERN.fullmatch(source_digest) is None:
        raise SvnGateContractError("Manifest-R source digest is invalid")
    artifacts = manifest_r.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise SvnGateContractError("Manifest-R artifacts must be non-empty")
    computed_digest = manifest_r_digest(manifest_r)
    if (
        manifest_r.get("digest") != computed_digest
        or _SHA256_PATTERN.fullmatch(computed_digest) is None
    ):
        raise SvnGateContractError("Manifest-R semantic digest is invalid")

    by_name: dict[str, Mapping[str, Any]] = {}
    folded_names: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, Mapping):
            raise SvnGateContractError(
                f"Manifest-R artifacts[{index}] must be an object"
            )
        logical_name = str(artifact.get("logical_name") or "")
        folded_name = logical_name.casefold()
        if (
            not logical_name
            or logical_name in {".", ".."}
            or any(character in logical_name for character in "/\\\r\n")
            or folded_name in folded_names
        ):
            raise SvnGateContractError(
                "Manifest-R logical names must be unique portable file names"
            )
        sha1 = artifact.get("sha1")
        sha256 = artifact.get("sha256")
        size = artifact.get("size")
        if (
            not isinstance(sha1, str)
            or _SHA1_PATTERN.fullmatch(sha1) is None
            or not isinstance(sha256, str)
            or _SHA256_PATTERN.fullmatch(sha256) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 1
        ):
            raise SvnGateContractError(
                f"Manifest-R artifact binding is invalid: {logical_name}"
            )
        folded_names.add(folded_name)
        by_name[logical_name] = artifact
    return by_name


def build_svn_handoff(
    *,
    event_id: str,
    manifest_r: Mapping[str, Any],
    product_name: str,
    product_version: str,
    repository_root: str,
    fixed_revision: int,
    pipeline_nonce: str,
    materials: Sequence[Mapping[str, Any]],
    pre_release_report_sha256: str,
    source_message_id: str,
    created_at: str,
) -> dict[str, Any]:
    normalized_event_id = _identifier(event_id, "event_id")
    normalized_nonce = _identifier(pipeline_nonce, "pipeline_nonce")
    normalized_product = _nonempty_line(product_name, "product_name")
    normalized_version = _nonempty_line(product_version, "product_version")
    normalized_repository = _nonempty_line(repository_root, "repository_root")
    parsed_repository = urlparse(normalized_repository)
    if (
        parsed_repository.scheme.casefold() != "https"
        or not parsed_repository.netloc
        or parsed_repository.username is not None
        or parsed_repository.password is not None
        or parsed_repository.query
        or parsed_repository.fragment
    ):
        raise SvnGateContractError(
            "repository_root must be an HTTPS URL without credentials, query, or fragment"
        )
    if (
        not isinstance(fixed_revision, int)
        or isinstance(fixed_revision, bool)
        or fixed_revision < 1
    ):
        raise SvnGateContractError("fixed_revision must be a positive integer")
    if not isinstance(materials, Sequence) or isinstance(
        materials, (str, bytes)
    ) or not materials:
        raise SvnGateContractError("materials must be a non-empty array")

    manifest_by_name = _manifest_artifacts(
        manifest_r,
        event_id=normalized_event_id,
    )
    release_materials: list[dict[str, Any]] = []
    mapped_names: set[str] = set()
    folded_ids: set[str] = set()
    folded_paths: set[str] = set()
    folded_svn_paths: set[str] = set()
    for index, material in enumerate(materials):
        if not isinstance(material, Mapping):
            raise SvnGateContractError(f"materials[{index}] must be an object")
        logical_name = _nonempty_line(
            material.get("logical_name"),
            f"materials[{index}].logical_name",
        )
        if logical_name in mapped_names or logical_name not in manifest_by_name:
            raise SvnGateContractError(
                "material logical names must map exactly once to Manifest-R"
            )
        material_id = _identifier(
            material.get("id", logical_name),
            f"materials[{index}].id",
        )
        material_path = _relative_path(
            material.get("path", f"materials/{logical_name}"),
            f"materials[{index}].path",
        )
        svn_path = _relative_path(
            material.get("svn_path"),
            f"materials[{index}].svn_path",
        )
        if (
            material_id.casefold() in folded_ids
            or material_path.casefold() in folded_paths
            or svn_path.casefold() in folded_svn_paths
        ):
            raise SvnGateContractError(
                "material id, path, and svn_path must each be unique"
            )
        artifact = manifest_by_name[logical_name]
        release_materials.append(
            {
                "id": material_id,
                "path": material_path,
                "svn_path": svn_path,
                "manifest_logical_name": logical_name,
                "expected_sha1": artifact["sha1"],
                "expected_sha256": artifact["sha256"],
                "expected_size_bytes": artifact["size"],
            }
        )
        mapped_names.add(logical_name)
        folded_ids.add(material_id.casefold())
        folded_paths.add(material_path.casefold())
        folded_svn_paths.add(svn_path.casefold())
    if mapped_names != set(manifest_by_name):
        raise SvnGateContractError(
            "materials must exactly cover every Manifest-R artifact"
        )

    request = {
        "request_id": normalized_event_id,
        "pipeline_nonce": normalized_nonce,
        "product": {
            "name": normalized_product,
            "version": normalized_version,
        },
        "svn": {
            "repository_root": normalized_repository,
            "fixed_revision": fixed_revision,
        },
        "release_materials": release_materials,
    }
    return {
        "schema": WORKFLOW_SCHEMA,
        "stage": WORKFLOW_STAGE,
        "event_id": normalized_event_id,
        "request": request,
        "request_sha256": workflow_digest(request),
        "source": {
            "pre_release_status": "PASS",
            "pre_release_report_sha256": _digest(
                pre_release_report_sha256,
                "pre_release_report_sha256",
            ),
            "manifest_sha256": "sha256:" + str(manifest_r["digest"]),
            "source_message_id": _nonempty_line(
                source_message_id,
                "source_message_id",
            ),
        },
        "created_at": _timestamp(created_at, "created_at"),
    }


def validate_verified_receipt(
    payload: Mapping[str, Any],
    *,
    event_id: str,
    request_sha256: str,
    manifest_r_digest: str,
    expected_project_id: int,
) -> dict[str, Any]:
    required_fields = {
        "schema",
        "verification_status",
        "verdict",
        "event_id",
        "request_sha256",
        "manifest_r_digest",
        "project_id",
        "pipeline_id",
        "job_id",
        "commit_sha",
        "gate_result_sha256",
        "artifact_manifest_sha256",
        "evidence_ref",
        "verified_at",
    }
    if not isinstance(payload, Mapping) or set(payload) != required_fields:
        raise SvnGateContractError(
            "verified receipt fields do not match the v1 contract"
        )
    if payload.get("schema") != VERIFIED_RECEIPT_SCHEMA:
        raise SvnGateContractError("verified receipt schema is invalid")
    if payload.get("verification_status") != "VERIFIED":
        raise SvnGateContractError("receipt was not independently verified")
    verdict = str(payload.get("verdict") or "").upper()
    if verdict not in {"CLEAN", "BLOCKED"}:
        raise SvnGateContractError("verified receipt verdict is invalid")
    normalized_event_id = _identifier(payload.get("event_id"), "receipt event_id")
    if normalized_event_id != _identifier(event_id, "event_id"):
        raise SvnGateContractError("receipt event_id does not match")
    normalized_request_digest = _digest(
        payload.get("request_sha256"),
        "receipt request_sha256",
    )
    if normalized_request_digest != _digest(request_sha256, "request_sha256"):
        raise SvnGateContractError("receipt request digest does not match")
    normalized_manifest_digest = _digest(
        payload.get("manifest_r_digest"),
        "receipt manifest_r_digest",
    )
    expected_manifest_digest = _digest(
        "sha256:" + str(manifest_r_digest).removeprefix("sha256:"),
        "manifest_r_digest",
    )
    if normalized_manifest_digest != expected_manifest_digest:
        raise SvnGateContractError("receipt Manifest-R digest does not match")
    project_id = payload.get("project_id")
    if (
        not isinstance(project_id, int)
        or isinstance(project_id, bool)
        or project_id != expected_project_id
    ):
        raise SvnGateContractError("receipt GitLab project does not match")
    for field in ("pipeline_id", "job_id"):
        value = payload.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise SvnGateContractError(f"receipt {field} must be positive")
    commit_sha = str(payload.get("commit_sha") or "").lower()
    if _COMMIT_PATTERN.fullmatch(commit_sha) is None:
        raise SvnGateContractError("receipt commit_sha must be 40 lowercase hex")
    gate_result_sha256 = _digest(
        payload.get("gate_result_sha256"),
        "receipt gate_result_sha256",
    )
    artifact_manifest_sha256 = _digest(
        payload.get("artifact_manifest_sha256"),
        "receipt artifact_manifest_sha256",
    )
    evidence_ref = _nonempty_line(payload.get("evidence_ref"), "evidence_ref")
    verified_at = _timestamp(payload.get("verified_at"), "verified_at")
    return {
        "schema": VERIFIED_RECEIPT_SCHEMA,
        "verification_status": "VERIFIED",
        "verdict": verdict,
        "event_id": normalized_event_id,
        "request_sha256": normalized_request_digest,
        "manifest_r_digest": normalized_manifest_digest,
        "project_id": project_id,
        "pipeline_id": payload["pipeline_id"],
        "job_id": payload["job_id"],
        "commit_sha": commit_sha,
        "gate_result_sha256": gate_result_sha256,
        "artifact_manifest_sha256": artifact_manifest_sha256,
        "evidence_ref": evidence_ref,
        "verified_at": verified_at,
    }
