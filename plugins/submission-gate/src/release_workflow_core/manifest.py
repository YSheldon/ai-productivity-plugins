from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import ProductMaterialSubmission, ProductMaterialWorkflow, validate_submission_payload, validate_workflow_payload
from .validation import ValidationError, canonical_json, freeze_digest, require_sha256_digest


def bind_material_file(
    path: str | Path,
    *,
    logical_name: str | None = None,
    source_ref: str = "",
) -> dict[str, Any]:
    file_path = Path(path).resolve(strict=True)
    digest_sha1 = hashlib.sha1()
    digest_sha256 = hashlib.sha256()
    with file_path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest_sha1.update(block)
            digest_sha256.update(block)
    return {
        "logical_name": (logical_name or file_path.name).strip() or file_path.name,
        "file_name": file_path.name,
        "size": file_path.stat().st_size,
        "sha1": digest_sha1.hexdigest(),
        "sha256": digest_sha256.hexdigest(),
        "source_ref": str(source_ref or "").strip(),
    }


def build_manifest_s(
    submission: ProductMaterialSubmission | Mapping[str, Any],
    *,
    policy_digest: str,
    file_bindings: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    submission_model = (
        submission if isinstance(submission, ProductMaterialSubmission) else validate_submission_payload(submission)
    )
    policy_value = require_sha256_digest({"policy_digest": policy_digest}, "policy_digest")
    files = _sorted_bindings(file_bindings)
    if not files:
        raise ValidationError("manifest S requires at least one bound material file.")
    payload = {
        "schema": "ProductMaterialManifestS/v1",
        "event_id": submission_model.event_id,
        "round_id": submission_model.round_id,
        "task": submission_model.task,
        "module": submission_model.module,
        "policy_profile": submission_model.policy_profile,
        "policy_digest": policy_value,
        "effective_checks": list(submission_model.effective_checks),
        "artifacts": files,
        "evidence_refs": list(submission_model.evidence_refs),
    }
    payload["manifest_s_digest"] = freeze_digest(payload)
    return payload


def build_manifest_r(
    workflow: ProductMaterialWorkflow | Mapping[str, Any],
    *,
    manifest_s_digest: str,
    material_files: Iterable[Mapping[str, Any]] = (),
    evidence_refs: Iterable[str] = (),
) -> dict[str, Any]:
    workflow_model = (
        workflow if isinstance(workflow, ProductMaterialWorkflow) else validate_workflow_payload(workflow)
    )
    source_digest = require_sha256_digest({"manifest_s_digest": manifest_s_digest}, "manifest_s_digest")
    files = _sorted_bindings(material_files)
    refs = sorted(dict.fromkeys(str(item).strip() for item in evidence_refs if str(item).strip()))
    payload = {
        "schema": "ProductMaterialManifestR/v1",
        "event_id": workflow_model.event_id,
        "round_id": workflow_model.round_id,
        "task": workflow_model.task,
        "module": workflow_model.module,
        "event_type": workflow_model.event_type,
        "state": workflow_model.state,
        "source_manifest_s_digest": source_digest,
        "policy_digest": workflow_model.policy_digest,
        "material_files": files,
        "evidence_refs": refs or list(workflow_model.evidence_refs),
    }
    if workflow_model.parent_event_id:
        payload["parent_event_id"] = workflow_model.parent_event_id
        payload["parent_round_id"] = workflow_model.parent_round_id
    if workflow_model.test_result:
        payload["test_result"] = workflow_model.test_result
    if workflow_model.gate_verdict:
        payload["gate_verdict"] = workflow_model.gate_verdict
    payload["manifest_r_digest"] = freeze_digest(payload)
    return payload


def combined_manifest_digest(manifest_s_digest: str, manifest_r_digest: str) -> str:
    s_digest = require_sha256_digest({"manifest_s_digest": manifest_s_digest}, "manifest_s_digest")
    r_digest = require_sha256_digest({"manifest_r_digest": manifest_r_digest}, "manifest_r_digest")
    return "sha256:" + hashlib.sha256(
        canonical_json({"manifest_s_digest": s_digest, "manifest_r_digest": r_digest}).encode("utf-8")
    ).hexdigest()


def _sorted_bindings(file_bindings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in file_bindings:
        payload = dict(item)
        for key in ("logical_name", "file_name", "sha1", "sha256"):
            if not str(payload.get(key) or "").strip():
                raise ValidationError(f"file binding {key} is required.")
        size = payload.get("size")
        if type(size) is not int or size < 0:
            raise ValidationError("file binding size must be a non-negative integer.")
        normalized.append(
            {
                "logical_name": str(payload["logical_name"]).strip(),
                "file_name": str(payload["file_name"]).strip(),
                "size": size,
                "sha1": str(payload["sha1"]).strip().lower(),
                "sha256": str(payload["sha256"]).strip().lower(),
                "source_ref": str(payload.get("source_ref") or "").strip(),
            }
        )
    return sorted(normalized, key=lambda item: (item["logical_name"], item["sha256"], item["file_name"]))
