from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .validation import (
    ValidationError,
    normalize_ref_list,
    require_event_id,
    require_non_empty_string,
    require_positive_int,
    require_sha256_digest,
    require_sha256_hex,
)


@dataclass(frozen=True)
class GitLabGateEvidence:
    adapter_contract: str
    provider: str
    verdict: str
    event_id: str
    round_id: int
    request_digest: str
    policy_digest: str
    manifest_digest: str
    material_sha256: str
    evidence_refs: tuple[str, ...]
    pipeline_ref: str = ""
    job_ref: str = ""
    artifact_ref: str = ""


class GateAdapterContractError(RuntimeError):
    """Raised when a gate-adapter payload cannot be trusted as canonical evidence."""


def validate_gitlab_gate_result(
    payload: Mapping[str, Any],
    *,
    expected_bindings: Mapping[str, Any] | None = None,
) -> GitLabGateEvidence:
    try:
        adapter_contract = require_non_empty_string(payload, "adapter_contract")
        if adapter_contract != "GitLabGateResult/v1":
            raise ValidationError("adapter_contract must be the exact value GitLabGateResult/v1.")
        provider = require_non_empty_string(payload, "provider").lower()
        if provider != "gitlab":
            raise ValidationError("provider must be gitlab.")
        verdict = require_non_empty_string(payload, "verdict").upper()
        if verdict != "CLEAN":
            raise ValidationError("verdict must be CLEAN.")
        evidence = GitLabGateEvidence(
            adapter_contract=adapter_contract,
            provider=provider,
            verdict=verdict,
            event_id=require_event_id(payload),
            round_id=require_positive_int(payload, "round_id"),
            request_digest=require_sha256_digest(payload, "request_digest"),
            policy_digest=require_sha256_digest(payload, "policy_digest"),
            manifest_digest=require_sha256_digest(payload, "manifest_digest"),
            material_sha256=require_sha256_hex(payload.get("material_sha256"), field_name="material_sha256"),
            evidence_refs=normalize_ref_list(payload.get("evidence_refs", []), field_name="evidence_refs"),
            pipeline_ref=str(payload.get("pipeline_ref") or "").strip(),
            job_ref=str(payload.get("job_ref") or "").strip(),
            artifact_ref=str(payload.get("artifact_ref") or "").strip(),
        )
        if not evidence.evidence_refs:
            raise ValidationError("evidence_refs must not be empty.")
        if expected_bindings is not None:
            _verify_bindings(evidence, expected_bindings)
        return evidence
    except ValidationError as exc:
        raise GateAdapterContractError(str(exc)) from exc


def _verify_bindings(evidence: GitLabGateEvidence, expected_bindings: Mapping[str, Any]) -> None:
    for field_name in ("event_id", "round_id", "request_digest", "policy_digest", "manifest_digest"):
        if field_name not in expected_bindings:
            continue
        if str(getattr(evidence, field_name)) != str(expected_bindings[field_name]):
            raise GateAdapterContractError(f"gate adapter binding mismatch: {field_name}.")
    if "material_sha256" in expected_bindings:
        expected_material = str(expected_bindings["material_sha256"] or "").strip().lower()
        if expected_material.startswith("sha256:"):
            expected_material = expected_material[7:]
        if evidence.material_sha256 != expected_material:
            raise GateAdapterContractError("gate adapter binding mismatch: material_sha256.")
    if "evidence_refs" in expected_bindings:
        expected_refs = tuple(
            sorted(dict.fromkeys(str(item).strip() for item in expected_bindings["evidence_refs"] or [] if str(item).strip()))
        )
        if evidence.evidence_refs != expected_refs:
            raise GateAdapterContractError("gate adapter binding mismatch: evidence_refs.")
