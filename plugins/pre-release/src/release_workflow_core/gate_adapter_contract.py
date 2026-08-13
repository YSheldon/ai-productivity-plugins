from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from .validation import (
    ValidationError,
    canonical_json,
    freeze_digest,
    normalize_ref_list,
    normalize_string_sequence,
    require_event_id,
    require_mapping,
    require_module,
    require_non_empty_string,
    require_positive_int,
    require_schema,
    require_sha1,
    require_sha256_digest,
    require_sha256_hex,
)


_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_MANIFEST_S_KEYS = frozenset(
    {
        "schema",
        "event_id",
        "round_id",
        "task",
        "module",
        "policy_profile",
        "policy_digest",
        "effective_checks",
        "artifacts",
        "evidence_refs",
        "manifest_s_digest",
    }
)
_ARTIFACT_KEYS = frozenset(
    {"logical_name", "file_name", "size", "sha1", "sha256", "source_ref"}
)
_VALID_RISK_LEVELS = frozenset({"standard", "high", "emergency"})
_MAX_REFERENCE_LENGTH = 4096


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
    task: str
    module: str
    manifest_s: Mapping[str, Any]
    rollback_ref: str
    risk_level: str
    lark_evidence_ref: str
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
        manifest_s = validate_manifest_s(
            require_mapping(payload.get("manifest_s"), field_name="manifest_s")
        )
        evidence_refs = _reference_list(
            payload.get("evidence_refs", []), field_name="evidence_refs"
        )
        material_sha256 = require_sha256_hex(
            payload.get("material_sha256"),
            field_name="material_sha256",
        )
        manifest_artifacts = manifest_s["artifacts"]
        expected_material_sha256 = (
            manifest_artifacts[0]["sha256"]
            if len(manifest_artifacts) == 1
            else hashlib.sha256(
                canonical_json(manifest_artifacts).encode("utf-8")
            ).hexdigest()
        )
        if material_sha256 != expected_material_sha256:
            raise ValidationError(
                "material_sha256 must bind the exact Manifest-S artifact set."
            )
        if evidence_refs != tuple(sorted(manifest_s["evidence_refs"])):
            raise ValidationError(
                "evidence_refs must match the Manifest-S evidence_refs."
            )
        manifest_digest = require_sha256_digest(payload, "manifest_digest")
        if manifest_digest != manifest_s["manifest_s_digest"]:
            raise ValidationError(
                "manifest_digest must match manifest_s.manifest_s_digest."
            )
        policy_digest = require_sha256_digest(payload, "policy_digest")
        if policy_digest != manifest_s["policy_digest"]:
            raise ValidationError(
                "policy_digest must match manifest_s.policy_digest."
            )
        evidence = GitLabGateEvidence(
            adapter_contract=adapter_contract,
            provider=provider,
            verdict=verdict,
            event_id=require_event_id(payload),
            round_id=require_positive_int(payload, "round_id"),
            request_digest=require_sha256_digest(payload, "request_digest"),
            policy_digest=policy_digest,
            manifest_digest=manifest_digest,
            material_sha256=material_sha256,
            evidence_refs=evidence_refs,
            task=str(manifest_s["task"]),
            module=str(manifest_s["module"]),
            manifest_s=manifest_s,
            rollback_ref=_reference(
                payload.get("rollback_ref"),
                field_name="rollback_ref",
                required=True,
            ),
            risk_level=_risk_level(payload.get("risk_level", "standard")),
            lark_evidence_ref=_reference(
                payload.get("lark_evidence_ref"),
                field_name="lark_evidence_ref",
                required=False,
            ),
            pipeline_ref=_reference(
                payload.get("pipeline_ref"),
                field_name="pipeline_ref",
                required=False,
            ),
            job_ref=_reference(
                payload.get("job_ref"),
                field_name="job_ref",
                required=False,
            ),
            artifact_ref=_reference(
                payload.get("artifact_ref"),
                field_name="artifact_ref",
                required=False,
            ),
        )
        if not evidence.evidence_refs:
            raise ValidationError("evidence_refs must not be empty.")
        if expected_bindings is not None:
            _verify_bindings(evidence, expected_bindings)
        return evidence
    except ValidationError as exc:
        raise GateAdapterContractError(str(exc)) from exc


def validate_manifest_s(
    payload: Mapping[str, Any],
    *,
    expected_bindings: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if set(payload) != _MANIFEST_S_KEYS:
        raise ValidationError(
            "Manifest-S fields must exactly match ProductMaterialManifestS/v1."
        )
    require_schema(payload, expected="ProductMaterialManifestS/v1")
    event_id = require_event_id(payload)
    round_id = require_positive_int(payload, "round_id")
    task = require_non_empty_string(payload, "task")
    module = require_module(payload)
    policy_profile = require_non_empty_string(payload, "policy_profile")
    policy_digest = require_sha256_digest(payload, "policy_digest")
    effective_checks = normalize_string_sequence(
        payload.get("effective_checks"),
        field_name="effective_checks",
    )
    evidence_refs = _reference_list(
        payload.get("evidence_refs"), field_name="evidence_refs"
    )
    if not evidence_refs:
        raise ValidationError("Manifest-S evidence_refs must not be empty.")
    raw_artifacts = payload.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise ValidationError("Manifest-S artifacts must be a non-empty list.")
    artifacts: list[dict[str, Any]] = []
    logical_names: set[str] = set()
    file_names: set[str] = set()
    for index, value in enumerate(raw_artifacts):
        artifact = require_mapping(value, field_name=f"artifacts[{index}]")
        if set(artifact) != _ARTIFACT_KEYS:
            raise ValidationError(
                f"artifacts[{index}] fields must exactly match the file binding contract."
            )
        logical_name = _portable_file_name(
            artifact.get("logical_name"),
            field_name=f"artifacts[{index}].logical_name",
        )
        file_name = _portable_file_name(
            artifact.get("file_name"),
            field_name=f"artifacts[{index}].file_name",
        )
        if logical_name.casefold() in logical_names:
            raise ValidationError("Manifest-S logical_name values must be unique case-insensitively.")
        if file_name.casefold() in file_names:
            raise ValidationError("Manifest-S file_name values must be unique case-insensitively.")
        logical_names.add(logical_name.casefold())
        file_names.add(file_name.casefold())
        size = artifact.get("size")
        if type(size) is not int or size < 0:
            raise ValidationError(f"artifacts[{index}].size must be a non-negative integer.")
        artifacts.append(
            {
                "logical_name": logical_name,
                "file_name": file_name,
                "size": size,
                "sha1": require_sha1(
                    artifact.get("sha1"),
                    field_name=f"artifacts[{index}].sha1",
                ),
                "sha256": require_sha256_hex(
                    artifact.get("sha256"),
                    field_name=f"artifacts[{index}].sha256",
                ),
                "source_ref": _reference(
                    artifact.get("source_ref"),
                    field_name=f"artifacts[{index}].source_ref",
                    required=True,
                ),
            }
        )
    claimed_digest = require_sha256_digest(payload, "manifest_s_digest")
    actual_digest = freeze_digest(payload, exclude=("manifest_s_digest",))
    if claimed_digest != actual_digest:
        raise ValidationError("Manifest-S digest does not match its frozen content.")
    normalized = {
        "schema": "ProductMaterialManifestS/v1",
        "event_id": event_id,
        "round_id": round_id,
        "task": task,
        "module": module,
        "policy_profile": policy_profile,
        "policy_digest": policy_digest,
        "effective_checks": list(effective_checks),
        "artifacts": artifacts,
        "evidence_refs": list(evidence_refs),
        "manifest_s_digest": claimed_digest,
    }
    if normalized != copy.deepcopy(dict(payload)):
        raise ValidationError("Manifest-S values must already be in canonical normalized form.")
    if expected_bindings is not None:
        for field_name in (
            "event_id",
            "round_id",
            "task",
            "module",
            "policy_digest",
            "manifest_s_digest",
        ):
            if field_name in expected_bindings and str(normalized[field_name]) != str(
                expected_bindings[field_name]
            ):
                raise ValidationError(f"Manifest-S binding mismatch: {field_name}.")
    return normalized


def _portable_file_name(value: Any, *, field_name: str) -> str:
    raw = str(value or "")
    name = raw.strip()
    stem = name.split(".", 1)[0].casefold()
    if (
        not name
        or raw != name
        or name in {".", ".."}
        or name.endswith(".")
        or "/" in name
        or "\\" in name
        or ":" in name
        or any(ord(character) < 32 for character in name)
        or stem in _WINDOWS_RESERVED_NAMES
    ):
        raise ValidationError(f"{field_name} must be one portable file name.")
    return name


def _reference(value: Any, *, field_name: str, required: bool) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string.")
    normalized = value.strip()
    if required and not normalized:
        raise ValidationError(f"{field_name} must be a non-empty string.")
    if not normalized:
        return ""
    if len(normalized) > _MAX_REFERENCE_LENGTH:
        raise ValidationError(
            f"{field_name} must not exceed {_MAX_REFERENCE_LENGTH} characters."
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValidationError(f"{field_name} must be a single-line reference.")
    return normalized


def _reference_list(value: Any, *, field_name: str) -> tuple[str, ...]:
    normalized = normalize_ref_list(value, field_name=field_name)
    return tuple(
        _reference(item, field_name=f"{field_name}[]", required=True)
        for item in normalized
    )


def _risk_level(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("risk_level must be a string.")
    normalized = value.strip().lower()
    if normalized not in _VALID_RISK_LEVELS:
        raise ValidationError(
            "risk_level must be one of: emergency, high, standard."
        )
    if value != normalized:
        raise ValidationError("risk_level must already be in canonical lowercase form.")
    return normalized


def _verify_bindings(evidence: GitLabGateEvidence, expected_bindings: Mapping[str, Any]) -> None:
    for field_name in (
        "event_id",
        "round_id",
        "task",
        "module",
        "request_digest",
        "policy_digest",
        "manifest_digest",
    ):
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
