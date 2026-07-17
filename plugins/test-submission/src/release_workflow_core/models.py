from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .validation import (
    ValidationError,
    normalize_email,
    normalize_ref_list,
    normalize_string_sequence,
    optional_positive_int,
    optional_rfc3339,
    optional_sha256_digest,
    optional_string,
    require_event_id,
    require_mapping,
    require_module,
    require_non_empty_string,
    require_positive_int,
    require_rfc3339,
    require_schema,
    require_sha1,
    require_sha256_digest,
    require_sha256_hex,
)


SUBMISSION_SCHEMA = "ProductMaterialSubmission/v1"
WORKFLOW_SCHEMA = "ProductMaterialWorkflow/v1"
_RETRIEVAL_METHODS = frozenset(("local", "unc", "https", "gitlab-package", "ssh", "svn"))


def _optional_submitter_email(payload: Mapping[str, Any]) -> str:
    candidate = payload.get("submitter_email")
    if candidate in (None, ""):
        candidate = payload.get("sender_email")
    return normalize_email(candidate, field_name="submitter_email")


@dataclass(frozen=True)
class ProductMaterialArtifact:
    logical_name: str
    retrieval_method: str
    server_url: str = ""
    repository_path: str = ""
    revision: str = ""
    retrieval_instructions: str = ""
    version: str = ""
    source_ref: str = ""
    material_sha256: str = ""
    material_sha1: str = ""
    size: int = 0

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ProductMaterialArtifact":
        logical_name = require_non_empty_string(payload, "logical_name")
        retrieval_method = (optional_string(payload, "retrieval_method") or "local").lower()
        if retrieval_method not in _RETRIEVAL_METHODS:
            raise ValidationError(
                f"retrieval_method must be one of: {', '.join(sorted(_RETRIEVAL_METHODS))}."
            )
        server_url = optional_string(payload, "server_url")
        repository_path = optional_string(payload, "repository_path") or optional_string(payload, "source_locator")
        revision = optional_string(payload, "revision")
        retrieval_instructions = optional_string(payload, "retrieval_instructions")
        version = optional_string(payload, "version")
        source_ref = optional_string(payload, "source_ref")
        size = payload.get("size", 0)
        if type(size) is not int or size < 0:
            raise ValidationError("artifact size must be a non-negative integer.")
        material_sha256 = optional_string(payload, "material_sha256").lower()
        material_sha1 = optional_string(payload, "material_sha1").lower()
        if material_sha256:
            material_sha256 = require_sha256_hex(material_sha256, field_name="material_sha256")
        if material_sha1:
            material_sha1 = require_sha1(material_sha1, field_name="material_sha1")

        if retrieval_method == "svn":
            if not repository_path:
                raise ValidationError("svn artifacts require repository_path or source_locator.")
            if not revision:
                raise ValidationError("svn artifacts require a fixed revision.")
            if not version:
                raise ValidationError("svn artifacts require a sender-declared version.")
        else:
            if not material_sha256 or not material_sha1:
                raise ValidationError(
                    "non-svn artifacts require material_sha256 and material_sha1 sender inputs."
                )

        return cls(
            logical_name=logical_name,
            retrieval_method=retrieval_method,
            server_url=server_url,
            repository_path=repository_path,
            revision=revision,
            retrieval_instructions=retrieval_instructions,
            version=version,
            source_ref=source_ref,
            material_sha256=material_sha256,
            material_sha1=material_sha1,
            size=size,
        )

    def to_mapping(self) -> dict[str, Any]:
        payload = {
            "logical_name": self.logical_name,
            "retrieval_method": self.retrieval_method,
            "server_url": self.server_url,
            "repository_path": self.repository_path,
            "revision": self.revision,
            "retrieval_instructions": self.retrieval_instructions,
            "version": self.version,
            "source_ref": self.source_ref,
            "material_sha256": self.material_sha256,
            "material_sha1": self.material_sha1,
            "size": self.size,
        }
        return {key: value for key, value in payload.items() if value not in ("", None)}


@dataclass(frozen=True)
class ProductMaterialSubmission:
    schema: str
    event_id: str
    round_id: int
    task: str
    module: str
    created_at: str
    policy_profile: str
    effective_checks: tuple[str, ...]
    artifacts: tuple[ProductMaterialArtifact, ...]
    submitter_email: str = ""
    retrieval_method: str = "local"
    source_locator: str = ""
    revision: str = ""
    retrieval_instructions: str = ""
    version: str = ""
    change_summary: str = ""
    expected_delivery_at: str = ""
    evidence_refs: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ProductMaterialSubmission":
        require_schema(payload, expected=SUBMISSION_SCHEMA)
        retrieval_method = (optional_string(payload, "retrieval_method") or "local").lower()
        if retrieval_method not in _RETRIEVAL_METHODS:
            raise ValidationError(
                f"retrieval_method must be one of: {', '.join(sorted(_RETRIEVAL_METHODS))}."
            )
        artifacts_value = payload.get("artifacts", [])
        if not isinstance(artifacts_value, list):
            raise ValidationError("artifacts must be a list.")
        artifacts = tuple(
            ProductMaterialArtifact.from_mapping(require_mapping(item, field_name="artifact"))
            for item in artifacts_value
        )
        source_locator = optional_string(payload, "source_locator") or optional_string(payload, "repository_path")
        revision = optional_string(payload, "revision")
        version = optional_string(payload, "version")
        retrieval_instructions = optional_string(payload, "retrieval_instructions")

        if retrieval_method == "svn":
            if not source_locator:
                raise ValidationError("svn submissions require source_locator or repository_path.")
            if not revision:
                raise ValidationError("svn submissions require a fixed revision.")
            if not version:
                raise ValidationError("svn submissions require a sender-declared version.")
        elif not artifacts:
            raise ValidationError("non-svn submissions require at least one declared artifact.")

        return cls(
            schema=SUBMISSION_SCHEMA,
            event_id=require_event_id(payload),
            round_id=require_positive_int(payload, "round_id"),
            task=require_non_empty_string(payload, "task"),
            module=require_module(payload),
            created_at=require_rfc3339(payload, "created_at"),
            policy_profile=require_non_empty_string(payload, "policy_profile"),
            effective_checks=normalize_string_sequence(
                payload.get("effective_checks"), field_name="effective_checks"
            ),
            artifacts=artifacts,
            submitter_email=_optional_submitter_email(payload),
            retrieval_method=retrieval_method,
            source_locator=source_locator,
            revision=revision,
            retrieval_instructions=retrieval_instructions,
            version=version,
            change_summary=optional_string(payload, "change_summary"),
            expected_delivery_at=optional_rfc3339(payload, "expected_delivery_at"),
            evidence_refs=normalize_ref_list(payload.get("evidence_refs", []), field_name="evidence_refs"),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "event_id": self.event_id,
            "round_id": self.round_id,
            "task": self.task,
            "module": self.module,
            "created_at": self.created_at,
            "policy_profile": self.policy_profile,
            "effective_checks": list(self.effective_checks),
            "artifacts": [artifact.to_mapping() for artifact in self.artifacts],
            "submitter_email": self.submitter_email,
            "retrieval_method": self.retrieval_method,
            "source_locator": self.source_locator,
            "revision": self.revision,
            "retrieval_instructions": self.retrieval_instructions,
            "version": self.version,
            "change_summary": self.change_summary,
            "expected_delivery_at": self.expected_delivery_at,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class ProductMaterialWorkflow:
    schema: str
    event_id: str
    round_id: int
    event_type: str
    state: str
    task: str
    module: str
    created_at: str
    policy_profile: str
    policy_digest: str
    evidence_refs: tuple[str, ...]
    submitter_email: str = ""
    provenance_classification: str = ""
    parent_event_id: str = ""
    parent_round_id: int | None = None
    manifest_s_digest: str = ""
    manifest_r_digest: str = ""
    manifest_digest: str = ""
    request_digest: str = ""
    test_result: str = ""
    gate_verdict: str = ""
    failure_reason: str = ""

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ProductMaterialWorkflow":
        require_schema(payload, expected=WORKFLOW_SCHEMA)
        parent_event_id = optional_string(payload, "parent_event_id")
        parent_round_id = optional_positive_int(payload, "parent_round_id")
        if bool(parent_event_id) != bool(parent_round_id):
            raise ValidationError(
                "parent_event_id and parent_round_id must either both be present or both be absent."
            )
        if parent_event_id:
            require_event_id({"event_id": parent_event_id})
        return cls(
            schema=WORKFLOW_SCHEMA,
            event_id=require_event_id(payload),
            round_id=require_positive_int(payload, "round_id"),
            event_type=require_non_empty_string(payload, "event_type"),
            state=require_non_empty_string(payload, "state"),
            task=require_non_empty_string(payload, "task"),
            module=require_module(payload),
            created_at=require_rfc3339(payload, "created_at"),
            policy_profile=require_non_empty_string(payload, "policy_profile"),
            policy_digest=require_sha256_digest(payload, "policy_digest"),
            evidence_refs=normalize_ref_list(payload.get("evidence_refs", []), field_name="evidence_refs"),
            submitter_email=_optional_submitter_email(payload),
            provenance_classification=optional_string(payload, "provenance_classification"),
            parent_event_id=parent_event_id,
            parent_round_id=parent_round_id,
            manifest_s_digest=optional_sha256_digest(payload, "manifest_s_digest"),
            manifest_r_digest=optional_sha256_digest(payload, "manifest_r_digest"),
            manifest_digest=optional_sha256_digest(payload, "manifest_digest"),
            request_digest=optional_sha256_digest(payload, "request_digest"),
            test_result=optional_string(payload, "test_result").upper(),
            gate_verdict=optional_string(payload, "gate_verdict").upper(),
            failure_reason=optional_string(payload, "failure_reason"),
        )

    def to_mapping(self) -> dict[str, Any]:
        payload = {
            "schema": self.schema,
            "event_id": self.event_id,
            "round_id": self.round_id,
            "event_type": self.event_type,
            "state": self.state,
            "task": self.task,
            "module": self.module,
            "created_at": self.created_at,
            "policy_profile": self.policy_profile,
            "policy_digest": self.policy_digest,
            "evidence_refs": list(self.evidence_refs),
            "submitter_email": self.submitter_email,
            "provenance_classification": self.provenance_classification,
            "parent_event_id": self.parent_event_id,
            "parent_round_id": self.parent_round_id,
            "manifest_s_digest": self.manifest_s_digest,
            "manifest_r_digest": self.manifest_r_digest,
            "manifest_digest": self.manifest_digest,
            "request_digest": self.request_digest,
            "test_result": self.test_result,
            "gate_verdict": self.gate_verdict,
            "failure_reason": self.failure_reason,
        }
        return {key: value for key, value in payload.items() if value not in ("", None, [])}


def validate_submission_payload(payload: Mapping[str, Any]) -> ProductMaterialSubmission:
    return ProductMaterialSubmission.from_mapping(payload)


def validate_workflow_payload(payload: Mapping[str, Any]) -> ProductMaterialWorkflow:
    return ProductMaterialWorkflow.from_mapping(payload)
