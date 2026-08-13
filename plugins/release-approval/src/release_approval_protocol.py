from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, TypeVar


_RFC_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_RFC3339_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_SHA256_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_CONTRACT = "ReleaseAuthorizationRequest/v1"
_AUTHORITY_SCOPES = frozenset(("PRODUCTION_RELEASE", "RD_FLYWHEEL_GOVERNANCE"))
_GOVERNANCE_AUTHORITY_BOUNDARY = "DESIGN_CONSENT_ONLY"
_TPage = TypeVar("_TPage")


class ProtocolError(ValueError):
    """Raised when a release-approval request payload is invalid."""


@dataclass(frozen=True)
class GovernanceDecisionContext:
    authority_boundary: str
    missing_capability: str
    originating_plugin: str
    originating_event_id: str
    checkpoint_digest: str
    required_evidence: tuple[str, ...]
    visual_companion_html_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "authority_boundary": self.authority_boundary,
            "missing_capability": self.missing_capability,
            "originating_plugin": self.originating_plugin,
            "originating_event_id": self.originating_event_id,
            "checkpoint_digest": self.checkpoint_digest,
            "required_evidence": list(self.required_evidence),
            "visual_companion_html_sha256": self.visual_companion_html_sha256,
        }


@dataclass(frozen=True)
class ReleaseAuthorizationRequest:
    contract: str
    authority_scope: str
    event_id: str
    round_id: int
    task: str
    module: str
    manifest_s_digest: str
    manifest_r_digest: str
    manifest_digest: str
    request_digest: str
    role_snapshot_digest: str
    required_roles: tuple[str, ...]
    original_message_id: str
    references: tuple[str, ...]
    expires_at: str
    idempotency_key: str
    installed_role_id: str
    installed_role_email: str
    governance_context: GovernanceDecisionContext | None = None
    wire_payload_json: str = ""


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_request_digest(payload: Mapping[str, Any]) -> str:
    digest_payload = {key: value for key, value in payload.items() if key != "request_digest"}
    return "sha256:" + hashlib.sha256(canonical_json(digest_payload).encode("utf-8")).hexdigest()


def _require_non_empty_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(f"{key} must be a non-empty string.")
    return value.strip()


def _require_message_id(value: str, *, field_name: str) -> str:
    if not _RFC_MESSAGE_ID_PATTERN.fullmatch(value):
        raise ProtocolError(f"{field_name} must be an exact RFC Message-ID like <id@example.com>.")
    return value


def _require_sha256_digest(payload: Mapping[str, Any], key: str) -> str:
    value = _require_non_empty_string(payload, key)
    if not _SHA256_DIGEST_PATTERN.fullmatch(value):
        raise ProtocolError(f"{key} must be a sha256:<64-hex> digest.")
    return value


def _require_raw_sha256_digest(payload: Mapping[str, Any], key: str) -> str:
    value = _require_non_empty_string(payload, key)
    if not _RAW_SHA256_DIGEST_PATTERN.fullmatch(value):
        raise ProtocolError(f"{key} must be 64 lowercase hexadecimal characters.")
    return value


def _require_unique_string_list(
    payload: Mapping[str, Any],
    key: str,
    *,
    maximum: int = 64,
) -> tuple[str, ...]:
    raw = payload.get(key)
    if not isinstance(raw, list) or not raw:
        raise ProtocolError(f"{key} must be a non-empty list.")
    if len(raw) > maximum:
        raise ProtocolError(f"{key} exceeds the supported item count.")
    normalized = tuple(
        value.strip()
        for value in raw
        if isinstance(value, str) and value.strip()
    )
    if len(normalized) != len(raw):
        raise ProtocolError(f"{key} must contain only non-empty strings.")
    if len(set(normalized)) != len(normalized):
        raise ProtocolError(f"{key} must not contain duplicates.")
    return normalized


def _validate_governance_context(
    payload: Mapping[str, Any],
    *,
    authority_scope: str,
    task: str,
    module: str,
    manifest_r_digest: str,
) -> GovernanceDecisionContext | None:
    raw_context = payload.get("governance_context")
    if authority_scope == "PRODUCTION_RELEASE":
        if "governance_context" in payload:
            raise ProtocolError(
                "governance_context is only valid for RD_FLYWHEEL_GOVERNANCE requests."
            )
        return None
    if not isinstance(raw_context, Mapping):
        raise ProtocolError(
            "governance_context is required for RD_FLYWHEEL_GOVERNANCE requests."
        )

    expected_keys = {
        "authority_boundary",
        "missing_capability",
        "originating_plugin",
        "originating_event_id",
        "checkpoint_digest",
        "required_evidence",
        "visual_companion_html_sha256",
    }
    if set(raw_context) != expected_keys:
        raise ProtocolError(
            "governance_context must contain exactly the supported frozen decision fields."
        )

    authority_boundary = _require_non_empty_string(raw_context, "authority_boundary")
    if authority_boundary != _GOVERNANCE_AUTHORITY_BOUNDARY:
        raise ProtocolError("governance_context authority_boundary is invalid.")
    missing_capability = _require_non_empty_string(raw_context, "missing_capability")
    originating_plugin = _require_non_empty_string(raw_context, "originating_plugin")
    originating_event_id = _require_non_empty_string(raw_context, "originating_event_id")
    checkpoint_digest = _require_raw_sha256_digest(raw_context, "checkpoint_digest")
    required_evidence = _require_unique_string_list(raw_context, "required_evidence")
    visual_digest = _require_sha256_digest(raw_context, "visual_companion_html_sha256")

    source_ref = _require_non_empty_string(payload, "source_ref")
    top_level_checkpoint = _require_raw_sha256_digest(payload, "checkpoint_digest")
    visual = payload.get("visual_companion")
    if not isinstance(visual, Mapping) or set(visual) != {"html_sha256", "authority"}:
        raise ProtocolError("visual_companion must contain html_sha256 and authority.")
    visual_authority = _require_non_empty_string(visual, "authority")
    visual_html_sha256 = _require_sha256_digest(visual, "html_sha256")

    bindings = (
        (missing_capability, task, "missing_capability/task"),
        (originating_plugin, module, "originating_plugin/module"),
        (originating_event_id, source_ref, "originating_event_id/source_ref"),
        (checkpoint_digest, top_level_checkpoint, "checkpoint_digest"),
        (visual_digest, visual_html_sha256, "visual_companion_html_sha256"),
        (visual_digest, manifest_r_digest, "visual_companion/manifest_r_digest"),
        (authority_boundary, visual_authority, "authority_boundary"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            raise ProtocolError(f"governance_context binding mismatch: {label}.")

    return GovernanceDecisionContext(
        authority_boundary=authority_boundary,
        missing_capability=missing_capability,
        originating_plugin=originating_plugin,
        originating_event_id=originating_event_id,
        checkpoint_digest=checkpoint_digest,
        required_evidence=required_evidence,
        visual_companion_html_sha256=visual_digest,
    )


def _parse_timestamp(value: str, *, field_name: str) -> datetime:
    if not _RFC3339_TIMESTAMP_PATTERN.fullmatch(value):
        raise ProtocolError(f"{field_name} must be an RFC 3339 timestamp.")
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ProtocolError(f"{field_name} must be an RFC 3339 timestamp.") from exc
    return parsed.astimezone(timezone.utc)


def validate_release_request(
    payload: Mapping[str, Any],
    *,
    installed_role_id: str,
    installed_role_email: str,
    now: datetime | None = None,
) -> ReleaseAuthorizationRequest:
    contract = _require_non_empty_string(payload, "contract")
    if contract != _REQUEST_CONTRACT:
        raise ProtocolError(f"contract must be the exact value {_REQUEST_CONTRACT}.")
    authority_scope = _require_non_empty_string(payload, "authority_scope")
    if authority_scope not in _AUTHORITY_SCOPES:
        raise ProtocolError(
            "authority_scope must be PRODUCTION_RELEASE or RD_FLYWHEEL_GOVERNANCE."
        )

    round_id = payload.get("round_id")
    if not isinstance(round_id, int) or round_id <= 0:
        raise ProtocolError("round_id must be a positive round number.")

    required_roles = _require_unique_string_list(payload, "required_roles")
    if installed_role_id not in required_roles:
        raise ProtocolError("installed role is not present in required_roles.")

    original_message_id = _require_message_id(
        _require_non_empty_string(payload, "original_message_id"),
        field_name="original_message_id",
    )

    references_value = payload.get("references")
    if not isinstance(references_value, list):
        raise ProtocolError("references must be a list of exact RFC Message-ID values.")
    references = tuple(
        _require_message_id(reference, field_name="references")
        for reference in references_value
        if isinstance(reference, str)
    )
    if len(references) != len(references_value):
        raise ProtocolError("references must contain only exact RFC Message-ID values.")

    expires_at = _require_non_empty_string(payload, "expires_at")
    expires_at_utc = _parse_timestamp(expires_at, field_name="expires_at")
    comparison_now = now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc)
    if expires_at_utc <= comparison_now:
        raise ProtocolError("request is expired.")

    task = _require_non_empty_string(payload, "task")
    module = _require_non_empty_string(payload, "module")
    manifest_r_digest = _require_sha256_digest(payload, "manifest_r_digest")
    governance_context = _validate_governance_context(
        payload,
        authority_scope=authority_scope,
        task=task,
        module=module,
        manifest_r_digest=manifest_r_digest,
    )

    expected_digest = build_request_digest(payload)
    request_digest = _require_sha256_digest(payload, "request_digest")
    if request_digest != expected_digest:
        raise ProtocolError("request digest does not match the canonical request payload.")

    return ReleaseAuthorizationRequest(
        contract=contract,
        authority_scope=authority_scope,
        event_id=_require_non_empty_string(payload, "event_id"),
        round_id=round_id,
        task=task,
        module=module,
        manifest_s_digest=_require_sha256_digest(payload, "manifest_s_digest"),
        manifest_r_digest=manifest_r_digest,
        manifest_digest=_require_sha256_digest(payload, "manifest_digest"),
        request_digest=request_digest,
        role_snapshot_digest=_require_sha256_digest(payload, "role_snapshot_digest"),
        required_roles=required_roles,
        original_message_id=original_message_id,
        references=references,
        expires_at=expires_at,
        idempotency_key=_require_non_empty_string(payload, "idempotency_key"),
        installed_role_id=installed_role_id,
        installed_role_email=installed_role_email,
        governance_context=governance_context,
        wire_payload_json=canonical_json(payload),
    )


def prepare_page_request(
    payload: Mapping[str, Any],
    *,
    installed_role_id: str,
    installed_role_email: str,
    page_factory: Callable[[ReleaseAuthorizationRequest], _TPage],
    now: datetime | None = None,
) -> _TPage:
    request = validate_release_request(
        payload,
        installed_role_id=installed_role_id,
        installed_role_email=installed_role_email,
        now=now,
    )
    return page_factory(request)
