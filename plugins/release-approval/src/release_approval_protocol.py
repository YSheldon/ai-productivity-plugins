from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, TypeVar


_RFC_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUEST_CONTRACT = "ReleaseAuthorizationRequest/v1"
_TPage = TypeVar("_TPage")


class ProtocolError(ValueError):
    """Raised when a release-approval request payload is invalid."""


@dataclass(frozen=True)
class ReleaseAuthorizationRequest:
    contract: str
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


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_request_digest(payload: Mapping[str, Any]) -> str:
    digest_payload = {
        key: value
        for key, value in payload.items()
        if key != "request_digest"
    }
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


def _parse_timestamp(value: str, *, field_name: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ProtocolError(f"{field_name} must be an RFC 3339 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ProtocolError(f"{field_name} must include a timezone.")
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

    round_id = payload.get("round_id")
    if not isinstance(round_id, int) or round_id <= 0:
        raise ProtocolError("round_id must be a positive round number.")

    required_roles_value = payload.get("required_roles")
    if not isinstance(required_roles_value, list) or not required_roles_value:
        raise ProtocolError("required_roles must be a non-empty list.")
    required_roles = tuple(
        role.strip()
        for role in required_roles_value
        if isinstance(role, str) and role.strip()
    )
    if len(required_roles) != len(required_roles_value):
        raise ProtocolError("required_roles must contain only non-empty strings.")
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

    expected_digest = build_request_digest(payload)
    request_digest = _require_sha256_digest(payload, "request_digest")
    if request_digest != expected_digest:
        raise ProtocolError("request digest does not match the canonical request payload.")

    return ReleaseAuthorizationRequest(
        contract=contract,
        event_id=_require_non_empty_string(payload, "event_id"),
        round_id=round_id,
        task=_require_non_empty_string(payload, "task"),
        module=_require_non_empty_string(payload, "module"),
        manifest_s_digest=_require_sha256_digest(payload, "manifest_s_digest"),
        manifest_r_digest=_require_sha256_digest(payload, "manifest_r_digest"),
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
