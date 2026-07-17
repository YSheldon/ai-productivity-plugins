from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from role_snapshot import canonical_json


_BINDING_FIELDS = (
    "event_id",
    "round_id",
    "manifest_s_digest",
    "manifest_r_digest",
    "manifest_digest",
    "request_digest",
    "role_snapshot_digest",
    "expires_at",
)
_VALID_DECISIONS = frozenset(("APPROVE", "HOLD", "REJECT"))


class ReceiptError(RuntimeError):
    """Raised when a signed verification receipt is unsafe or invalid."""


def load_audit_key(environ: Mapping[str, str] | None = None) -> bytes:
    environment = os.environ if environ is None else environ
    raw = str(environment.get("RELEASE_APPROVAL_VERIFIER_AUDIT_KEY") or "")
    if raw.startswith("base64:"):
        try:
            key = base64.b64decode(raw[7:], validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ReceiptError("RELEASE_APPROVAL_VERIFIER_AUDIT_KEY has invalid base64 encoding.") from exc
    else:
        key = raw.encode("utf-8")
    return _validated_key(key)


def build_verification_receipt(
    request_binding: Mapping[str, Any],
    decisions: Sequence[Any],
    *,
    audit_checkpoint: tuple[int, str] | Mapping[str, Any],
    generated_at: datetime,
    audit_key: bytes,
) -> dict[str, Any]:
    key = _validated_key(audit_key)
    generated = _require_aware(generated_at, "generated_at").astimezone(timezone.utc)
    binding = _normalized_binding(request_binding)
    required_roles = _required_roles(request_binding)
    normalized_decisions = tuple(_normalize_decision(item) for item in decisions)
    normalized_decisions = tuple(sorted(normalized_decisions, key=lambda item: (item["role_id"], item["decision_id"])))
    status, diagnostics = _aggregate_status(
        required_roles=required_roles,
        decisions=normalized_decisions,
        expires_at=_parse_datetime(binding["expires_at"], "expires_at"),
        at=generated,
    )
    audit_count, audit_head = _normalize_audit_checkpoint(audit_checkpoint)
    identity = {
        **binding,
        "required_roles": list(required_roles),
        "current_decisions": list(normalized_decisions),
        "status": status,
    }
    receipt_id = "receipt-" + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    evidence = {
        **identity,
        "audit_event_count": audit_count,
        "audit_head_hash": audit_head,
    }
    payload: dict[str, Any] = {
        "contract": "ApprovalVerificationReceipt/v1",
        "receipt_id": receipt_id,
        **binding,
        "task": _optional_string(request_binding, "task"),
        "module": _optional_string(request_binding, "module"),
        "required_roles": list(required_roles),
        "current_decisions": list(normalized_decisions),
        "source_message_ids": sorted(
            item["source_message_id"] for item in normalized_decisions if item["source_message_id"]
        ),
        "status": status,
        "aggregate_status": _aggregate_label(status),
        "diagnostics": list(diagnostics),
        "generated_at": _format_datetime(generated),
        "audit_event_count": audit_count,
        "audit_head_hash": audit_head,
        "evidence_digest": "sha256:" + hashlib.sha256(canonical_json(evidence).encode("utf-8")).hexdigest(),
        "receipt_algorithm": "HMAC-SHA256",
    }
    payload["receipt_hmac"] = _sign(payload, key)
    return payload


def verify_verification_receipt(
    receipt: Mapping[str, Any],
    *,
    audit_key: bytes,
    expected_binding: Mapping[str, Any] | None = None,
    audit_store: Any | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    key = _validated_key(audit_key)
    payload = dict(receipt)
    if payload.get("contract") != "ApprovalVerificationReceipt/v1":
        raise ReceiptError("unsupported verification receipt contract.")
    if payload.get("receipt_algorithm") != "HMAC-SHA256":
        raise ReceiptError("verification receipt must use HMAC-SHA256.")
    signature = payload.pop("receipt_hmac", None)
    if not isinstance(signature, str) or not hmac.compare_digest(signature, _sign(payload, key)):
        raise ReceiptError("verification receipt HMAC is invalid.")
    payload["receipt_hmac"] = signature

    binding = _normalized_binding(payload)
    if expected_binding is not None:
        expected = _normalized_binding(expected_binding)
        for field in _BINDING_FIELDS:
            if binding[field] != expected[field]:
                raise ReceiptError(f"verification receipt binding mismatch: {field}.")

    required_roles = _required_roles(payload)
    raw_decisions = payload.get("current_decisions")
    if not isinstance(raw_decisions, list):
        raise ReceiptError("verification receipt current_decisions must be a list.")
    decisions = tuple(_normalize_decision(item) for item in raw_decisions)
    generated_at = _parse_datetime(payload.get("generated_at"), "generated_at")
    expected_status, expected_diagnostics = _aggregate_status(
        required_roles=required_roles,
        decisions=decisions,
        expires_at=_parse_datetime(binding["expires_at"], "expires_at"),
        at=generated_at,
    )
    if payload.get("status") != expected_status or payload.get("diagnostics") != list(expected_diagnostics):
        raise ReceiptError("verification receipt aggregate status is inconsistent with its decisions.")

    count, head = _normalize_audit_checkpoint(
        (payload.get("audit_event_count"), payload.get("audit_head_hash"))
    )
    if audit_store is not None:
        try:
            audit_store.verify_audit_checkpoint(count, head)
            receipt_id = payload.get("receipt_id")
            if not isinstance(receipt_id, str) or not receipt_id:
                raise ReceiptError("verification receipt is missing receipt_id.")
            audit_store.verify_receipt_record(receipt_id, payload)
        except Exception as exc:
            raise ReceiptError(f"verification receipt audit state is invalid: {exc}") from exc

    if now is not None:
        current = _require_aware(now, "now").astimezone(timezone.utc)
        expires_at = _parse_datetime(binding["expires_at"], "expires_at")
        if current >= expires_at and payload.get("status") != "APPROVAL_EXPIRED":
            raise ReceiptError("verification receipt is expired.")
    return payload


def _aggregate_status(
    *,
    required_roles: tuple[str, ...],
    decisions: Sequence[Mapping[str, Any]],
    expires_at: datetime,
    at: datetime,
) -> tuple[str, tuple[str, ...]]:
    by_role: dict[str, list[str]] = {}
    for item in decisions:
        by_role.setdefault(str(item["role_id"]), []).append(str(item["decision"]).upper())
    required_counts = {role: required_roles.count(role) for role in set(required_roles)}
    duplicate_required_roles = sorted(role for role, count in required_counts.items() if count != 1)
    duplicate_roles = sorted(role for role, values in by_role.items() if len(values) != 1)
    missing_roles = sorted(role for role in required_roles if role not in by_role)
    unknown_roles = sorted(role for role, values in by_role.items() if any(value not in _VALID_DECISIONS for value in values))
    hold_roles = sorted(role for role, values in by_role.items() if "HOLD" in values)
    reject_roles = sorted(role for role, values in by_role.items() if "REJECT" in values)
    diagnostics: list[str] = []
    if at >= expires_at:
        diagnostics.append("expired approval request")
        return "APPROVAL_EXPIRED", tuple(diagnostics)
    if reject_roles:
        diagnostics.append("reject decision from: " + ", ".join(reject_roles))
        return "APPROVAL_REJECTED", tuple(diagnostics)
    if duplicate_required_roles:
        diagnostics.append("duplicate required role in frozen request: " + ", ".join(duplicate_required_roles))
    if duplicate_roles:
        diagnostics.append("duplicate current decision for: " + ", ".join(duplicate_roles))
    if missing_roles:
        diagnostics.append("missing required decision for: " + ", ".join(missing_roles))
    if hold_roles:
        diagnostics.append("hold decision from: " + ", ".join(hold_roles))
    if unknown_roles:
        diagnostics.append("unknown decision from: " + ", ".join(unknown_roles))
    if diagnostics:
        return "APPROVAL_PAUSED", tuple(diagnostics)
    return "APPROVAL_VERIFIED", ()


def _normalize_decision(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        value = asdict(value)
    if not isinstance(value, Mapping):
        raise ReceiptError("each current decision must be an object.")
    role_id = _first_string(value, "role_id", "role")
    decision_id = _first_string(value, "decision_id")
    decision = _first_string(value, "decision").upper()
    return {
        "role_id": role_id,
        "decision_id": decision_id,
        "decision": decision,
        "approver_email": _first_string(value, "approver_email"),
        "authentication_path": _first_string(value, "authentication_path", "source"),
        "source_message_id": _first_string(value, "source_message_id", "original_message_id"),
        "decided_at": _first_string(value, "decided_at"),
    }


def _normalized_binding(payload: Mapping[str, Any]) -> dict[str, Any]:
    binding: dict[str, Any] = {}
    for field in _BINDING_FIELDS:
        value = payload.get(field)
        if field == "round_id":
            if type(value) is not int or value <= 0:
                raise ReceiptError("round_id must be a positive integer.")
            binding[field] = value
        elif not isinstance(value, str) or not value.strip():
            raise ReceiptError(f"{field} is required for verification receipt binding.")
        else:
            binding[field] = value.strip()
    _parse_datetime(binding["expires_at"], "expires_at")
    return binding


def _required_roles(payload: Mapping[str, Any]) -> tuple[str, ...]:
    value = payload.get("required_roles")
    if not isinstance(value, (list, tuple)) or not value:
        raise ReceiptError("required_roles must be a non-empty list.")
    roles = tuple(str(item).strip() for item in value if isinstance(item, str) and item.strip())
    if len(roles) != len(value):
        raise ReceiptError("required_roles must contain non-empty strings.")
    return roles


def _normalize_audit_checkpoint(value: tuple[int, str] | Mapping[str, Any]) -> tuple[int, str]:
    if isinstance(value, Mapping):
        count = value.get("count")
        head = value.get("head_hash")
    else:
        try:
            count, head = value
        except (TypeError, ValueError) as exc:
            raise ReceiptError("audit_checkpoint must contain count and head hash.") from exc
    if type(count) is not int or count < 0:
        raise ReceiptError("audit checkpoint count must be a non-negative integer.")
    if not isinstance(head, str) or len(head) != 64:
        raise ReceiptError("audit checkpoint head must be a SHA-256 hex digest.")
    try:
        int(head, 16)
    except ValueError as exc:
        raise ReceiptError("audit checkpoint head must be a SHA-256 hex digest.") from exc
    return count, head.lower()


def _validated_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ReceiptError("verification audit key must contain at least 32 bytes.")
    return key


def _sign(payload: Mapping[str, Any], key: bytes) -> str:
    body = {field: value for field, value in payload.items() if field != "receipt_hmac"}
    digest = hmac.new(key, canonical_json(body).encode("utf-8"), hashlib.sha256).digest()
    return "base64:" + base64.b64encode(digest).decode("ascii")


def _aggregate_label(status: str) -> str:
    return {
        "APPROVAL_VERIFIED": "APPROVED",
        "APPROVAL_REJECTED": "REJECTED",
        "APPROVAL_PAUSED": "PAUSED",
        "APPROVAL_EXPIRED": "EXPIRED",
    }[status]


def _first_string(payload: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise ReceiptError(f"decision is missing {keys[0]}.")


def _optional_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    return value.strip() if isinstance(value, str) else ""


def _parse_datetime(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ReceiptError(f"{field_name} must be an RFC3339 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReceiptError(f"{field_name} must be an RFC3339 timestamp.") from exc
    return _require_aware(parsed, field_name).astimezone(timezone.utc)


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReceiptError(f"{field_name} must be timezone-aware.")
    return value


def _format_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
