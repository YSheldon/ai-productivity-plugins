from __future__ import annotations

import email.utils
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Mapping

from decision_parser import classify_decision
from role_snapshot import RoleRecord
from verifier_config import AuthenticationPolicyConfig
from verifier_store import StoreError, StoredDecision, VerifierStore


_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")


class MessageValidationError(RuntimeError):
    """Raised when an approval reply cannot be safely used for verifier state."""


@dataclass(frozen=True)
class ValidatedDecision:
    decision_id: str
    decision: str
    normalized_text: str
    ambiguous: bool
    approver_email: str
    authentication_path: str
    source_message_id: str
    decided_at: str


def validate_and_record_message(
    message: EmailMessage,
    *,
    request_binding: Mapping[str, Any],
    expected_role: RoleRecord,
    authentication_policy: AuthenticationPolicyConfig,
    store: VerifierStore,
    now: datetime,
) -> ValidatedDecision:
    message_id = _require_message_id(str(message.get("Message-ID", "")).strip())
    if store.has_message_id(message_id):
        raise MessageValidationError("APPROVAL_MESSAGE_QUARANTINED: duplicate Message-ID.")

    decided_at = _message_datetime(message, now)
    raw_headers_sha256 = _raw_headers_sha256(message)
    event_id = _require_string(request_binding, "event_id")
    round_id = _require_int(request_binding, "round_id")
    role_snapshot_digest = _require_string(request_binding, "role_snapshot_digest")
    manifest_digest = _require_string(request_binding, "manifest_digest")

    try:
        _ensure_not_expired(request_binding, now)
        from_email = _parse_email_header(message.get("From"))
        return_path = _parse_email_header(message.get("Return-Path"))
        if from_email != expected_role.email or return_path != expected_role.email:
            raise MessageValidationError("APPROVAL_MESSAGE_QUARANTINED: From and Return-Path must match the frozen role email.")
        _ensure_thread_binding(message, request_binding)
        _ensure_optional_binding_header(message, "X-RD-Event-Id", event_id, "event")
        _ensure_optional_binding_header(message, "X-RD-Round-Id", str(round_id), "round")
        _ensure_optional_binding_header(message, "X-RD-Manifest-Digest", manifest_digest, "manifest")
        _ensure_optional_binding_header(message, "X-RD-Role-Snapshot-Digest", role_snapshot_digest, "snapshot")
        authentication_path = _detect_authentication_path(message, authentication_policy)
        parsed = classify_decision(_extract_text_body(message))
        decision_id = _build_decision_id(event_id=event_id, round_id=round_id, role_id=expected_role.role_id, message_id=message_id)
        stored = store.record_decision(
            decision_id=decision_id,
            event_id=event_id,
            round_id=round_id,
            role_id=expected_role.role_id,
            decision=parsed.decision,
            normalized_text=parsed.normalized_text,
            ambiguous=parsed.ambiguous,
            approver_email=expected_role.email,
            authentication_path=authentication_path,
            source_message_id=message_id,
            raw_headers_sha256=raw_headers_sha256,
            decided_at=decided_at.isoformat().replace("+00:00", "Z"),
        )
        return _to_validated_decision(stored)
    except MessageValidationError:
        store.quarantine_message(
            message_id=message_id,
            event_id=event_id,
            round_id=round_id,
            role_id=expected_role.role_id,
            reason=_safe_reason_from_exception(),
            raw_headers_sha256=raw_headers_sha256,
            recorded_at=decided_at.isoformat().replace("+00:00", "Z"),
            payload={
                "from": str(message.get("From", "")),
                "return_path": str(message.get("Return-Path", "")),
                "subject": str(message.get("Subject", "")),
            },
        )
        raise
    except StoreError as exc:
        raise MessageValidationError(f"APPROVAL_MESSAGE_QUARANTINED: {exc}") from exc


def _safe_reason_from_exception() -> str:
    import sys

    exc = sys.exc_info()[1]
    return str(exc) if exc is not None else "APPROVAL_MESSAGE_QUARANTINED"


def _to_validated_decision(stored: StoredDecision) -> ValidatedDecision:
    return ValidatedDecision(
        decision_id=stored.decision_id,
        decision=stored.decision,
        normalized_text=stored.normalized_text,
        ambiguous=stored.ambiguous,
        approver_email=stored.approver_email,
        authentication_path=stored.authentication_path,
        source_message_id=stored.source_message_id,
        decided_at=stored.decided_at,
    )


def _require_message_id(value: str) -> str:
    if not _MESSAGE_ID_PATTERN.fullmatch(value):
        raise MessageValidationError("APPROVAL_MESSAGE_QUARANTINED: Message-ID must be one exact RFC Message-ID.")
    return value


def _parse_email_header(value: Any) -> str:
    return email.utils.parseaddr(str(value or ""))[1].strip().lower()


def _ensure_thread_binding(message: EmailMessage, request_binding: Mapping[str, Any]) -> None:
    original_message_id = _require_string(request_binding, "original_message_id")
    references_value = request_binding.get("references")
    if isinstance(references_value, (tuple, list)):
        references = tuple(str(item).strip() for item in references_value if isinstance(item, str))
    else:
        references = ()
    in_reply_to = str(message.get("In-Reply-To", "")).strip()
    message_references = _normalize_message_ids(message.get_all("References", []))
    bound_ids = set(references)
    bound_ids.add(original_message_id)
    if in_reply_to == original_message_id:
        return
    if bound_ids.intersection(message_references):
        return
    raise MessageValidationError("APPROVAL_MESSAGE_QUARANTINED: reply thread does not bind to the frozen request.")


def _ensure_optional_binding_header(message: EmailMessage, header_name: str, expected: str, label: str) -> None:
    value = str(message.get(header_name, "")).strip()
    if value and value != expected:
        raise MessageValidationError(f"APPROVAL_MESSAGE_QUARANTINED: {label} binding drifted from the frozen request.")


def _detect_authentication_path(
    message: EmailMessage,
    authentication_policy: AuthenticationPolicyConfig,
) -> str:
    trusted_results = _trusted_authentication_results(
        message,
        authentication_policy.allowed_authserv_ids,
    )
    received_spf = "\n".join(
        str(value) for value in message.get_all("Received-SPF", [])
    ).lower()
    from_email = _parse_email_header(message.get("From"))
    return_path = _parse_email_header(message.get("Return-Path"))
    sender_domain = from_email.rsplit("@", 1)[1] if "@" in from_email else ""
    header_name = authentication_policy.trusted_internal_header
    header_value = str(message.get(header_name, "")).strip()
    for path_name in authentication_policy.accepted_paths:
        if (
            path_name == "dmarc"
            and _authentication_method_passed(trusted_results, "dmarc")
            and _authentication_parameter(trusted_results, "header.from")
            == sender_domain
        ):
            return "dmarc"
        if (
            path_name == "dkim"
            and _authentication_method_passed(trusted_results, "dkim")
            and _authentication_parameter(trusted_results, "header.d")
            == sender_domain
        ):
            return "dkim"
        if (
            path_name == "spf"
            and return_path == from_email
            and _authentication_method_passed(trusted_results, "spf")
            and received_spf.strip().startswith("pass")
        ):
            return "spf"
        if (
            path_name == "trusted_internal"
            and header_value == authentication_policy.trusted_internal_value
        ):
            return "trusted_internal"
    raise MessageValidationError(
        "APPROVAL_MESSAGE_QUARANTINED: no configured authenticated path passed."
    )


def _trusted_authentication_results(
    message: EmailMessage,
    allowed_authserv_ids: tuple[str, ...],
) -> str:
    allowed = set(allowed_authserv_ids)
    trusted: list[str] = []
    for value in message.get_all("Authentication-Results", []):
        candidate = str(value)
        authserv_id = candidate.split(";", 1)[0].strip().lower()
        if authserv_id in allowed:
            trusted.append(candidate)
    return "\n".join(trusted)


def _authentication_method_passed(value: str, method: str) -> bool:
    return bool(
        re.search(
            rf"(?:^|[;\s]){re.escape(method)}\s*=\s*pass(?:[;\s]|$)",
            value,
            flags=re.IGNORECASE,
        )
    )


def _authentication_parameter(value: str, name: str) -> str:
    match = re.search(
        rf"(?:^|[;\s]){re.escape(name)}\s*=\s*([A-Za-z0-9.-]+)",
        value,
        flags=re.IGNORECASE,
    )
    return "" if match is None else match.group(1).lower()


def _extract_text_body(message: EmailMessage) -> str:
    raw_bytes = b""
    if message.is_multipart():
        preferred = message.get_body(preferencelist=("plain", "html"))
        if preferred is not None:
            raw_bytes = preferred.get_payload(decode=True) or b""
            if raw_bytes:
                try:
                    return raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    return raw_bytes.decode("utf-8", errors="replace")
            return str(preferred.get_content())
    raw_bytes = message.get_payload(decode=True) or b""
    if raw_bytes:
        try:
            return raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return raw_bytes.decode("utf-8", errors="replace")
    try:
        return str(message.get_content())
    except LookupError:
        return ""


def _raw_headers_sha256(message: EmailMessage) -> str:
    readback_digest = str(
        message.get("X-RD-Readback-Headers-SHA256", "")
    ).strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", readback_digest):
        return readback_digest
    header_block = "".join(f"{key}: {value}\n" for key, value in message.items())
    return hashlib.sha256(header_block.encode("utf-8")).hexdigest()


def _message_datetime(message: EmailMessage, fallback: datetime) -> datetime:
    parsed = email.utils.parsedate_to_datetime(str(message.get("Date", "")))
    if parsed is None:
        return fallback.astimezone(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ensure_not_expired(request_binding: Mapping[str, Any], now: datetime) -> None:
    expires_at = _require_string(request_binding, "expires_at")
    normalized = expires_at.replace("Z", "+00:00")
    expires = datetime.fromisoformat(normalized).astimezone(timezone.utc)
    if expires <= now.astimezone(timezone.utc):
        raise MessageValidationError("APPROVAL_MESSAGE_QUARANTINED: approval event is expired.")


def _require_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MessageValidationError(f"APPROVAL_MESSAGE_QUARANTINED: missing {key}.")
    return value.strip()


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if type(value) is not int:
        raise MessageValidationError(f"APPROVAL_MESSAGE_QUARANTINED: missing {key}.")
    return value


def _normalize_message_ids(values: list[str]) -> tuple[str, ...]:
    matches: list[str] = []
    for value in values:
        matches.extend(re.findall(r"<[^<>\r\n]+>", value or ""))
    return tuple(dict.fromkeys(matches))


def _build_decision_id(*, event_id: str, round_id: int, role_id: str, message_id: str) -> str:
    payload = "|".join((event_id, str(round_id), role_id, message_id))
    return "decision-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
