from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Callable, Mapping, Sequence

from reminder_policy import ReminderPolicy
from role_snapshot import RoleRecord, canonical_json
from verification_receipt import ReceiptError, build_verification_receipt
from verifier_store import StoredReceipt, VerifierStore


class VerifierServiceError(RuntimeError):
    """Raised when verifier orchestration cannot preserve fail-closed semantics."""


@dataclass(frozen=True)
class ReminderOutcome:
    role_id: str
    idempotency_key: str
    accepted: bool
    smtp_message_id: str | None
    error: str | None


@dataclass(frozen=True)
class ReconciliationResult:
    status: str
    receipt: dict[str, Any]
    transition: str | None
    idempotent: bool


class VerifierService:
    def __init__(
        self,
        *,
        store: VerifierStore,
        audit_key: bytes,
        smtp_sender: Callable[..., Any] | None = None,
    ) -> None:
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise VerifierServiceError("audit_key must contain at least 32 bytes.")
        self.store = store
        self.audit_key = audit_key
        self.smtp_sender = smtp_sender

    def send_due_reminders(
        self,
        request_binding: Mapping[str, Any],
        roles: Sequence[RoleRecord],
        *,
        policy: ReminderPolicy,
        now: datetime,
    ) -> tuple[ReminderOutcome, ...]:
        if self.smtp_sender is None:
            raise VerifierServiceError("CAPABILITY_BLOCKED: SMTP sender is required for reminders.")
        current = _require_aware(now, "now").astimezone(timezone.utc)
        event_id = _required_string(request_binding, "event_id")
        round_id = _required_round(request_binding)
        created_at = _parse_datetime(request_binding.get("created_at"), "created_at")
        outcomes: list[ReminderOutcome] = []
        for role in sorted((item for item in roles if item.enabled), key=lambda item: item.role_id):
            if self.store.get_current_decision(event_id, round_id, role.role_id) is not None:
                continue
            accepted_times = tuple(
                _parse_datetime(value, "accepted_at")
                for value in self.store.get_accepted_reminder_times(event_id, round_id, role.role_id)
            )
            if not policy.due(created_at, current, accepted_times):
                continue
            timestamp = _format_datetime(current)
            attempt = self.store.prepare_reminder_attempt(
                event_id=event_id,
                round_id=round_id,
                role_id=role.role_id,
                prepared_at=timestamp,
            )
            message = _build_reminder_message(request_binding, role)
            accepted = False
            smtp_message_id: str | None = None
            error: str | None = None
            try:
                result = self.smtp_sender(message, idempotency_key=attempt.idempotency_key)
                accepted, smtp_message_id, error = _smtp_result(result)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
            updated = self.store.complete_reminder_attempt(
                attempt.idempotency_key,
                accepted=accepted,
                attempted_at=timestamp,
                smtp_message_id=smtp_message_id,
                error=error,
            )
            outcomes.append(
                ReminderOutcome(
                    role_id=role.role_id,
                    idempotency_key=updated.idempotency_key,
                    accepted=updated.status == "ACCEPTED",
                    smtp_message_id=updated.smtp_message_id,
                    error=updated.error,
                )
            )
        return tuple(outcomes)

    def reconcile(
        self,
        request_binding: Mapping[str, Any],
        roles: Sequence[RoleRecord],
        *,
        now: datetime,
    ) -> ReconciliationResult:
        event_id = _required_string(request_binding, "event_id")
        round_id = _required_round(request_binding)
        _validate_frozen_roles(request_binding, roles)
        current_decisions = self.store.list_current_decisions(event_id, round_id)
        previous = self.store.get_latest_receipt(event_id, round_id)
        try:
            receipt = build_verification_receipt(
                request_binding,
                current_decisions,
                audit_checkpoint=self.store.audit_checkpoint(),
                generated_at=now,
                audit_key=self.audit_key,
            )
        except ReceiptError as exc:
            raise VerifierServiceError(str(exc)) from exc
        existing = self.store.get_receipt(str(receipt["receipt_id"]))
        if existing is not None:
            predecessor = next(
                (
                    item
                    for item in self.store.list_receipts(event_id, round_id)
                    if item.superseded_by == existing.receipt_id
                ),
                None,
            )
            transition = self._record_revocation_if_needed(predecessor, existing, now=now)
            return ReconciliationResult(
                status=existing.status,
                receipt=existing.payload,
                transition=transition,
                idempotent=True,
            )

        stored, created = self.store.record_receipt(receipt)
        transition = self._record_revocation_if_needed(previous, stored, now=now)
        return ReconciliationResult(
            status=stored.status,
            receipt=stored.payload,
            transition=transition,
            idempotent=not created,
        )

    def _record_revocation_if_needed(
        self,
        previous: StoredReceipt | None,
        current: StoredReceipt,
        *,
        now: datetime,
    ) -> str | None:
        if (
            previous is None
            or previous.status != "APPROVAL_VERIFIED"
            or current.status == "APPROVAL_VERIFIED"
            or _decision_fingerprint(previous.payload) == _decision_fingerprint(current.payload)
        ):
            return None
        transition = "RELEASE_HOLD_REQUESTED" if previous.handoff_consumed_at else "APPROVAL_REVOKED"
        role_id = _changed_role(previous.payload, current.payload)
        event_key_seed = "|".join((transition, previous.receipt_id, current.receipt_id, role_id))
        event_key = transition.lower() + ":" + hashlib.sha256(event_key_seed.encode("utf-8")).hexdigest()
        self.store.record_workflow_event(
            event_key=event_key,
            event_id=current.event_id,
            round_id=current.round_id,
            event_type=transition,
            receipt_id=current.receipt_id,
            role_id=role_id,
            created_at=_format_datetime(_require_aware(now, "now")),
            payload={
                "previous_receipt_id": previous.receipt_id,
                "current_receipt_id": current.receipt_id,
                "handoff_id": previous.handoff_id or "",
            },
        )
        return transition


def _build_reminder_message(request: Mapping[str, Any], role: RoleRecord) -> EmailMessage:
    original_message_id = _required_string(request, "original_message_id")
    references_value = request.get("references")
    references = [str(value).strip() for value in references_value or () if isinstance(value, str) and value.strip()]
    if original_message_id not in references:
        references.append(original_message_id)
    subject = _required_string(request, "subject") if request.get("subject") else "[Release approval request]"
    emergency = request.get("emergency_approved") is True
    message = EmailMessage()
    message["To"] = role.email
    message["Subject"] = subject if subject.lower().startswith("re:") else f"Re: {subject}"
    message["In-Reply-To"] = original_message_id
    message["References"] = " ".join(dict.fromkeys(references))
    message["X-RD-Event-Id"] = _required_string(request, "event_id")
    message["X-RD-Round-Id"] = str(_required_round(request))
    if emergency:
        context = "This request is marked as an approved emergency release."
    else:
        context = "This is a routine reminder and no immediate response is required outside working hours."
    message.set_content(
        "Hello,\n\n"
        "A release approval request is waiting for your decision. "
        "Please review the evidence when convenient.\n\n"
        "You may open the local approval page generated by your approval plugin, "
        "or reply in this thread with \"\u540c\u610f\", \"\u5f85\u8bc4\u4f30\", or \"\u9a73\u56de\".\n\n"
        f"{context}\n\n"
        "Thank you.\n"
    )
    return message


def _smtp_result(value: Any) -> tuple[bool, str | None, str | None]:
    if value is True:
        return True, None, None
    if value is False or value is None:
        return False, None, "SMTP did not provide an acceptance result."
    if not isinstance(value, Mapping):
        return False, None, "SMTP result was not a recognized acceptance record."
    accepted = value.get("accepted") is True
    message_id = value.get("message_id")
    normalized_message_id = str(message_id).strip() if isinstance(message_id, str) and message_id.strip() else None
    if accepted:
        return True, normalized_message_id, None
    refused = value.get("refused")
    error = value.get("error")
    if isinstance(error, str) and error.strip():
        reason = error.strip()
    elif isinstance(refused, Mapping) and refused:
        reason = "SMTP refused one or more recipients."
    else:
        reason = "SMTP did not accept the reminder."
    return False, normalized_message_id, reason


def _validate_frozen_roles(request: Mapping[str, Any], roles: Sequence[RoleRecord]) -> None:
    configured = {role.role_id for role in roles if role.enabled}
    required_value = request.get("required_roles")
    if not isinstance(required_value, (list, tuple)) or not required_value:
        raise VerifierServiceError("required_roles must be a non-empty frozen list.")
    required = {str(value).strip() for value in required_value if isinstance(value, str) and value.strip()}
    if len(required) != len(required_value) or not required.issubset(configured):
        raise VerifierServiceError("required_roles do not match the frozen role snapshot.")


def _decision_fingerprint(receipt: Mapping[str, Any]) -> str:
    decisions = receipt.get("current_decisions")
    return hashlib.sha256(canonical_json(decisions if isinstance(decisions, list) else []).encode("utf-8")).hexdigest()


def _changed_role(previous: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    def index(payload: Mapping[str, Any]) -> dict[str, str]:
        result: dict[str, str] = {}
        values = payload.get("current_decisions")
        if isinstance(values, list):
            for value in values:
                if isinstance(value, Mapping):
                    role_id = str(value.get("role_id") or "")
                    decision_id = str(value.get("decision_id") or "")
                    if role_id:
                        result[role_id] = decision_id
        return result

    before = index(previous)
    after = index(current)
    for role_id in sorted(set(before) | set(after)):
        if before.get(role_id) != after.get(role_id):
            return role_id
    return "unknown"


def _required_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise VerifierServiceError(f"{key} is required.")
    return value.strip()


def _required_round(payload: Mapping[str, Any]) -> int:
    value = payload.get("round_id")
    if type(value) is not int or value <= 0:
        raise VerifierServiceError("round_id must be a positive integer.")
    return value


def _parse_datetime(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise VerifierServiceError(f"{field_name} must be an RFC3339 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerifierServiceError(f"{field_name} must be an RFC3339 timestamp.") from exc
    return _require_aware(parsed, field_name).astimezone(timezone.utc)


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VerifierServiceError(f"{field_name} must be timezone-aware.")
    return value


def _format_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
