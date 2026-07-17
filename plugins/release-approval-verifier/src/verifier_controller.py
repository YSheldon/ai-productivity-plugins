from __future__ import annotations

import base64
import email.utils
import hashlib
import json
import os
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, time, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from lark_audit import AuditRecord, AuditWriteResult, LarkAuditAdapter
from message_validator import MessageValidationError, validate_and_record_message
from product_gate_adapter import ProductGateMcpAdapter
from reminder_policy import ReminderPolicy
from role_snapshot import RoleRecord, RoleSnapshot, canonical_json, fetch_role_snapshot
from verification_receipt import load_audit_key, verify_verification_receipt
from verifier_config import StaticRoleSourceConfig, VerifierConfig
from verifier_lock import RunOnceLock
from verifier_mail import MailGateway
from verifier_scheduler import VerifierScheduler
from verifier_service import VerifierService
from verifier_store import StoredReceipt, VerifierStore


Scanner = Callable[[], Sequence[EmailMessage] | Iterable[EmailMessage]]
RoleSnapshotFetcher = Callable[[], RoleSnapshot]
LockFactory = Callable[..., Any]

_REQUEST_HEADER_MAP = {
    "contract": "X-RD-Contract",
    "event_id": "X-RD-Event-Id",
    "round_id": "X-RD-Round-Id",
    "task": "X-RD-Task",
    "module": "X-RD-Module",
    "manifest_s_digest": "X-RD-Manifest-S-Digest",
    "manifest_r_digest": "X-RD-Manifest-R-Digest",
    "manifest_digest": "X-RD-Manifest-Digest",
    "request_digest": "X-RD-Request-Digest",
    "role_snapshot_digest": "X-RD-Role-Snapshot-Digest",
    "required_roles": "X-RD-Required-Roles",
    "expires_at": "X-RD-Expires-At",
}
_REQUEST_BEGIN_MARKER = "-----BEGIN RELEASE APPROVAL REQUEST-----"
_REQUEST_END_MARKER = "-----END RELEASE APPROVAL REQUEST-----"
_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

_DIGEST_FIELDS = (
    "manifest_s_digest",
    "manifest_r_digest",
    "manifest_digest",
    "request_digest",
    "role_snapshot_digest",
)


class VerifierControllerError(RuntimeError):
    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


class VerifierController:
    def __init__(
        self,
        config: VerifierConfig,
        config_path: str | Path,
        *,
        store: VerifierStore | None = None,
        service: VerifierService | None = None,
        scheduler: VerifierScheduler | Any | None = None,
        mail_gateway: MailGateway | Any | None = None,
        role_snapshot_fetcher: RoleSnapshotFetcher | None = None,
        request_scanner: Scanner | None = None,
        reply_scanner: Scanner | None = None,
        audit_adapter: LarkAuditAdapter | Any | None = None,
        lock_factory: LockFactory | None = None,
        now_fn: Callable[[], datetime] | None = None,
        audit_key: bytes | None = None,
        product_gate_adapter: Any | None = None,
    ) -> None:
        self.config = config
        self.config_path = Path(config_path).expanduser().resolve(strict=False)
        self._store_instance = store
        self._service_instance = service
        self._scheduler = scheduler
        self._mail_gateway = mail_gateway
        self._role_snapshot_fetcher = role_snapshot_fetcher
        self._request_scanner = request_scanner
        self._reply_scanner = reply_scanner
        self._audit_adapter = audit_adapter
        self._lock_factory = lock_factory or (lambda path, *, owner: RunOnceLock(path, owner=owner))
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._audit_key = load_audit_key() if audit_key is None else audit_key
        self._product_gate_adapter = product_gate_adapter
        self._default_mail_scan_cache: tuple[EmailMessage, ...] | None = None

    def preflight(self) -> dict[str, Any]:
        checks = self._capability_checks()
        return {
            "status": "ready" if not checks["missing_capabilities"] else "CAPABILITY_BLOCKED",
            "config_path": str(self.config_path),
            "mode": self.config.mode,
            "role_source": checks["role_source"],
            "scheduler": checks["scheduler"],
            "missing_capabilities": checks["missing_capabilities"],
        }

    def run_once(self) -> dict[str, Any]:
        lock = self._lock_factory(self._lock_path(), owner=self._lock_owner())
        acquired = dict(lock.acquire())
        if acquired.get("status") != "acquired":
            return {
                "status": "RUN_ALREADY_ACTIVE",
                "busy": True,
                "owner": str(acquired.get("owner") or "unknown"),
            }

        try:
            self._default_mail_scan_cache = None
            recovered_owner = str(acquired.get("recovered_owner") or "").strip()
            if recovered_owner:
                self._store().append_audit_event(
                    "run-lock-orphan-recovered",
                    {"recovered_owner": recovered_owner, "new_owner": self._lock_owner()},
                    created_at=self._isoformat(self._now()),
                )
            snapshot = self._freeze_role_snapshot()
            request_count = self._ingest_requests(snapshot)
            reply_summary = self._ingest_replies()
            event_results: list[dict[str, Any]] = []
            reminders: list[dict[str, Any]] = []
            overall_status = "ready"
            latest_capability_event: dict[str, Any] | None = None
            for event in self._load_all_events():
                result = self._finalize_event(event)
                event_results.append(result)
                reminders.extend(result["reminders"])
                if result["status"] == "CAPABILITY_BLOCKED":
                    overall_status = "CAPABILITY_BLOCKED"
                    if result.get("capability_event") is not None:
                        latest_capability_event = dict(result["capability_event"])
            payload: dict[str, Any] = {
                "status": overall_status,
                "processed": {
                    "requests": request_count,
                    "validated": reply_summary["validated"],
                    "quarantined": reply_summary["quarantined"],
                },
                "reminders": reminders,
                "events": event_results,
            }
            if event_results:
                last = event_results[-1]
                payload["event_id"] = last["event_id"]
                payload["round_id"] = last["round_id"]
                payload["receipt"] = last["receipt"]
                payload["receipt_path"] = last["receipt_path"]
                payload["handoff"] = last["handoff"]
            if latest_capability_event is not None:
                payload["capability_event"] = latest_capability_event
            return payload
        finally:
            lock.release()

    def status(self) -> dict[str, Any]:
        events = self._load_all_events()
        latest_statuses: list[str] = []
        pending_missing = 0
        for event in events:
            receipt = self._latest_receipt(event)
            if receipt is not None:
                latest_statuses.append(receipt.status)
            pending_missing += len(self._missing_roles_for_event(event))
        return {
            "status": "ready",
            "config_path": str(self.config_path.resolve(strict=False)),
            "event_count": len(events),
            "current_receipt_statuses": sorted(latest_statuses),
            "missing_roles": pending_missing,
            "scheduler": self._scheduler_status(),
        }

    def doctor(self) -> dict[str, Any]:
        checks = self._capability_checks()
        return {
            "status": "ready" if not checks["missing_capabilities"] else "CAPABILITY_BLOCKED",
            "ready": not checks["missing_capabilities"],
            "config_path": str(self.config_path),
            "workflow": {"mode": "independent_release_approval_verifier"},
            "role_source": checks["role_source"],
            "mail_checks": checks["mail_checks"],
            "audit": checks["audit"],
            "product_gate": checks["product_gate"],
            "scheduler": checks["scheduler"],
            "missing_capabilities": checks["missing_capabilities"],
        }

    def get_event(self, *, event_id: str, round_id: int) -> dict[str, Any]:
        record = self._load_event(event_id, round_id)
        if record is None:
            raise VerifierControllerError("EVENT_NOT_FOUND", f"unknown event {event_id} round {round_id}")
        return self._public_event(record)

    def list_missing_roles(self, *, event_id: str, round_id: int) -> dict[str, Any]:
        record = self._load_event(event_id, round_id)
        if record is None:
            raise VerifierControllerError("EVENT_NOT_FOUND", f"unknown event {event_id} round {round_id}")
        return {
            "status": "ready",
            "event_id": event_id,
            "round_id": round_id,
            "missing_roles": self._missing_roles_for_event(record),
        }

    def verify_receipt(self, *, path: str | Path) -> dict[str, Any]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        verified = verify_verification_receipt(
            payload,
            audit_key=self._audit_key,
            audit_store=self._store(),
            now=self._now(),
        )
        return {
            "status": str(verified["status"]),
            "verified": True,
            "receipt": verified,
            "path": str(Path(path).resolve(strict=False)),
        }

    def verify_audit_chain(self) -> dict[str, Any]:
        store = self._store()
        store.verify_audit_chain()
        count, head = store.audit_checkpoint()
        return {
            "status": "ready",
            "audit_event_count": count,
            "audit_head_hash": head,
        }

    def _capability_checks(self) -> dict[str, Any]:
        missing: list[str] = []

        try:
            snapshot = self._freeze_role_snapshot(store_snapshot=False)
            role_source = {"status": "ready", "role_count": len(snapshot.roles), "digest": snapshot.digest}
        except Exception as exc:
            role_source = {"status": "CAPABILITY_BLOCKED", "reason": str(exc)}
            missing.append("role_source")

        mail_checks = {"thread_reply": "ready", "authenticated_readback": "ready"}
        try:
            self._mail().require_thread_reply_capability(
                {
                    "reply_subject": "Re: [发布申请]",
                    "original_message_id": "<request@example.com>",
                    "references": ["<root@example.com>", "<request@example.com>"],
                }
            )
        except Exception as exc:
            mail_checks["thread_reply"] = str(exc)
            missing.append("mail_thread_reply")
        try:
            self._mail().require_authenticated_readback_capability(
                {
                    "message_id": "<decision@example.com>",
                    "evidence": {
                        "raw_headers_sha256": "a" * 64,
                        "in_reply_to": "<request@example.com>",
                        "references": ["<root@example.com>", "<request@example.com>"],
                    },
                }
            )
        except Exception as exc:
            mail_checks["authenticated_readback"] = str(exc)
            missing.append("mail_readback")

        audit = {"status": "ready"}
        if not isinstance(self._audit_key, bytes) or len(self._audit_key) < 32:
            audit = {"status": "CAPABILITY_BLOCKED", "reason": "verification audit key must contain at least 32 bytes"}
            missing.append("audit_key")

        scheduler = self._scheduler_status()
        if scheduler.get("status") != "ready":
            missing.append("scheduler")

        product_gate = self._product_gate_preflight()
        if product_gate.get("status") != "ready":
            missing.append("product_gate")

        return {
            "missing_capabilities": sorted(dict.fromkeys(missing)),
            "role_source": role_source,
            "mail_checks": mail_checks,
            "audit": audit,
            "scheduler": scheduler,
            "product_gate": product_gate,
        }

    def _ingest_requests(self, snapshot: RoleSnapshot) -> int:
        count = 0
        for message in self._scan_requests():
            if not self._is_request_message(message):
                continue
            binding = self._build_request_binding(message, snapshot)
            existing = self._load_event(binding["event_id"], int(binding["round_id"]))
            if existing is None:
                record = self._new_event_record(binding, snapshot)
                self._save_event(record)
                count += 1
                self._write_audit(
                    record,
                    "REQUEST_CREATED",
                    "APPROVAL_COLLECTING",
                    {"request_digest": binding["request_digest"]},
                    required=False,
                )
                continue
            if canonical_json(existing["request_binding"]) != canonical_json(binding):
                self._append_capability_event(existing, "request binding drifted from the frozen first-seen payload", replayable=False)
                self._save_event(existing)
        return count

    def _ingest_replies(self) -> dict[str, int]:
        validated = 0
        quarantined = 0
        events = {(record["event_id"], int(record["round_id"])): record for record in self._load_all_events()}
        for message in self._scan_replies():
            matched = self._match_event_for_reply(message, events.values())
            if matched is None:
                continue
            roles = self._roles_from_record(matched)
            expected_role = self._expected_role_for_reply(message, roles)
            if expected_role is None:
                self._quarantine_unknown_role(matched, message)
                quarantined += 1
                continue
            try:
                decision = validate_and_record_message(
                    message,
                    request_binding=matched["request_binding"],
                    expected_role=expected_role,
                    authentication_policy=self.config.authentication_policy,
                    store=self._store(),
                    now=self._now(),
                )
                validated += 1
                self._write_audit(
                    matched,
                    "MAIL_DECISION",
                    "APPROVAL_COLLECTING",
                    {"role_id": expected_role.role_id, "decision": decision.decision},
                    required=False,
                )
            except MessageValidationError:
                quarantined += 1
                self._record_quarantined_message(matched, message)
                self._write_audit(
                    matched,
                    "APPROVAL_MESSAGE_QUARANTINED",
                    "APPROVAL_COLLECTING",
                    {"role_id": expected_role.role_id, "message_id": str(message.get("Message-ID", "")).strip()},
                    required=False,
                )
        return {"validated": validated, "quarantined": quarantined}

    def _finalize_event(self, record: dict[str, Any]) -> dict[str, Any]:
        roles = self._roles_from_record(record)
        reconcile = self._service().reconcile(record["request_binding"], roles, now=self._now())
        receipt_path = self._write_receipt_file(reconcile.receipt)
        record["receipt_path"] = receipt_path
        record["updated_at"] = self._isoformat(self._now())
        self._save_event(record)

        integrity_event = self._non_replayable_capability_event(record)
        audit_state = (
            "CAPABILITY_BLOCKED"
            if integrity_event is not None
            else str(reconcile.receipt["status"])
        )
        audit_payload = {
            "receipt_id": reconcile.receipt["receipt_id"],
            "receipt_status": reconcile.receipt["status"],
        }
        if integrity_event is not None:
            audit_payload["blocked_reason"] = str(
                integrity_event.get("reason") or "request integrity blocked"
            )
        audit_result = self._write_audit(
            record,
            "AGGREGATE_VERIFICATION",
            audit_state,
            audit_payload,
            required=True,
        )
        reminders: list[dict[str, Any]] = []
        handoff: dict[str, Any] = {"status": "skipped"}
        capability_event: dict[str, Any] | None = None

        if integrity_event is not None:
            capability_event = integrity_event
            handoff = {
                "status": "CAPABILITY_BLOCKED",
                "reason": str(integrity_event.get("reason") or "request integrity blocked"),
            }
            status = "CAPABILITY_BLOCKED"
        elif audit_result is not None and audit_result.status == "CAPABILITY_BLOCKED":
            capability_event = self._append_capability_event(
                record,
                audit_result.failure_reason or "aggregate audit write blocked state advance",
            )
            status = "CAPABILITY_BLOCKED"
        elif reconcile.receipt["status"] == "APPROVAL_VERIFIED":
            handoff, capability_event = self._handoff_verified_receipt(
                record,
                receipt=reconcile.receipt,
                receipt_path=receipt_path,
            )
            status = "ready" if handoff["status"] == "PRE_RELEASE_REQUESTED" else "CAPABILITY_BLOCKED"
        else:
            reminders = [self._jsonify(item) for item in self._send_due_reminders(record, roles)]
            status = "ready"

        public = self._public_event(record)
        return {
            "status": status,
            "event_id": record["event_id"],
            "round_id": int(record["round_id"]),
            "receipt": public["receipt"],
            "receipt_path": receipt_path,
            "handoff": handoff,
            "capability_event": capability_event,
            "reminders": reminders,
        }

    def _handoff_verified_receipt(
        self,
        record: dict[str, Any],
        *,
        receipt: dict[str, Any],
        receipt_path: str,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        stored = self._store().get_receipt(str(receipt["receipt_id"]))
        if stored is not None and stored.handoff_consumed_at is not None:
            return (
                {
                    "status": "PRE_RELEASE_REQUESTED",
                    "handoff_id": stored.handoff_id,
                    "consumed": True,
                    "idempotent": True,
                },
                None,
            )

        preflight = self._product_gate_preflight()
        if preflight.get("status") != "ready":
            reason = str(preflight.get("reason") or "product gate adapter missing")
            event = self._append_capability_event(record, reason)
            return ({"status": "CAPABILITY_BLOCKED", "reason": reason}, event)

        adapter = self._product_gate()
        if adapter is None:
            reason = "product gate adapter missing"
            event = self._append_capability_event(record, reason)
            return ({"status": "CAPABILITY_BLOCKED", "reason": reason}, event)
        try:
            response = adapter.request_pre_release(
                request_binding=dict(record["request_binding"]),
                receipt=dict(receipt),
                receipt_path=receipt_path,
            )
        except Exception as exc:
            reason = f"product gate handoff failed: {type(exc).__name__}: {exc}"
            event = self._append_capability_event(record, reason)
            return ({"status": "CAPABILITY_BLOCKED", "reason": reason}, event)
        if str(response.get("status") or "") != "PRE_RELEASE_REQUESTED" or str(response.get("event_id") or "") != record["event_id"]:
            reason = "unexpected post-handoff state"
            event = self._append_capability_event(record, reason)
            return ({"status": "CAPABILITY_BLOCKED", "reason": reason}, event)

        handoff_id = str(response.get("handoff_id") or f"pre-release:{record['event_id']}:{record['round_id']}")
        consumed = self._store().mark_handoff_consumed(
            str(receipt["receipt_id"]),
            handoff_id=handoff_id,
            consumed_at=self._isoformat(self._now()),
        )
        self._write_audit(
            record,
            "PRE_RELEASE_REQUESTED",
            "PRE_RELEASE_REQUESTED",
            {"handoff_id": handoff_id, "receipt_id": receipt["receipt_id"]},
            required=False,
        )
        return (
            {
                "status": "PRE_RELEASE_REQUESTED",
                "handoff_id": handoff_id,
                "consumed": consumed.handoff_consumed_at is not None,
                "idempotent": False,
                "pre_release_request_path": response.get("pre_release_request_path"),
            },
            None,
        )

    def _send_due_reminders(self, record: dict[str, Any], roles: Sequence[RoleRecord]) -> tuple[Any, ...]:
        policy = ReminderPolicy(
            initial_delay=timedelta(minutes=self.config.reminder_policy.initial_delay_minutes),
            repeat=timedelta(minutes=self.config.reminder_policy.repeat_minutes),
            maximum=self.config.reminder_policy.maximum,
            working_days=self.config.working_hours.days,
            working_start=time.fromisoformat(self.config.working_hours.start),
            working_end=time.fromisoformat(self.config.working_hours.end),
            timezone_name=self.config.timezone,
        )
        outcomes = self._service().send_due_reminders(
            record["request_binding"],
            roles,
            policy=policy,
            now=self._now(),
        )
        for outcome in outcomes:
            self._write_audit(
                record,
                "REMINDER_SENT",
                "APPROVAL_COLLECTING",
                {"role_id": outcome.role_id, "accepted": outcome.accepted},
                required=False,
            )
        return outcomes

    def _freeze_role_snapshot(self, *, store_snapshot: bool = True) -> RoleSnapshot:
        snapshot = self._role_fetcher()()
        if store_snapshot:
            self._store().record_role_snapshot(snapshot, fetched_at=self._isoformat(self._now()))
        return snapshot

    def _role_fetcher(self) -> RoleSnapshotFetcher:
        if self._role_snapshot_fetcher is not None:
            return self._role_snapshot_fetcher
        if isinstance(self.config.role_source, StaticRoleSourceConfig):
            digest = self._static_snapshot_digest(self.config.role_source.roles)
            snapshot = RoleSnapshot(
                document_url="static://test-roles",
                heading="## 审批角色",
                roles=self.config.role_source.roles,
                digest=digest,
            )
            return lambda: snapshot
        return lambda: fetch_role_snapshot(
            self.config.role_source.document_url,
            heading=self.config.role_source.heading,
        )

    def _new_event_record(self, binding: dict[str, Any], snapshot: RoleSnapshot) -> dict[str, Any]:
        return {
            "schema": "ReleaseApprovalVerifierEvent/v1",
            "event_id": binding["event_id"],
            "round_id": int(binding["round_id"]),
            "request_binding": binding,
            "role_snapshot": {
                "document_url": snapshot.document_url,
                "heading": snapshot.heading,
                "digest": snapshot.digest,
            },
            "roles": [self._jsonify(role) for role in snapshot.roles],
            "quarantined_messages": [],
            "capability_events": [],
            "receipt_path": None,
            "created_at": self._isoformat(self._now()),
            "updated_at": self._isoformat(self._now()),
        }

    def _public_event(self, record: dict[str, Any]) -> dict[str, Any]:
        receipt = self._latest_receipt(record)
        decisions = [self._jsonify(item) for item in self._store().list_current_decisions(record["event_id"], int(record["round_id"]))]
        return {
            "status": "ready",
            "event_id": record["event_id"],
            "round_id": int(record["round_id"]),
            "request": dict(record["request_binding"]),
            "role_snapshot": dict(record["role_snapshot"]),
            "roles": list(record["roles"]),
            "missing_roles": self._missing_roles_for_event(record),
            "current_decisions": decisions,
            "quarantined_messages": list(record.get("quarantined_messages", [])),
            "capability_events": list(record.get("capability_events", [])),
            "workflow_events": [self._jsonify(item) for item in self._store().list_workflow_events(record["event_id"], int(record["round_id"]))],
            "receipt": self._public_receipt(receipt, record.get("receipt_path")),
        }

    def _public_receipt(self, receipt: StoredReceipt | None, receipt_path: str | None) -> dict[str, Any] | None:
        if receipt is None:
            return None
        payload = dict(receipt.payload)
        payload["handoff_consumed_at"] = receipt.handoff_consumed_at
        payload["handoff_id"] = receipt.handoff_id
        payload["receipt_path"] = receipt_path
        return payload

    def _missing_roles_for_event(self, record: dict[str, Any]) -> list[str]:
        roles = self._roles_from_record(record)
        current_roles = {
            item.role_id
            for item in self._store().list_current_decisions(record["event_id"], int(record["round_id"]))
        }
        return sorted(role.role_id for role in roles if role.required and role.role_id not in current_roles)

    def _record_quarantined_message(self, record: dict[str, Any], message: EmailMessage) -> None:
        message_id = str(message.get("Message-ID", "")).strip()
        processed = self._store().get_processed_message(message_id)
        if processed is None:
            return
        entry = {
            "message_id": processed.message_id,
            "role_id": processed.role_id,
            "reason": processed.reason,
            "status": processed.status,
        }
        if entry not in record["quarantined_messages"]:
            record["quarantined_messages"].append(entry)
            record["updated_at"] = self._isoformat(self._now())
            self._save_event(record)

    def _quarantine_unknown_role(self, record: dict[str, Any], message: EmailMessage) -> None:
        message_id = str(message.get("Message-ID", "")).strip()
        if not message_id or self._store().has_message_id(message_id):
            return
        raw_headers_sha256 = hashlib.sha256(
            "".join(f"{key}: {value}\n" for key, value in message.items()).encode("utf-8")
        ).hexdigest()
        self._store().quarantine_message(
            message_id=message_id,
            event_id=record["event_id"],
            round_id=int(record["round_id"]),
            role_id="unknown",
            reason="APPROVAL_MESSAGE_QUARANTINED: sender email is not a frozen approval role.",
            raw_headers_sha256=raw_headers_sha256,
            recorded_at=self._isoformat(self._now()),
            payload={"from": str(message.get("From", "")), "subject": str(message.get("Subject", ""))},
        )
        self._record_quarantined_message(record, message)

    def _write_audit(
        self,
        record: dict[str, Any],
        event_type: str,
        state: str,
        payload: Mapping[str, Any],
        *,
        required: bool,
    ) -> AuditWriteResult | None:
        adapter = self._audit()
        if adapter is None:
            return None
        audit_record = AuditRecord(
            event_id=record["event_id"],
            round_id=str(record["round_id"]),
            event_type=event_type,
            manifest_digest=str(record["request_binding"]["manifest_digest"]),
            role_snapshot_digest=str(record["request_binding"]["role_snapshot_digest"]),
            state=state,
            required_role_emails={
                role["role_id"]: role["email"]
                for role in record["roles"]
                if role.get("required") is True and role.get("enabled") is True
            },
            audit_payload=dict(payload),
        )
        if required and hasattr(adapter, "required"):
            adapter.required = True
        return adapter.write(audit_record)

    @staticmethod
    def _non_replayable_capability_event(
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        events = record.get("capability_events")
        if not isinstance(events, list):
            return None
        for event in reversed(events):
            if (
                isinstance(event, Mapping)
                and event.get("event_type") == "CAPABILITY_BLOCKED"
                and event.get("replayable") is False
            ):
                return dict(event)
        return None

    def _append_capability_event(self, record: dict[str, Any], reason: str, *, replayable: bool = True) -> dict[str, Any]:
        existing = record.setdefault("capability_events", [])
        for item in existing:
            if (
                isinstance(item, Mapping)
                and item.get("event_type") == "CAPABILITY_BLOCKED"
                and item.get("reason") == reason
                and item.get("replayable") is replayable
            ):
                return dict(item)
        event = {
            "event_type": "CAPABILITY_BLOCKED",
            "reason": reason,
            "replayable": replayable,
            "created_at": self._isoformat(self._now()),
        }
        existing.append(event)
        record["updated_at"] = event["created_at"]
        self._save_event(record)
        return event

    def _build_request_binding(
        self,
        message: EmailMessage,
        snapshot: RoleSnapshot,
    ) -> dict[str, Any]:
        payload = self._extract_request_payload(message)
        if payload["contract"] != "ReleaseAuthorizationRequest/v1":
            raise VerifierControllerError(
                "INVALID_REQUEST", "unsupported release request contract"
            )
        if payload["role_snapshot_digest"] != snapshot.digest:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request role snapshot digest drifted"
            )
        expected_roles = list(snapshot.required_role_ids)
        if payload["required_roles"] != expected_roles:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request roles differ from the frozen role snapshot"
            )

        for key, header in _REQUEST_HEADER_MAP.items():
            expected: str
            if key == "required_roles":
                expected = ",".join(payload[key])
            else:
                expected = str(payload[key])
            if str(message.get(header, "")).strip() != expected:
                raise VerifierControllerError(
                    "INVALID_REQUEST", f"release request header {header} drifted from the machine block"
                )

        original_message_id = str(message.get("Message-ID", "")).strip()
        if original_message_id != payload["original_message_id"]:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request Message-ID drifted from the machine block"
            )
        transport_references = self._message_ids(message.get_all("References", []))
        if transport_references != payload["references"]:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request References drifted from the machine block"
            )
        recipients = {
            address.strip().lower()
            for _name, address in email.utils.getaddresses(message.get_all("To", []))
            if address.strip()
        }
        if self.config.release_group not in recipients:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request was not delivered to the configured release group"
            )

        references = list(payload["references"])
        if original_message_id not in references:
            references.append(original_message_id)
        created_at = str(payload.get("requested_at") or "").strip()
        if created_at:
            created_at = self._normalized_contract_timestamp(created_at, "requested_at")
        else:
            created_at = self._isoformat(self._message_datetime(message))
        return {
            "contract": payload["contract"],
            "event_id": payload["event_id"],
            "round_id": payload["round_id"],
            "task": payload["task"],
            "module": payload["module"],
            "target_scope": payload["target_scope"],
            "manifest_s_digest": payload["manifest_s_digest"],
            "manifest_r_digest": payload["manifest_r_digest"],
            "manifest_digest": payload["manifest_digest"],
            "request_digest": payload["request_digest"],
            "role_snapshot_digest": payload["role_snapshot_digest"],
            "required_roles": list(payload["required_roles"]),
            "subject": str(message.get("Subject", "")).strip() or "【发布申请】",
            "original_message_id": original_message_id,
            "references": references,
            "expires_at": payload["expires_at"],
            "idempotency_key": payload["idempotency_key"],
            "created_at": created_at,
        }

    def _extract_request_payload(self, message: EmailMessage) -> dict[str, Any]:
        body = self._message_text(message)
        if body.count(_REQUEST_BEGIN_MARKER) != 1 or body.count(_REQUEST_END_MARKER) != 1:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request machine block is missing or ambiguous"
            )
        encoded = body.split(_REQUEST_BEGIN_MARKER, 1)[1].split(
            _REQUEST_END_MARKER, 1
        )[0].strip()
        try:
            decoded = base64.urlsafe_b64decode(
                (encoded + "=" * (-len(encoded) % 4)).encode("ascii")
            ).decode("utf-8")
            payload = json.loads(decoded)
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError, json.JSONDecodeError) as exc:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request machine block is invalid"
            ) from exc
        if not isinstance(payload, dict):
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request machine block must decode to an object"
            )

        required_strings = (
            "contract",
            "event_id",
            "task",
            "module",
            "target_scope",
            "manifest_s_digest",
            "manifest_r_digest",
            "manifest_digest",
            "request_digest",
            "role_snapshot_digest",
            "original_message_id",
            "expires_at",
            "idempotency_key",
        )
        for key in required_strings:
            if not isinstance(payload.get(key), str) or not str(payload[key]).strip():
                raise VerifierControllerError(
                    "INVALID_REQUEST", f"release request field {key} is required"
                )
            payload[key] = str(payload[key]).strip()
        round_id = payload.get("round_id")
        if not isinstance(round_id, int) or isinstance(round_id, bool) or round_id <= 0:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request round id must be positive"
            )
        for field in _DIGEST_FIELDS:
            self._require_digest(str(payload[field]), field)

        expected_manifest = "sha256:" + hashlib.sha256(
            canonical_json(
                {
                    "manifest_s_digest": payload["manifest_s_digest"],
                    "manifest_r_digest": payload["manifest_r_digest"],
                }
            ).encode("utf-8")
        ).hexdigest()
        if payload["manifest_digest"] != expected_manifest:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request combined manifest digest is invalid"
            )
        expected_request_digest = "sha256:" + hashlib.sha256(
            canonical_json(
                {key: value for key, value in payload.items() if key != "request_digest"}
            ).encode("utf-8")
        ).hexdigest()
        if payload["request_digest"] != expected_request_digest:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request digest does not match the machine block"
            )

        required_roles = payload.get("required_roles")
        if not isinstance(required_roles, list) or not required_roles:
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request required_roles must be a non-empty list"
            )
        normalized_roles = [
            str(role).strip()
            for role in required_roles
            if isinstance(role, str) and str(role).strip()
        ]
        if len(normalized_roles) != len(required_roles) or len(set(normalized_roles)) != len(normalized_roles):
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request required_roles are invalid or duplicated"
            )
        payload["required_roles"] = normalized_roles

        if not _MESSAGE_ID_PATTERN.fullmatch(payload["original_message_id"]):
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request original_message_id is invalid"
            )
        references = payload.get("references")
        if not isinstance(references, list) or any(
            not isinstance(value, str) or not _MESSAGE_ID_PATTERN.fullmatch(value)
            for value in references
        ):
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request references must be exact Message-ID values"
            )
        if len(set(references)) != len(references):
            raise VerifierControllerError(
                "INVALID_REQUEST", "release request references contain duplicates"
            )
        payload["references"] = list(references)
        payload["expires_at"] = self._normalized_contract_timestamp(
            payload["expires_at"], "expires_at"
        )
        return payload

    def _message_text(self, message: EmailMessage) -> str:
        if message.is_multipart():
            preferred = message.get_body(preferencelist=("plain", "html"))
            if preferred is None:
                return ""
            return str(preferred.get_content())
        return str(message.get_content())

    def _normalized_contract_timestamp(self, value: str, field_name: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise VerifierControllerError(
                "INVALID_REQUEST", f"release request {field_name} is not ISO-8601"
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise VerifierControllerError(
                "INVALID_REQUEST", f"release request {field_name} must include a timezone"
            )
        return self._isoformat(parsed)

    def _is_request_message(self, message: EmailMessage) -> bool:
        subject = str(message.get("Subject", "")).strip()
        canonical_subject = (
            "【发布申请】" in subject
            or "[发布申请]" in subject
            or "[release approval]" in subject.lower()
        )
        return (
            canonical_subject
            and not str(message.get("In-Reply-To", "")).strip()
            and not self._message_ids(message.get_all("References", []))
            and not subject.lower().startswith(("re:", "fw:", "fwd:"))
        )
    def _match_event_for_reply(self, message: EmailMessage, records: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
        in_reply_to = str(message.get("In-Reply-To", "")).strip()
        references = set(self._message_ids(message.get_all("References", [])))
        for record in records:
            binding = record["request_binding"]
            if in_reply_to == binding["original_message_id"]:
                return record
            if references.intersection(set(binding.get("references", [])) | {binding["original_message_id"]}):
                return record
        return None

    def _expected_role_for_reply(self, message: EmailMessage, roles: Sequence[RoleRecord]) -> RoleRecord | None:
        candidates = {
            email.utils.parseaddr(str(message.get("From", "")))[1].strip().lower(),
            email.utils.parseaddr(str(message.get("Return-Path", "")))[1].strip().lower(),
        }
        for role in roles:
            if role.email in candidates:
                return role
        return None

    def _write_receipt_file(self, receipt: Mapping[str, Any]) -> str:
        path = self._receipt_path(str(receipt["receipt_id"]))
        payload = canonical_json(receipt) + "\n"
        if path.is_file() and path.read_text(encoding="utf-8") == payload:
            return str(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, path)
        return str(path)

    def _scan_requests(self) -> tuple[EmailMessage, ...]:
        if self._request_scanner is not None:
            return tuple(self._request_scanner())
        return tuple(
            message
            for message in self._default_mail_scan()
            if self._is_request_message(message)
        )

    def _scan_replies(self) -> tuple[EmailMessage, ...]:
        if self._reply_scanner is not None:
            return tuple(self._reply_scanner())
        return tuple(
            message
            for message in self._default_mail_scan()
            if not self._is_request_message(message)
        )

    def _default_mail_scan(self) -> tuple[EmailMessage, ...]:
        if self._default_mail_scan_cache is not None:
            return self._default_mail_scan_cache
        since = (self._now() - timedelta(days=7)).date().isoformat()
        result = self._mail().search_messages(
            {
                "account": self.config.verifier_mail_account.profile,
                "mailbox": self.config.mailbox,
                "query": {"subject": "发布申请", "since": since},
                "limit": 50,
                "scan_limit": 500,
            }
        )
        summaries = result.get("messages")
        if not isinstance(summaries, list):
            raise VerifierControllerError(
                "MAIL_READBACK_INVALID", "mail search did not return a messages array"
            )
        messages: list[EmailMessage] = []
        for summary in summaries:
            if not isinstance(summary, Mapping):
                raise VerifierControllerError(
                    "MAIL_READBACK_INVALID", "mail search returned an invalid summary"
                )
            uid = str(summary.get("uid") or "").strip()
            if not uid:
                raise VerifierControllerError(
                    "MAIL_READBACK_INVALID", "mail search summary is missing uid"
                )
            payload = self._mail().read_message(
                {
                    "account": self.config.verifier_mail_account.profile,
                    "mailbox": self.config.mailbox,
                    "uid": uid,
                }
            )
            messages.append(self._message_from_readback(payload))
        self._default_mail_scan_cache = tuple(messages)
        return self._default_mail_scan_cache

    def _message_from_readback(self, payload: Mapping[str, Any]) -> EmailMessage:
        evidence = payload.get("evidence")
        workflow_headers = payload.get("release_workflow_headers")
        if not isinstance(evidence, Mapping) or not isinstance(workflow_headers, Mapping):
            raise VerifierControllerError(
                "MAIL_READBACK_INVALID", "mail readback evidence or workflow headers are missing"
            )
        raw_headers_sha256 = str(evidence.get("raw_headers_sha256") or "").strip().lower()
        if not _RAW_SHA256_PATTERN.fullmatch(raw_headers_sha256):
            raise VerifierControllerError(
                "MAIL_READBACK_INVALID", "mail readback raw header digest is invalid"
            )
        message_id = str(payload.get("message_id") or "").strip()
        evidence_message_id = str(evidence.get("message_id") or "").strip()
        if (
            not _MESSAGE_ID_PATTERN.fullmatch(message_id)
            or evidence_message_id != message_id
        ):
            raise VerifierControllerError(
                "MAIL_READBACK_INVALID", "mail readback Message-ID evidence is invalid"
            )

        message = EmailMessage()
        from_header = self._format_readback_addresses(payload.get("from"))
        to_header = self._format_readback_addresses(payload.get("to"))
        cc_header = self._format_readback_addresses(payload.get("cc"))
        if from_header:
            message["From"] = from_header
        if to_header:
            message["To"] = to_header
        if cc_header:
            message["Cc"] = cc_header
        message["Subject"] = str(payload.get("subject") or "").strip()
        message["Message-ID"] = message_id

        date_value = str(payload.get("date") or "").strip()
        if date_value:
            try:
                parsed_date = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
                if parsed_date.tzinfo is None or parsed_date.utcoffset() is None:
                    parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                message["Date"] = email.utils.format_datetime(
                    parsed_date.astimezone(timezone.utc), usegmt=True
                )
            except ValueError:
                message["Date"] = date_value

        in_reply_to = str(evidence.get("in_reply_to") or "").strip()
        if in_reply_to:
            if not _MESSAGE_ID_PATTERN.fullmatch(in_reply_to):
                raise VerifierControllerError(
                    "MAIL_READBACK_INVALID", "mail readback In-Reply-To is invalid"
                )
            message["In-Reply-To"] = in_reply_to
        references = evidence.get("references")
        if not isinstance(references, list) or any(
            not isinstance(value, str) or not _MESSAGE_ID_PATTERN.fullmatch(value)
            for value in references
        ):
            raise VerifierControllerError(
                "MAIL_READBACK_INVALID", "mail readback References evidence is invalid"
            )
        if references:
            message["References"] = " ".join(references)

        return_path = str(evidence.get("return_path") or "").strip().lower()
        if return_path:
            message["Return-Path"] = f"<{return_path}>"
        authentication_results = str(evidence.get("authentication_results") or "").strip()
        if authentication_results:
            message["Authentication-Results"] = authentication_results
        received_spf = str(evidence.get("received_spf") or "").strip()
        if received_spf:
            message["Received-SPF"] = received_spf
        message["X-RD-Readback-Headers-SHA256"] = raw_headers_sha256

        for key, header in _REQUEST_HEADER_MAP.items():
            value = workflow_headers.get(key)
            if value is None or not str(value).strip():
                continue
            message[header] = str(value).strip()
        message.set_content(str(payload.get("body_text") or ""))
        return message

    @staticmethod
    def _format_readback_addresses(value: Any) -> str:
        if not isinstance(value, list):
            return ""
        addresses: list[str] = []
        for item in value:
            if not isinstance(item, Mapping):
                continue
            address = str(item.get("email") or "").strip().lower()
            if not address:
                continue
            name = str(item.get("name") or "").strip()
            addresses.append(email.utils.formataddr((name, address)) if name else address)
        return ", ".join(addresses)
    def _load_all_events(self) -> list[dict[str, Any]]:
        root = self._events_dir()
        if not root.is_dir():
            return []
        records: list[dict[str, Any]] = []
        for path in sorted(root.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                records.append(payload)
        return records

    def _load_event(self, event_id: str, round_id: int) -> dict[str, Any] | None:
        path = self._event_path(event_id, round_id)
        if not path.is_file():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None

    def _save_event(self, record: Mapping[str, Any]) -> None:
        path = self._event_path(str(record["event_id"]), int(record["round_id"]))
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(dict(record), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)

    def _store(self) -> VerifierStore:
        if self._store_instance is None:
            self._store_instance = VerifierStore(self._state_dir() / "verifier-state.sqlite3")
        return self._store_instance

    def _service(self) -> VerifierService:
        if self._service_instance is None:
            self._service_instance = VerifierService(
                store=self._store(),
                audit_key=self._audit_key,
                smtp_sender=self._smtp_sender,
            )
        return self._service_instance

    def _scheduler_status(self) -> dict[str, Any]:
        scheduler = self._scheduler
        if scheduler is None:
            scheduler = VerifierScheduler(
                plugin_name="release-approval-verifier",
                role_id="runtime",
                config_path=self.config_path,
                state_dir=self.config.state_dir,
                poll_minutes=self.config.poll_minutes,
            )
            self._scheduler = scheduler
        return dict(scheduler.status(mode="auto"))

    def _audit(self) -> Any | None:
        if self._audit_adapter is None:
            self._audit_adapter = LarkAuditAdapter(self.config.audit_document.url, required=True)
        return self._audit_adapter

    def _mail(self) -> Any:
        if self._mail_gateway is None:
            self._mail_gateway = MailGateway(
                self.config.dependency_lock,
                dependency_lock_sha256=self.config.dependency_lock_sha256,
            )
        return self._mail_gateway

    def _product_gate(self) -> Any | None:
        if self._product_gate_adapter is not None:
            return self._product_gate_adapter
        config_path = self.config.product_gate_config_path
        if config_path is None:
            return None
        self._product_gate_adapter = ProductGateMcpAdapter(
            self.config.dependency_lock,
            config_path,
            dependency_lock_sha256=self.config.dependency_lock_sha256,
        )
        return self._product_gate_adapter

    def _product_gate_preflight(self) -> dict[str, Any]:
        adapter = self._product_gate()
        if adapter is None:
            return {
                "status": "CAPABILITY_BLOCKED",
                "reason": "product gate adapter missing",
            }
        if hasattr(adapter, "preflight"):
            try:
                return dict(adapter.preflight())
            except Exception as exc:
                return {
                    "status": "CAPABILITY_BLOCKED",
                    "reason": f"product gate preflight failed: {type(exc).__name__}: {exc}",
                }
        return {"status": "ready"}
    def _latest_receipt(self, record: Mapping[str, Any]) -> StoredReceipt | None:
        return self._store().get_latest_receipt(str(record["event_id"]), int(record["round_id"]))

    def _smtp_sender(
        self,
        message: EmailMessage,
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        domain = self.config.verifier_mail_account.email.rsplit("@", 1)[-1]
        message_id = (
            "<release-approval-reminder-"
            + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:32]
            + f"@{domain}>"
        )
        payload = {
            "account": self.config.verifier_mail_account.profile,
            "to": [str(message.get("To", "")).strip()],
            "subject": str(message.get("Subject", "")).strip(),
            "text": message.get_content(),
            "message_id": message_id,
            "in_reply_to": str(message.get("In-Reply-To", "")).strip(),
            "references": self._message_ids(message.get_all("References", [])),
            "headers": {
                "X-RD-Event-Id": str(message.get("X-RD-Event-Id", "")).strip(),
                "X-RD-Round-Id": str(message.get("X-RD-Round-Id", "")).strip(),
                "X-RD-Idempotency-Key": idempotency_key,
            },
            "dry_run": False,
        }
        result = self._mail().send_email(payload)
        if isinstance(result, Mapping):
            sent = result.get("sent") is True
            returned_message_id = str(result.get("message_id") or "").strip()
            refused = result.get("refused") or {}
        else:
            sent = getattr(result, "sent", False) is True
            returned_message_id = str(
                getattr(result, "message_id", "") or ""
            ).strip()
            refused = getattr(result, "refused", {}) or {}
        return {
            "accepted": sent and not refused and returned_message_id == message_id,
            "message_id": returned_message_id or None,
            "refused": refused,
        }
    def _roles_from_record(self, record: Mapping[str, Any]) -> tuple[RoleRecord, ...]:
        roles: list[RoleRecord] = []
        for value in record.get("roles", []):
            if not isinstance(value, Mapping):
                continue
            roles.append(
                RoleRecord(
                    role_id=str(value.get("role_id") or ""),
                    email=str(value.get("email") or "").strip().lower(),
                    required=bool(value.get("required")),
                    enabled=bool(value.get("enabled")),
                )
            )
        return tuple(roles)

    def _message_datetime(self, message: EmailMessage) -> datetime:
        parsed = email.utils.parsedate_to_datetime(str(message.get("Date", "")))
        if parsed is None:
            return self._now()
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _message_ids(self, values: Sequence[str]) -> list[str]:
        results: list[str] = []
        for value in values:
            results.extend(
                part for part in value.split() if _MESSAGE_ID_PATTERN.fullmatch(part)
            )
        return list(dict.fromkeys(results))

    def _state_dir(self) -> Path:
        return self.config.state_dir.expanduser().resolve(strict=False)

    def _events_dir(self) -> Path:
        return self._state_dir() / "events"

    def _lock_path(self) -> Path:
        return self._state_dir() / "runtime.lock"

    def _receipt_path(self, receipt_id: str) -> Path:
        return self._state_dir() / "receipts" / f"{receipt_id}.json"

    def _event_path(self, event_id: str, round_id: int) -> Path:
        safe = "".join(character if character.isalnum() or character in {"-", "_"} else "_" for character in event_id)
        suffix = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:8]
        return self._events_dir() / f"{safe}--round-{round_id}--{suffix}.json"

    def _lock_owner(self) -> str:
        return f"verifier-{os.getpid()}"

    def _static_snapshot_digest(self, roles: Sequence[RoleRecord]) -> str:
        payload = canonical_json(
            [
                {
                    "email": role.email,
                    "enabled": role.enabled,
                    "required": role.required,
                    "role_id": role.role_id,
                }
                for role in sorted(roles, key=lambda item: item.role_id)
            ]
        )
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _jsonify(self, value: Any) -> Any:
        if is_dataclass(value):
            return asdict(value)
        if isinstance(value, Path):
            return str(value)
        return value

    def _require_digest(self, value: str, field_name: str) -> None:
        if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
            raise VerifierControllerError("INVALID_REQUEST", f"{field_name} must be a sha256 digest")

    def _now(self) -> datetime:
        current = self._now_fn()
        if current.tzinfo is None or current.utcoffset() is None:
            raise VerifierControllerError("INVALID_CLOCK", "now_fn must return a timezone-aware datetime")
        return current.astimezone(timezone.utc)

    def _isoformat(self, value: datetime) -> str:
        return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
