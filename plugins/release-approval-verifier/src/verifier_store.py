from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from role_snapshot import RoleSnapshot, canonical_json


SCHEMA_VERSION = 2
_GENESIS_PREVIOUS_HASH = "0" * 64


class StoreError(RuntimeError):
    """Raised when the verifier SQLite state store cannot satisfy an operation."""


@dataclass(frozen=True)
class ProcessedMessageRecord:
    message_id: str
    status: str
    event_id: str
    round_id: int
    role_id: str
    reason: str


@dataclass(frozen=True)
class StoredDecision:
    decision_id: str
    event_id: str
    round_id: int
    role_id: str
    decision: str
    normalized_text: str
    ambiguous: bool
    approver_email: str
    authentication_path: str
    source_message_id: str
    decided_at: str
    superseded_by: str | None


@dataclass(frozen=True)
class ReminderAttempt:
    idempotency_key: str
    event_id: str
    round_id: int
    role_id: str
    sequence: int
    status: str
    prepared_at: str
    attempted_at: str | None
    accepted_at: str | None
    smtp_message_id: str | None
    error: str | None


@dataclass(frozen=True)
class StoredReceipt:
    receipt_id: str
    event_id: str
    round_id: int
    status: str
    payload: dict[str, Any]
    generated_at: str
    superseded_by: str | None
    handoff_consumed_at: str | None
    handoff_id: str | None


@dataclass(frozen=True)
class WorkflowEvent:
    event_key: str
    event_id: str
    round_id: int
    event_type: str
    receipt_id: str
    role_id: str
    created_at: str
    payload: dict[str, Any]


class VerifierStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), timeout=5.0, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._initialize_schema()

    def close(self) -> None:
        self.connection.close()

    def has_message_id(self, message_id: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM processed_messages WHERE message_id = ? LIMIT 1",
            (message_id,),
        ).fetchone()
        return row is not None

    def record_role_snapshot(self, snapshot: RoleSnapshot, *, fetched_at: str) -> None:
        payload = canonical_json(
            [
                {
                    "email": role.email,
                    "enabled": role.enabled,
                    "required": role.required,
                    "role_id": role.role_id,
                }
                for role in snapshot.roles
            ]
        )
        self._run_write(
            "role snapshot",
            lambda: self.connection.execute(
                """
                INSERT INTO role_snapshots (snapshot_digest, document_url, heading, roles_json, fetched_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(snapshot_digest)
                DO UPDATE SET document_url = excluded.document_url,
                              heading = excluded.heading,
                              roles_json = excluded.roles_json,
                              fetched_at = excluded.fetched_at
                """,
                (snapshot.digest, snapshot.document_url, snapshot.heading, payload, fetched_at),
            ),
        )

    def quarantine_message(
        self,
        *,
        message_id: str,
        event_id: str,
        round_id: int,
        role_id: str,
        reason: str,
        raw_headers_sha256: str,
        recorded_at: str,
        payload: Mapping[str, Any],
    ) -> None:
        payload_json = canonical_json(payload)

        def writer() -> None:
            self.connection.execute(
                """
                INSERT INTO processed_messages (
                    message_id,
                    status,
                    event_id,
                    round_id,
                    role_id,
                    reason,
                    raw_headers_sha256,
                    payload_json,
                    recorded_at
                )
                VALUES (?, 'QUARANTINED', ?, ?, ?, ?, ?, ?, ?)
                """,
                (message_id, event_id, round_id, role_id, reason, raw_headers_sha256, payload_json, recorded_at),
            )
            self._append_audit_event(
                "quarantined-message",
                {
                    "event_id": event_id,
                    "message_id": message_id,
                    "reason": reason,
                    "role_id": role_id,
                    "round_id": round_id,
                },
                created_at=recorded_at,
            )

        self._run_write("quarantine message", writer)

    def record_decision(
        self,
        *,
        decision_id: str,
        event_id: str,
        round_id: int,
        role_id: str,
        decision: str,
        normalized_text: str,
        ambiguous: bool,
        approver_email: str,
        authentication_path: str,
        source_message_id: str,
        raw_headers_sha256: str,
        decided_at: str,
    ) -> StoredDecision:
        def writer() -> StoredDecision:
            current = self.connection.execute(
                """
                SELECT decision_id
                FROM decisions
                WHERE event_id = ? AND round_id = ? AND role_id = ? AND superseded_by IS NULL
                ORDER BY id DESC
                LIMIT 1
                """,
                (event_id, round_id, role_id),
            ).fetchone()
            if current is not None:
                self.connection.execute(
                    "UPDATE decisions SET superseded_by = ? WHERE decision_id = ?",
                    (decision_id, current["decision_id"]),
                )
            self.connection.execute(
                """
                INSERT INTO decisions (
                    decision_id,
                    event_id,
                    round_id,
                    role_id,
                    decision,
                    normalized_text,
                    ambiguous,
                    approver_email,
                    authentication_path,
                    source_message_id,
                    decided_at,
                    superseded_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    decision_id,
                    event_id,
                    round_id,
                    role_id,
                    decision,
                    normalized_text,
                    1 if ambiguous else 0,
                    approver_email,
                    authentication_path,
                    source_message_id,
                    decided_at,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO processed_messages (
                    message_id,
                    status,
                    event_id,
                    round_id,
                    role_id,
                    reason,
                    raw_headers_sha256,
                    payload_json,
                    recorded_at
                )
                VALUES (?, 'VALIDATED', ?, ?, ?, '', ?, ?, ?)
                """,
                (
                    source_message_id,
                    event_id,
                    round_id,
                    role_id,
                    raw_headers_sha256,
                    canonical_json({"decision_id": decision_id, "decision": decision}),
                    decided_at,
                ),
            )
            self._append_audit_event(
                "validated-decision",
                {
                    "authentication_path": authentication_path,
                    "decision": decision,
                    "decision_id": decision_id,
                    "event_id": event_id,
                    "message_id": source_message_id,
                    "role_id": role_id,
                    "round_id": round_id,
                },
                created_at=decided_at,
            )
            stored = self.get_decision(decision_id)
            if stored is None:
                raise StoreError("decision insert did not produce a readable record.")
            return stored

        return self._run_write("record decision", writer)

    def get_processed_message(self, message_id: str) -> ProcessedMessageRecord | None:
        row = self.connection.execute(
            """
            SELECT message_id, status, event_id, round_id, role_id, reason
            FROM processed_messages
            WHERE message_id = ?
            """,
            (message_id,),
        ).fetchone()
        if row is None:
            return None
        return ProcessedMessageRecord(
            message_id=row["message_id"],
            status=row["status"],
            event_id=row["event_id"],
            round_id=int(row["round_id"]),
            role_id=row["role_id"],
            reason=row["reason"],
        )

    def get_decision(self, decision_id: str) -> StoredDecision | None:
        row = self.connection.execute(
            """
            SELECT
                decision_id,
                event_id,
                round_id,
                role_id,
                decision,
                normalized_text,
                ambiguous,
                approver_email,
                authentication_path,
                source_message_id,
                decided_at,
                superseded_by
            FROM decisions
            WHERE decision_id = ?
            """,
            (decision_id,),
        ).fetchone()
        if row is None:
            return None
        return StoredDecision(
            decision_id=row["decision_id"],
            event_id=row["event_id"],
            round_id=int(row["round_id"]),
            role_id=row["role_id"],
            decision=row["decision"],
            normalized_text=row["normalized_text"],
            ambiguous=bool(row["ambiguous"]),
            approver_email=row["approver_email"],
            authentication_path=row["authentication_path"],
            source_message_id=row["source_message_id"],
            decided_at=row["decided_at"],
            superseded_by=row["superseded_by"],
        )

    def get_current_decision(self, event_id: str, round_id: int, role_id: str) -> StoredDecision | None:
        row = self.connection.execute(
            """
            SELECT
                decision_id,
                event_id,
                round_id,
                role_id,
                decision,
                normalized_text,
                ambiguous,
                approver_email,
                authentication_path,
                source_message_id,
                decided_at,
                superseded_by
            FROM decisions
            WHERE event_id = ? AND round_id = ? AND role_id = ? AND superseded_by IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_id, round_id, role_id),
        ).fetchone()
        if row is None:
            return None
        return self.get_decision(row["decision_id"])

    def list_current_decisions(self, event_id: str, round_id: int) -> tuple[StoredDecision, ...]:
        rows = self.connection.execute(
            """
            SELECT decision_id
            FROM decisions
            WHERE event_id = ? AND round_id = ? AND superseded_by IS NULL
            ORDER BY role_id ASC, id ASC
            """,
            (event_id, round_id),
        ).fetchall()
        decisions: list[StoredDecision] = []
        for row in rows:
            decision = self.get_decision(row["decision_id"])
            if decision is not None:
                decisions.append(decision)
        return tuple(decisions)

    def prepare_reminder_attempt(
        self,
        *,
        event_id: str,
        round_id: int,
        role_id: str,
        prepared_at: str,
    ) -> ReminderAttempt:
        def writer() -> ReminderAttempt:
            accepted_count = int(
                self.connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM reminder_attempts
                    WHERE event_id = ? AND round_id = ? AND role_id = ? AND status = 'ACCEPTED'
                    """,
                    (event_id, round_id, role_id),
                ).fetchone()[0]
            )
            sequence = accepted_count + 1
            existing = self.connection.execute(
                """
                SELECT idempotency_key
                FROM reminder_attempts
                WHERE event_id = ? AND round_id = ? AND role_id = ? AND sequence = ?
                """,
                (event_id, round_id, role_id, sequence),
            ).fetchone()
            if existing is not None:
                attempt = self.get_reminder_attempt(existing["idempotency_key"])
                if attempt is None:
                    raise StoreError("reminder attempt disappeared during preparation.")
                return attempt
            idempotency_key = f"reminder:{event_id}:{round_id}:{role_id}:{sequence}"
            self.connection.execute(
                """
                INSERT INTO reminder_attempts (
                    idempotency_key, event_id, round_id, role_id, sequence, status, prepared_at,
                    attempted_at, accepted_at, smtp_message_id, error
                )
                VALUES (?, ?, ?, ?, ?, 'PREPARED', ?, NULL, NULL, NULL, NULL)
                """,
                (idempotency_key, event_id, round_id, role_id, sequence, prepared_at),
            )
            attempt = self.get_reminder_attempt(idempotency_key)
            if attempt is None:
                raise StoreError("reminder attempt insert did not produce a readable record.")
            return attempt

        return self._run_write("prepare reminder attempt", writer)

    def complete_reminder_attempt(
        self,
        idempotency_key: str,
        *,
        accepted: bool,
        attempted_at: str,
        smtp_message_id: str | None = None,
        error: str | None = None,
    ) -> ReminderAttempt:
        def writer() -> ReminderAttempt:
            current = self.get_reminder_attempt(idempotency_key)
            if current is None:
                raise StoreError("unknown reminder idempotency key.")
            if current.status == "ACCEPTED":
                return current
            status = "ACCEPTED" if accepted else "FAILED"
            accepted_at = attempted_at if accepted else None
            safe_error = (error or "")[:1000] or None
            self.connection.execute(
                """
                UPDATE reminder_attempts
                SET status = ?, attempted_at = ?, accepted_at = ?, smtp_message_id = ?, error = ?
                WHERE idempotency_key = ?
                """,
                (status, attempted_at, accepted_at, smtp_message_id, safe_error, idempotency_key),
            )
            self._append_audit_event(
                "reminder-smtp-result",
                {
                    "accepted": accepted,
                    "event_id": current.event_id,
                    "idempotency_key": idempotency_key,
                    "role_id": current.role_id,
                    "round_id": current.round_id,
                    "sequence": current.sequence,
                    "smtp_message_id": smtp_message_id or "",
                },
                created_at=attempted_at,
            )
            updated = self.get_reminder_attempt(idempotency_key)
            if updated is None:
                raise StoreError("reminder result update did not produce a readable record.")
            return updated

        return self._run_write("complete reminder attempt", writer)

    def get_reminder_attempt(self, idempotency_key: str) -> ReminderAttempt | None:
        row = self.connection.execute(
            """
            SELECT idempotency_key, event_id, round_id, role_id, sequence, status, prepared_at,
                   attempted_at, accepted_at, smtp_message_id, error
            FROM reminder_attempts
            WHERE idempotency_key = ?
            """,
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        return ReminderAttempt(
            idempotency_key=row["idempotency_key"],
            event_id=row["event_id"],
            round_id=int(row["round_id"]),
            role_id=row["role_id"],
            sequence=int(row["sequence"]),
            status=row["status"],
            prepared_at=row["prepared_at"],
            attempted_at=row["attempted_at"],
            accepted_at=row["accepted_at"],
            smtp_message_id=row["smtp_message_id"],
            error=row["error"],
        )

    def get_accepted_reminder_times(self, event_id: str, round_id: int, role_id: str) -> tuple[str, ...]:
        rows = self.connection.execute(
            """
            SELECT accepted_at
            FROM reminder_attempts
            WHERE event_id = ? AND round_id = ? AND role_id = ? AND status = 'ACCEPTED'
            ORDER BY sequence ASC
            """,
            (event_id, round_id, role_id),
        ).fetchall()
        return tuple(str(row["accepted_at"]) for row in rows)

    def record_receipt(self, receipt: Mapping[str, Any]) -> tuple[StoredReceipt, bool]:
        receipt_id = _required_receipt_string(receipt, "receipt_id")
        event_id = _required_receipt_string(receipt, "event_id")
        round_id = receipt.get("round_id")
        if type(round_id) is not int or round_id <= 0:
            raise StoreError("receipt round_id must be a positive integer.")
        status = _required_receipt_string(receipt, "status")
        generated_at = _required_receipt_string(receipt, "generated_at")
        payload_json = canonical_json(receipt)

        def writer() -> tuple[StoredReceipt, bool]:
            existing = self.get_receipt(receipt_id)
            if existing is not None:
                if canonical_json(existing.payload) != payload_json:
                    raise StoreError("receipt id collision with different immutable payload.")
                return existing, False
            previous_rows = self.connection.execute(
                """
                SELECT receipt_id
                FROM verification_receipts
                WHERE event_id = ? AND round_id = ? AND superseded_by IS NULL
                ORDER BY id DESC
                """,
                (event_id, round_id),
            ).fetchall()
            for previous in previous_rows:
                self.connection.execute(
                    "UPDATE verification_receipts SET superseded_by = ? WHERE receipt_id = ?",
                    (receipt_id, previous["receipt_id"]),
                )
            self.connection.execute(
                """
                INSERT INTO verification_receipts (
                    receipt_id, event_id, round_id, status, payload_json, generated_at,
                    superseded_by, handoff_consumed_at, handoff_id
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (receipt_id, event_id, round_id, status, payload_json, generated_at),
            )
            self._append_audit_event(
                "verification-receipt-issued",
                {
                    "event_id": event_id,
                    "evidence_digest": str(receipt.get("evidence_digest") or ""),
                    "receipt_id": receipt_id,
                    "round_id": round_id,
                    "status": status,
                },
                created_at=generated_at,
            )
            stored = self.get_receipt(receipt_id)
            if stored is None:
                raise StoreError("receipt insert did not produce a readable record.")
            return stored, True

        return self._run_write("record verification receipt", writer)

    def get_receipt(self, receipt_id: str) -> StoredReceipt | None:
        row = self.connection.execute(
            """
            SELECT receipt_id, event_id, round_id, status, payload_json, generated_at,
                   superseded_by, handoff_consumed_at, handoff_id
            FROM verification_receipts
            WHERE receipt_id = ?
            """,
            (receipt_id,),
        ).fetchone()
        return self._receipt_from_row(row)

    def get_latest_receipt(self, event_id: str, round_id: int) -> StoredReceipt | None:
        row = self.connection.execute(
            """
            SELECT receipt_id, event_id, round_id, status, payload_json, generated_at,
                   superseded_by, handoff_consumed_at, handoff_id
            FROM verification_receipts
            WHERE event_id = ? AND round_id = ? AND superseded_by IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_id, round_id),
        ).fetchone()
        return self._receipt_from_row(row)

    def list_receipts(self, event_id: str, round_id: int) -> tuple[StoredReceipt, ...]:
        rows = self.connection.execute(
            """
            SELECT receipt_id, event_id, round_id, status, payload_json, generated_at,
                   superseded_by, handoff_consumed_at, handoff_id
            FROM verification_receipts
            WHERE event_id = ? AND round_id = ?
            ORDER BY id ASC
            """,
            (event_id, round_id),
        ).fetchall()
        return tuple(receipt for row in rows if (receipt := self._receipt_from_row(row)) is not None)

    def mark_handoff_consumed(self, receipt_id: str, *, handoff_id: str, consumed_at: str) -> StoredReceipt:
        def writer() -> StoredReceipt:
            receipt = self.get_receipt(receipt_id)
            if receipt is None:
                raise StoreError("cannot consume an unknown verification receipt.")
            if receipt.status != "APPROVAL_VERIFIED" or receipt.superseded_by is not None:
                raise StoreError("only the current APPROVAL_VERIFIED receipt can be consumed.")
            if receipt.handoff_consumed_at is not None:
                if receipt.handoff_id != handoff_id:
                    raise StoreError("verification receipt was already consumed by a different handoff.")
                return receipt
            self.connection.execute(
                """
                UPDATE verification_receipts
                SET handoff_consumed_at = ?, handoff_id = ?
                WHERE receipt_id = ?
                """,
                (consumed_at, handoff_id, receipt_id),
            )
            self._append_audit_event(
                "approval-handoff-consumed",
                {"handoff_id": handoff_id, "receipt_id": receipt_id},
                created_at=consumed_at,
            )
            updated = self.get_receipt(receipt_id)
            if updated is None:
                raise StoreError("handoff consumption update did not produce a readable record.")
            return updated

        return self._run_write("mark approval handoff consumed", writer)

    def record_workflow_event(
        self,
        *,
        event_key: str,
        event_id: str,
        round_id: int,
        event_type: str,
        receipt_id: str,
        role_id: str,
        created_at: str,
        payload: Mapping[str, Any],
    ) -> bool:
        payload_json = canonical_json(payload)

        def writer() -> bool:
            existing = self.connection.execute(
                "SELECT 1 FROM workflow_events WHERE event_key = ?",
                (event_key,),
            ).fetchone()
            if existing is not None:
                return False
            self.connection.execute(
                """
                INSERT INTO workflow_events (
                    event_key, event_id, round_id, event_type, receipt_id, role_id, created_at, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (event_key, event_id, round_id, event_type, receipt_id, role_id, created_at, payload_json),
            )
            self._append_audit_event(
                event_type.lower().replace("_", "-"),
                {
                    "event_id": event_id,
                    "event_key": event_key,
                    "receipt_id": receipt_id,
                    "role_id": role_id,
                    "round_id": round_id,
                },
                created_at=created_at,
            )
            return True

        return bool(self._run_write("record workflow event", writer))

    def list_workflow_events(self, event_id: str, round_id: int) -> tuple[WorkflowEvent, ...]:
        rows = self.connection.execute(
            """
            SELECT event_key, event_id, round_id, event_type, receipt_id, role_id, created_at, payload_json
            FROM workflow_events
            WHERE event_id = ? AND round_id = ?
            ORDER BY id ASC
            """,
            (event_id, round_id),
        ).fetchall()
        return tuple(
            WorkflowEvent(
                event_key=row["event_key"],
                event_id=row["event_id"],
                round_id=int(row["round_id"]),
                event_type=row["event_type"],
                receipt_id=row["receipt_id"],
                role_id=row["role_id"],
                created_at=row["created_at"],
                payload=json.loads(row["payload_json"]),
            )
            for row in rows
        )

    def append_audit_event(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: str,
    ) -> None:
        normalized_type = str(event_type).strip()
        normalized_created_at = str(created_at).strip()
        if not normalized_type or not normalized_created_at:
            raise StoreError("audit event type and created_at are required.")

        def writer() -> None:
            self._append_audit_event(
                normalized_type,
                dict(payload),
                created_at=normalized_created_at,
            )

        self._run_write("append audit event", writer)

    def audit_checkpoint(self) -> tuple[int, str]:
        self.verify_audit_chain()
        row = self.connection.execute(
            "SELECT COUNT(*) AS event_count, MAX(id) AS maximum_id FROM audit_events"
        ).fetchone()
        count = int(row["event_count"])
        if count == 0:
            return 0, _GENESIS_PREVIOUS_HASH
        head = self.connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return count, str(head["event_hash"])

    def verify_audit_checkpoint(self, expected_count: int, expected_head_hash: str) -> None:
        self.verify_audit_chain()
        if expected_count == 0:
            if expected_head_hash != _GENESIS_PREVIOUS_HASH:
                raise StoreError("audit checkpoint genesis hash mismatch.")
            return
        rows = self.connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY id ASC"
        ).fetchall()
        if len(rows) < expected_count:
            raise StoreError("audit chain was truncated before the signed checkpoint.")
        if str(rows[expected_count - 1]["event_hash"]) != expected_head_hash:
            raise StoreError("audit checkpoint head hash mismatch.")

    def verify_receipt_record(self, receipt_id: str, payload: Mapping[str, Any]) -> None:
        self.verify_audit_chain()
        stored = self.get_receipt(receipt_id)
        if stored is None:
            raise StoreError("signed receipt is missing from the local immutable receipt store.")
        if canonical_json(stored.payload) != canonical_json(payload):
            raise StoreError("stored receipt payload differs from the signed receipt.")
        if stored.superseded_by is not None:
            raise StoreError(f"signed receipt was superseded by {stored.superseded_by}.")
        issuance_rows = self.connection.execute(
            """
            SELECT payload_json
            FROM audit_events
            WHERE event_type = 'verification-receipt-issued'
            ORDER BY id ASC
            """
        ).fetchall()
        matches = 0
        for row in issuance_rows:
            audit_payload = json.loads(row["payload_json"])
            if audit_payload.get("receipt_id") == receipt_id:
                matches += 1
        if matches != 1:
            raise StoreError("audit chain is missing the unique receipt issuance event.")

    def _receipt_from_row(self, row: sqlite3.Row | None) -> StoredReceipt | None:
        if row is None:
            return None
        return StoredReceipt(
            receipt_id=row["receipt_id"],
            event_id=row["event_id"],
            round_id=int(row["round_id"]),
            status=row["status"],
            payload=json.loads(row["payload_json"]),
            generated_at=row["generated_at"],
            superseded_by=row["superseded_by"],
            handoff_consumed_at=row["handoff_consumed_at"],
            handoff_id=row["handoff_id"],
        )

    def verify_audit_chain(self) -> None:
        previous_hash = _GENESIS_PREVIOUS_HASH
        rows = self.connection.execute(
            """
            SELECT id, event_type, payload_json, created_at, previous_hash, event_hash
            FROM audit_events
            ORDER BY id ASC
            """
        ).fetchall()
        for row in rows:
            if row["previous_hash"] != previous_hash:
                raise StoreError(f"audit tamper detected at event {row['id']}: previous hash mismatch.")
            expected_hash = self._hash_audit_event(
                event_type=row["event_type"],
                payload_json=row["payload_json"],
                created_at=row["created_at"],
                previous_hash=row["previous_hash"],
            )
            if row["event_hash"] != expected_hash:
                raise StoreError(f"audit tamper detected at event {row['id']}: event hash mismatch.")
            previous_hash = row["event_hash"]

    def _initialize_schema(self) -> None:
        user_version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        if user_version == 0:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS role_snapshots (
                    snapshot_digest TEXT PRIMARY KEY,
                    document_url TEXT NOT NULL,
                    heading TEXT NOT NULL,
                    roles_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS processed_messages (
                    message_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    round_id INTEGER NOT NULL,
                    role_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    raw_headers_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_id TEXT NOT NULL UNIQUE,
                    event_id TEXT NOT NULL,
                    round_id INTEGER NOT NULL,
                    role_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    normalized_text TEXT NOT NULL,
                    ambiguous INTEGER NOT NULL,
                    approver_email TEXT NOT NULL,
                    authentication_path TEXT NOT NULL,
                    source_message_id TEXT NOT NULL UNIQUE,
                    decided_at TEXT NOT NULL,
                    superseded_by TEXT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS decisions_one_current_per_role
                ON decisions(event_id, round_id, role_id)
                WHERE superseded_by IS NULL;

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                """
            )
            self._ensure_task8_schema()
            self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.connection.commit()
            return
        if user_version == 1:
            self._ensure_task8_schema()
            self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.connection.commit()
            return
        if user_version != SCHEMA_VERSION:
            raise StoreError(
                f"unsupported schema version {user_version}; expected {SCHEMA_VERSION}. Start with a fresh state database or migrate it explicitly."
            )

    def _ensure_task8_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS reminder_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL UNIQUE,
                event_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                role_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                status TEXT NOT NULL,
                prepared_at TEXT NOT NULL,
                attempted_at TEXT NULL,
                accepted_at TEXT NULL,
                smtp_message_id TEXT NULL,
                error TEXT NULL,
                UNIQUE(event_id, round_id, role_id, sequence)
            );

            CREATE TABLE IF NOT EXISTS verification_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                event_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                superseded_by TEXT NULL,
                handoff_consumed_at TEXT NULL,
                handoff_id TEXT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS receipts_one_current_per_round
            ON verification_receipts(event_id, round_id)
            WHERE superseded_by IS NULL;

            CREATE TABLE IF NOT EXISTS workflow_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                event_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                role_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            """
        )
    def _run_write(self, operation_name: str, writer) -> Any:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            result = writer()
            self.connection.commit()
            return result
        except sqlite3.IntegrityError as exc:
            self.connection.rollback()
            message = str(exc)
            if "processed_messages.message_id" in message:
                raise StoreError("duplicate Message-ID.") from exc
            if "decisions.source_message_id" in message:
                raise StoreError("duplicate Message-ID.") from exc
            raise StoreError(f"{operation_name} failed: {message}") from exc
        except Exception:
            self.connection.rollback()
            raise

    def _append_audit_event(self, event_type: str, payload: Mapping[str, Any], *, created_at: str) -> None:
        previous_hash = self._last_audit_hash()
        payload_json = canonical_json(payload)
        event_hash = self._hash_audit_event(
            event_type=event_type,
            payload_json=payload_json,
            created_at=created_at,
            previous_hash=previous_hash,
        )
        self.connection.execute(
            """
            INSERT INTO audit_events (event_type, payload_json, created_at, previous_hash, event_hash)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_type, payload_json, created_at, previous_hash, event_hash),
        )

    def _last_audit_hash(self) -> str:
        row = self.connection.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return _GENESIS_PREVIOUS_HASH
        return str(row["event_hash"])

    @staticmethod
    def _hash_audit_event(*, event_type: str, payload_json: str, created_at: str, previous_hash: str) -> str:
        envelope = "\n".join((created_at, event_type, previous_hash, payload_json))
        return hashlib.sha256(envelope.encode("utf-8")).hexdigest()


def _required_receipt_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise StoreError(f"receipt {key} is required.")
    return value.strip()