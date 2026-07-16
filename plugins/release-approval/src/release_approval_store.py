from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from release_approval_protocol import ReleaseAuthorizationRequest, canonical_json


_GENESIS_PREVIOUS_HASH = "0" * 64


class StoreError(RuntimeError):
    """Raised when the release-approval SQLite state store cannot satisfy an operation."""


class AuditTamperError(StoreError):
    """Raised when the append-only audit chain fails verification."""


@dataclass(frozen=True)
class StoredRequest:
    event_id: str
    round_id: int
    role: str
    request_digest: str
    installed_role_email: str


@dataclass(frozen=True)
class StoredDecision:
    decision_id: str
    request_event_id: str
    request_round_id: int
    role: str
    decision: str
    approver_email: str
    superseded_by: str | None


class ReleaseApprovalStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._initialize_schema()

    def close(self) -> None:
        self.connection.close()

    def _initialize_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT NOT NULL,
                mailbox TEXT NOT NULL,
                uidvalidity INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                message_id TEXT NOT NULL UNIQUE,
                UNIQUE(account, mailbox, uidvalidity, uid)
            );

            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                manifest_digest TEXT NOT NULL,
                manifest_s_digest TEXT NOT NULL,
                manifest_r_digest TEXT NOT NULL,
                role_snapshot_digest TEXT NOT NULL,
                original_message_id TEXT NOT NULL,
                required_roles_json TEXT NOT NULL,
                references_json TEXT NOT NULL,
                installed_role_email TEXT NOT NULL,
                task TEXT NOT NULL,
                module TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                UNIQUE(event_id, round_id, role)
            );

            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id TEXT NOT NULL UNIQUE,
                request_event_id TEXT NOT NULL,
                request_round_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                approver_email TEXT NOT NULL,
                decision TEXT NOT NULL,
                comment TEXT NOT NULL,
                source TEXT NOT NULL,
                original_message_id TEXT NOT NULL,
                decided_at TEXT NOT NULL,
                page_html_sha256 TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                superseded_by TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                html_path TEXT NOT NULL,
                html_sha256 TEXT NOT NULL,
                nonce_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(event_id, round_id, role)
            );

            CREATE TABLE IF NOT EXISTS smtp_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                smtp_message_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                detail TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );

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
        self.connection.commit()

    def record_message(
        self,
        *,
        account: str,
        mailbox: str,
        uidvalidity: int,
        uid: int,
        message_id: str,
    ) -> None:
        try:
            self.connection.execute(
                """
                INSERT INTO messages (account, mailbox, uidvalidity, uid, message_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (account, mailbox, uidvalidity, uid, message_id),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            message = str(exc)
            if "messages.account, messages.mailbox, messages.uidvalidity, messages.uid" in message:
                raise StoreError("duplicate UID for account/mailbox/UIDVALIDITY.") from exc
            if "messages.message_id" in message:
                raise StoreError("duplicate Message-ID.") from exc
            raise StoreError(message) from exc

    def record_request(self, request: ReleaseAuthorizationRequest) -> None:
        self.connection.execute(
            """
            INSERT INTO requests (
                event_id,
                round_id,
                role,
                request_digest,
                manifest_digest,
                manifest_s_digest,
                manifest_r_digest,
                role_snapshot_digest,
                original_message_id,
                required_roles_json,
                references_json,
                installed_role_email,
                task,
                module,
                expires_at,
                idempotency_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.event_id,
                request.round_id,
                request.installed_role_id,
                request.request_digest,
                request.manifest_digest,
                request.manifest_s_digest,
                request.manifest_r_digest,
                request.role_snapshot_digest,
                request.original_message_id,
                canonical_json(list(request.required_roles)),
                canonical_json(list(request.references)),
                request.installed_role_email,
                request.task,
                request.module,
                request.expires_at,
                request.idempotency_key,
            ),
        )
        self.connection.commit()

    def get_request(self, event_id: str, round_id: int, role: str) -> StoredRequest | None:
        row = self.connection.execute(
            """
            SELECT event_id, round_id, role, request_digest, installed_role_email
            FROM requests
            WHERE event_id = ? AND round_id = ? AND role = ?
            """,
            (event_id, round_id, role),
        ).fetchone()
        if row is None:
            return None
        return StoredRequest(
            event_id=row["event_id"],
            round_id=int(row["round_id"]),
            role=row["role"],
            request_digest=row["request_digest"],
            installed_role_email=row["installed_role_email"],
        )

    def record_page(
        self,
        *,
        event_id: str,
        round_id: int,
        role: str,
        html_path: str | Path,
        html_sha256: str,
        nonce_sha256: str,
        created_at: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO pages (
                event_id,
                round_id,
                role,
                html_path,
                html_sha256,
                nonce_sha256,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, round_id, role, str(Path(html_path)), html_sha256, nonce_sha256, created_at),
        )
        self.connection.commit()

    def record_decision(
        self,
        *,
        decision_id: str,
        request_event_id: str,
        request_round_id: int,
        role: str,
        approver_email: str,
        decision: str,
        comment: str,
        source: str,
        original_message_id: str,
        decided_at: str,
        page_html_sha256: str,
        request_digest: str,
        idempotency_key: str,
    ) -> StoredDecision:
        with self.connection:
            current = self.connection.execute(
                """
                SELECT decision_id
                FROM decisions
                WHERE request_event_id = ? AND request_round_id = ? AND role = ? AND superseded_by IS NULL
                ORDER BY id DESC
                LIMIT 1
                """,
                (request_event_id, request_round_id, role),
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
                    request_event_id,
                    request_round_id,
                    role,
                    approver_email,
                    decision,
                    comment,
                    source,
                    original_message_id,
                    decided_at,
                    page_html_sha256,
                    request_digest,
                    idempotency_key,
                    superseded_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    decision_id,
                    request_event_id,
                    request_round_id,
                    role,
                    approver_email,
                    decision,
                    comment,
                    source,
                    original_message_id,
                    decided_at,
                    page_html_sha256,
                    request_digest,
                    idempotency_key,
                ),
            )
        return self.get_decision(decision_id)  # type: ignore[return-value]

    def get_decision(self, decision_id: str) -> StoredDecision | None:
        row = self.connection.execute(
            """
            SELECT decision_id, request_event_id, request_round_id, role, decision, approver_email, superseded_by
            FROM decisions
            WHERE decision_id = ?
            """,
            (decision_id,),
        ).fetchone()
        if row is None:
            return None
        return StoredDecision(
            decision_id=row["decision_id"],
            request_event_id=row["request_event_id"],
            request_round_id=int(row["request_round_id"]),
            role=row["role"],
            decision=row["decision"],
            approver_email=row["approver_email"],
            superseded_by=row["superseded_by"],
        )

    def get_current_decision(self, event_id: str, round_id: int, role: str) -> StoredDecision | None:
        row = self.connection.execute(
            """
            SELECT decision_id
            FROM decisions
            WHERE request_event_id = ? AND request_round_id = ? AND role = ? AND superseded_by IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_id, round_id, role),
        ).fetchone()
        if row is None:
            return None
        return self.get_decision(row["decision_id"])

    def record_smtp_outcome(
        self,
        *,
        event_id: str,
        round_id: int,
        role: str,
        smtp_message_id: str,
        outcome: str,
        detail: str,
        recorded_at: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO smtp_outcomes (
                event_id,
                round_id,
                role,
                smtp_message_id,
                outcome,
                detail,
                recorded_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, round_id, role, smtp_message_id, outcome, detail, recorded_at),
        )
        self.connection.commit()

    def append_audit_event(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: str,
    ) -> str:
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
        self.connection.commit()
        return event_hash

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
                raise AuditTamperError(f"audit tamper detected at event {row['id']}: previous hash mismatch.")
            expected_hash = self._hash_audit_event(
                event_type=row["event_type"],
                payload_json=row["payload_json"],
                created_at=row["created_at"],
                previous_hash=row["previous_hash"],
            )
            if row["event_hash"] != expected_hash:
                raise AuditTamperError(f"audit tamper detected at event {row['id']}: event hash mismatch.")
            previous_hash = row["event_hash"]

    def _last_audit_hash(self) -> str:
        row = self.connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return _GENESIS_PREVIOUS_HASH
        return str(row["event_hash"])

    @staticmethod
    def _hash_audit_event(
        *,
        event_type: str,
        payload_json: str,
        created_at: str,
        previous_hash: str,
    ) -> str:
        envelope = canonical_json(
            {
                "created_at": created_at,
                "event_type": event_type,
                "payload": json.loads(payload_json),
                "previous_hash": previous_hash,
            }
        )
        return hashlib.sha256(envelope.encode("utf-8")).hexdigest()
