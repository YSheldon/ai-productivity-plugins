from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from release_approval_protocol import ReleaseAuthorizationRequest, canonical_json


SCHEMA_VERSION = 1
_GENESIS_PREVIOUS_HASH = "0" * 64
_REQUIRED_TABLES = {
    "messages",
    "requests",
    "decisions",
    "pages",
    "smtp_outcomes",
    "audit_events",
}


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
        self.connection = sqlite3.connect(str(self.path), timeout=5.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._initialize_schema()

    def close(self) -> None:
        self.connection.close()

    def _initialize_schema(self) -> None:
        user_version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        user_objects = self._user_objects()

        if user_version == 0 and not user_objects:
            self._create_schema()
            self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.connection.commit()
            return

        if user_version != SCHEMA_VERSION:
            if user_version == 0:
                raise StoreError(
                    "unsupported legacy schema without version; start with a fresh state database or migrate it explicitly."
                )
            raise StoreError(
                f"unsupported schema version {user_version}; expected {SCHEMA_VERSION}. Start with a fresh state database or migrate it explicitly."
            )

        missing_tables = _REQUIRED_TABLES.difference(user_objects)
        if missing_tables:
            missing = ", ".join(sorted(missing_tables))
            raise StoreError(f"schema version {SCHEMA_VERSION} is incomplete; missing tables: {missing}.")

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account TEXT NOT NULL,
                mailbox TEXT NOT NULL,
                uidvalidity INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                message_id TEXT NOT NULL UNIQUE,
                UNIQUE(account, mailbox, uidvalidity, uid)
            );

            CREATE TABLE requests (
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
            CREATE UNIQUE INDEX requests_idempotency_key_unique
            ON requests(idempotency_key);

            CREATE TABLE decisions (
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
                superseded_by TEXT NULL,
                FOREIGN KEY (request_event_id, request_round_id, role)
                    REFERENCES requests(event_id, round_id, role)
                    ON DELETE RESTRICT
            );
            CREATE UNIQUE INDEX decisions_idempotency_key_unique
            ON decisions(idempotency_key);
            CREATE UNIQUE INDEX decisions_one_current_per_role
            ON decisions(request_event_id, request_round_id, role)
            WHERE superseded_by IS NULL;

            CREATE TABLE pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                html_path TEXT NOT NULL,
                html_sha256 TEXT NOT NULL,
                nonce_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(event_id, round_id, role),
                FOREIGN KEY (event_id, round_id, role)
                    REFERENCES requests(event_id, round_id, role)
                    ON DELETE RESTRICT
            );

            CREATE TABLE smtp_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                smtp_message_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                detail TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                FOREIGN KEY (event_id, round_id, role)
                    REFERENCES requests(event_id, round_id, role)
                    ON DELETE RESTRICT
            );

            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );
            """
        )

    def _user_objects(self) -> set[str]:
        rows = self.connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        return {str(row[0]) for row in rows}

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
            raise self._translate_integrity_error(exc) from exc

    def record_request(self, request: ReleaseAuthorizationRequest) -> StoredRequest:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            existing_by_key = self._get_request_row_by_idempotency(request.idempotency_key)
            if existing_by_key is not None:
                if self._request_row_matches(existing_by_key, request):
                    self.connection.commit()
                    return self._row_to_stored_request(existing_by_key)
                self.connection.rollback()
                raise StoreError("request idempotency key is already bound to a different payload.")

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
            stored = self.get_request(request.event_id, request.round_id, request.installed_role_id)
            if stored is None:
                raise StoreError("request insert did not produce a readable record.")
            self.connection.commit()
            return stored
        except StoreError:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise self._translate_integrity_error(exc) from exc
        except sqlite3.OperationalError as exc:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise StoreError(f"request transaction failed: {exc}") from exc
        except Exception:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise

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
        return self._row_to_stored_request(row)

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
        try:
            self.connection.execute(
                """
                INSERT INTO pages (
                    event_id,
                    round_id,
                    role,
                    html_path,
                    html_sha256,
                    nonce_sha256,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id, round_id, role)
                DO UPDATE SET
                    html_path = excluded.html_path,
                    html_sha256 = excluded.html_sha256,
                    nonce_sha256 = excluded.nonce_sha256,
                    created_at = excluded.created_at
                """,
                (event_id, round_id, role, str(Path(html_path)), html_sha256, nonce_sha256, created_at),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            raise self._translate_integrity_error(exc) from exc

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
        payload = {
            "decision_id": decision_id,
            "request_event_id": request_event_id,
            "request_round_id": request_round_id,
            "role": role,
            "approver_email": approver_email,
            "decision": decision,
            "comment": comment,
            "source": source,
            "original_message_id": original_message_id,
            "decided_at": decided_at,
            "page_html_sha256": page_html_sha256,
            "request_digest": request_digest,
            "idempotency_key": idempotency_key,
        }
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            existing_by_key = self._get_decision_row_by_idempotency(idempotency_key)
            if existing_by_key is not None:
                if self._decision_row_matches(existing_by_key, payload):
                    self.connection.commit()
                    return self._row_to_stored_decision(existing_by_key)
                self.connection.rollback()
                raise StoreError("decision idempotency key is already bound to a different payload.")

            existing_by_id = self._get_decision_row_by_decision_id(decision_id)
            if existing_by_id is not None:
                if self._decision_row_matches(existing_by_id, payload):
                    self.connection.commit()
                    return self._row_to_stored_decision(existing_by_id)
                self.connection.rollback()
                raise StoreError("decision_id is already bound to a different payload.")

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
            self.connection.commit()
        except StoreError:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise self._translate_integrity_error(exc) from exc
        except sqlite3.OperationalError as exc:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise StoreError(f"decision transaction failed: {exc}") from exc
        except Exception:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise

        stored = self.get_decision(decision_id)
        if stored is None:
            raise StoreError("decision insert did not produce a readable record.")
        return stored

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
        return self._row_to_stored_decision(row)

    def get_current_decision(self, event_id: str, round_id: int, role: str) -> StoredDecision | None:
        row = self.connection.execute(
            """
            SELECT decision_id, request_event_id, request_round_id, role, decision, approver_email, superseded_by
            FROM decisions
            WHERE request_event_id = ? AND request_round_id = ? AND role = ? AND superseded_by IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_id, round_id, role),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_stored_decision(row)

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
        try:
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
        except sqlite3.IntegrityError as exc:
            raise self._translate_integrity_error(exc) from exc

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

    def _get_request_row_by_idempotency(self, idempotency_key: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM requests WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()

    def _get_decision_row_by_idempotency(self, idempotency_key: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM decisions WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()

    def _get_decision_row_by_decision_id(self, decision_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()

    @staticmethod
    def _request_row_matches(row: sqlite3.Row, request: ReleaseAuthorizationRequest) -> bool:
        return (
            row["event_id"] == request.event_id
            and int(row["round_id"]) == request.round_id
            and row["role"] == request.installed_role_id
            and row["request_digest"] == request.request_digest
            and row["manifest_digest"] == request.manifest_digest
            and row["manifest_s_digest"] == request.manifest_s_digest
            and row["manifest_r_digest"] == request.manifest_r_digest
            and row["role_snapshot_digest"] == request.role_snapshot_digest
            and row["original_message_id"] == request.original_message_id
            and row["required_roles_json"] == canonical_json(list(request.required_roles))
            and row["references_json"] == canonical_json(list(request.references))
            and row["installed_role_email"] == request.installed_role_email
            and row["task"] == request.task
            and row["module"] == request.module
            and row["expires_at"] == request.expires_at
            and row["idempotency_key"] == request.idempotency_key
        )

    @staticmethod
    def _decision_row_matches(row: sqlite3.Row, payload: Mapping[str, Any]) -> bool:
        return (
            row["decision_id"] == payload["decision_id"]
            and row["request_event_id"] == payload["request_event_id"]
            and int(row["request_round_id"]) == payload["request_round_id"]
            and row["role"] == payload["role"]
            and row["approver_email"] == payload["approver_email"]
            and row["decision"] == payload["decision"]
            and row["comment"] == payload["comment"]
            and row["source"] == payload["source"]
            and row["original_message_id"] == payload["original_message_id"]
            and row["decided_at"] == payload["decided_at"]
            and row["page_html_sha256"] == payload["page_html_sha256"]
            and row["request_digest"] == payload["request_digest"]
            and row["idempotency_key"] == payload["idempotency_key"]
        )

    @staticmethod
    def _row_to_stored_request(row: sqlite3.Row) -> StoredRequest:
        return StoredRequest(
            event_id=row["event_id"],
            round_id=int(row["round_id"]),
            role=row["role"],
            request_digest=row["request_digest"],
            installed_role_email=row["installed_role_email"],
        )

    @staticmethod
    def _row_to_stored_decision(row: sqlite3.Row) -> StoredDecision:
        return StoredDecision(
            decision_id=row["decision_id"],
            request_event_id=row["request_event_id"],
            request_round_id=int(row["request_round_id"]),
            role=row["role"],
            decision=row["decision"],
            approver_email=row["approver_email"],
            superseded_by=row["superseded_by"],
        )

    @staticmethod
    def _translate_integrity_error(exc: sqlite3.IntegrityError) -> StoreError:
        message = str(exc)
        if "messages.account, messages.mailbox, messages.uidvalidity, messages.uid" in message:
            return StoreError("duplicate UID for account/mailbox/UIDVALIDITY.")
        if "messages.message_id" in message:
            return StoreError("duplicate Message-ID.")
        if "requests_idempotency_key_unique" in message or "requests.idempotency_key" in message:
            return StoreError("request idempotency key is already bound to a different payload.")
        if "requests.event_id, requests.round_id, requests.role" in message:
            return StoreError("request already exists for this event/round/role binding.")
        if "decisions_idempotency_key_unique" in message or "decisions.idempotency_key" in message:
            return StoreError("decision idempotency key is already bound to a different payload.")
        if "decisions.decision_id" in message:
            return StoreError("decision_id is already bound to an existing decision.")
        if "FOREIGN KEY constraint failed" in message:
            return StoreError("request parent record must exist before writing child state.")
        return StoreError(message)

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
        envelope = "\n".join(
            (
                created_at,
                event_type,
                previous_hash,
                payload_json,
            )
        )
        return hashlib.sha256(envelope.encode("utf-8")).hexdigest()
