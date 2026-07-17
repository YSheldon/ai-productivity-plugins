from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TypeVar

from rd_flywheel_protocol import (
    CapabilityGapEvent,
    EvidenceReference,
    canonical_json,
    sha256_text,
    validate_transition,
)


SCHEMA_VERSION = 1
_GENESIS_HASH = "0" * 64
_REQUIRED_TABLES = {
    "events",
    "state_transitions",
    "evidence",
    "processed_inputs",
    "audit_events",
}
_T = TypeVar("_T")


class StoreError(RuntimeError):
    """Raised when durable flywheel state cannot be safely read or written."""


class AuditTamperError(StoreError):
    """Raised when the append-only audit hash chain is invalid."""


@dataclass(frozen=True)
class StoredEvent:
    idempotency_key: str
    payload_digest: str
    payload: Mapping[str, Any]
    originating_plugin: str
    originating_event_id: str
    originating_round_id: int
    checkpoint_digest: str
    missing_capability: str
    state: str
    adapter_profile: str | None
    last_detail: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class StoredTransition:
    from_state: str | None
    to_state: str
    detail: str
    changed_at: str


class RDFlywheelStore:
    def __init__(
        self,
        path: str | Path,
        *,
        verify_chain_on_open: bool = True,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.connection = sqlite3.connect(
                str(self.path),
                timeout=10.0,
                check_same_thread=False,
            )
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA journal_mode = WAL")
            self._initialize_schema()
            if verify_chain_on_open:
                self.verify_audit_chain()
        except sqlite3.Error as exc:
            raise StoreError(f"cannot open state database: {exc}") from exc

    def close(self) -> None:
        self.connection.close()

    def _initialize_schema(self) -> None:
        version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        objects = self._user_tables()
        if version == 0 and not objects:
            def writer() -> None:
                self.connection.executescript(
                    """
                    CREATE TABLE events (
                        idempotency_key TEXT PRIMARY KEY,
                        payload_digest TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        originating_plugin TEXT NOT NULL,
                        originating_event_id TEXT NOT NULL,
                        originating_round_id INTEGER NOT NULL,
                        checkpoint_digest TEXT NOT NULL,
                        missing_capability TEXT NOT NULL,
                        state TEXT NOT NULL,
                        adapter_profile TEXT NULL,
                        last_detail TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE state_transitions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        idempotency_key TEXT NOT NULL,
                        from_state TEXT NULL,
                        to_state TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        changed_at TEXT NOT NULL,
                        FOREIGN KEY (idempotency_key)
                            REFERENCES events(idempotency_key)
                            ON DELETE RESTRICT
                    );

                    CREATE TABLE evidence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        idempotency_key TEXT NOT NULL,
                        state TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        uri TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        verifier TEXT NOT NULL,
                        verified INTEGER NOT NULL CHECK (verified IN (0, 1)),
                        recorded_at TEXT NOT NULL,
                        UNIQUE (
                            idempotency_key, state, kind, uri, sha256, verifier, verified
                        ),
                        FOREIGN KEY (idempotency_key)
                            REFERENCES events(idempotency_key)
                            ON DELETE RESTRICT
                    );

                    CREATE TABLE processed_inputs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source TEXT NOT NULL,
                        content_digest TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        recorded_at TEXT NOT NULL,
                        UNIQUE(source, content_digest)
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
                self.connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

            self._run_write("schema initialization", writer, immediate=True)
            return
        if version != SCHEMA_VERSION:
            raise StoreError(
                f"unsupported schema version {version}; expected {SCHEMA_VERSION}."
            )
        missing = _REQUIRED_TABLES.difference(objects)
        if missing:
            raise StoreError(
                f"schema version {SCHEMA_VERSION} is incomplete; missing tables: "
                + ", ".join(sorted(missing))
                + "."
            )

    def _user_tables(self) -> set[str]:
        rows = self.connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return {str(row[0]) for row in rows}

    def _run_write(
        self,
        operation: str,
        writer: Callable[[], _T],
        *,
        immediate: bool = False,
    ) -> _T:
        try:
            self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            result = writer()
            self.connection.commit()
            return result
        except (StoreError, AuditTamperError):
            self._rollback()
            raise
        except sqlite3.IntegrityError as exc:
            self._rollback()
            raise StoreError(f"{operation} integrity failure: {exc}") from exc
        except sqlite3.Error as exc:
            self._rollback()
            raise StoreError(f"{operation} transaction failed: {exc}") from exc
        except Exception:
            self._rollback()
            raise

    def _rollback(self) -> None:
        try:
            if self.connection.in_transaction:
                self.connection.rollback()
        except sqlite3.Error:
            pass

    def record_event(
        self,
        event: CapabilityGapEvent,
        *,
        recorded_at: str,
    ) -> StoredEvent:
        actual_digest = sha256_text(canonical_json(dict(event.payload)))
        if actual_digest != event.payload_digest:
            raise StoreError("event idempotency key is bound to a different payload digest.")

        def writer() -> StoredEvent:
            existing = self._event_row(event.idempotency_key)
            if existing is not None:
                if existing["payload_digest"] != event.payload_digest:
                    raise StoreError(
                        "event idempotency key is already bound to a different payload."
                    )
                return self._row_to_event(existing)

            payload_json = canonical_json(dict(event.payload))
            self.connection.execute(
                """
                INSERT INTO events (
                    idempotency_key, payload_digest, payload_json,
                    originating_plugin, originating_event_id,
                    originating_round_id, checkpoint_digest,
                    missing_capability, state, adapter_profile,
                    last_detail, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'RECEIVED', NULL, ?, ?, ?)
                """,
                (
                    event.idempotency_key,
                    event.payload_digest,
                    payload_json,
                    event.originating_plugin,
                    event.originating_event_id,
                    event.originating_round_id,
                    event.checkpoint_digest,
                    event.missing_capability,
                    "event accepted into durable inbox",
                    recorded_at,
                    recorded_at,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO state_transitions (
                    idempotency_key, from_state, to_state, detail, changed_at
                ) VALUES (?, NULL, 'RECEIVED', ?, ?)
                """,
                (
                    event.idempotency_key,
                    "event accepted into durable inbox",
                    recorded_at,
                ),
            )
            self._append_audit(
                "event_received",
                {
                    "idempotency_key": event.idempotency_key,
                    "payload_digest": event.payload_digest,
                    "checkpoint_digest": event.checkpoint_digest,
                },
                created_at=recorded_at,
            )
            row = self._event_row(event.idempotency_key)
            if row is None:
                raise StoreError("event insert did not produce a readable record.")
            return self._row_to_event(row)

        return self._run_write("event", writer, immediate=True)

    def transition(
        self,
        idempotency_key: str,
        to_state: str,
        evidence: Sequence[EvidenceReference],
        *,
        changed_at: str,
        detail: str,
        adapter_profile: str | None = None,
    ) -> StoredEvent:
        def writer() -> StoredEvent:
            row = self._event_row(idempotency_key)
            if row is None:
                raise StoreError("event does not exist.")
            from_state = str(row["state"])
            validate_transition(from_state, to_state, evidence)
            self._insert_evidence(
                idempotency_key,
                to_state,
                evidence,
                recorded_at=changed_at,
            )
            next_adapter = (
                adapter_profile
                if adapter_profile is not None
                else row["adapter_profile"]
            )
            self.connection.execute(
                """
                UPDATE events
                SET state = ?, adapter_profile = ?, last_detail = ?, updated_at = ?
                WHERE idempotency_key = ?
                """,
                (
                    to_state,
                    next_adapter,
                    detail,
                    changed_at,
                    idempotency_key,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO state_transitions (
                    idempotency_key, from_state, to_state, detail, changed_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (idempotency_key, from_state, to_state, detail, changed_at),
            )
            self._append_audit(
                "state_transition",
                {
                    "idempotency_key": idempotency_key,
                    "from_state": from_state,
                    "to_state": to_state,
                    "detail": detail,
                    "evidence_digests": [item.sha256 for item in evidence],
                },
                created_at=changed_at,
            )
            updated = self._event_row(idempotency_key)
            if updated is None:
                raise StoreError("event transition did not produce a readable record.")
            return self._row_to_event(updated)

        return self._run_write("state transition", writer, immediate=True)

    def record_evidence(
        self,
        idempotency_key: str,
        evidence: Sequence[EvidenceReference],
        *,
        recorded_at: str,
    ) -> None:
        def writer() -> None:
            row = self._event_row(idempotency_key)
            if row is None:
                raise StoreError("event does not exist.")
            self._insert_evidence(
                idempotency_key,
                str(row["state"]),
                evidence,
                recorded_at=recorded_at,
            )
            self._append_audit(
                "evidence_recorded",
                {
                    "idempotency_key": idempotency_key,
                    "evidence": [item.as_dict() for item in evidence],
                },
                created_at=recorded_at,
            )

        self._run_write("evidence", writer, immediate=True)

    def _insert_evidence(
        self,
        idempotency_key: str,
        state: str,
        evidence: Sequence[EvidenceReference],
        *,
        recorded_at: str,
    ) -> None:
        for item in evidence:
            self.connection.execute(
                """
                INSERT OR IGNORE INTO evidence (
                    idempotency_key, state, kind, uri, sha256,
                    verifier, verified, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    idempotency_key,
                    state,
                    item.kind,
                    item.uri,
                    item.sha256,
                    item.verifier,
                    int(item.verified),
                    recorded_at,
                ),
            )

    def has_input(self, *, source: str, content_digest: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM processed_inputs WHERE source = ? AND content_digest = ?",
            (source, content_digest),
        ).fetchone()
        return row is not None

    def record_input(
        self,
        *,
        source: str,
        content_digest: str,
        outcome: str,
        recorded_at: str,
    ) -> bool:
        def writer() -> bool:
            existing = self.connection.execute(
                """
                SELECT 1 FROM processed_inputs
                WHERE source = ? AND content_digest = ?
                """,
                (source, content_digest),
            ).fetchone()
            if existing is not None:
                return False
            self.connection.execute(
                """
                INSERT INTO processed_inputs (
                    source, content_digest, outcome, recorded_at
                ) VALUES (?, ?, ?, ?)
                """,
                (source, content_digest, outcome, recorded_at),
            )
            self._append_audit(
                "input_recorded",
                {
                    "source": source,
                    "content_digest": content_digest,
                    "outcome": outcome,
                },
                created_at=recorded_at,
            )
            return True

        return self._run_write("input receipt", writer, immediate=True)

    def append_audit_event(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: str,
    ) -> str:
        return self._run_write(
            "audit event",
            lambda: self._append_audit(
                event_type,
                payload,
                created_at=created_at,
            ),
            immediate=True,
        )

    def _append_audit(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: str,
    ) -> str:
        previous_hash = self._last_audit_hash()
        payload_json = canonical_json(payload)
        event_hash = self._audit_hash(
            event_type=event_type,
            payload_json=payload_json,
            created_at=created_at,
            previous_hash=previous_hash,
        )
        self.connection.execute(
            """
            INSERT INTO audit_events (
                event_type, payload_json, created_at, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (event_type, payload_json, created_at, previous_hash, event_hash),
        )
        return event_hash

    def verify_audit_chain(self) -> dict[str, Any]:
        previous_hash = _GENESIS_HASH
        count = 0
        rows = self.connection.execute(
            """
            SELECT id, event_type, payload_json, created_at,
                   previous_hash, event_hash
            FROM audit_events ORDER BY id ASC
            """
        ).fetchall()
        for row in rows:
            count += 1
            if row["previous_hash"] != previous_hash:
                raise AuditTamperError(
                    f"audit tamper detected at event {row['id']}: previous hash mismatch."
                )
            expected = self._audit_hash(
                event_type=row["event_type"],
                payload_json=row["payload_json"],
                created_at=row["created_at"],
                previous_hash=row["previous_hash"],
            )
            if row["event_hash"] != expected:
                raise AuditTamperError(
                    f"audit tamper detected at event {row['id']}: event hash mismatch."
                )
            previous_hash = str(row["event_hash"])
        return {"ok": True, "count": count, "head_hash": previous_hash}

    def get_event(self, idempotency_key: str) -> StoredEvent | None:
        row = self._event_row(idempotency_key)
        return None if row is None else self._row_to_event(row)

    def list_events(
        self,
        states: Sequence[str] | None = None,
    ) -> tuple[StoredEvent, ...]:
        if states:
            placeholders = ",".join("?" for _ in states)
            rows = self.connection.execute(
                f"SELECT * FROM events WHERE state IN ({placeholders}) "
                "ORDER BY created_at, idempotency_key",
                tuple(states),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM events ORDER BY created_at, idempotency_key"
            ).fetchall()
        return tuple(self._row_to_event(row) for row in rows)

    def list_evidence(
        self,
        idempotency_key: str,
    ) -> tuple[EvidenceReference, ...]:
        rows = self.connection.execute(
            """
            SELECT kind, uri, sha256, verifier, verified
            FROM evidence
            WHERE idempotency_key = ?
            ORDER BY id ASC
            """,
            (idempotency_key,),
        ).fetchall()
        return tuple(
            EvidenceReference(
                kind=row["kind"],
                uri=row["uri"],
                sha256=row["sha256"],
                verifier=row["verifier"],
                verified=bool(row["verified"]),
            )
            for row in rows
        )

    def list_transitions(
        self,
        idempotency_key: str,
    ) -> tuple[StoredTransition, ...]:
        rows = self.connection.execute(
            """
            SELECT from_state, to_state, detail, changed_at
            FROM state_transitions
            WHERE idempotency_key = ?
            ORDER BY id ASC
            """,
            (idempotency_key,),
        ).fetchall()
        return tuple(
            StoredTransition(
                from_state=row["from_state"],
                to_state=row["to_state"],
                detail=row["detail"],
                changed_at=row["changed_at"],
            )
            for row in rows
        )

    def audit_events(self) -> tuple[dict[str, Any], ...]:
        rows = self.connection.execute(
            """
            SELECT id, event_type, payload_json, created_at,
                   previous_hash, event_hash
            FROM audit_events ORDER BY id ASC
            """
        ).fetchall()
        return tuple(
            {
                "id": int(row["id"]),
                "event_type": row["event_type"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        )

    def audit_count(self) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM audit_events"
            ).fetchone()[0]
        )

    def _event_row(self, idempotency_key: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM events WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> StoredEvent:
        return StoredEvent(
            idempotency_key=row["idempotency_key"],
            payload_digest=row["payload_digest"],
            payload=json.loads(row["payload_json"]),
            originating_plugin=row["originating_plugin"],
            originating_event_id=row["originating_event_id"],
            originating_round_id=int(row["originating_round_id"]),
            checkpoint_digest=row["checkpoint_digest"],
            missing_capability=row["missing_capability"],
            state=row["state"],
            adapter_profile=row["adapter_profile"],
            last_detail=row["last_detail"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _last_audit_hash(self) -> str:
        row = self.connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return _GENESIS_HASH if row is None else str(row["event_hash"])

    @staticmethod
    def _audit_hash(
        *,
        event_type: str,
        payload_json: str,
        created_at: str,
        previous_hash: str,
    ) -> str:
        envelope = "\n".join(
            (created_at, event_type, previous_hash, payload_json)
        )
        return hashlib.sha256(envelope.encode("utf-8")).hexdigest()
