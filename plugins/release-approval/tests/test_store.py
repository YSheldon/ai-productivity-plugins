from __future__ import annotations

import sqlite3
import sys
import threading
from dataclasses import replace
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_protocol import ReleaseAuthorizationRequest
from release_approval_store import (
    SCHEMA_VERSION,
    AuditTamperError,
    ReleaseApprovalStore,
    StoreError,
)


def _request() -> ReleaseAuthorizationRequest:
    return ReleaseAuthorizationRequest(
        contract="ReleaseAuthorizationRequest/v1",
        event_id="rel-2026-07-15-0001",
        round_id=1,
        task="Task 4",
        module="release-approval",
        manifest_s_digest="sha256:" + "1" * 64,
        manifest_r_digest="sha256:" + "2" * 64,
        manifest_digest="sha256:" + "3" * 64,
        request_digest="sha256:" + "4" * 64,
        role_snapshot_digest="sha256:" + "5" * 64,
        required_roles=("release-manager", "security-reviewer"),
        original_message_id="<release-approval-request@example.com>",
        references=(
            "<release-approval-thread-root@example.com>",
            "<release-approval-request@example.com>",
        ),
        expires_at="2026-07-16T00:00:00Z",
        idempotency_key="release-approval-request-rel-2026-07-15-0001-round-1",
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
    )


def _decision_kwargs(request: ReleaseAuthorizationRequest, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "decision_id": "decision-1",
        "request_event_id": request.event_id,
        "request_round_id": request.round_id,
        "role": request.installed_role_id,
        "approver_email": request.installed_role_email,
        "decision": "APPROVE",
        "comment": "first",
        "source": "LOCAL_PAGE",
        "original_message_id": request.original_message_id,
        "decided_at": "2026-07-15T11:00:00Z",
        "page_html_sha256": "sha256:" + "8" * 64,
        "request_digest": request.request_digest,
        "idempotency_key": "decision-1",
    }
    payload.update(overrides)
    return payload


def test_fresh_database_sets_current_schema_version_and_current_reopen_works(tmp_path: Path) -> None:
    database_path = tmp_path / "state.sqlite3"

    store = ReleaseApprovalStore(database_path)
    version = store.connection.execute("PRAGMA user_version").fetchone()[0]
    assert version == SCHEMA_VERSION
    request = _request()
    stored = store.record_request(request)
    store.close()

    reopened = ReleaseApprovalStore(database_path)
    assert reopened.connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert reopened.get_request(request.event_id, request.round_id, request.installed_role_id) == stored


def test_unsupported_legacy_schema_fails_closed(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.sqlite3"
    legacy = sqlite3.connect(database_path)
    legacy.execute("CREATE TABLE legacy_entries (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    legacy.execute("INSERT INTO legacy_entries (value) VALUES ('legacy')")
    legacy.commit()
    legacy.close()

    with pytest.raises(StoreError, match="schema"):
        ReleaseApprovalStore(database_path)


def test_message_store_rejects_duplicate_uid_and_duplicate_message_id(tmp_path: Path) -> None:
    store = ReleaseApprovalStore(tmp_path / "state.sqlite3")
    store.record_message(
        account="release-manager@example.com",
        mailbox="INBOX",
        uidvalidity=100,
        uid=1,
        message_id="<message-1@example.com>",
    )

    with pytest.raises(StoreError, match="duplicate UID"):
        store.record_message(
            account="release-manager@example.com",
            mailbox="INBOX",
            uidvalidity=100,
            uid=1,
            message_id="<message-2@example.com>",
        )

    with pytest.raises(StoreError, match="duplicate Message-ID"):
        store.record_message(
            account="release-manager@example.com",
            mailbox="INBOX",
            uidvalidity=100,
            uid=2,
            message_id="<message-1@example.com>",
        )
def test_connection_recovers_after_duplicate_message_failure(tmp_path: Path) -> None:
    store = ReleaseApprovalStore(tmp_path / "state.sqlite3")
    request = _request()
    store.record_message(
        account="release-manager@example.com",
        mailbox="INBOX",
        uidvalidity=100,
        uid=1,
        message_id="<message-1@example.com>",
    )

    with pytest.raises(StoreError, match="duplicate Message-ID"):
        store.record_message(
            account="release-manager@example.com",
            mailbox="INBOX",
            uidvalidity=100,
            uid=2,
            message_id="<message-1@example.com>",
        )

    stored_request = store.record_request(request)
    stored_decision = store.record_decision(**_decision_kwargs(request))

    assert store.get_request(request.event_id, request.round_id, request.installed_role_id) == stored_request
    assert store.get_decision(stored_decision.decision_id) == stored_decision


def test_request_replay_is_idempotent_and_divergent_reuse_is_rejected(tmp_path: Path) -> None:
    store = ReleaseApprovalStore(tmp_path / "state.sqlite3")
    request = _request()

    first = store.record_request(request)
    replay = store.record_request(request)

    assert replay == first

    divergent = replace(request, request_digest="sha256:" + "9" * 64)
    with pytest.raises(StoreError, match="idempotency"):
        store.record_request(divergent)


def test_request_replay_is_atomic_across_connections(tmp_path: Path) -> None:
    database_path = tmp_path / "state.sqlite3"
    request = _request()
    initializer = ReleaseApprovalStore(database_path)
    initializer.close()
    barrier = threading.Barrier(2)
    results: list[object | None] = [None, None]
    errors: list[BaseException | None] = [None, None]

    def worker(index: int) -> None:
        store = ReleaseApprovalStore(database_path)
        try:
            barrier.wait(timeout=5)
            results[index] = store.record_request(request)
        except BaseException as exc:  # noqa: BLE001
            errors[index] = exc
        finally:
            store.close()

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(thread.is_alive() is False for thread in threads)
    assert errors == [None, None]
    assert results[0] == results[1]

    checker = ReleaseApprovalStore(database_path)
    count = checker.connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    assert count == 1
    assert checker.get_request(request.event_id, request.round_id, request.installed_role_id) == results[0]
    checker.close()


def test_restart_recovery_persists_requests_and_allows_uidvalidity_reset(tmp_path: Path) -> None:
    database_path = tmp_path / "state.sqlite3"
    request = _request()

    store = ReleaseApprovalStore(database_path)
    store.record_message(
        account="release-manager@example.com",
        mailbox="INBOX",
        uidvalidity=100,
        uid=7,
        message_id="<message-7@example.com>",
    )
    store.record_request(request)
    store.record_page(
        event_id=request.event_id,
        round_id=request.round_id,
        role=request.installed_role_id,
        html_path=tmp_path / "page.html",
        html_sha256="sha256:" + "6" * 64,
        nonce_sha256="sha256:" + "7" * 64,
        created_at="2026-07-15T10:00:00Z",
    )
    store.close()

    reopened = ReleaseApprovalStore(database_path)
    recovered = reopened.get_request(request.event_id, request.round_id, request.installed_role_id)
    assert recovered is not None
    assert recovered.request_digest == request.request_digest
    reopened.record_message(
        account="release-manager@example.com",
        mailbox="INBOX",
        uidvalidity=101,
        uid=7,
        message_id="<message-8@example.com>",
    )


def test_decision_replay_is_idempotent_and_divergent_reuse_is_rejected(tmp_path: Path) -> None:
    store = ReleaseApprovalStore(tmp_path / "state.sqlite3")
    request = _request()
    store.record_request(request)

    first = store.record_decision(**_decision_kwargs(request))
    replay = store.record_decision(**_decision_kwargs(request))

    assert replay == first
    current = store.get_current_decision(request.event_id, request.round_id, request.installed_role_id)
    assert current is not None
    assert current.decision_id == first.decision_id

    with pytest.raises(StoreError, match="idempotency"):
        store.record_decision(**_decision_kwargs(request, decision="REJECT"))


def test_current_decision_supersession_is_atomic_across_connections_and_db_enforces_one_current(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "state.sqlite3"
    request = _request()
    store_a = ReleaseApprovalStore(database_path)
    store_b = ReleaseApprovalStore(database_path)
    store_a.record_request(request)

    first = store_a.record_decision(**_decision_kwargs(request))
    second = store_b.record_decision(
        **_decision_kwargs(
            request,
            decision_id="decision-2",
            decision="REJECT",
            comment="second",
            source="EMAIL_REPLY",
            original_message_id="<reply@example.com>",
            decided_at="2026-07-15T12:00:00Z",
            page_html_sha256="sha256:" + "9" * 64,
            idempotency_key="decision-2",
        )
    )

    current = store_a.get_current_decision(request.event_id, request.round_id, request.installed_role_id)
    assert current is not None
    assert current.decision_id == second.decision_id

    first_row = store_a.get_decision(first.decision_id)
    assert first_row is not None
    assert first_row.superseded_by == second.decision_id

    with pytest.raises(sqlite3.IntegrityError):
        store_b.connection.execute(
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
                "decision-3",
                request.event_id,
                request.round_id,
                request.installed_role_id,
                request.installed_role_email,
                "APPROVE",
                "third",
                "LOCAL_PAGE",
                request.original_message_id,
                "2026-07-15T12:05:00Z",
                "sha256:" + "a" * 64,
                request.request_digest,
                "decision-3",
            ),
        )


def test_orphan_child_records_are_rejected_and_connection_recovers(tmp_path: Path) -> None:
    store = ReleaseApprovalStore(tmp_path / "state.sqlite3")
    request = _request()

    with pytest.raises(StoreError, match="request"):
        store.record_decision(**_decision_kwargs(request))

    with pytest.raises(StoreError, match="request"):
        store.record_page(
            event_id=request.event_id,
            round_id=request.round_id,
            role=request.installed_role_id,
            html_path=tmp_path / "page.html",
            html_sha256="sha256:" + "6" * 64,
            nonce_sha256="sha256:" + "7" * 64,
            created_at="2026-07-15T10:00:00Z",
        )

    with pytest.raises(StoreError, match="request"):
        store.record_smtp_outcome(
            event_id=request.event_id,
            round_id=request.round_id,
            role=request.installed_role_id,
            smtp_message_id="<smtp@example.com>",
            outcome="SENT",
            detail="ok",
            recorded_at="2026-07-15T10:05:00Z",
        )

    stored_request = store.record_request(request)
    stored_decision = store.record_decision(**_decision_kwargs(request))
    store.record_page(
        event_id=request.event_id,
        round_id=request.round_id,
        role=request.installed_role_id,
        html_path=tmp_path / "page.html",
        html_sha256="sha256:" + "6" * 64,
        nonce_sha256="sha256:" + "7" * 64,
        created_at="2026-07-15T10:00:00Z",
    )
    store.record_smtp_outcome(
        event_id=request.event_id,
        round_id=request.round_id,
        role=request.installed_role_id,
        smtp_message_id="<smtp@example.com>",
        outcome="SENT",
        detail="ok",
        recorded_at="2026-07-15T10:05:00Z",
    )

    assert store.get_request(request.event_id, request.round_id, request.installed_role_id) == stored_request
    assert store.get_decision(stored_decision.decision_id) == stored_decision


def test_audit_chain_tamper_detection(tmp_path: Path) -> None:
    store = ReleaseApprovalStore(tmp_path / "state.sqlite3")
    request = _request()
    store.record_request(request)
    second = store.record_decision(
        **_decision_kwargs(
            request,
            decision_id="decision-2",
            decision="REJECT",
            comment="second",
            source="EMAIL_REPLY",
            original_message_id="<reply@example.com>",
            decided_at="2026-07-15T12:00:00Z",
            page_html_sha256="sha256:" + "9" * 64,
            idempotency_key="decision-2",
        )
    )

    store.append_audit_event(
        "request-recorded",
        {"event_id": request.event_id, "round_id": request.round_id},
        created_at="2026-07-15T12:10:00Z",
    )
    store.append_audit_event(
        "decision-recorded",
        {"decision_id": second.decision_id},
        created_at="2026-07-15T12:11:00Z",
    )
    store.verify_audit_chain()

    store.connection.execute("UPDATE audit_events SET payload_json = '{\"tampered\":true}' WHERE id = 2")
    store.connection.commit()

    with pytest.raises(AuditTamperError, match="tamper"):
        store.verify_audit_chain()


def test_audit_chain_detects_formatting_only_payload_text_tamper(tmp_path: Path) -> None:
    store = ReleaseApprovalStore(tmp_path / "state.sqlite3")
    store.append_audit_event(
        "request-recorded",
        {"event_id": "rel-2026-07-15-0001", "round_id": 1},
        created_at="2026-07-15T12:10:00Z",
    )
    store.verify_audit_chain()

    store.connection.execute(
        """
        UPDATE audit_events
        SET payload_json = '{ "round_id" : 1 , "event_id" : "rel-2026-07-15-0001" }'
        WHERE id = 1
        """
    )
    store.connection.commit()

    with pytest.raises(AuditTamperError, match="tamper"):
        store.verify_audit_chain()
