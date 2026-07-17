import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_protocol import (  # noqa: E402
    PRODUCTION_EVIDENCE_TYPES,
    CapabilityGapEvent,
    EvidenceReference,
    compute_idempotency_key,
)
from rd_flywheel_store import AuditTamperError, RDFlywheelStore, StoreError  # noqa: E402


def event() -> CapabilityGapEvent:
    payload = {
        "schema": "CapabilityGapEvent/v1",
        "originating_plugin": "release-approval",
        "originating_event_id": "event-1",
        "originating_round_id": 1,
        "checkpoint_digest": "a" * 64,
        "missing_capability": "mail.raw_headers",
        "required_evidence": list(PRODUCTION_EVIDENCE_TYPES),
        "allowed_tool_profiles": ["imap-smtp-mail", "gitlab"],
        "created_at": "2026-07-16T08:00:00Z",
    }
    payload["idempotency_key"] = compute_idempotency_key(payload)
    return CapabilityGapEvent.from_mapping(payload)


def proof(kind: str = "validation") -> EvidenceReference:
    return EvidenceReference(
        kind=kind,
        uri=f"urn:proof:{kind}",
        sha256="b" * 64,
        verifier="deterministic-verifier",
        verified=True,
    )


def test_store_records_event_once_and_preserves_checkpoint(tmp_path):
    store = RDFlywheelStore(tmp_path / "state.sqlite3")
    first = store.record_event(event(), recorded_at="2026-07-16T08:01:00Z")
    second = store.record_event(event(), recorded_at="2026-07-16T08:02:00Z")

    assert first.idempotency_key == second.idempotency_key
    assert first.checkpoint_digest == "a" * 64
    assert len(store.list_events()) == 1
    assert store.audit_count() == 1


def test_idempotency_collision_with_different_payload_is_rejected(tmp_path):
    store = RDFlywheelStore(tmp_path / "state.sqlite3")
    original = event()
    store.record_event(original, recorded_at="2026-07-16T08:01:00Z")
    payload = dict(original.payload)
    payload["missing_capability"] = "different"
    changed = CapabilityGapEvent(
        **{**original.__dict__, "missing_capability": "different", "payload": payload}
    )

    with pytest.raises(StoreError, match="different payload"):
        store.record_event(changed, recorded_at="2026-07-16T08:02:00Z")


def test_state_transition_and_evidence_are_one_transaction(tmp_path):
    store = RDFlywheelStore(tmp_path / "state.sqlite3")
    key = store.record_event(event(), recorded_at="2026-07-16T08:01:00Z").idempotency_key
    store.transition(
        key,
        "VALIDATED",
        (),
        changed_at="2026-07-16T08:02:00Z",
        detail="schema and digest validated",
    )
    store.transition(
        key,
        "WAITING_AGENT",
        (proof("adapter_selection"),),
        changed_at="2026-07-16T08:03:00Z",
        detail="approved adapter selected",
    )

    stored = store.get_event(key)
    assert stored is not None
    assert stored.state == "WAITING_AGENT"
    assert [item.kind for item in store.list_evidence(key)] == ["adapter_selection"]
    assert [item.to_state for item in store.list_transitions(key)] == [
        "RECEIVED",
        "VALIDATED",
        "WAITING_AGENT",
    ]


def test_illegal_transition_rolls_back_evidence(tmp_path):
    store = RDFlywheelStore(tmp_path / "state.sqlite3")
    key = store.record_event(event(), recorded_at="2026-07-16T08:01:00Z").idempotency_key

    with pytest.raises(Exception):
        store.transition(
            key,
            "COMPLETE",
            (proof("tests"),),
            changed_at="2026-07-16T08:02:00Z",
            detail="must not skip validation",
        )

    assert store.get_event(key).state == "RECEIVED"
    assert store.list_evidence(key) == ()


def test_append_only_audit_chain_detects_tampering(tmp_path):
    path = tmp_path / "state.sqlite3"
    store = RDFlywheelStore(path)
    store.record_event(event(), recorded_at="2026-07-16T08:01:00Z")
    verification = store.verify_audit_chain()
    assert verification["ok"] is True
    assert verification["count"] >= 1
    store.close()

    connection = sqlite3.connect(path)
    connection.execute("UPDATE audit_events SET payload_json = ?", ('{"tampered":true}',))
    connection.commit()
    connection.close()

    reopened = RDFlywheelStore(path, verify_chain_on_open=False)
    with pytest.raises(AuditTamperError, match="tamper"):
        reopened.verify_audit_chain()


def test_input_receipts_are_idempotent_for_invalid_or_duplicate_files(tmp_path):
    store = RDFlywheelStore(tmp_path / "state.sqlite3")
    first = store.record_input(
        source="inbox/bad.json",
        content_digest="c" * 64,
        outcome="REJECTED",
        recorded_at="2026-07-16T08:01:00Z",
    )
    second = store.record_input(
        source="inbox/bad.json",
        content_digest="c" * 64,
        outcome="REJECTED",
        recorded_at="2026-07-16T08:02:00Z",
    )
    assert first is True
    assert second is False


def test_schema_version_and_required_tables_fail_closed(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE legacy (id INTEGER)")
    connection.commit()
    connection.close()
    with pytest.raises(StoreError, match="schema"):
        RDFlywheelStore(path)
