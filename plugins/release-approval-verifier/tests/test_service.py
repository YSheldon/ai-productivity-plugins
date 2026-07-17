from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from role_snapshot import RoleRecord
from verification_receipt import verify_verification_receipt
from verifier_service import VerifierService
from verifier_store import StoreError, VerifierStore


AUDIT_KEY = b"s" * 32
NOW = datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc)


def _request() -> dict[str, object]:
    return {
        "event_id": "evt-service", "round_id": 1, "task": "Task 8",
        "module": "release-approval-verifier", "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64, "manifest_digest": "sha256:" + "3" * 64,
        "request_digest": "sha256:" + "4" * 64, "role_snapshot_digest": "sha256:" + "5" * 64,
        "required_roles": ["release-manager", "security-reviewer"],
        "original_message_id": "<request@example.com>",
        "references": ["<root@example.com>", "<request@example.com>"],
        "created_at": "2026-07-16T01:00:00Z", "expires_at": "2026-07-17T04:00:00Z",
    }


def _roles() -> tuple[RoleRecord, ...]:
    return (RoleRecord("release-manager", "manager@example.com", True, True),
            RoleRecord("security-reviewer", "security@example.com", True, True))


def _record(store: VerifierStore, role: RoleRecord, decision: str, suffix: str) -> None:
    store.record_decision(
        decision_id=f"decision-{role.role_id}-{suffix}", event_id="evt-service", round_id=1,
        role_id=role.role_id, decision=decision, normalized_text=decision.lower(), ambiguous=False,
        approver_email=role.email, authentication_path="dmarc",
        source_message_id=f"<{role.role_id}-{suffix}@example.com>", raw_headers_sha256="a" * 64,
        decided_at="2026-07-16T03:00:00Z",
    )


def _approved_service(tmp_path: Path):
    store = VerifierStore(tmp_path / "state.sqlite3")
    roles = _roles()
    for role in roles:
        _record(store, role, "APPROVE", "approve")
    return store, roles, VerifierService(store=store, audit_key=AUDIT_KEY)


def test_reconcile_is_idempotent_and_keeps_one_signed_verified_receipt(tmp_path: Path) -> None:
    store, roles, service = _approved_service(tmp_path)
    first = service.reconcile(_request(), roles, now=NOW)
    second = service.reconcile(_request(), roles, now=NOW)
    assert first.status == "APPROVAL_VERIFIED"
    assert first.receipt["receipt_id"] == second.receipt["receipt_id"]
    assert second.idempotent is True
    assert len(store.list_receipts("evt-service", 1)) == 1
    verify_verification_receipt(first.receipt, audit_key=AUDIT_KEY, audit_store=store, now=NOW)


def test_later_valid_decision_revokes_before_handoff_and_preserves_old_receipt(tmp_path: Path) -> None:
    store, roles, service = _approved_service(tmp_path)
    approved = service.reconcile(_request(), roles, now=NOW)
    _record(store, roles[0], "HOLD", "withdraw-before-handoff")
    revoked = service.reconcile(_request(), roles, now=NOW)
    assert revoked.status == "APPROVAL_PAUSED"
    assert revoked.transition == "APPROVAL_REVOKED"
    receipts = store.list_receipts("evt-service", 1)
    assert len(receipts) == 2
    assert any(item.receipt_id == approved.receipt["receipt_id"] for item in receipts)
    assert store.get_receipt(approved.receipt["receipt_id"]).superseded_by == revoked.receipt["receipt_id"]
    assert [event.event_type for event in store.list_workflow_events("evt-service", 1)] == ["APPROVAL_REVOKED"]


def test_later_valid_decision_requests_release_hold_after_handoff_consumption(tmp_path: Path) -> None:
    store, roles, service = _approved_service(tmp_path)
    approved = service.reconcile(_request(), roles, now=NOW)
    store.mark_handoff_consumed(
        approved.receipt["receipt_id"], handoff_id="pre-release-evt-service-1",
        consumed_at="2026-07-16T04:05:00Z",
    )
    _record(store, roles[1], "REJECT", "withdraw-after-handoff")
    held = service.reconcile(_request(), roles, now=datetime(2026, 7, 16, 4, 10, tzinfo=timezone.utc))
    assert held.status == "APPROVAL_REJECTED"
    assert held.transition == "RELEASE_HOLD_REQUESTED"
    assert len(store.list_receipts("evt-service", 1)) == 2
    assert [event.event_type for event in store.list_workflow_events("evt-service", 1)] == ["RELEASE_HOLD_REQUESTED"]



def test_handoff_consumption_rejects_paused_or_superseded_receipts(tmp_path: Path) -> None:
    store, roles, service = _approved_service(tmp_path)
    approved = service.reconcile(_request(), roles, now=NOW)
    _record(store, roles[0], "HOLD", "pause")
    paused = service.reconcile(_request(), roles, now=NOW)

    with pytest.raises(StoreError, match="current APPROVAL_VERIFIED"):
        store.mark_handoff_consumed(
            paused.receipt["receipt_id"],
            handoff_id="invalid-paused",
            consumed_at="2026-07-16T04:05:00Z",
        )
    with pytest.raises(StoreError, match="current APPROVAL_VERIFIED"):
        store.mark_handoff_consumed(
            approved.receipt["receipt_id"],
            handoff_id="invalid-superseded",
            consumed_at="2026-07-16T04:05:00Z",
        )


def test_reconcile_repairs_revocation_event_after_crash_between_receipt_and_event(tmp_path: Path) -> None:
    store, roles, service = _approved_service(tmp_path)
    service.reconcile(_request(), roles, now=NOW)
    _record(store, roles[0], "HOLD", "crash-window")
    original = store.record_workflow_event

    def interrupted(**kwargs):
        raise RuntimeError("simulated process interruption")

    store.record_workflow_event = interrupted  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="simulated process interruption"):
        service.reconcile(_request(), roles, now=NOW)
    store.record_workflow_event = original  # type: ignore[method-assign]

    repaired = service.reconcile(_request(), roles, now=NOW)

    assert repaired.idempotent is True
    assert repaired.transition == "APPROVAL_REVOKED"
    assert [event.event_type for event in store.list_workflow_events("evt-service", 1)] == ["APPROVAL_REVOKED"]

def test_superseded_verified_receipt_remains_stored_but_cannot_authorize(tmp_path: Path) -> None:
    store, roles, service = _approved_service(tmp_path)
    approved = service.reconcile(_request(), roles, now=NOW)
    _record(store, roles[0], "HOLD", "supersede")
    service.reconcile(_request(), roles, now=NOW)

    assert store.get_receipt(approved.receipt["receipt_id"]) is not None
    with pytest.raises(Exception, match="superseded"):
        verify_verification_receipt(
            approved.receipt,
            audit_key=AUDIT_KEY,
            audit_store=store,
            now=NOW,
        )