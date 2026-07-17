from __future__ import annotations

import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from verification_receipt import ReceiptError, build_verification_receipt, load_audit_key, verify_verification_receipt
from verifier_store import VerifierStore


AUDIT_KEY = b"k" * 32
NOW = datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc)


def _request() -> dict[str, object]:
    return {
        "event_id": "evt-receipt",
        "round_id": 7,
        "task": "Task 8",
        "module": "release-approval-verifier",
        "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64,
        "manifest_digest": "sha256:" + "3" * 64,
        "request_digest": "sha256:" + "4" * 64,
        "role_snapshot_digest": "sha256:" + "5" * 64,
        "required_roles": ["release-manager", "security-reviewer"],
        "original_message_id": "<request@example.com>",
        "expires_at": "2026-07-17T04:00:00Z",
    }


def _decision(role: str, decision: str = "APPROVE", *, suffix: str = "1") -> dict[str, object]:
    return {
        "role_id": role,
        "decision_id": f"decision-{role}-{suffix}",
        "decision": decision,
        "approver_email": f"{role}@example.com",
        "authentication_path": "dmarc",
        "source_message_id": f"<{role}-{suffix}@example.com>",
        "decided_at": "2026-07-16T03:00:00Z",
        "superseded_by": None,
    }


def _build(decisions, *, request=None, audit_checkpoint=(2, "a" * 64), now=NOW):
    return build_verification_receipt(
        request or _request(), decisions, audit_checkpoint=audit_checkpoint, generated_at=now, audit_key=AUDIT_KEY
    )


def test_audit_key_requires_at_least_32_bytes() -> None:
    with pytest.raises(ReceiptError, match="32 bytes"):
        load_audit_key({"RELEASE_APPROVAL_VERIFIER_AUDIT_KEY": "too-short"})
    assert load_audit_key({"RELEASE_APPROVAL_VERIFIER_AUDIT_KEY": "x" * 32}) == b"x" * 32


def test_all_required_approvals_produce_bound_hmac_sha256_receipt() -> None:
    receipt = _build((_decision("release-manager"), _decision("security-reviewer")))
    assert receipt["status"] == "APPROVAL_VERIFIED"
    assert receipt["receipt_algorithm"] == "HMAC-SHA256"
    assert receipt["receipt_hmac"].startswith("base64:")
    for field in (
        "event_id", "round_id", "manifest_s_digest", "manifest_r_digest", "manifest_digest",
        "request_digest", "role_snapshot_digest", "expires_at",
    ):
        assert receipt[field] == _request()[field]
    assert verify_verification_receipt(
        receipt, audit_key=AUDIT_KEY, expected_binding=_request(), now=NOW
    )["status"] == "APPROVAL_VERIFIED"


@pytest.mark.parametrize(
    ("decisions", "status", "reason"),
    [
        ((_decision("release-manager"),), "APPROVAL_PAUSED", "missing"),
        ((_decision("release-manager"), _decision("release-manager", suffix="2"), _decision("security-reviewer")),
         "APPROVAL_PAUSED", "duplicate"),
        ((_decision("release-manager"), _decision("security-reviewer", "HOLD")), "APPROVAL_PAUSED", "hold"),
        ((_decision("release-manager"), _decision("security-reviewer", "REJECT")), "APPROVAL_REJECTED", "reject"),
    ],
)
def test_missing_duplicate_hold_and_reject_fail_closed(decisions, status: str, reason: str) -> None:
    receipt = _build(decisions)
    assert receipt["status"] == status
    assert any(reason in item.lower() for item in receipt["diagnostics"])
    verify_verification_receipt(receipt, audit_key=AUDIT_KEY, now=NOW)


def test_duplicate_required_role_fails_closed() -> None:
    request = _request()
    request["required_roles"] = ["release-manager", "release-manager"]

    receipt = _build((_decision("release-manager"),), request=request)

    assert receipt["status"] == "APPROVAL_PAUSED"
    assert any("duplicate required" in item.lower() for item in receipt["diagnostics"])


def test_expired_request_is_signed_as_expired() -> None:
    request = _request()
    request["expires_at"] = "2026-07-16T03:59:59Z"
    receipt = _build((_decision("release-manager"), _decision("security-reviewer")), request=request)
    assert receipt["status"] == "APPROVAL_EXPIRED"
    verify_verification_receipt(receipt, audit_key=AUDIT_KEY, now=NOW)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("event_id", "evt-other"),
        ("round_id", 8),
        ("manifest_s_digest", "sha256:" + "6" * 64),
        ("manifest_r_digest", "sha256:" + "7" * 64),
        ("manifest_digest", "sha256:" + "9" * 64),
        ("request_digest", "sha256:" + "a" * 64),
        ("role_snapshot_digest", "sha256:" + "8" * 64),
        ("expires_at", "2026-07-18T04:00:00Z"),
    ],
)
def test_expected_binding_detects_wrong_digest_round_and_role_snapshot(field: str, replacement: object) -> None:
    receipt = _build((_decision("release-manager"), _decision("security-reviewer")))
    expected = _request()
    expected[field] = replacement
    with pytest.raises(ReceiptError, match="binding"):
        verify_verification_receipt(receipt, audit_key=AUDIT_KEY, expected_binding=expected, now=NOW)


def test_altered_receipt_fails_hmac_verification() -> None:
    receipt = _build((_decision("release-manager"), _decision("security-reviewer")))
    altered = copy.deepcopy(receipt)
    altered["current_decisions"][0]["decision"] = "REJECT"
    with pytest.raises(ReceiptError, match="HMAC"):
        verify_verification_receipt(altered, audit_key=AUDIT_KEY, now=NOW)


def test_truncated_audit_chain_invalidates_receipt_checkpoint(tmp_path: Path) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    for role in ("release-manager", "security-reviewer"):
        decision = _decision(role)
        store.record_decision(
            decision_id=decision["decision_id"], event_id="evt-receipt", round_id=7, role_id=role,
            decision="APPROVE", normalized_text="approve", ambiguous=False,
            approver_email=decision["approver_email"], authentication_path="dmarc",
            source_message_id=decision["source_message_id"], raw_headers_sha256="f" * 64,
            decided_at=decision["decided_at"],
        )
    receipt = _build(store.list_current_decisions("evt-receipt", 7), audit_checkpoint=store.audit_checkpoint())
    store.record_receipt(receipt)
    verify_verification_receipt(receipt, audit_key=AUDIT_KEY, audit_store=store, now=NOW)
    store.connection.execute("DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)")
    store.connection.commit()
    with pytest.raises(ReceiptError, match="audit"):
        verify_verification_receipt(receipt, audit_key=AUDIT_KEY, audit_store=store, now=NOW)
