from __future__ import annotations

import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_DIR = ROOT / "contracts" / "release-approval"
CANONICAL_FILES = [
    "release-authorization-request-v1.json",
    "approval-decision-v1.json",
    "approval-verification-receipt-v1.json",
]
COPY_TARGETS = [
    ROOT / "plugins" / "release-approval" / "contracts",
    ROOT / "plugins" / "release-approval-verifier" / "contracts",
]


def load_contract(name: str) -> dict[str, object]:
    return json.loads((CANONICAL_DIR / name).read_text(encoding="utf-8"))


def test_canonical_contract_file_set_is_frozen() -> None:
    assert sorted(path.name for path in CANONICAL_DIR.glob("*.json")) == sorted(CANONICAL_FILES)


def test_release_authorization_request_example_contains_required_bindings() -> None:
    contract = load_contract("release-authorization-request-v1.json")

    assert contract["contract"] == "ReleaseAuthorizationRequest/v1"
    assert contract["event_id"]
    assert contract["round_id"] > 0
    assert contract["task"]
    assert contract["module"]
    assert contract["manifest_s_digest"].startswith("sha256:")
    assert contract["manifest_r_digest"].startswith("sha256:")
    assert contract["manifest_digest"].startswith("sha256:")
    assert contract["request_digest"].startswith("sha256:")
    assert contract["role_snapshot_digest"].startswith("sha256:")
    assert contract["required_roles"]
    assert contract["original_message_id"].startswith("<")
    assert contract["references"]
    assert contract["expires_at"].endswith("Z")
    assert contract["idempotency_key"]


def test_approval_decision_example_contains_required_bindings() -> None:
    contract = load_contract("approval-decision-v1.json")

    assert list(contract.keys()) == [
        "schema",
        "decision_id",
        "event_id",
        "round_id",
        "manifest_digest",
        "role_snapshot_digest",
        "approver_email",
        "decision",
        "comment",
        "source",
        "original_message_id",
        "page_html_sha256",
        "decided_at",
        "idempotency_key",
    ]
    assert contract["schema"] == "ApprovalDecision/v1"
    assert contract["event_id"]
    assert contract["round_id"] > 0
    assert contract["manifest_digest"].startswith("sha256:")
    assert contract["role_snapshot_digest"].startswith("sha256:")
    assert contract["decision_id"]
    assert contract["approver_email"]
    assert contract["decision"] in {"APPROVE", "HOLD", "REJECT"}
    assert contract["comment"]
    assert contract["source"] == "LOCAL_PAGE"
    assert contract["original_message_id"].startswith("<")
    assert contract["page_html_sha256"].startswith("sha256:")
    assert contract["decided_at"].endswith("Z")
    assert contract["idempotency_key"]
    assert "contract" not in contract
    assert "request_event_id" not in contract
    assert "request_round_id" not in contract
    assert "role" not in contract
    assert "task" not in contract
    assert "module" not in contract
    assert "request_digest" not in contract


def test_approval_verification_receipt_example_contains_required_aggregates() -> None:
    contract = load_contract("approval-verification-receipt-v1.json")

    assert contract["contract"] == "ApprovalVerificationReceipt/v1"
    assert contract["event_id"]
    assert contract["round_id"] > 0
    assert contract["task"]
    assert contract["module"]
    assert contract["manifest_digest"].startswith("sha256:")
    assert contract["request_digest"].startswith("sha256:")
    assert contract["required_roles"]
    assert set(contract["required_roles"]) == {decision["role"] for decision in contract["current_decisions"]}
    assert contract["source_message_ids"]
    assert all(decision["original_message_id"].startswith("<") for decision in contract["current_decisions"])
    assert contract["aggregate_status"] in {"APPROVED", "HOLD", "REJECTED"}
    assert contract["generated_at"].endswith("Z")
    assert contract["evidence_digest"].startswith("sha256:")
    assert contract["receipt_algorithm"]
    assert contract["receipt_hmac"]


@pytest.mark.parametrize("copy_root", COPY_TARGETS, ids=["release-approval", "release-approval-verifier"])
@pytest.mark.parametrize("file_name", CANONICAL_FILES)
def test_plugin_contract_copy_matches_canonical_bytes(copy_root: Path, file_name: str) -> None:
    canonical = CANONICAL_DIR / file_name
    copy_path = copy_root / file_name
    assert copy_path.is_file(), f"missing contract copy: {copy_path.relative_to(ROOT)}"
    assert copy_path.read_bytes() == canonical.read_bytes()
