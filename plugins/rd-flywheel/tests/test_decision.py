import hashlib
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_decision import (  # noqa: E402
    DecisionError,
    build_governance_decision_request,
    parse_decision_role_snapshot,
    validate_governance_decision_verification,
)
from rd_flywheel_protocol import (  # noqa: E402
    PRODUCTION_EVIDENCE_TYPES,
    CapabilityGapEvent,
    compute_idempotency_key,
)


def _event() -> CapabilityGapEvent:
    payload = {
        "schema": "CapabilityGapEvent/v1",
        "originating_plugin": "submission-gate",
        "originating_event_id": "capability-17",
        "originating_round_id": 3,
        "checkpoint_digest": "a" * 64,
        "missing_capability": "cloud_scan.real_api",
        "required_evidence": list(PRODUCTION_EVIDENCE_TYPES),
        "allowed_tool_profiles": ["gitlab", "lark-cli", "imap-smtp-mail"],
        "created_at": "2026-08-12T01:00:00Z",
    }
    payload["idempotency_key"] = compute_idempotency_key(payload)
    return CapabilityGapEvent.from_mapping(payload)


def _snapshot():
    return parse_decision_role_snapshot(
        """# Roles

## 决策角色

| role_id | email | required | enabled |
| --- | --- | --- | --- |
| security | security@example.com | true | true |
| client | client@example.com | false | true |
| director | director@example.com | true | true |

## History
| value |
| --- |
| ignored@example.com |
""",
        document_url="https://example.feishu.cn/docx/roles",
        heading="## 决策角色",
    )


def _package():
    return build_governance_decision_request(
        _event(),
        _snapshot(),
        requested_at="2026-08-12T01:10:00Z",
        expires_at="2026-08-13T01:10:00Z",
        original_message_id="<rd-flywheel-capability-17@example.com>",
    )


def _receipt(package):
    request = package.request
    decisions = [
        {
            "role_id": role_id,
            "decision_id": f"decision-{role_id}",
            "decision": "APPROVE",
            "approver_email": f"{role_id}@example.com",
            "authentication_path": "dkim",
            "source_message_id": f"<{role_id}@example.com>",
            "decided_at": "2026-08-12T02:00:00Z",
        }
        for role_id in request["required_roles"]
    ]
    return {
        "contract": "ApprovalVerificationReceipt/v1",
        "authority_scope": "RD_FLYWHEEL_GOVERNANCE",
        "status": "APPROVAL_VERIFIED",
        "event_id": request["event_id"],
        "round_id": request["round_id"],
        "manifest_s_digest": request["manifest_s_digest"],
        "manifest_r_digest": request["manifest_r_digest"],
        "manifest_digest": request["manifest_digest"],
        "request_digest": request["request_digest"],
        "role_snapshot_digest": request["role_snapshot_digest"],
        "expires_at": request["expires_at"],
        "required_roles": list(request["required_roles"]),
        "current_decisions": decisions,
        "receipt_id": "receipt-governance-1",
        "receipt_hmac": "base64:independently-verified",
    }


def test_role_snapshot_uses_only_enabled_rows_and_freezes_required_roles():
    snapshot = _snapshot()

    assert [role.role_id for role in snapshot.roles] == ["client", "director", "security"]
    assert snapshot.required_role_ids == ("director", "security")
    assert snapshot.digest.startswith("sha256:")


def test_role_snapshot_digest_binds_feishu_document_identity():
    markdown = """## 决策角色
| role_id | email | required | enabled |
| --- | --- | --- | --- |
| director | director@example.com | true | true |
"""

    first = parse_decision_role_snapshot(
        markdown,
        document_url="https://example.feishu.cn/docx/roles-a",
        heading="## 决策角色",
    )
    second = parse_decision_role_snapshot(
        markdown,
        document_url="https://example.feishu.cn/docx/roles-b",
        heading="## 决策角色",
    )

    assert first.digest != second.digest


def test_governance_request_binds_event_roles_and_visual_companion():
    package = _package()
    request = package.request

    assert request["authority_scope"] == "RD_FLYWHEEL_GOVERNANCE"
    assert request["event_id"] == _event().idempotency_key
    assert request["round_id"] == 3
    assert request["role_snapshot_digest"] == _snapshot().digest
    assert request["required_roles"] == ["director", "security"]
    assert request["governance_context"] == {
        "authority_boundary": "DESIGN_CONSENT_ONLY",
        "missing_capability": _event().missing_capability,
        "originating_plugin": _event().originating_plugin,
        "originating_event_id": _event().originating_event_id,
        "checkpoint_digest": _event().checkpoint_digest,
        "required_evidence": list(_event().required_evidence),
        "visual_companion_html_sha256": request["visual_companion"]["html_sha256"],
    }
    assert "Visual Companion" in package.screen_html
    assert request["manifest_s_digest"] == "sha256:" + _event().payload_digest
    assert request["manifest_r_digest"] == "sha256:" + hashlib.sha256(
        package.screen_html.encode("utf-8")
    ).hexdigest()
    digest_payload = {key: value for key, value in request.items() if key != "request_digest"}
    expected = "sha256:" + hashlib.sha256(
        json.dumps(
            digest_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert request["request_digest"] == expected


def test_verified_receipt_cannot_cross_event_or_authority_scope():
    package = _package()
    receipt = _receipt(package)
    verified = {
        "verified": True,
        "verifier": "release-approval-verifier",
        "receipt": receipt,
    }

    result = validate_governance_decision_verification(package.request, verified)
    assert result["status"] == "APPROVAL_VERIFIED"

    wrong_scope = dict(receipt, authority_scope="PRODUCTION_RELEASE")
    with pytest.raises(DecisionError, match="authority_scope"):
        validate_governance_decision_verification(
            package.request,
            dict(verified, receipt=wrong_scope),
        )

    wrong_event = dict(receipt, event_id="f" * 64)
    with pytest.raises(DecisionError, match="event_id"):
        validate_governance_decision_verification(
            package.request,
            dict(verified, receipt=wrong_event),
        )


def test_receipt_requires_one_approval_from_every_frozen_required_role():
    package = _package()
    receipt = _receipt(package)
    receipt["current_decisions"] = receipt["current_decisions"][:1]

    with pytest.raises(DecisionError, match="required role decisions"):
        validate_governance_decision_verification(
            package.request,
            {
                "verified": True,
                "verifier": "release-approval-verifier",
                "receipt": receipt,
            },
        )
