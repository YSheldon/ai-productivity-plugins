from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = ROOT / "shared"
if str(SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_ROOT))

from release_workflow_core.legacy_intake import BLOCKED_STATE, DRAFT_STATE, parse_legacy_submission_mail
from release_workflow_core.mail_contract import (
    AuthenticationFailedError,
    parse_message,
    provenance_badge,
    render_message,
)
from release_workflow_core.models import validate_submission_payload
from release_workflow_core.policy import freeze_policy


def test_svn_submission_accepts_source_descriptors_without_sender_hash_inventory() -> None:
    payload = {
        "schema": "ProductMaterialSubmission/v1",
        "event_id": "evt-svn-1",
        "round_id": 1,
        "task": "Task SVN",
        "module": "server",
        "submitter_email": "submitter@example.com",
        "created_at": "2026-07-17T12:00:00Z",
        "policy_profile": "submission-svn/v1",
        "retrieval_method": "svn",
        "source_locator": "https://svn.example.invalid/repos/project/server",
        "revision": "1305",
        "retrieval_instructions": "export release path",
        "version": "24.7.17",
        "effective_checks": [
            "provenance_locator_present",
            "fixed_revision_present",
            "trusted_retrieval_succeeded",
            "retrieved_nonempty",
            "audit_recorded",
        ],
        "artifacts": [],
    }
    submission = validate_submission_payload(payload)
    assert submission.retrieval_method == "svn"
    assert submission.artifacts == ()
    assert submission.revision == "1305"


def test_svn_policy_defaults_to_retrieval_provenance_checks_without_clean_verdict() -> None:
    policy = freeze_policy(
        "server",
        policy_profile="submission-svn/v1",
        retrieval_method="svn",
        configured_mandatory=(
            "provenance_locator_present",
            "fixed_revision_present",
            "trusted_retrieval_succeeded",
            "retrieved_nonempty",
            "audit_recorded",
        ),
        enabled_optional=(),
    )
    assert policy["effective_checks"] == [
        "provenance_locator_present",
        "fixed_revision_present",
        "trusted_retrieval_succeeded",
        "retrieved_nonempty",
        "audit_recorded",
    ]
    assert policy["required_verdict"] == ""


def test_mail_contract_optional_auth_and_verified_auth_provenance() -> None:
    payload = {
        "schema": "ProductMaterialWorkflow/v1",
        "event_id": "evt-mail-1",
        "round_id": 1,
        "event_type": "PRERELEASE_REQUEST",
        "state": "PRERELEASE_REQUESTED",
        "task": "Task Mail",
        "module": "client",
        "submitter_email": "submitter@example.com",
        "created_at": "2026-07-17T12:30:00Z",
        "policy_profile": "release-gate/v1",
        "policy_digest": "sha256:" + "a" * 64,
        "evidence_refs": [],
    }
    unsigned = render_message("release_gate_check", payload, when="2026-07-17", summary_lines=())
    parsed_unsigned = parse_message(unsigned["body_text"])
    assert parsed_unsigned["provenance_classification"] == "STRUCTURED_UNVERIFIED"
    assert unsigned["headers"]["X-RD-Intake-Badge"] == provenance_badge("STRUCTURED_UNVERIFIED")

    signed = render_message(
        "release_gate_check",
        payload,
        secret=b"s" * 32,
        key_id="node-a",
        identity_id="plugin-node-a",
        when="2026-07-17",
        summary_lines=(),
    )
    parsed_signed = parse_message(signed["body_text"], secret={"node-a": b"s" * 32})
    assert parsed_signed["provenance_classification"] == "COMPLIANT_PLUGIN_VERIFIED"
    assert signed["headers"]["X-RD-Intake-Badge"] == provenance_badge("COMPLIANT_PLUGIN_VERIFIED")

    with pytest.raises(AuthenticationFailedError):
        parse_message(signed["body_text"], secret={"node-a": b"x" * 32})


def test_legacy_intake_accepts_svn_revision_label_variants_and_rejects_non_numeric_revision() -> None:
    message = {
        "uid": "1305",
        "message_id": "<legacy-1305@example.invalid>",
        "subject": "[提测][RD1305-服务端修复]20260717-12:34:56",
        "headers": {"Message-ID": "<legacy-1305@example.invalid>", "From": "submitter@example.invalid"},
        "body_text": "\n".join(
            [
                "提测类型：服务端",
                "目录：/release/server/",
                "SVN Revision: 1305",
                "修改说明：redacted",
            ]
        ),
    }
    accepted = parse_legacy_submission_mail(message)
    assert accepted["state"] == DRAFT_STATE
    assert accepted["revision"] == "1305"
    assert accepted["submitter_email"] == "submitter@example.invalid"

    message["body_text"] = message["body_text"].replace("1305", "HEAD")
    blocked = parse_legacy_submission_mail(message)
    assert blocked["state"] == BLOCKED_STATE
    assert "revision" in blocked["required_inputs"]
