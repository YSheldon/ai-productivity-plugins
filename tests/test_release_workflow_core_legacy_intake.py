from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = ROOT / "shared"
if str(SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_ROOT))

from release_workflow_core.legacy_intake import (
    BLOCKED_STATE,
    DRAFT_STATE,
    UNTRUSTED_EVENT_TYPE,
    parse_legacy_submission_mail,
)


FIXTURE = ROOT / "tests" / "fixtures" / "release_workflow_core" / "legacy_submission_mail_redacted.json"
SUBJECT_MODULE_ONLY_FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "release_workflow_core"
    / "legacy_submission_mail_subject_module_only_redacted.json"
)


def test_legacy_plain_text_mail_stays_unverified_and_preserves_evidence_bindings() -> None:
    message = json.loads(FIXTURE.read_text(encoding="utf-8"))
    intake = parse_legacy_submission_mail(message)

    assert intake["schema"] == "ProductMaterialWorkflow/v1"
    assert intake["event_type"] == UNTRUSTED_EVENT_TYPE
    assert intake["state"] == DRAFT_STATE
    assert intake["trust_level"] == "UNTRUSTED"
    assert intake["provenance_classification"] == "PLAIN_EMAIL_UNVERIFIED"
    assert intake["module"] == "client"
    assert intake["locator"] == "/releases/client/"
    assert intake["revision"] == "123456"
    assert intake["required_inputs"] == []
    assert intake["source"]["uid"] == "8024"
    assert intake["source"]["message_id"] == "<legacy-submission@example.invalid>"
    assert intake["source"]["headers_sha256"].startswith("sha256:")
    assert intake["submitter_email"] == "submitter@example.invalid"
    assert intake["submitter_email_status"] == "valid"
    assert "manifest_s_digest" not in intake
    assert "manifest_r_digest" not in intake
    assert intake["promotion_requirements"]["independent_gate_allowed"] is True
    assert intake["promotion_requirements"]["required_verdict"] == ""


def test_legacy_plain_text_mail_blocks_when_module_cannot_be_determined() -> None:
    message = json.loads(FIXTURE.read_text(encoding="utf-8"))
    message["body_text"] = message["body_text"].replace("提测类型：客户端\n", "")
    message["body_text"] = message["body_text"].replace("标题：客户端修复\n", "标题：兼容性修复\n")
    message["body_text"] = message["body_text"].replace("目录：/releases/client/\n", "目录：/releases/build/\n")
    message["body_text"] = message["body_text"].replace("SVN 地址：https://svn.example.invalid/repos/project/client\n", "SVN 地址：https://svn.example.invalid/repos/project/build\n")
    message["subject"] = "[提测][RD20260717-兼容性修复]20260717-10:11:12"

    intake = parse_legacy_submission_mail(message)

    assert intake["event_type"] == UNTRUSTED_EVENT_TYPE
    assert intake["state"] == BLOCKED_STATE
    assert intake["module"] == ""
    assert intake["required_inputs"] == ["module"]
    assert intake["failure_reason"]


def test_legacy_plain_text_mail_accepts_module_found_only_in_full_subject() -> None:
    message = json.loads(SUBJECT_MODULE_ONLY_FIXTURE.read_text(encoding="utf-8"))

    intake = parse_legacy_submission_mail(message)

    assert intake["state"] == DRAFT_STATE
    assert intake["module"] == "client"
    assert intake["required_inputs"] == []
    assert intake["promotion_requirements"]["independent_gate_allowed"] is True


def test_legacy_plain_text_mail_blocks_conflicting_module_tokens() -> None:
    message = json.loads(SUBJECT_MODULE_ONLY_FIXTURE.read_text(encoding="utf-8"))
    message["body_text"] = message["body_text"].replace("提测类型：常规", "提测类型：内核")

    intake = parse_legacy_submission_mail(message)

    assert intake["state"] == BLOCKED_STATE
    assert intake["module"] == ""
    assert intake["required_inputs"] == ["module_conflict"]
    assert intake["promotion_requirements"]["independent_gate_allowed"] is False
    assert "conflicting module tokens" in intake["failure_reason"]


def test_legacy_plain_text_mail_marks_missing_or_invalid_submitter_without_blocking() -> None:
    message = json.loads(FIXTURE.read_text(encoding="utf-8"))
    message["headers"]["From"] = "invalid-from"

    intake = parse_legacy_submission_mail(message)

    assert intake["state"] == DRAFT_STATE
    assert intake["submitter_email"] == ""
    assert intake["submitter_email_status"] == "missing_or_invalid"
