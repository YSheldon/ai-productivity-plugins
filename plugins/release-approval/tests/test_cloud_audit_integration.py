from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from lark_audit import AuditWriteResult
from release_approval_config import (
    AuditConfig,
    ConfigError,
    MailAccountConfig,
    PageConfig,
    RequestAuthenticationConfig,
    ReleaseApprovalConfig,
    WorkingHoursConfig,
    load_config,
)
from release_approval_mcp import ReleaseApprovalController
from release_approval_protocol import build_request_digest, canonical_json, validate_release_request
from release_approval_service import SubmissionResult


NOW = datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc)
BEGIN = "-----BEGIN RELEASE APPROVAL REQUEST-----"
END = "-----END RELEASE APPROVAL REQUEST-----"


def _request_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "contract": "ReleaseAuthorizationRequest/v1",
        "event_id": "audit-event-1",
        "round_id": 1,
        "task": "Release task",
        "module": "client",
        "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64,
        "manifest_digest": "sha256:" + "3" * 64,
        "role_snapshot_digest": "sha256:" + "4" * 64,
        "required_roles": ["release-manager"],
        "original_message_id": "<request@example.com>",
        "references": ["<root@example.com>"],
        "expires_at": "2099-07-17T00:00:00Z",
        "idempotency_key": "request:audit-event-1:1",
    }
    payload["request_digest"] = build_request_digest(payload)
    return payload


def _config(tmp_path: Path, *, document_url: str | None) -> ReleaseApprovalConfig:
    return ReleaseApprovalConfig(
        role_id="release-manager",
        role_email="release-manager@example.com",
        mail_account=MailAccountConfig("release-manager", "release-manager@example.com"),
        request_authentication=RequestAuthenticationConfig(
            allowed_sender_emails=("release-gate@example.com",),
            allowed_authserv_ids=("mx.example.com",),
            accepted_paths=("dmarc", "dkim", "spf"),
        ),
        release_group="release-approvers@example.com",
        mailbox="INBOX",
        page=PageConfig("127.0.0.1", 8765),
        poll_minutes=60,
        timezone="UTC",
        working_hours=WorkingHoursConfig(("Mon", "Tue", "Wed", "Thu", "Fri"), "09:00", "18:00"),
        state_dir=tmp_path,
        dependency_lock=REPO_ROOT / "dependency-lock.json",
        audit=AuditConfig(True, 3650, document_url),
    )


class FakeMail:
    def __init__(self) -> None:
        encoded = base64.urlsafe_b64encode(
            canonical_json(_request_payload()).encode("utf-8")
        ).decode("ascii").rstrip("=")
        request = _request_payload()
        self.message = {
            "uid": "7",
            "uidvalidity": "11",
            "message_id": "<request@example.com>",
            "subject": "【发布申请】Release task-client-2026-07-16",
            "body_text": f"{BEGIN}\n{encoded}\n{END}",
            "from": [
                {"name": "Release Gate", "email": "release-gate@example.com"}
            ],
            "evidence": {
                "raw_headers_sha256": "a" * 64,
                "references": ["<root@example.com>"],
                "message_id": "<request@example.com>",
                "return_path": "release-gate@example.com",
                "authentication_results": (
                    "mx.example.com; dmarc=pass "
                    "header.from=example.com; dkim=pass header.d=example.com"
                ),
                "received_spf": "pass",
            },
            "release_workflow_headers": {
                "contract": str(request["contract"]),
                "event_id": str(request["event_id"]),
                "round_id": str(request["round_id"]),
                "task": str(request["task"]),
                "module": str(request["module"]),
                "manifest_s_digest": str(request["manifest_s_digest"]),
                "manifest_r_digest": str(request["manifest_r_digest"]),
                "manifest_digest": str(request["manifest_digest"]),
                "request_digest": str(request["request_digest"]),
                "role_snapshot_digest": str(request["role_snapshot_digest"]),
                "required_roles": ",".join(request["required_roles"]),
                "expires_at": str(request["expires_at"]),
            },
        }

    def search_messages(self, _payload):
        return {"messages": [{"uid": "7"}]}

    def read_message(self, _payload):
        return dict(self.message)

    def list_accounts(self):
        return {"accounts": [{"name": "release-manager", "email": "release-manager@example.com"}]}


class FakeAudit:
    def __init__(self, *, status: str = "AUDIT_WRITTEN") -> None:
        self.status = status
        self.records = []

    def write(self, record):
        self.records.append(record)
        return AuditWriteResult(
            status=self.status,
            state_advance_allowed=True,
            cloud_readback_verified=self.status == "AUDIT_WRITTEN",
            audit_payload_digest="sha256:" + "9" * 64,
            recorded_state=record.state,
            failure_reason=None if self.status == "AUDIT_WRITTEN" else "LARK_READBACK_FAILED",
        )


def test_config_accepts_optional_absolute_audit_document_and_rejects_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv("RELEASE_APPROVAL_REPO_ROOT", str(tmp_path))
    payload = {
        "role_id": "release-manager",
        "role_email": "release-manager@example.com",
        "mail_account": {"profile": "release-manager", "email": "release-manager@example.com"},
        "request_authentication": {
            "allowed_sender_emails": ["release-gate@example.com"],
            "allowed_authserv_ids": ["mx.example.com"],
            "accepted_paths": ["dmarc", "dkim", "spf"],
        },
        "release_group": "release-approvers@example.com",
        "mailbox": "INBOX",
        "page": {"host": "127.0.0.1", "port": 8765},
        "working_hours": {"days": ["Mon"], "start": "09:00", "end": "18:00"},
        "state_dir": "%RELEASE_APPROVAL_STATE_ROOT%\\state",
        "dependency_lock": "%RELEASE_APPROVAL_REPO_ROOT%\\dependency-lock.json",
        "audit": {
            "verify_chain_on_startup": True,
            "retention_days": 3650,
            "document_url": "https://open.feishu.cn/wiki/audit-ledger",
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_config(path).audit.document_url == "https://open.feishu.cn/wiki/audit-ledger"

    payload["audit"]["document_url"] = "relative/audit"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigError, match="absolute HTTP"):
        load_config(path)


def test_authenticated_request_cloud_audit_is_idempotent_and_degradation_is_explicit(
    tmp_path: Path,
) -> None:
    audit = FakeAudit(status="AUDIT_DEGRADED")
    controller = ReleaseApprovalController(
        config=_config(tmp_path, document_url="https://open.feishu.cn/wiki/audit-ledger"),
        mail_gateway=FakeMail(),
        lark_audit_adapter=audit,
        browser_opener=lambda _url: None,
        now_fn=lambda: NOW,
    )

    first = controller.run_once()
    second = controller.run_once()

    assert first["status"] == "ready"
    assert first["events"][0]["cloud_audit"]["status"] == "AUDIT_DEGRADED"
    assert second["events"][0]["cloud_audit"] is None
    assert [record.event_type for record in audit.records] == ["REQUEST_CREATED"]
    assert audit.records[0].required_role_emails == {
        "release-manager": "release-manager@example.com"
    }
    degraded_count = controller.store.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type = 'cloud_audit_degraded'"
    ).fetchone()[0]
    assert degraded_count == 1


def test_page_decision_records_decision_fact_separately_from_smtp_result(tmp_path: Path) -> None:
    audit = FakeAudit()

    class FakeService:
        def submit_local_decision(self, **_kwargs):
            return SubmissionResult(status="retry_queued", response_text="retry queued")

    controller = ReleaseApprovalController(
        config=_config(tmp_path, document_url="https://open.feishu.cn/wiki/audit-ledger"),
        mail_gateway=FakeMail(),
        service=FakeService(),
        lark_audit_adapter=audit,
        browser_opener=lambda _url: None,
        now_fn=lambda: NOW,
    )
    request = validate_release_request(
        _request_payload(),
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
        now=NOW,
    )

    result = controller._submit_page_decision(  # noqa: SLF001
        request=request,
        request_payload={"reply_subject": "Re: 【发布申请】"},
        page_session=object(),
        form={
            "decision": "APPROVE",
            "comment": "",
            "nonce": "nonce",
            "page_html_sha256": "sha256:" + "8" * 64,
        },
    )

    assert result.status == "retry_queued"
    assert [record.event_type for record in audit.records] == ["PAGE_DECISION"]
    assert audit.records[0].state == "APPROVE"
    assert audit.records[0].audit_payload["status"] == "retry_queued"
