from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_config import (
    AuditConfig,
    MailAccountConfig,
    PageConfig,
    ReleaseApprovalConfig,
    WorkingHoursConfig,
)
from release_approval_mail import MailCapabilityError, MailSendResult
from release_approval_protocol import ReleaseAuthorizationRequest, canonical_json
from release_approval_service import ReleaseApprovalService, ReleaseApprovalServiceError
from release_approval_store import ReleaseApprovalStore


class FakeMailGateway:
    def __init__(self, result: MailSendResult | Exception) -> None:
        self.result = result
        self.sent_payloads: list[dict[str, object]] = []

    def require_thread_reply_capability(self, payload: dict[str, object]) -> None:
        reply_subject = str(payload.get("reply_subject") or "")
        if not reply_subject:
            raise MailCapabilityError("CAPABILITY_BLOCKED: reply threading fields are missing.")

    def send_email(self, payload: dict[str, object]) -> MailSendResult:
        self.sent_payloads.append(payload)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _config(state_dir: Path) -> ReleaseApprovalConfig:
    return ReleaseApprovalConfig(
        role_id="release-manager",
        role_email="release-manager@example.com",
        mail_account=MailAccountConfig(profile="release-manager", email="release-manager@example.com"),
        release_group="release-approvers@example.com",
        mailbox="INBOX",
        page=PageConfig(host="127.0.0.1", port=8765),
        poll_minutes=60,
        timezone="UTC",
        working_hours=WorkingHoursConfig(days=("Mon",), start="09:00", end="18:00"),
        state_dir=state_dir,
        dependency_lock=state_dir / "dependency-lock.json",
        audit=AuditConfig(verify_chain_on_startup=True, retention_days=3650),
    )


def _request() -> ReleaseAuthorizationRequest:
    return ReleaseAuthorizationRequest(
        contract="ReleaseAuthorizationRequest/v1",
        event_id="rel-2026-07-15-0001",
        round_id=1,
        task="Task 5",
        module="release-approval",
        manifest_s_digest="sha256:" + "1" * 64,
        manifest_r_digest="sha256:" + "2" * 64,
        manifest_digest="sha256:" + "3" * 64,
        request_digest="sha256:" + "4" * 64,
        role_snapshot_digest="sha256:" + "5" * 64,
        required_roles=("release-manager", "security-reviewer"),
        original_message_id="<request-1@example.com>",
        references=("<root@example.com>",),
        expires_at="2099-07-16T00:00:00Z",
        idempotency_key="release-approval-request-rel-2026-07-15-0001-round-1",
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
    )


def test_service_builds_exact_threaded_reply_and_writes_audit_artifacts(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    mail = FakeMailGateway(MailSendResult(sent=True, message_id="<smtp-message@example.com>", refused={}, raw={"sent": True}))
    service = ReleaseApprovalService(config=config, store=store, mail_gateway=mail)
    request = _request()
    request_payload = {"reply_subject": "Re: Release approval"}

    service.record_request(request)
    page_session = service.create_page_session(request=request, request_payload=request_payload)
    result = service.submit_local_decision(
        request=request,
        request_payload=request_payload,
        page_session=page_session,
        decision="APPROVE",
        comment="Ship it.",
        nonce=page_session.nonce,
        page_html_sha256=page_session.page_html_sha256,
    )

    assert result.status == "sent"
    assert result.response_text == "sent"
    payload = mail.sent_payloads[0]
    assert payload["account"] == "release-manager"
    assert payload["to"] == ["release-approvers@example.com"]
    assert payload["subject"] == "Re: Release approval"
    assert payload["dry_run"] is False
    assert payload["in_reply_to"] == "<request-1@example.com>"
    assert payload["references"] == ["<root@example.com>", "<request-1@example.com>"]
    assert payload["headers"] == {
        "X-RD-Decision-Schema": "ApprovalDecision/v1",
        "X-RD-Event-Id": "rel-2026-07-15-0001",
        "X-RD-Round-Id": "1",
        "X-RD-Manifest-Digest": request.manifest_digest,
        "X-RD-Role-Snapshot-Digest": request.role_snapshot_digest,
    }

    text_body = str(payload["text"])
    assert "Ship it." in text_body
    begin_marker = "-----BEGIN APPROVAL DECISION-----"
    end_marker = "-----END APPROVAL DECISION-----"
    encoded_block = text_body.split(begin_marker, 1)[1].split(end_marker, 1)[0].strip()
    decoded_payload = json.loads(base64.urlsafe_b64decode(encoded_block + "=" * (-len(encoded_block) % 4)).decode("utf-8"))
    assert canonical_json(decoded_payload) == canonical_json(service.build_decision_payload(request, "APPROVE", "Ship it.", page_session.page_html_sha256))

    artifact_dir = config.state_dir / "audit" / request.event_id / "round-1" / "role-release-manager"
    assert (artifact_dir / "page.html").exists()
    assert (artifact_dir / "page-state.json").exists()
    assert (artifact_dir / "browser-events.jsonl").exists()
    assert (artifact_dir / "decision.json").exists()
    assert (artifact_dir / "smtp-result.json").exists()
    assert (artifact_dir / "SHA256SUMS").exists()
    assert "<smtp-message@example.com>" in (artifact_dir / "smtp-result.json").read_text(encoding="utf-8")
    state_text = (artifact_dir / "page-state.json").read_text(encoding="utf-8")
    assert page_session.nonce not in state_text
    assert page_session.url_key not in state_text


def test_service_queues_retry_when_smtp_refuses_any_recipient(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    mail = FakeMailGateway(
        MailSendResult(
            sent=True,
            message_id="<smtp-message@example.com>",
            refused={"blocked@example.com": [550, "Rejected"]},
            raw={"sent": True},
        )
    )
    service = ReleaseApprovalService(config=config, store=store, mail_gateway=mail)
    request = _request()
    request_payload = {"reply_subject": "Re: Release approval"}

    service.record_request(request)
    page_session = service.create_page_session(request=request, request_payload=request_payload)
    result = service.submit_local_decision(
        request=request,
        request_payload=request_payload,
        page_session=page_session,
        decision="HOLD",
        comment="Need one more smoke test.",
        nonce=page_session.nonce,
        page_html_sha256=page_session.page_html_sha256,
    )

    assert result.status == "retry_queued"
    assert result.response_text == "retry queued"
    smtp_result = json.loads((page_session.artifact_dir / "smtp-result.json").read_text(encoding="utf-8"))
    assert smtp_result["status"] == "retry_queued"
    assert smtp_result["refused"] == {"blocked@example.com": [550, "Rejected"]}


def test_service_fails_closed_for_missing_threading_fields_and_invalid_artifact_path_ids(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    mail = FakeMailGateway(MailSendResult(sent=True, message_id="<smtp-message@example.com>", refused={}, raw={}))
    service = ReleaseApprovalService(config=config, store=store, mail_gateway=mail)
    request = _request()
    service.record_request(request)

    with pytest.raises(MailCapabilityError, match="CAPABILITY_BLOCKED"):
        service.create_page_session(request=request, request_payload={"reply_subject": ""})

    with pytest.raises(ReleaseApprovalServiceError, match="safe path"):
        service.artifact_dir_for_request(ReleaseAuthorizationRequest(
            contract=request.contract,
            event_id="../escape",
            round_id=request.round_id,
            task=request.task,
            module=request.module,
            manifest_s_digest=request.manifest_s_digest,
            manifest_r_digest=request.manifest_r_digest,
            manifest_digest=request.manifest_digest,
            request_digest=request.request_digest,
            role_snapshot_digest=request.role_snapshot_digest,
            required_roles=request.required_roles,
            original_message_id=request.original_message_id,
            references=request.references,
            expires_at=request.expires_at,
            idempotency_key=request.idempotency_key,
            installed_role_id=request.installed_role_id,
            installed_role_email=request.installed_role_email,
        ))
