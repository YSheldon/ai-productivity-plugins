from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_page import DecisionPageBinding, ReleaseApprovalPage
from release_approval_config import (
    AuditConfig,
    MailAccountConfig,
    PageConfig,
    ReleaseApprovalConfig,
    WorkingHoursConfig,
)
from release_approval_mail import MailCapabilityError, MailSendResult
from release_approval_protocol import ReleaseAuthorizationRequest
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


class SequencedMailGateway:
    def __init__(self, results: list[MailSendResult | Exception]) -> None:
        self.results = list(results)
        self.sent_payloads: list[dict[str, object]] = []

    def require_thread_reply_capability(self, payload: dict[str, object]) -> None:
        reply_subject = str(payload.get("reply_subject") or "")
        if not reply_subject:
            raise MailCapabilityError("CAPABILITY_BLOCKED: reply threading fields are missing.")

    def send_email(self, payload: dict[str, object]) -> MailSendResult:
        self.sent_payloads.append(payload)
        if not self.results:
            raise AssertionError("No queued mail result.")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _fixed_now() -> datetime:
    return datetime(2026, 7, 16, 1, 2, 3, tzinfo=timezone.utc)


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
        event_id="rel-2026-07-16-0001",
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
        idempotency_key="release-approval-request-rel-2026-07-16-0001-round-1",
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
    )


def _expected_decision_payload(
    request: ReleaseAuthorizationRequest,
    *,
    decision: str,
    comment: str,
    page_html_sha256: str,
    decided_at: str,
) -> dict[str, object]:
    stable_fields = {
        "event_id": request.event_id,
        "round_id": request.round_id,
        "role_id": request.installed_role_id,
        "manifest_digest": request.manifest_digest,
        "role_snapshot_digest": request.role_snapshot_digest,
        "approver_email": request.installed_role_email,
        "decision": decision,
        "comment": comment,
        "source": "LOCAL_PAGE",
        "original_message_id": request.original_message_id,
        "page_html_sha256": page_html_sha256,
    }
    stable_digest = hashlib.sha256(
        json.dumps(stable_fields, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "schema": "ApprovalDecision/v1",
        "decision_id": f"decision-{request.event_id}-round-{request.round_id}-{request.installed_role_id}-{stable_digest}",
        "event_id": request.event_id,
        "round_id": request.round_id,
        "manifest_digest": request.manifest_digest,
        "role_snapshot_digest": request.role_snapshot_digest,
        "approver_email": request.installed_role_email,
        "decision": decision,
        "comment": comment,
        "source": "LOCAL_PAGE",
        "original_message_id": request.original_message_id,
        "page_html_sha256": page_html_sha256,
        "decided_at": decided_at,
        "idempotency_key": f"decision:{request.event_id}:{request.round_id}:{request.installed_role_id}:{stable_digest}",
    }


def _assert_sha256sums_current(artifact_dir: Path) -> None:
    sums_path = artifact_dir / "SHA256SUMS"
    lines = [line for line in sums_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    expected_files = sorted(path.name for path in artifact_dir.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    seen_files: list[str] = []
    for line in lines:
        digest, star_name = line.split(" *", 1)
        file_path = artifact_dir / star_name
        seen_files.append(star_name)
        assert hashlib.sha256(file_path.read_bytes()).hexdigest() == digest
    assert sorted(seen_files) == expected_files


def _decode_machine_block(text_body: str) -> dict[str, object]:
    begin_marker = "-----BEGIN APPROVAL DECISION-----"
    end_marker = "-----END APPROVAL DECISION-----"
    encoded_block = text_body.split(begin_marker, 1)[1].split(end_marker, 1)[0].strip()
    padded = encoded_block + "=" * (-len(encoded_block) % 4)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


def _hidden_fields_from_html(page_html: str) -> dict[str, str]:
    pattern = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)">')
    return {match.group(1): match.group(2) for match in pattern.finditer(page_html)}


def test_service_builds_exact_threaded_reply_and_writes_audit_artifacts(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    mail = FakeMailGateway(MailSendResult(sent=True, message_id="<smtp-message@example.com>", refused={}, raw={"sent": True}))
    service = ReleaseApprovalService(config=config, store=store, mail_gateway=mail, now_fn=_fixed_now)
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
        "X-RD-Event-Id": "rel-2026-07-16-0001",
        "X-RD-Round-Id": "1",
        "X-RD-Manifest-Digest": request.manifest_digest,
        "X-RD-Role-Snapshot-Digest": request.role_snapshot_digest,
    }

    text_body = str(payload["text"])
    assert "Ship it." in text_body
    decoded_payload = _decode_machine_block(text_body)
    assert decoded_payload == _expected_decision_payload(
        request,
        decision="APPROVE",
        comment="Ship it.",
        page_html_sha256=page_session.page_html_sha256,
        decided_at="2026-07-16T01:02:03Z",
    )

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
    _assert_sha256sums_current(artifact_dir)


def test_build_decision_payload_is_stable_for_retry_and_round_scoped(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    mail = FakeMailGateway(MailSendResult(sent=True, message_id="<smtp-message@example.com>", refused={}, raw={"sent": True}))
    service = ReleaseApprovalService(config=config, store=store, mail_gateway=mail, now_fn=_fixed_now)
    request_round_1 = _request()
    request_round_2 = replace(
        request_round_1,
        round_id=2,
        idempotency_key="release-approval-request-rel-2026-07-16-0001-round-2",
    )
    page_html_sha256 = "sha256:" + "a" * 64

    first = service.build_decision_payload(request_round_1, "APPROVE", "Ship it.", page_html_sha256)
    replay = service.build_decision_payload(request_round_1, "APPROVE", "Ship it.", page_html_sha256)
    second_round = service.build_decision_payload(request_round_2, "APPROVE", "Ship it.", page_html_sha256)

    assert first == replay
    assert first == _expected_decision_payload(
        request_round_1,
        decision="APPROVE",
        comment="Ship it.",
        page_html_sha256=page_html_sha256,
        decided_at="2026-07-16T01:02:03Z",
    )
    assert second_round == _expected_decision_payload(
        request_round_2,
        decision="APPROVE",
        comment="Ship it.",
        page_html_sha256=page_html_sha256,
        decided_at="2026-07-16T01:02:03Z",
    )
    assert first["decision_id"] != second_round["decision_id"]
    assert first["idempotency_key"] != second_round["idempotency_key"]
    assert set(first.keys()) == {
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
    }


def test_service_page_round_trip_serves_service_artifacts_and_keeps_page_html_immutable(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    mail = FakeMailGateway(MailSendResult(sent=True, message_id="<smtp-message@example.com>", refused={}, raw={"sent": True}))
    service = ReleaseApprovalService(config=config, store=store, mail_gateway=mail, now_fn=_fixed_now)
    request = _request()
    request_payload = {"reply_subject": "Re: Release approval"}

    service.record_request(request)
    page_session = service.create_page_session(request=request, request_payload=request_payload)
    persisted_html = page_session.page_html_path.read_text(encoding="utf-8")

    page = ReleaseApprovalPage.from_page_session(
        host="127.0.0.1",
        artifact_dir=page_session.artifact_dir,
        binding=DecisionPageBinding(
            event_id=request.event_id,
            round_id=request.round_id,
            role_id=request.installed_role_id,
            expires_at=request.expires_at,
            page_html_sha256=page_session.page_html_sha256,
        ),
        page_session=page_session,
        submit_decision=lambda form: service.submit_local_decision(
            request=request,
            request_payload=request_payload,
            page_session=page_session,
            decision=form["decision"],
            comment=form["comment"],
            nonce=form["nonce"],
            page_html_sha256=form["page_html_sha256"],
        ),
        open_browser=lambda _url: None,
        now_fn=_fixed_now,
    )

    page.start()
    try:
        served_html = urllib.request.urlopen(page.url, timeout=5).read().decode("utf-8")
        hidden_fields = _hidden_fields_from_html(served_html)

        assert "__NONCE__" not in served_html
        assert "__PAGE_HTML_SHA256__" not in served_html
        assert hidden_fields["nonce"] == page_session.nonce
        assert hidden_fields["page_html_sha256"] == page_session.page_html_sha256
        assert page.url.endswith(f"/{page_session.url_key}/")

        payload = urllib.parse.urlencode(
            {
                **hidden_fields,
                "decision": "APPROVE",
                "comment": "Ship it.",
            }
        ).encode("utf-8")
        response = urllib.request.urlopen(page.url, data=payload, timeout=5)
        assert response.read().decode("utf-8") == "sent"
    finally:
        page.close()

    assert page_session.page_html_path.read_text(encoding="utf-8") == persisted_html
    assert "__NONCE__" in persisted_html
    assert "__PAGE_HTML_SHA256__" in persisted_html
    assert _decode_machine_block(str(mail.sent_payloads[0]["text"]))["page_html_sha256"] == page_session.page_html_sha256
    _assert_sha256sums_current(page_session.artifact_dir)


def test_service_retry_reuses_original_decision_identity_after_retry_queued_in_same_process(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    gateway = SequencedMailGateway(
        [
            MailSendResult(
                sent=True,
                message_id="<smtp-refused@example.com>",
                refused={"release-approvers@example.com": [451, "Retry later"]},
                raw={"sent": True},
            ),
            MailSendResult(sent=True, message_id="<smtp-success@example.com>", refused={}, raw={"sent": True}),
        ]
    )
    first_now = datetime(2026, 7, 16, 1, 2, 3, tzinfo=timezone.utc)
    second_now = datetime(2026, 7, 16, 2, 3, 4, tzinfo=timezone.utc)
    current_now = {"value": first_now}

    def dynamic_now() -> datetime:
        return current_now["value"]

    service = ReleaseApprovalService(config=config, store=store, mail_gateway=gateway, now_fn=dynamic_now)
    request = _request()
    request_payload = {"reply_subject": "Re: Release approval"}

    service.record_request(request)
    page_session = service.create_page_session(request=request, request_payload=request_payload)
    first = service.submit_local_decision(
        request=request,
        request_payload=request_payload,
        page_session=page_session,
        decision="HOLD",
        comment="Need one more smoke test.",
        nonce=page_session.nonce,
        page_html_sha256=page_session.page_html_sha256,
    )

    current_now["value"] = second_now
    second = service.submit_local_decision(
        request=request,
        request_payload=request_payload,
        page_session=page_session,
        decision="HOLD",
        comment="Need one more smoke test.",
        nonce=page_session.nonce,
        page_html_sha256=page_session.page_html_sha256,
    )

    assert first.status == "retry_queued"
    assert second.status == "sent"
    current = store.get_current_decision(request.event_id, request.round_id, request.installed_role_id)
    assert current is not None
    assert current.decided_at == "2026-07-16T01:02:03Z"
    assert store.connection.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 1
    sent_payload = _decode_machine_block(str(gateway.sent_payloads[-1]["text"]))
    assert sent_payload["decision_id"] == current.decision_id
    assert sent_payload["idempotency_key"] == current.idempotency_key
    assert sent_payload["decided_at"] == current.decided_at
    _assert_sha256sums_current(page_session.artifact_dir)


def test_service_retry_reuses_original_decision_identity_after_service_restart(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    request = _request()
    request_payload = {"reply_subject": "Re: Release approval"}
    first_store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    first_gateway = FakeMailGateway(
        MailSendResult(
            sent=True,
            message_id="<smtp-refused@example.com>",
            refused={"release-approvers@example.com": [451, "Retry later"]},
            raw={"sent": True},
        )
    )
    first_service = ReleaseApprovalService(
        config=config,
        store=first_store,
        mail_gateway=first_gateway,
        now_fn=lambda: datetime(2026, 7, 16, 1, 2, 3, tzinfo=timezone.utc),
    )

    first_service.record_request(request)
    page_session = first_service.create_page_session(request=request, request_payload=request_payload)
    first = first_service.submit_local_decision(
        request=request,
        request_payload=request_payload,
        page_session=page_session,
        decision="APPROVE",
        comment="Ship it.",
        nonce=page_session.nonce,
        page_html_sha256=page_session.page_html_sha256,
    )
    first_store.close()

    restarted_store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    restarted_gateway = FakeMailGateway(
        MailSendResult(sent=True, message_id="<smtp-success@example.com>", refused={}, raw={"sent": True})
    )
    restarted_service = ReleaseApprovalService(
        config=config,
        store=restarted_store,
        mail_gateway=restarted_gateway,
        now_fn=lambda: datetime(2026, 7, 16, 3, 4, 5, tzinfo=timezone.utc),
    )
    second = restarted_service.submit_local_decision(
        request=request,
        request_payload=request_payload,
        page_session=page_session,
        decision="APPROVE",
        comment="Ship it.",
        nonce=page_session.nonce,
        page_html_sha256=page_session.page_html_sha256,
    )

    assert first.status == "retry_queued"
    assert second.status == "sent"
    current = restarted_store.get_current_decision(request.event_id, request.round_id, request.installed_role_id)
    assert current is not None
    assert current.decided_at == "2026-07-16T01:02:03Z"
    assert restarted_store.connection.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 1
    sent_payload = _decode_machine_block(str(restarted_gateway.sent_payloads[0]["text"]))
    assert sent_payload["decision_id"] == current.decision_id
    assert sent_payload["idempotency_key"] == current.idempotency_key
    assert sent_payload["decided_at"] == current.decided_at
    _assert_sha256sums_current(page_session.artifact_dir)


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
    _assert_sha256sums_current(page_session.artifact_dir)


def test_service_preserves_reference_order_deduplicates_and_keeps_original_exactly_once(tmp_path: Path) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    mail = FakeMailGateway(MailSendResult(sent=True, message_id="<smtp-message@example.com>", refused={}, raw={"sent": True}))
    service = ReleaseApprovalService(config=config, store=store, mail_gateway=mail)
    request = ReleaseAuthorizationRequest(
        contract="ReleaseAuthorizationRequest/v1",
        event_id="rel-2026-07-16-0002",
        round_id=1,
        task="Task 5",
        module="release-approval",
        manifest_s_digest="sha256:" + "1" * 64,
        manifest_r_digest="sha256:" + "2" * 64,
        manifest_digest="sha256:" + "3" * 64,
        request_digest="sha256:" + "4" * 64,
        role_snapshot_digest="sha256:" + "5" * 64,
        required_roles=("release-manager",),
        original_message_id="<request-2@example.com>",
        references=(
            "<root@example.com>",
            "<request-2@example.com>",
            "<root@example.com>",
            "<peer@example.com>",
        ),
        expires_at="2099-07-16T00:00:00Z",
        idempotency_key="release-approval-request-rel-2026-07-16-0002-round-1",
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
    )

    service.record_request(request)
    page_session = service.create_page_session(request=request, request_payload={"reply_subject": "Re: Release approval"})
    service.submit_local_decision(
        request=request,
        request_payload={"reply_subject": "Re: Release approval"},
        page_session=page_session,
        decision="APPROVE",
        comment="Ship it.",
        nonce=page_session.nonce,
        page_html_sha256=page_session.page_html_sha256,
    )

    assert mail.sent_payloads[0]["references"] == [
        "<root@example.com>",
        "<request-2@example.com>",
        "<peer@example.com>",
    ]


@pytest.mark.parametrize(
    ("event_id", "role_id", "message"),
    [
        ("..", "release-manager", "safe path"),
        ("rel-2026-07-16-0003", ".", "safe path"),
        ("CON", "release-manager", "reserved"),
    ],
)
def test_service_rejects_dot_components_and_reserved_path_forms(
    tmp_path: Path,
    event_id: str,
    role_id: str,
    message: str,
) -> None:
    config = _config(tmp_path / "state")
    store = ReleaseApprovalStore(config.state_dir / "state.sqlite3")
    mail = FakeMailGateway(MailSendResult(sent=True, message_id="<smtp-message@example.com>", refused={}, raw={}))
    service = ReleaseApprovalService(config=config, store=store, mail_gateway=mail)
    request = ReleaseAuthorizationRequest(
        contract="ReleaseAuthorizationRequest/v1",
        event_id=event_id,
        round_id=1,
        task="Task 5",
        module="release-approval",
        manifest_s_digest="sha256:" + "1" * 64,
        manifest_r_digest="sha256:" + "2" * 64,
        manifest_digest="sha256:" + "3" * 64,
        request_digest="sha256:" + "4" * 64,
        role_snapshot_digest="sha256:" + "5" * 64,
        required_roles=("release-manager",),
        original_message_id="<request-3@example.com>",
        references=("<root@example.com>",),
        expires_at="2099-07-16T00:00:00Z",
        idempotency_key="release-approval-request-rel-2026-07-16-0003-round-1",
        installed_role_id=role_id,
        installed_role_email="release-manager@example.com",
    )

    with pytest.raises(ReleaseApprovalServiceError, match=message):
        service.artifact_dir_for_request(request)


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
        service.artifact_dir_for_request(
            ReleaseAuthorizationRequest(
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
            )
        )
