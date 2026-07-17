from __future__ import annotations

import base64
import email.utils
import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from datetime import datetime, time, timezone, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "verifier_controller.py"
sys.path.insert(0, str(SRC_ROOT))

from lark_audit import AuditWriteResult
from role_snapshot import RoleRecord, RoleSnapshot, canonical_json
from verifier_config import (
    AuditDocumentConfig,
    AuthenticationPolicyConfig,
    MailAccountConfig,
    ReminderPolicyConfig,
    StaticRoleSourceConfig,
    VerifierConfig,
    WorkingHoursConfig,
)


def _load_module():
    assert MODULE_PATH.is_file(), f"missing controller module: {MODULE_PATH}"
    spec = importlib.util.spec_from_file_location("verifier_controller", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("verifier_controller", module)
    spec.loader.exec_module(module)
    return module


def _roles() -> tuple[RoleRecord, ...]:
    return (
        RoleRecord("release-manager", "manager@example.com", True, True),
        RoleRecord("security-reviewer", "security@example.com", True, True),
    )


def _snapshot() -> RoleSnapshot:
    return RoleSnapshot(
        document_url="https://example.feishu.cn/docx/release-roles",
        heading="## 审批角色",
        roles=_roles(),
        digest="sha256:" + "5" * 64,
    )


def _config(tmp_path: Path) -> VerifierConfig:
    return VerifierConfig(
        mode="test",
        role_source=StaticRoleSourceConfig(kind="static", roles=_roles()),
        release_group="release@example.com",
        mailbox="INBOX",
        verifier_mail_account=MailAccountConfig(profile="mail-primary", email="verifier@example.com"),
        event_expiry_hours=24,
        poll_minutes=60,
        timezone="UTC",
        working_hours=WorkingHoursConfig(days=("Mon", "Tue", "Wed", "Thu", "Fri"), start="09:00", end="18:00"),
        reminder_policy=ReminderPolicyConfig(initial_delay_minutes=60, repeat_minutes=240, maximum=3),
        authentication_policy=AuthenticationPolicyConfig(
            accepted_paths=("dmarc", "dkim", "spf"),
            allowed_authserv_ids=("mx.example.com",),
            trusted_internal_header="X-Trusted-Relay",
            trusted_internal_value="release-gateway",
        ),
        state_dir=tmp_path / "state",
        dependency_lock=tmp_path / "dependency-lock.json",
        dependency_lock_sha256="0" * 64,
        audit_document=AuditDocumentConfig(url="https://example.feishu.cn/wiki/release-audit"),
    )


def _manifest_digest() -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(
            {
                "manifest_s_digest": "sha256:" + "1" * 64,
                "manifest_r_digest": "sha256:" + "2" * 64,
            }
        ).encode("utf-8")
    ).hexdigest()


def _request_payload(
    *,
    event_id: str,
    round_id: int,
    message_id: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "contract": "ReleaseAuthorizationRequest/v1",
        "schema": "ReleaseAuthorizationRequest/v1",
        "event_id": event_id,
        "round_id": round_id,
        "requested_by": "bot@example.com",
        "target_scope": "preproduction,production_canary",
        "task_id": "Task 9",
        "task": "Task 9",
        "module": "release-approval-verifier",
        "source_ref": "commit:test",
        "risk_level": "standard",
        "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64,
        "manifest_digest": _manifest_digest(),
        "role_snapshot_digest": "sha256:" + "5" * 64,
        "required_roles": ["release-manager", "security-reviewer"],
        "required_role_bindings": [
            {"role_id": "release-manager", "email": "manager@example.com", "required": True},
            {"role_id": "security-reviewer", "email": "security@example.com", "required": True},
        ],
        "original_message_id": message_id,
        "references": [],
        "expires_at": "2026-07-17T04:00:00Z",
        "idempotency_key": f"release-approval:{event_id}:{round_id}",
        "requested_at": "2026-07-16T01:00:00Z",
    }
    payload["request_digest"] = "sha256:" + hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return payload


def _request_message(
    *,
    event_id: str = "evt-runtime",
    round_id: int = 1,
    created_at: str = "Thu, 16 Jul 2026 01:00:00 +0000",
) -> EmailMessage:
    message_id = "<request-evt-runtime@example.com>"
    payload = _request_payload(
        event_id=event_id,
        round_id=round_id,
        message_id=message_id,
    )
    encoded = base64.urlsafe_b64encode(
        canonical_json(payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    message = EmailMessage()
    message["From"] = "Release Bot <bot@example.com>"
    message["To"] = "release@example.com"
    message["Subject"] = "【发布申请】Task 9-release-approval-verifier-20260716"
    message["Date"] = created_at
    message["Message-ID"] = message_id
    message["X-RD-Contract"] = str(payload["contract"])
    message["X-RD-Event-Id"] = event_id
    message["X-RD-Round-Id"] = str(round_id)
    message["X-RD-Task"] = str(payload["task"])
    message["X-RD-Module"] = str(payload["module"])
    message["X-RD-Manifest-S-Digest"] = str(payload["manifest_s_digest"])
    message["X-RD-Manifest-R-Digest"] = str(payload["manifest_r_digest"])
    message["X-RD-Manifest-Digest"] = str(payload["manifest_digest"])
    message["X-RD-Request-Digest"] = str(payload["request_digest"])
    message["X-RD-Role-Snapshot-Digest"] = str(payload["role_snapshot_digest"])
    message["X-RD-Required-Roles"] = ",".join(payload["required_roles"])
    message["X-RD-Expires-At"] = str(payload["expires_at"])
    message.set_content(
        "请审批本次发布。\n\n"
        f"-----BEGIN RELEASE APPROVAL REQUEST-----\n{encoded}\n"
        "-----END RELEASE APPROVAL REQUEST-----"
    )
    return message

def _reply_message(
    *,
    message_id: str,
    sender: str,
    return_path: str,
    body: str,
    in_reply_to: str = "<request-evt-runtime@example.com>",
    references: str = "<thread-root@example.com> <request-evt-runtime@example.com>",
) -> EmailMessage:
    message = EmailMessage()
    message["Return-Path"] = f"<{return_path}>"
    message["From"] = f"Reviewer <{sender}>"
    message["To"] = "release@example.com"
    message["Subject"] = "Re: 【发布申请】Task 9-release-approval-verifier-20260716"
    message["Date"] = "Thu, 16 Jul 2026 03:00:00 +0000"
    message["Message-ID"] = message_id
    message["In-Reply-To"] = in_reply_to
    message["References"] = references
    message["Authentication-Results"] = (
        "mx.example.com; dkim=pass header.d=example.com; dmarc=pass action=none header.from=example.com"
    )
    message["Received-SPF"] = "pass"
    message["X-RD-Event-Id"] = "evt-runtime"
    message["X-RD-Round-Id"] = "1"
    message["X-RD-Manifest-Digest"] = _manifest_digest()
    message["X-RD-Role-Snapshot-Digest"] = "sha256:" + "5" * 64
    message.set_content(body)
    return message


def _readback_payload(message: EmailMessage, uid: str) -> dict[str, Any]:
    def addresses(header_name: str) -> list[dict[str, str]]:
        return [
            {"name": name, "email": address.lower()}
            for name, address in email.utils.getaddresses(message.get_all(header_name, []))
            if address
        ]

    workflow_map = {
        "contract": "X-RD-Contract",
        "event_id": "X-RD-Event-Id",
        "round_id": "X-RD-Round-Id",
        "task": "X-RD-Task",
        "module": "X-RD-Module",
        "manifest_s_digest": "X-RD-Manifest-S-Digest",
        "manifest_r_digest": "X-RD-Manifest-R-Digest",
        "manifest_digest": "X-RD-Manifest-Digest",
        "request_digest": "X-RD-Request-Digest",
        "role_snapshot_digest": "X-RD-Role-Snapshot-Digest",
        "required_roles": "X-RD-Required-Roles",
        "expires_at": "X-RD-Expires-At",
    }
    return_path = email.utils.parseaddr(str(message.get("Return-Path", "")))[1]
    references = [
        value
        for value in str(message.get("References", "")).split()
        if value.startswith("<") and value.endswith(">")
    ]
    return {
        "uid": uid,
        "uidvalidity": "71",
        "subject": str(message.get("Subject", "")),
        "from": addresses("From"),
        "to": addresses("To"),
        "cc": addresses("Cc"),
        "date": str(message.get("Date", "")),
        "message_id": str(message.get("Message-ID", "")),
        "body_text": str(message.get_content()),
        "evidence": {
            "message_id": str(message.get("Message-ID", "")),
            "in_reply_to": str(message.get("In-Reply-To", "")),
            "references": references,
            "return_path": return_path,
            "authentication_results": str(message.get("Authentication-Results", "")),
            "received_spf": str(message.get("Received-SPF", "")),
            "raw_headers_sha256": hashlib.sha256(
                bytes(message)
            ).hexdigest(),
        },
        "release_workflow_headers": {
            key: str(message.get(header, "")).strip()
            for key, header in workflow_map.items()
            if str(message.get(header, "")).strip()
        },
    }

@dataclass
class _AcquireResult:
    status: str
    owner: str | None = None
    recovered_owner: str | None = None


class FakeLock:
    def __init__(self, result: _AcquireResult) -> None:
        self.result = result
        self.acquire_calls = 0
        self.release_calls = 0

    def acquire(self) -> dict[str, Any]:
        self.acquire_calls += 1
        payload = {"status": self.result.status}
        if self.result.owner is not None:
            payload["owner"] = self.result.owner
        if self.result.recovered_owner is not None:
            payload["recovered_owner"] = self.result.recovered_owner
        return payload

    def release(self) -> None:
        self.release_calls += 1


class FakeMailGateway:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.thread_checks: list[dict[str, Any]] = []
        self.readback_checks: list[dict[str, Any]] = []

    def require_thread_reply_capability(self, payload: dict[str, Any]) -> None:
        self.thread_checks.append(dict(payload))

    def require_authenticated_readback_capability(self, payload: dict[str, Any]) -> None:
        self.readback_checks.append(dict(payload))

    def send_email(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(dict(payload))
        return {
            "sent": True,
            "message_id": str(payload.get("message_id") or ""),
            "refused": {},
        }


class FakeReadbackMailGateway(FakeMailGateway):
    def __init__(self, messages: list[EmailMessage]) -> None:
        super().__init__()
        self.payloads = {
            str(index): _readback_payload(message, str(index))
            for index, message in enumerate(messages, start=1)
        }
        self.search_payloads: list[dict[str, Any]] = []
        self.read_payloads: list[dict[str, Any]] = []

    def search_messages(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.search_payloads.append(dict(payload))
        return {"messages": [{"uid": uid} for uid in self.payloads]}

    def read_message(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.read_payloads.append(dict(payload))
        return dict(self.payloads[str(payload["uid"])])

class FakeAuditAdapter:
    def __init__(self, *, required: bool = True) -> None:
        self.required = required
        self.records: list[Any] = []

    def write(self, record: Any) -> AuditWriteResult:
        self.records.append(record)
        return AuditWriteResult(
            status="AUDIT_WRITTEN",
            state_advance_allowed=True,
            cloud_readback_verified=True,
            audit_payload_digest="sha256:" + "6" * 64,
            recorded_state=record.state,
        )


class FakeScheduler:
    def status(self, *, mode: str = "auto") -> dict[str, Any]:
        return {"status": "ready", "mode": mode, "installed": True}


class MissingGateAdapter:
    def preflight(self) -> dict[str, Any]:
        return {"status": "CAPABILITY_BLOCKED", "reason": "product gate adapter missing"}


def _controller(
    tmp_path: Path,
    *,
    request_messages: list[EmailMessage],
    reply_messages: list[EmailMessage],
    lock: FakeLock | None = None,
) -> Any:
    module = _load_module()
    config = _config(tmp_path)
    config.dependency_lock.write_text("{}\n", encoding="utf-8")
    return module.VerifierController(
        config=config,
        config_path=tmp_path / "config.json",
        now_fn=lambda: datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc),
        audit_key=b"a" * 32,
        role_snapshot_fetcher=lambda: _snapshot(),
        request_scanner=lambda *_args, **_kwargs: tuple(request_messages),
        reply_scanner=lambda *_args, **_kwargs: tuple(reply_messages),
        mail_gateway=FakeMailGateway(),
        audit_adapter=FakeAuditAdapter(),
        scheduler=FakeScheduler(),
        lock_factory=(lambda *_args, **_kwargs: lock or FakeLock(_AcquireResult("acquired"))),
        product_gate_adapter=MissingGateAdapter(),
    )


def test_run_once_rejects_overlap_before_any_side_effect(tmp_path: Path) -> None:
    lock = FakeLock(_AcquireResult("active", owner="other-runtime"))
    controller = _controller(
        tmp_path,
        request_messages=[_request_message()],
        reply_messages=[],
        lock=lock,
    )

    result = controller.run_once()

    assert result == {"status": "RUN_ALREADY_ACTIVE", "busy": True, "owner": "other-runtime"}
    assert lock.acquire_calls == 1
    assert lock.release_calls == 0
    assert not (tmp_path / "state").exists()


def test_run_once_quarantines_spoof_and_only_reminds_missing_roles(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        request_messages=[_request_message()],
        reply_messages=[
            _reply_message(
                message_id="<decision-approve@example.com>",
                sender="manager@example.com",
                return_path="manager@example.com",
                body="通过",
            ),
            _reply_message(
                message_id="<spoofed-security@example.com>",
                sender="security@example.com",
                return_path="attacker@example.com",
                body="通过",
            ),
        ],
    )

    result = controller.run_once()
    event = controller.get_event(event_id="evt-runtime", round_id=1)
    missing = controller.list_missing_roles(event_id="evt-runtime", round_id=1)

    assert result["status"] == "ready"
    assert result["receipt"]["status"] == "APPROVAL_PAUSED"
    assert result["processed"]["validated"] == 1
    assert result["processed"]["quarantined"] == 1
    assert missing["missing_roles"] == ["security-reviewer"]
    assert [item["role_id"] for item in result["reminders"]] == ["security-reviewer"]
    assert event["current_decisions"][0]["decision"] == "APPROVE"
    assert event["quarantined_messages"][0]["message_id"] == "<spoofed-security@example.com>"
    assert event["receipt"]["status"] == "APPROVAL_PAUSED"


def test_hold_decision_pauses_without_handoff_and_status_doctor_surface_runtime_state(tmp_path: Path) -> None:
    controller = _controller(
        tmp_path,
        request_messages=[_request_message()],
        reply_messages=[
            _reply_message(
                message_id="<decision-manager@example.com>",
                sender="manager@example.com",
                return_path="manager@example.com",
                body="通过",
            ),
            _reply_message(
                message_id="<decision-hold@example.com>",
                sender="security@example.com",
                return_path="security@example.com",
                body="待评估",
            ),
        ],
    )

    result = controller.run_once()
    status = controller.status()
    doctor = controller.doctor()
    receipt_path = Path(result["receipt_path"])
    verified = controller.verify_receipt(path=receipt_path)
    audit = controller.verify_audit_chain()

    assert result["receipt"]["status"] == "APPROVAL_PAUSED"
    assert result["handoff"]["status"] == "skipped"
    assert status["event_count"] == 1
    assert status["current_receipt_statuses"] == ["APPROVAL_PAUSED"]
    assert doctor["status"] == "CAPABILITY_BLOCKED"
    assert "product_gate" in doctor["missing_capabilities"]
    assert verified["status"] == "APPROVAL_PAUSED"
    assert audit["status"] == "ready"

def test_run_once_records_orphan_lock_recovery_after_acquisition(tmp_path: Path) -> None:
    lock = FakeLock(_AcquireResult("acquired", recovered_owner="old-runtime"))
    controller = _controller(
        tmp_path,
        request_messages=[],
        reply_messages=[],
        lock=lock,
    )

    result = controller.run_once()
    row = controller._store().connection.execute(
        "SELECT event_type, payload_json FROM audit_events ORDER BY id ASC LIMIT 1"
    ).fetchone()

    assert result["status"] == "ready"
    assert row["event_type"] == "run-lock-orphan-recovered"
    assert json.loads(row["payload_json"]) == {
        "new_owner": controller._lock_owner(),
        "recovered_owner": "old-runtime",
    }

def test_default_mail_scan_reads_once_and_preserves_authenticated_evidence(
    tmp_path: Path,
) -> None:
    module = _load_module()
    config = _config(tmp_path)
    config.dependency_lock.write_text("{}\n", encoding="utf-8")
    gateway = FakeReadbackMailGateway(
        [
            _request_message(),
            _reply_message(
                message_id="<decision-default-scan@example.com>",
                sender="manager@example.com",
                return_path="manager@example.com",
                body="通过",
            ),
        ]
    )
    controller = module.VerifierController(
        config=config,
        config_path=tmp_path / "config.json",
        now_fn=lambda: datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc),
        audit_key=b"a" * 32,
        role_snapshot_fetcher=lambda: _snapshot(),
        mail_gateway=gateway,
        audit_adapter=FakeAuditAdapter(),
        scheduler=FakeScheduler(),
        lock_factory=lambda *_args, **_kwargs: FakeLock(_AcquireResult("acquired")),
        product_gate_adapter=MissingGateAdapter(),
    )

    result = controller.run_once()

    assert result["processed"] == {"requests": 1, "validated": 1, "quarantined": 0}
    assert len(gateway.search_payloads) == 1
    assert gateway.search_payloads[0]["account"] == "mail-primary"
    assert gateway.search_payloads[0]["query"]["subject"] == "发布申请"
    assert len(gateway.read_payloads) == 2
    assert [item["role_id"] for item in result["reminders"]] == ["security-reviewer"]
    reminder = gateway.sent[0]
    assert reminder["account"] == "mail-primary"
    assert reminder["text"]
    assert reminder["in_reply_to"] == "<request-evt-runtime@example.com>"
    assert reminder["message_id"].startswith("<release-approval-reminder-")
    assert result["reminders"][0]["accepted"] is True
