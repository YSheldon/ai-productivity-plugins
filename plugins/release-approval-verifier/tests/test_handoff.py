from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
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


def _request_payload() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "contract": "ReleaseAuthorizationRequest/v1",
        "schema": "ReleaseAuthorizationRequest/v1",
        "event_id": "evt-handoff",
        "round_id": 1,
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
        "original_message_id": "<request-evt-handoff@example.com>",
        "references": [],
        "expires_at": "2026-07-17T04:00:00Z",
        "idempotency_key": "release-approval:evt-handoff:1",
        "requested_at": "2026-07-16T01:00:00Z",
    }
    payload["request_digest"] = "sha256:" + hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return payload


def _request_message(*, task: str = "Task 9") -> EmailMessage:
    payload = _request_payload()
    if task != payload["task"]:
        payload["task"] = task
        payload["task_id"] = task
        digest_payload = {
            key: value for key, value in payload.items() if key != "request_digest"
        }
        payload["request_digest"] = "sha256:" + hashlib.sha256(
            canonical_json(digest_payload).encode("utf-8")
        ).hexdigest()
    encoded = base64.urlsafe_b64encode(
        canonical_json(payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    message = EmailMessage()
    message["From"] = "Release Bot <bot@example.com>"
    message["To"] = "release@example.com"
    message["Subject"] = "【发布申请】Task 9-release-approval-verifier-20260716"
    message["Date"] = "Thu, 16 Jul 2026 01:00:00 +0000"
    message["Message-ID"] = str(payload["original_message_id"])
    message["X-RD-Contract"] = str(payload["contract"])
    message["X-RD-Event-Id"] = str(payload["event_id"])
    message["X-RD-Round-Id"] = str(payload["round_id"])
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

def _reply(role_email: str, message_id: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["Return-Path"] = f"<{role_email}>"
    message["From"] = f"Reviewer <{role_email}>"
    message["To"] = "release@example.com"
    message["Subject"] = "Re: 【发布申请】Task 9-release-approval-verifier-20260716"
    message["Date"] = "Thu, 16 Jul 2026 03:00:00 +0000"
    message["Message-ID"] = message_id
    message["In-Reply-To"] = "<request-evt-handoff@example.com>"
    message["References"] = "<thread-root@example.com> <request-evt-handoff@example.com>"
    message["Authentication-Results"] = (
        "mx.example.com; dkim=pass header.d=example.com; dmarc=pass action=none header.from=example.com"
    )
    message["Received-SPF"] = "pass"
    message["X-RD-Event-Id"] = "evt-handoff"
    message["X-RD-Round-Id"] = "1"
    message["X-RD-Manifest-Digest"] = _manifest_digest()
    message["X-RD-Role-Snapshot-Digest"] = "sha256:" + "5" * 64
    message.set_content(body)
    return message


class FakeMailGateway:
    def require_thread_reply_capability(self, payload: dict[str, Any]) -> None:
        return None

    def require_authenticated_readback_capability(self, payload: dict[str, Any]) -> None:
        return None

    def send_email(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"sent": True, "message_id": "<reminder@example.com>", "refused": {}}


class FakeAuditAdapter:
    def __init__(self) -> None:
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


class GateReadyAdapter:
    def __init__(self, *, post_status: str = "PRE_RELEASE_REQUESTED") -> None:
        self.calls: list[tuple[dict[str, Any], dict[str, Any], str]] = []
        self.post_status = post_status

    def preflight(self) -> dict[str, Any]:
        return {"status": "ready"}

    def request_pre_release(self, *, request_binding: dict[str, Any], receipt: dict[str, Any], receipt_path: str) -> dict[str, Any]:
        self.calls.append((dict(request_binding), dict(receipt), receipt_path))
        return {
            "status": self.post_status,
            "event_id": request_binding["event_id"],
            "handoff_id": f"pre-release:{request_binding['event_id']}:{request_binding['round_id']}",
            "pre_release_request_path": str(Path(receipt_path).with_name("pre-release-request.json")),
        }


class GateMissingAdapter:
    def preflight(self) -> dict[str, Any]:
        return {"status": "CAPABILITY_BLOCKED", "reason": "product gate adapter missing"}


def _controller(
    tmp_path: Path,
    gate_adapter: Any,
    *,
    request_messages: tuple[EmailMessage, ...] | None = None,
    audit_adapter: FakeAuditAdapter | None = None,
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
        request_scanner=lambda *_args, **_kwargs: request_messages
        or (_request_message(),),
        reply_scanner=lambda *_args, **_kwargs: (
            _reply("manager@example.com", "<decision-manager@example.com>", "通过"),
            _reply("security@example.com", "<decision-security@example.com>", "同意"),
        ),
        mail_gateway=FakeMailGateway(),
        audit_adapter=audit_adapter or FakeAuditAdapter(),
        scheduler=FakeScheduler(),
        product_gate_adapter=gate_adapter,
    )


def test_verified_receipt_hands_off_once_and_marks_consumed_after_pre_release_readback(tmp_path: Path) -> None:
    gate = GateReadyAdapter()
    controller = _controller(tmp_path, gate)

    first = controller.run_once()
    second = controller.run_once()
    event = controller.get_event(event_id="evt-handoff", round_id=1)

    assert first["status"] == "ready"
    assert first["receipt"]["status"] == "APPROVAL_VERIFIED"
    assert first["handoff"]["status"] == "PRE_RELEASE_REQUESTED"
    assert first["handoff"]["consumed"] is True
    assert len(gate.calls) == 1
    assert second["handoff"]["idempotent"] is True
    assert event["receipt"]["handoff_consumed_at"]
    assert event["receipt"]["handoff_id"] == "pre-release:evt-handoff:1"
    assert "ReleaseAuthorizationCredential" not in json.dumps(first)
    assert "RELEASE_AUTHORIZED" not in json.dumps(first)


def test_verified_receipt_without_gate_capability_keeps_receipt_and_emits_replayable_capability_event(tmp_path: Path) -> None:
    controller = _controller(tmp_path, GateMissingAdapter())

    result = controller.run_once()
    event = controller.get_event(event_id="evt-handoff", round_id=1)

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert result["receipt"]["status"] == "APPROVAL_VERIFIED"
    assert result["handoff"]["status"] == "CAPABILITY_BLOCKED"
    assert result["capability_event"]["event_type"] == "CAPABILITY_BLOCKED"
    assert result["capability_event"]["replayable"] is True
    assert event["receipt"]["handoff_consumed_at"] is None
    assert event["capability_events"][-1]["reason"] == "product gate adapter missing"


def test_wrong_product_gate_post_state_blocks_without_consuming_verified_receipt(tmp_path: Path) -> None:
    controller = _controller(tmp_path, GateReadyAdapter(post_status="APPROVAL_COLLECTING"))

    result = controller.run_once()
    event = controller.get_event(event_id="evt-handoff", round_id=1)

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert result["handoff"]["status"] == "CAPABILITY_BLOCKED"
    assert result["handoff"]["reason"] == "unexpected post-handoff state"
    assert event["receipt"]["status"] == "APPROVAL_VERIFIED"
    assert event["receipt"]["handoff_consumed_at"] is None


def test_request_binding_drift_is_non_replayable_and_blocks_handoff(
    tmp_path: Path,
) -> None:
    gate = GateReadyAdapter()
    audit = FakeAuditAdapter()
    controller = _controller(
        tmp_path,
        gate,
        request_messages=(
            _request_message(),
            _request_message(task="Drifted task"),
        ),
        audit_adapter=audit,
    )

    result = controller.run_once()
    event = controller.get_event(event_id="evt-handoff", round_id=1)

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert result["handoff"]["status"] == "CAPABILITY_BLOCKED"
    assert result["capability_event"]["replayable"] is False
    assert "request binding drifted" in result["capability_event"]["reason"]
    assert event["receipt"]["handoff_consumed_at"] is None
    aggregate_records = [
        record for record in audit.records if record.event_type == "AGGREGATE_VERIFICATION"
    ]
    assert aggregate_records
    assert aggregate_records[-1].state == "CAPABILITY_BLOCKED"
    assert all(record.state != "APPROVAL_VERIFIED" for record in aggregate_records)
    assert gate.calls == []
