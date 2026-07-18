from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from pre_release_config import MailAccountConfig, PreReleaseConfig, ProductGateConfig
from pre_release_controller import PLAIN_BADGE, VERIFIED_BADGE, PreReleaseController, PreReleaseError
from pre_release_mail import encode_machine_event, sign_machine_event


FIXED_NOW = datetime(2026, 7, 17, 1, 2, 3, tzinfo=timezone.utc)


class FakeMailGateway:
    def __init__(self, messages: list[dict[str, object]]) -> None:
        self.messages = messages
        self.sent: list[dict[str, object]] = []

    def search_messages(self, _arguments: dict[str, object]) -> dict[str, object]:
        return {"messages": [{"uid": message["uid"]} for message in self.messages]}

    def read_message(self, arguments: dict[str, object]) -> dict[str, object]:
        uid = str(arguments["uid"])
        return next(message for message in self.messages if message["uid"] == uid)

    def send_email(self, arguments: dict[str, object]) -> dict[str, object]:
        self.sent.append(dict(arguments))
        return {"message_id": "<pre-release@example.com>"}


class FakeProductGate:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append((operation, dict(payload)))
        if operation == "build_final_release":
            return {
                "status": "ready",
                "manifest_r_digest": "sha256:" + "b" * 64,
                "manifest_r_ref": "artifact://manifest-r.json",
            }
        return {"status": "ready"}


def _config(tmp_path: Path) -> PreReleaseConfig:
    secret = tmp_path / "state" / "keys" / "shared-handoff.key"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_bytes(b"1" * 32)
    return PreReleaseConfig(
        mail_account=MailAccountConfig(profile="qa-owner", email="qa-owner@example.com"),
        submission_group="submission@example.com",
        release_gate_group="release-gate@example.com",
        mailbox="INBOX",
        timezone="UTC",
        poll_minutes=60,
        state_dir=tmp_path / "state",
        dependency_lock=tmp_path / "dependency-lock.json",
        dependency_lock_sha256="0" * 64,
        shared_hmac_secret_path=secret,
        mail_command=("py", "-3", "mail.py"),
        product_gate=ProductGateConfig(config_path=tmp_path / "product-config.json", command=("py", "-3", "gate.py")),
        policy_profile="pre-release/v1",
        enabled_optional_checks=(),
    )


def _submission_message(config: PreReleaseConfig) -> dict[str, object]:
    payload = sign_machine_event(
        {
            "contract": "ProductMaterialWorkflowEvent/v1",
            "event_type": "SUBMISSION_GATE_PASS",
            "event_id": "evt-1",
            "round_id": 2,
            "task": "Task A",
            "module": "client",
            "submitter_email": "submitter@example.com",
            "manifest_s_digest": "sha256:" + "a" * 64,
            "policy_digest": "sha256:" + "c" * 64,
            "gitlab_evidence_digest": "sha256:" + "d" * 64,
            "gitlab_evidence_ref": "gitlab://pipeline/1",
            "lark_evidence_ref": "lark://doc/1",
            "source_message_id": "<submission@example.com>",
            "thread_references": ["<submission@example.com>"],
            "checked_items": ["sha256", "signature", "cloud_scan"],
            "artifacts": [{"logical_name": "demo.exe"}],
        },
        config.shared_hmac_secret_path.read_bytes(),
    )
    return {
        "uid": "7",
        "message_id": "<submission@example.com>",
        "body_text": encode_machine_event(payload),
        "evidence": {
            "message_id": "<submission@example.com>",
            "references": ["<submission@example.com>"],
            "raw_headers_sha256": "a" * 64,
        },
    }


def test_run_once_creates_one_pending_task_and_pass_builds_request(tmp_path: Path) -> None:
    config = _config(tmp_path)
    controller = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway([_submission_message(config)]),
        product_gate=FakeProductGate(),
        now_fn=lambda: FIXED_NOW,
    )
    first = controller.run_once()
    second = controller.run_once()
    assert first["matched_events"] == 1
    assert second["matched_events"] == 0
    listed = controller.list_tasks()
    assert listed["tasks"][0]["status"] == "TEST_READY"
    result = controller.create_request(
        event_id="evt-1",
        round_id=2,
        test_result="PASS",
        summary="回归通过",
        output_dir=str(tmp_path / "out"),
    )
    assert result["status"] == "PRERELEASE_SENT"
    task = json.loads((tmp_path / "state" / "tasks" / "evt-1--2.json").read_text(encoding="utf-8"))
    assert task["status"] == "PRERELEASE_SENT"
    assert task["submitter_email"] == "submitter@example.com"
    assert task["manifest_r_digest"] == "sha256:" + "b" * 64
    assert controller.mail_gateway.sent[0]["headers"]["X-RD-Submitter-Email"] == "submitter@example.com"
    assert "提测人邮箱：submitter@example.com" in controller.mail_gateway.sent[0]["body_text"]


def test_fail_requires_reason_and_never_sends_request(tmp_path: Path) -> None:
    config = _config(tmp_path)
    mail = FakeMailGateway([_submission_message(config)])
    controller = PreReleaseController(
        config,
        mail_gateway=mail,
        product_gate=FakeProductGate(),
        now_fn=lambda: FIXED_NOW,
    )
    controller.run_once()
    result = controller.create_request(
        event_id="evt-1",
        round_id=2,
        test_result="FAIL",
        summary="失败",
        failure_reason="冒烟失败",
    )
    assert result["status"] == "TEST_FAILED"
    assert mail.sent == []


def test_send_fails_closed_when_persisted_and_outbound_badges_differ(tmp_path: Path) -> None:
    config = _config(tmp_path)
    mail = FakeMailGateway([_submission_message(config)])
    controller = PreReleaseController(
        config,
        mail_gateway=mail,
        product_gate=FakeProductGate(),
        now_fn=lambda: FIXED_NOW,
    )
    controller.run_once()
    task = controller._load_task("evt-1", 2)  # noqa: SLF001
    task["transport_badge"] = VERIFIED_BADGE
    task["origin_badge"] = VERIFIED_BADGE
    task["request_payload"] = {
        "event_id": "evt-1",
        "round_id": 2,
        "source_origin_badge": VERIFIED_BADGE,
        "transport_badge": PLAIN_BADGE,
    }
    task["request_subject"] = "test"

    try:
        controller._send_prerelease_request(task)  # noqa: SLF001
    except PreReleaseError as exc:
        assert exc.code == "TRANSPORT_BADGE_MISMATCH"
    else:
        raise AssertionError("badge mismatch must fail closed")
    assert mail.sent == []
