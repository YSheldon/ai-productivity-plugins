from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_config import MailAccountConfig, ProductGateConfig, ReleaseGateConfig
from release_gate_controller import ReleaseGateController
from release_gate_mail import decode_machine_event, encode_machine_event, sign_machine_event


FIXED_NOW = datetime(2026, 7, 17, 2, 3, 4, tzinfo=timezone.utc)


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
        return {"message_id": "<release@example.com>"}


class FakeProductGate:
    def __init__(self, *, status: str = "RELEASE_GATE_PASSED") -> None:
        self.status = status
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append((operation, dict(payload)))
        return {"status": self.status}


def _config(tmp_path: Path) -> ReleaseGateConfig:
    secret = tmp_path / "state" / "keys" / "shared-handoff.key"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_bytes(b"2" * 32)
    return ReleaseGateConfig(
        mail_account=MailAccountConfig(profile="release-gate", email="release-gate@example.com"),
        release_gate_group="release-gate@example.com",
        release_group="release@example.com",
        mailbox="INBOX",
        timezone="UTC",
        poll_minutes=60,
        state_dir=tmp_path / "state",
        dependency_lock=tmp_path / "dependency-lock.json",
        dependency_lock_sha256="0" * 64,
        shared_hmac_secret_path=secret,
        mail_command=("py", "-3", "mail.py"),
        product_gate=ProductGateConfig(config_path=tmp_path / "product-config.json", command=("py", "-3", "gate.py")),
        policy_profile="release-gate/v1",
        required_checks=("hmac", "manifest", "test_result", "shared_kernel_release_gate"),
        enabled_optional_checks=(),
    )


def _message(config: ReleaseGateConfig) -> dict[str, object]:
    payload = sign_machine_event(
        {
            "contract": "ProductMaterialWorkflowEvent/v1",
            "event_type": "PRERELEASE_REQUEST",
            "event_id": "evt-1",
            "round_id": 2,
            "task": "Task A",
            "module": "client",
            "submitter_email": "submitter@example.com",
            "source_message_id": "<submission@example.com>",
            "thread_references": ["<submission@example.com>"],
            "manifest_s_digest": "sha256:" + "a" * 64,
            "manifest_r_digest": "sha256:" + "b" * 64,
            "submission_policy_digest": "sha256:" + "c" * 64,
            "pre_release_policy_digest": "sha256:" + "d" * 64,
            "gitlab_evidence_digest": "sha256:" + "e" * 64,
            "gitlab_evidence_ref": "gitlab://pipeline/1",
            "lark_evidence_ref": "lark://doc/1",
            "checked_items": ["sha256", "signature", "cloud_scan", "tester_pass", "manifest_r_built"],
            "test_result": "PASS",
        },
        config.shared_hmac_secret_path.read_bytes(),
    )
    return {
        "uid": "5",
        "message_id": "<pre-release@example.com>",
        "body_text": encode_machine_event(payload),
        "evidence": {
            "message_id": "<pre-release@example.com>",
            "references": ["<submission@example.com>"],
            "raw_headers_sha256": "a" * 64,
        },
    }


def test_run_once_sends_release_ready_once(tmp_path: Path) -> None:
    config = _config(tmp_path)
    mail = FakeMailGateway([_message(config)])
    controller = ReleaseGateController(config, mail_gateway=mail, product_gate=FakeProductGate(), now_fn=lambda: FIXED_NOW)
    first = controller.run_once()
    second = controller.run_once()
    assert first["processed"] == 1
    assert second["processed"] == 0
    record = json.loads((tmp_path / "state" / "events" / "evt-1--2.json").read_text(encoding="utf-8"))
    assert record["status"] == "RELEASE_READY_NOTIFIED"
    assert record["submitter_email"] == "submitter@example.com"
    assert any(item["subject"].startswith("【发布申请】") for item in mail.sent)
    assert mail.sent[0]["headers"]["X-RD-Submitter-Email"] == "submitter@example.com"
    assert "提测人邮箱：submitter@example.com" in mail.sent[0]["body_text"]


def test_missing_hmac_downgrades_to_unverified_but_invalid_hmac_blocks(tmp_path: Path) -> None:
    config = _config(tmp_path)
    missing_hmac = _message(config)
    payload = decode_machine_event(str(missing_hmac["body_text"]))
    del payload["hmac_sha256"]
    downgraded_mail = FakeMailGateway([{"uid": "5", "message_id": "<pre-release@example.com>", "body_text": encode_machine_event(payload), "evidence": missing_hmac["evidence"]}])
    downgraded = ReleaseGateController(config, mail_gateway=downgraded_mail, product_gate=FakeProductGate(), now_fn=lambda: FIXED_NOW)
    downgraded_result = downgraded.run_once()
    assert downgraded_result["processed"] == 1
    assert any(item["subject"].startswith("【发布申请】") for item in downgraded_mail.sent)

    invalid_hmac = decode_machine_event(str(_message(config)["body_text"]))
    invalid_hmac["hmac_sha256"] = "0" * 64
    blocked_mail = FakeMailGateway([{"uid": "6", "message_id": "<pre-release@example.com>", "body_text": encode_machine_event(invalid_hmac), "evidence": {"message_id": "<pre-release@example.com>", "references": ["<submission@example.com>"], "raw_headers_sha256": "a" * 64}}])
    blocked = ReleaseGateController(config, mail_gateway=blocked_mail, product_gate=FakeProductGate(), now_fn=lambda: FIXED_NOW)
    blocked_result = blocked.run_once()
    assert blocked_result["blocked"] == 1
    assert blocked_mail.sent == []
