from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from pre_release_config import MailAccountConfig, PreReleaseConfig, ProductGateConfig
from pre_release_controller import PreReleaseController


FIXED_NOW = datetime(2026, 7, 17, 5, 6, 7, tzinfo=timezone.utc)


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
    def call(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
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


def test_plain_human_mail_fallback_can_progress_as_unverified(tmp_path: Path) -> None:
    config = _config(tmp_path)
    body = "\n".join(
        [
            "事件：evt-plain#3",
            "任务：Task Plain",
            "模块：client",
            "Manifest-S：sha256:" + "1" * 64,
            "- 提测门禁策略摘要：sha256:" + "2" * 64,
            "- GitLab：gitlab://pipeline/plain",
            "- 飞书：lark://doc/plain",
            "发起标识：普通邮件发起（未验证）",
        ]
    )
    controller = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway(
            [
                {
                    "uid": "9",
                    "message_id": "<plain@example.com>",
                    "body_text": body,
                    "evidence": {
                        "message_id": "<plain@example.com>",
                        "references": ["<plain@example.com>"],
                        "raw_headers_sha256": "a" * 64,
                    },
                }
            ]
        ),
        product_gate=FakeProductGate(),
        now_fn=lambda: FIXED_NOW,
    )
    result = controller.run_once()
    assert result["matched_events"] == 1
    listed = controller.list_tasks()["tasks"]
    assert listed[0]["event_id"] == "evt-plain"


def test_svn_submission_does_not_require_gitlab_evidence(tmp_path: Path) -> None:
    config = _config(tmp_path)
    body = "\n".join(
        [
            "事件：evt-svn#4",
            "任务：Task SVN",
            "模块：server",
            "Manifest-S：sha256:" + "3" * 64,
            "- 提测门禁策略摘要：sha256:" + "4" * 64,
            "- SVN：svn://repo/path@12345",
            "- 飞书：lark://doc/svn",
            "发起标识：普通邮件发起（未验证）",
        ]
    )
    controller = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway(
            [
                {
                    "uid": "10",
                    "message_id": "<svn@example.com>",
                    "body_text": body,
                    "evidence": {
                        "message_id": "<svn@example.com>",
                        "references": ["<svn@example.com>"],
                        "raw_headers_sha256": "b" * 64,
                    },
                }
            ]
        ),
        product_gate=FakeProductGate(),
        now_fn=lambda: FIXED_NOW,
    )
    result = controller.run_once()
    assert result["matched_events"] == 1
    task = controller._load_task("evt-svn", 4)  # noqa: SLF001
    assert task["retrieval_method"] == "svn"
    assert task["gitlab_evidence_ref"] == ""
