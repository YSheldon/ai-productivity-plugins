from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_config import MailAccountConfig, ProductGateConfig, ReleaseGateConfig
from release_gate_controller import ReleaseGateController


FIXED_NOW = datetime(2026, 7, 17, 6, 7, 8, tzinfo=timezone.utc)


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

    def call(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
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


def test_plain_fallback_request_can_progress_as_unverified(tmp_path: Path) -> None:
    config = _config(tmp_path)
    body = "\n".join(
        [
            "事件：evt-plain#5",
            "任务：Task Plain",
            "模块：client",
            "状态：PRERELEASE_SENT",
            "测试结论：PASS",
            "Manifest-S：sha256:" + "1" * 64,
            "Manifest-R：sha256:" + "2" * 64,
            "- 提测门禁策略摘要：sha256:" + "3" * 64,
            "- 预发布策略摘要：sha256:" + "4" * 64,
            "- GitLab：gitlab://pipeline/plain",
            "- 飞书：lark://doc/plain",
            "发起标识：普通邮件发起（未验证）",
        ]
    )
    controller = ReleaseGateController(
        config,
        mail_gateway=FakeMailGateway(
            [
                {
                    "uid": "11",
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
    assert result["processed"] == 1
    record = json.loads((tmp_path / "state" / "events" / "evt-plain--5.json").read_text(encoding="utf-8"))
    assert record["origin_badge"] == "普通邮件发起（未验证）"


def test_svn_request_does_not_require_gitlab_evidence(tmp_path: Path) -> None:
    config = _config(tmp_path)
    body = "\n".join(
        [
            "事件：evt-svn#6",
            "任务：Task SVN",
            "模块：server",
            "状态：PRERELEASE_SENT",
            "测试结论：PASS",
            "Manifest-S：sha256:" + "5" * 64,
            "Manifest-R：sha256:" + "6" * 64,
            "- 提测门禁策略摘要：sha256:" + "7" * 64,
            "- 预发布策略摘要：sha256:" + "8" * 64,
            "- SVN：svn://repo/path@12345",
            "- 飞书：lark://doc/svn",
            "发起标识：普通邮件发起（未验证）",
        ]
    )
    controller = ReleaseGateController(
        config,
        mail_gateway=FakeMailGateway(
            [
                {
                    "uid": "12",
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
    assert result["processed"] == 1
    record = json.loads((tmp_path / "state" / "events" / "evt-svn--6.json").read_text(encoding="utf-8"))
    assert record["retrieval_method"] == "svn"
    assert record["gitlab_evidence_ref"] == ""
