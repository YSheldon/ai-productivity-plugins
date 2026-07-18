from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_config import MailAccountConfig, ProductGateConfig, ReleaseGateConfig
from release_gate_controller import PLAIN_BADGE, VERIFIED_BADGE, ReleaseGateController, _AUTHORITATIVE_PROVENANCE_ERROR
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
    def __init__(
        self,
        *,
        status: str = "RELEASE_GATE_PASSED",
        authoritative_state: dict[str, object] | None = None,
    ) -> None:
        self.status = status
        self.authoritative_state = authoritative_state
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append((operation, dict(payload)))
        if operation == "get_event":
            return dict(self.authoritative_state or {})
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


def _unsigned_message(config: ReleaseGateConfig, **overrides: object) -> dict[str, object]:
    message = _message(config)
    payload = decode_machine_event(str(message["body_text"]))
    payload.pop("hmac_sha256", None)
    payload.update(overrides)
    return {**message, "body_text": encode_machine_event(payload)}


def _authoritative_state(
    *,
    event_id: str = "evt-1",
    round_id: int = 2,
    status: str = "RELEASE_READY",
    origin_badge: str = VERIFIED_BADGE,
    retrieval_method: str = "build",
    manifest_s_digest: str = "sha256:" + "1" * 64,
    manifest_r_digest: str = "sha256:" + "2" * 64,
    gitlab_evidence_ref: str = "gitlab://pipeline/authoritative",
    gitlab_evidence_digest: str = "sha256:" + "3" * 64,
    lark_evidence_ref: str = "lark://doc/authoritative",
) -> dict[str, object]:
    event: dict[str, object] = {
        "event_id": event_id,
        "round_id": round_id,
        "status": status,
        "manifest_s_digest": manifest_s_digest,
        "manifest_r_digest": manifest_r_digest,
        "origin_badge": origin_badge,
        "lark_evidence_ref": lark_evidence_ref,
        "retrieval_method": retrieval_method,
    }
    if retrieval_method == "svn":
        event["retrieval_provenance"] = {"repository_path": "svn://repo/path", "revision": "12345"}
    else:
        event["gitlab_evidence_ref"] = gitlab_evidence_ref
        event["gitlab_evidence_digest"] = gitlab_evidence_digest
    return {
        "event": event,
        "manifest_s": {"digest": manifest_s_digest},
        "manifest_r": {"digest": manifest_r_digest, "source_manifest_s_digest": manifest_s_digest},
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


def test_unverified_machine_event_rebinds_authoritative_provenance_before_send(tmp_path: Path) -> None:
    config = _config(tmp_path)
    authoritative = _authoritative_state(origin_badge=VERIFIED_BADGE)
    core_event = authoritative["event"]
    assert isinstance(core_event, dict)
    for field in ("origin_badge", "lark_evidence_ref", "retrieval_method", "gitlab_evidence_ref", "gitlab_evidence_digest"):
        core_event.pop(field, None)
    core_event["round_number"] = core_event.pop("round_id")
    mail = FakeMailGateway(
        [
            _unsigned_message(
                config,
                manifest_s_digest="sha256:" + "a" * 64,
                manifest_r_digest="sha256:" + "b" * 64,
                gitlab_evidence_digest="sha256:" + "c" * 64,
                gitlab_evidence_ref="gitlab://pipeline/spoofed",
                lark_evidence_ref="lark://doc/spoofed",
                source_origin_badge=VERIFIED_BADGE,
                submission_policy_digest="sha256:" + "d" * 64,
                pre_release_policy_digest="sha256:" + "e" * 64,
                checked_items=["spoofed_check:PASS"],
            )
        ]
    )
    gate = FakeProductGate(authoritative_state=authoritative)
    controller = ReleaseGateController(config, mail_gateway=mail, product_gate=gate, now_fn=lambda: FIXED_NOW)
    result = controller.run_once()

    assert result["processed"] == 1
    assert gate.calls == [("run_release_gate", {"event_id": "evt-1"}), ("get_event", {"event_id": "evt-1"})]
    record = json.loads((tmp_path / "state" / "events" / "evt-1--2.json").read_text(encoding="utf-8"))
    assert record["status"] == "RELEASE_READY_NOTIFIED"
    assert record["authoritative_provenance_rebound"] is True
    assert record["manifest_s_digest"] == authoritative["event"]["manifest_s_digest"]
    assert record["manifest_r_digest"] == authoritative["event"]["manifest_r_digest"]
    assert record["gitlab_evidence_ref"] == ""
    assert record["lark_evidence_ref"] == ""
    assert record["origin_badge"] == PLAIN_BADGE
    assert record["transport_badge"] == PLAIN_BADGE
    assert record["submission_policy_digest"] == "unverified"
    assert record["pre_release_policy_digest"] == "unverified"
    assert record["checked_items"] == []
    outbound = decode_machine_event(str(mail.sent[0]["body_text"]))
    assert outbound["transport_badge"] == PLAIN_BADGE
    assert outbound["source_origin_badge"] == PLAIN_BADGE
    assert outbound["manifest_s_digest"] == authoritative["event"]["manifest_s_digest"]
    assert outbound["manifest_r_digest"] == authoritative["event"]["manifest_r_digest"]
    assert outbound["gitlab_evidence_ref"] == ""
    assert outbound["lark_evidence_ref"] == ""
    assert outbound["submission_policy_digest"] == "unverified"
    assert outbound["pre_release_policy_digest"] == "unverified"
    assert outbound["checked_items"] == []
    assert {item["check"]: item["result"] for item in outbound["check_results"]}["upstream_body_evidence"] == "NOT_PROPAGATED"
    assert "gitlab://pipeline/spoofed" not in mail.sent[0]["body_text"]
    assert "lark://doc/spoofed" not in mail.sent[0]["body_text"]
    assert "spoofed_check" not in mail.sent[0]["body_text"]
    assert "sha256:" + "d" * 64 not in mail.sent[0]["body_text"]
    assert "请在审批页独立核验" in mail.sent[0]["body_text"]
    assert "hmac_sha256" in outbound


def test_missing_authoritative_state_blocks_unverified_without_send(tmp_path: Path) -> None:
    config = _config(tmp_path)
    authoritative = _authoritative_state()
    authoritative.pop("manifest_r")
    mail = FakeMailGateway([_unsigned_message(config)])
    controller = ReleaseGateController(config, mail_gateway=mail, product_gate=FakeProductGate(authoritative_state=authoritative), now_fn=lambda: FIXED_NOW)
    result = controller.run_once()

    assert result["blocked"] == 1
    assert mail.sent == []
    record = json.loads((tmp_path / "state" / "events" / "evt-1--2.json").read_text(encoding="utf-8"))
    assert record["status"] == "RELEASE_GATE_BLOCKED"
    assert record["blocked_reason"] == _AUTHORITATIVE_PROVENANCE_ERROR
    assert "pending_notice" not in record


def test_mismatched_authoritative_round_blocks_unverified_without_send(tmp_path: Path) -> None:
    config = _config(tmp_path)
    mail = FakeMailGateway([_unsigned_message(config)])
    controller = ReleaseGateController(
        config,
        mail_gateway=mail,
        product_gate=FakeProductGate(authoritative_state=_authoritative_state(round_id=3)),
        now_fn=lambda: FIXED_NOW,
    )
    result = controller.run_once()

    assert result["blocked"] == 1
    assert mail.sent == []
    record = json.loads((tmp_path / "state" / "events" / "evt-1--2.json").read_text(encoding="utf-8"))
    assert record["status"] == "RELEASE_GATE_BLOCKED"
    assert record["blocked_reason"] == _AUTHORITATIVE_PROVENANCE_ERROR


def test_unverified_blocked_release_gate_does_not_send_notice(tmp_path: Path) -> None:
    config = _config(tmp_path)
    mail = FakeMailGateway([_unsigned_message(config)])
    gate = FakeProductGate(status="RELEASE_GATE_BLOCKED", authoritative_state=_authoritative_state())
    controller = ReleaseGateController(config, mail_gateway=mail, product_gate=gate, now_fn=lambda: FIXED_NOW)
    result = controller.run_once()

    assert result["blocked"] == 1
    assert gate.calls == [("run_release_gate", {"event_id": "evt-1"})]
    assert mail.sent == []
    record = json.loads((tmp_path / "state" / "events" / "evt-1--2.json").read_text(encoding="utf-8"))
    assert record["status"] == "RELEASE_GATE_BLOCKED"
    assert record["blocked_reason"] == "RELEASE_GATE_BLOCKED"
    assert "pending_notice" not in record


def test_invalid_hmac_blocks_without_send(tmp_path: Path) -> None:
    config = _config(tmp_path)
    invalid_hmac = decode_machine_event(str(_message(config)["body_text"]))
    invalid_hmac["hmac_sha256"] = "0" * 64
    blocked_mail = FakeMailGateway(
        [
            {
                "uid": "6",
                "message_id": "<pre-release@example.com>",
                "body_text": encode_machine_event(invalid_hmac),
                "evidence": {
                    "message_id": "<pre-release@example.com>",
                    "references": ["<submission@example.com>"],
                    "raw_headers_sha256": "a" * 64,
                },
            }
        ]
    )
    blocked = ReleaseGateController(config, mail_gateway=blocked_mail, product_gate=FakeProductGate(), now_fn=lambda: FIXED_NOW)
    blocked_result = blocked.run_once()
    assert blocked_result["blocked"] == 1
    assert blocked_mail.sent == []
