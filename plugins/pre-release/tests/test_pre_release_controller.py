from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from pre_release_config import MailAccountConfig, PreReleaseConfig, ProductGateConfig
from pre_release_controller import PLAIN_BADGE, VERIFIED_BADGE, PreReleaseController, PreReleaseError
from pre_release_mail import decode_machine_event, encode_machine_event, sign_machine_event


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
        return {"message_id": str(arguments.get("message_id") or "")}


class FakeProductGate:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append((operation, dict(payload)))
        if operation == "import_submission_gate_handoff":
            return {"status": "TESTING"}
        if operation == "record_test_result":
            return {"status": "RELEASE_PREPARING"}
        if operation == "build_final_release":
            return {
                "status": "RELEASE_GATING",
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
    artifact_bytes = b"demo"
    manifest_s: dict[str, object] = {
        "schema": "ProductMaterialManifestS/v1",
        "event_id": "evt-1",
        "round_id": 2,
        "task": "Task A",
        "module": "client",
        "policy_profile": "submission-client/v1",
        "policy_digest": "sha256:" + "c" * 64,
        "effective_checks": ["sha256", "signature", "cloud_scan"],
        "artifacts": [
            {
                "logical_name": "demo.exe",
                "file_name": "demo.exe",
                "size": len(artifact_bytes),
                "sha1": hashlib.sha1(artifact_bytes).hexdigest(),
                "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "source_ref": "gitlab://pipeline/1/artifact/demo.exe",
            }
        ],
        "evidence_refs": ["gitlab://pipeline/1"],
    }
    frozen = json.dumps(
        manifest_s,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    manifest_s["manifest_s_digest"] = "sha256:" + hashlib.sha256(
        frozen.encode("utf-8")
    ).hexdigest()
    payload = sign_machine_event(
        {
            "contract": "ProductMaterialWorkflowEvent/v1",
            "event_type": "SUBMISSION_GATE_PASS",
            "event_id": "evt-1",
            "round_id": 2,
            "task": "Task A",
            "module": "client",
            "submitter_email": "submitter@example.com",
            "manifest_s_digest": manifest_s["manifest_s_digest"],
            "manifest_s": manifest_s,
            "policy_digest": "sha256:" + "c" * 64,
            "gitlab_evidence_digest": "sha256:" + "d" * 64,
            "gitlab_evidence_ref": "gitlab://pipeline/1",
            "lark_evidence_ref": "lark://doc/1",
            "source_message_id": "<submission@example.com>",
            "thread_references": ["<submission@example.com>"],
            "checked_items": ["sha256", "signature", "cloud_scan"],
            "artifacts": manifest_s["artifacts"],
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
    tested_material_dir = tmp_path / "tested-materials"
    tested_material_dir.mkdir()
    (tested_material_dir / "demo.exe").write_bytes(b"demo")
    result = controller.create_request(
        event_id="evt-1",
        round_id=2,
        test_result="PASS",
        summary="回归通过",
        output_dir=str(tmp_path / "out"),
        tested_material_dir=str(tested_material_dir),
    )
    assert result["status"] == "PRERELEASE_SENT"
    task = json.loads((tmp_path / "state" / "tasks" / "evt-1--2.json").read_text(encoding="utf-8"))
    assert task["status"] == "PRERELEASE_SENT"
    assert task["submitter_email"] == "submitter@example.com"
    assert task["manifest_r_digest"] == "sha256:" + "b" * 64
    assert controller.mail_gateway.sent[0]["headers"]["X-RD-Submitter-Email"] == "submitter@example.com"
    assert "提测人邮箱：submitter@example.com" in controller.mail_gateway.sent[0]["body_text"]
    operations = [operation for operation, _payload in controller.product_gate.calls]
    assert operations == [
        "import_submission_gate_handoff",
        "record_test_result",
        "build_final_release",
    ]
    imported = controller.product_gate.calls[0][1]
    assert imported["manifest_s"] == task["manifest_s"]
    assert imported["tested_material_dir"] == str(tested_material_dir)
    assert controller.mail_gateway.sent[0]["message_id"].startswith(
        "<pmg-prerelease-"
    )


def test_run_once_blocks_signed_manifest_with_multiline_reference(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    message = _submission_message(config)
    payload = decode_machine_event(str(message["body_text"]))
    payload.pop("hmac_sha256")
    manifest_s = payload["manifest_s"]
    manifest_s["artifacts"][0]["source_ref"] = (
        "gitlab://artifact/1\r\nBcc: attacker@example.test"
    )
    frozen = {
        key: value
        for key, value in manifest_s.items()
        if key != "manifest_s_digest"
    }
    manifest_s["manifest_s_digest"] = "sha256:" + hashlib.sha256(
        json.dumps(
            frozen,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    payload["manifest_s_digest"] = manifest_s["manifest_s_digest"]
    message["body_text"] = encode_machine_event(
        sign_machine_event(
            payload,
            config.shared_hmac_secret_path.read_bytes(),
        )
    )
    controller = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway([message]),
        product_gate=FakeProductGate(),
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    assert result["blocked"] == 1
    assert result["matched_events"] == 0
    assert controller.list_tasks()["tasks"] == []


def test_task_state_tamper_blocks_headless_processing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    controller = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway([_submission_message(config)]),
        product_gate=FakeProductGate(),
        now_fn=lambda: FIXED_NOW,
    )
    assert controller.run_once()["matched_events"] == 1
    task_path = tmp_path / "state" / "tasks" / "evt-1--2.json"
    task = json.loads(task_path.read_text(encoding="utf-8"))
    task["risk_level"] = "emergency"
    task_path.write_text(
        json.dumps(task, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert result["reason"] == "task_state_integrity_invalid"


def test_outbound_failure_retries_same_message_without_repeating_product_steps(
    tmp_path: Path,
) -> None:
    class FailingOnceMailGateway(FakeMailGateway):
        def __init__(self, messages: list[dict[str, object]]) -> None:
            super().__init__(messages)
            self.attempts: list[dict[str, object]] = []

        def send_email(self, arguments: dict[str, object]) -> dict[str, object]:
            self.attempts.append(dict(arguments))
            if len(self.attempts) == 1:
                raise RuntimeError("injected SMTP outage")
            return super().send_email(arguments)

    config = _config(tmp_path)
    mail = FailingOnceMailGateway([_submission_message(config)])
    product_gate = FakeProductGate()
    controller = PreReleaseController(
        config,
        mail_gateway=mail,
        product_gate=product_gate,
        now_fn=lambda: FIXED_NOW,
    )
    controller.run_once()
    tested_material_dir = tmp_path / "tested-materials-retry"
    tested_material_dir.mkdir()
    (tested_material_dir / "demo.exe").write_bytes(b"demo")
    arguments = {
        "event_id": "evt-1",
        "round_id": 2,
        "test_result": "PASS",
        "summary": "回归通过",
        "output_dir": str(tmp_path / "out-retry"),
        "tested_material_dir": str(tested_material_dir),
    }

    try:
        controller.create_request(**arguments)
    except PreReleaseError as exc:
        assert exc.code == "OUTBOUND_RETRY_PENDING"
    else:
        raise AssertionError("first outbound attempt must fail")
    product_call_count = len(product_gate.calls)

    retried = controller.run_once()

    assert retried["retry_attempted"] == 1
    assert retried["retry_sent"] == 1
    assert retried["retry_pending"] == 0
    assert controller._load_task("evt-1", 2)["status"] == "PRERELEASE_SENT"  # noqa: SLF001
    assert len(product_gate.calls) == product_call_count
    assert len(mail.attempts) == 2
    assert mail.attempts[0]["message_id"] == mail.attempts[1]["message_id"]


def test_pass_pauses_for_test_approval_and_resumes_from_authoritative_state(
    tmp_path: Path,
) -> None:
    class ApprovalProductGate(FakeProductGate):
        def __init__(self) -> None:
            super().__init__()
            self.import_status = "TESTING"

        def call(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
            self.calls.append((operation, dict(payload)))
            if operation == "import_submission_gate_handoff":
                return {"event": {"status": self.import_status}}
            if operation == "record_test_result":
                self.import_status = "TEST_APPROVAL_REQUIRED"
                return {"status": "TEST_APPROVAL_REQUIRED"}
            if operation == "build_final_release":
                return {
                    "status": "RELEASE_GATING",
                    "manifest_r_digest": "sha256:" + "b" * 64,
                    "manifest_r_ref": "artifact://manifest-r.json",
                }
            raise AssertionError(f"unexpected operation: {operation}")

    config = _config(tmp_path)
    mail = FakeMailGateway([_submission_message(config)])
    product_gate = ApprovalProductGate()
    controller = PreReleaseController(
        config,
        mail_gateway=mail,
        product_gate=product_gate,
        now_fn=lambda: FIXED_NOW,
    )
    controller.run_once()
    tested_material_dir = tmp_path / "tested-materials-approval"
    tested_material_dir.mkdir()
    (tested_material_dir / "demo.exe").write_bytes(b"demo")
    arguments = {
        "event_id": "evt-1",
        "round_id": 2,
        "test_result": "PASS",
        "summary": "回归通过",
        "output_dir": str(tmp_path / "out-approval"),
        "tested_material_dir": str(tested_material_dir),
    }

    pending = controller.create_request(**arguments)
    assert pending["status"] == "TEST_APPROVAL_REQUIRED"
    assert mail.sent == []
    assert [name for name, _payload in product_gate.calls] == [
        "import_submission_gate_handoff",
        "record_test_result",
    ]

    product_gate.import_status = "RELEASE_PREPARING"
    resumed = controller.create_request(**arguments)
    assert resumed["status"] == "PRERELEASE_SENT"
    assert [name for name, _payload in product_gate.calls][-2:] == [
        "import_submission_gate_handoff",
        "build_final_release",
    ]


def test_pass_without_tested_material_dir_does_not_mutate_task(tmp_path: Path) -> None:
    config = _config(tmp_path)
    product_gate = FakeProductGate()
    controller = PreReleaseController(
        config,
        mail_gateway=FakeMailGateway([_submission_message(config)]),
        product_gate=product_gate,
        now_fn=lambda: FIXED_NOW,
    )
    controller.run_once()

    try:
        controller.create_request(
            event_id="evt-1",
            round_id=2,
            test_result="PASS",
            summary="回归通过",
            output_dir=str(tmp_path / "out"),
        )
    except PreReleaseError as exc:
        assert exc.code == "INVALID_ARGUMENT"
        assert "tested_material_dir" in str(exc)
    else:
        raise AssertionError("PASS without tested_material_dir must fail closed")

    assert controller._load_task("evt-1", 2)["status"] == "TEST_READY"  # noqa: SLF001
    assert product_gate.calls == []


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
