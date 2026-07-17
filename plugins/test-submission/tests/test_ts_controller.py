from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "test_submission_core.py"
sys.path.insert(0, str(SRC_ROOT))


def _load_module():
    spec = importlib.util.spec_from_file_location("test_submission_core", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeMailGateway:
    def __init__(self) -> None:
        self.sent: list[dict[str, object]] = []

    def list_accounts(self) -> dict[str, object]:
        return {"accounts": [{"name": "mail-primary", "email": "submitter@example.com"}]}

    def send_email(self, payload: dict[str, object]) -> dict[str, object]:
        self.sent.append(payload)
        return {"sent": True, "message_id": "<submission@example.com>", "refused": {}}


class FakePreviewBridge:
    def preflight(self) -> dict[str, object]:
        return {"ready": True}

    def preview_submission(self, **kwargs):
        return {"submission": {"manifest_s": {"manifest_digest": "sha256:" + "1" * 64}}, "kwargs": kwargs}


class FlakyMailGateway(FakeMailGateway):
    def __init__(self) -> None:
        super().__init__()
        self.attempt = 0

    def send_email(self, payload: dict[str, object]) -> dict[str, object]:
        self.sent.append(payload)
        self.attempt += 1
        if self.attempt == 1:
            return {"sent": True, "message_id": "<submission@example.com>", "refused": {"submission-gate@example.com": "421 retry"}}
        return {"sent": True, "message_id": "<submission@example.com>", "refused": {}}


def _base_config(tmp_path: Path) -> dict[str, object]:
    return {
        "mail_account": {"profile": "mail-primary", "email": "submitter@example.com"},
        "submission_gate_address": "submission-gate@example.com",
        "state_dir": str(tmp_path / "state"),
        "event_store_dir": str(tmp_path / "events"),
        "dependency_lock": str(tmp_path / "dependency-lock.json"),
        "dependency_lock_sha256": "0" * 64,
        "product_gate_preview_config": str(tmp_path / "product-release-gate.preview.json"),
    }


def test_submit_builds_signed_request_and_persists_event(tmp_path: Path) -> None:
    module = _load_module()
    artifact = tmp_path / "driver.sys"
    artifact.write_bytes(b"kernel-driver")
    config_path = tmp_path / "config.json"
    base_config = _base_config(tmp_path)
    config_path.write_text(json.dumps(base_config), encoding="utf-8")
    controller = module.TestSubmissionController(
        config_path,
        mail_gateway=FakeMailGateway(),
        product_gate=FakePreviewBridge(),
        now_fn=lambda: datetime(2026, 7, 17, 9, 30, tzinfo=timezone.utc),
        environ={"TEST_SUBMISSION_HMAC_KEY": "test-key"},
    )

    result = controller.submit({
        "event_id": "event-1",
        "round_id": 1,
        "task_name": "TASK-1",
        "module": "kernel",
        "change_summary": "fix one bug",
        "expected_delivery_at": "2026-07-18T18:00:00+08:00",
        "artifacts": [{"logical_name": "driver.sys", "local_path": str(artifact), "retrieval_method": "local"}],
    })

    assert result["status"] == "SUBMITTED"
    event = controller.get_event(event_id="event-1", round_id=1)["event"]
    assert event["request"]["contract"] == "rd.test-submission.v1"
    assert event["request"]["module"] == "kernel"
    assert event["request"]["submitter_email"] == "submitter@example.com"
    assert event["request"]["artifacts"][0]["sha1"] == module.sha1_file(artifact)
    assert controller.mail_gateway.sent[0]["headers"]["X-RD-Submitter-Email"] == "submitter@example.com"
    assert "提测人邮箱：submitter@example.com" in controller.mail_gateway.sent[0]["text"]
    assert "hmac_sha256" in event["request"]


def test_extract_machine_block_requires_one_signed_section() -> None:
    module = _load_module()
    payload = {"hello": "world"}
    body = "intro\n-----BEGIN RD TEST SUBMISSION BLOCK-----\n" + json.dumps(payload) + "\n-----END RD TEST SUBMISSION BLOCK-----\n"
    assert module.extract_machine_block(body) == payload


def test_submit_requires_explicit_module_and_has_no_default(tmp_path: Path) -> None:
    module = _load_module()
    artifact = tmp_path / "driver.sys"
    artifact.write_bytes(b"kernel-driver")
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_base_config(tmp_path)), encoding="utf-8")
    controller = module.TestSubmissionController(
        config_path,
        mail_gateway=FakeMailGateway(),
        product_gate=FakePreviewBridge(),
        now_fn=lambda: datetime(2026, 7, 17, 9, 30, tzinfo=timezone.utc),
        environ={"TEST_SUBMISSION_HMAC_KEY": "test-key"},
    )

    try:
        controller.submit({
            "event_id": "event-1",
            "round_id": 1,
            "task_name": "TASK-1",
            "artifacts": [{"logical_name": "driver.sys", "local_path": str(artifact), "retrieval_method": "local"}],
        })
    except Exception as exc:
        assert getattr(exc, "code", "") == "MODULE_REQUIRED"
    else:
        raise AssertionError("submit should require an explicit module")


def test_mandatory_checks_are_retained_and_zero_effective_checks_block(tmp_path: Path) -> None:
    module = _load_module()
    artifact = tmp_path / "driver.sys"
    artifact.write_bytes(b"kernel-driver")
    config_path = tmp_path / "config.json"
    base_config = _base_config(tmp_path)
    config_path.write_text(json.dumps(base_config), encoding="utf-8")
    controller = module.TestSubmissionController(
        config_path,
        config={**base_config, "mandatory_checks_by_module": {"kernel": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required", "must-keep"], "client": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"], "server": ["artifacts_present", "hashes_match", "source_revision_present", "package_digest_present", "cloud_scan_required"]}},
        mail_gateway=FakeMailGateway(),
        product_gate=FakePreviewBridge(),
        now_fn=lambda: datetime(2026, 7, 17, 9, 30, tzinfo=timezone.utc),
        environ={"TEST_SUBMISSION_HMAC_KEY": "test-key"},
    )
    result = controller.submit({
        "event_id": "event-2",
        "round_id": 1,
        "task_name": "TASK-2",
        "module": "kernel",
        "artifacts": [{"logical_name": "driver.sys", "local_path": str(artifact), "retrieval_method": "local"}],
        "enabled_optional_checks": [],
    })
    assert result["status"] == "SUBMITTED"
    event = controller.get_event(event_id="event-2", round_id=1)["event"]
    assert event["request"]["effective_checks"] == ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required", "must-keep"]

    blocking_controller = module.TestSubmissionController(
        config_path,
        config={**base_config, "mandatory_checks_by_module": {"kernel": ["artifacts_present", "hashes_match", "version_present", "cloud_scan_required"], "client": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"], "server": ["artifacts_present", "hashes_match", "source_revision_present", "package_digest_present", "cloud_scan_required"]}},
        mail_gateway=FakeMailGateway(),
        product_gate=FakePreviewBridge(),
        now_fn=lambda: datetime(2026, 7, 17, 9, 30, tzinfo=timezone.utc),
        environ={"TEST_SUBMISSION_HMAC_KEY": "test-key"},
    )
    try:
        blocking_controller.submit({
            "event_id": "event-3",
            "round_id": 1,
            "task_name": "TASK-3",
            "module": "kernel",
            "artifacts": [{"logical_name": "driver.sys", "local_path": str(artifact), "retrieval_method": "local"}],
            "enabled_optional_checks": [],
        })
    except Exception as exc:
        assert getattr(exc, "code", "") == "GATE_POLICY_INVALID"
    else:
        raise AssertionError("zero effective checks must block")


def test_run_once_is_idempotent_after_restart_for_pending_mail(tmp_path: Path) -> None:
    module = _load_module()
    artifact = tmp_path / "driver.sys"
    artifact.write_bytes(b"kernel-driver")
    config_path = tmp_path / "config.json"
    config = {**_base_config(tmp_path), "mandatory_checks_by_module": {"kernel": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"], "client": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"], "server": ["artifacts_present", "hashes_match", "source_revision_present", "package_digest_present", "cloud_scan_required"]}}
    config_path.write_text(json.dumps(config), encoding="utf-8")
    mail = FlakyMailGateway()
    controller = module.TestSubmissionController(
        config_path,
        config=config,
        mail_gateway=mail,
        product_gate=FakePreviewBridge(),
        now_fn=lambda: datetime(2026, 7, 17, 9, 30, tzinfo=timezone.utc),
        environ={"TEST_SUBMISSION_HMAC_KEY": "test-key"},
    )
    first = controller.submit({
        "event_id": "event-4",
        "round_id": 1,
        "task_name": "TASK-4",
        "module": "kernel",
        "artifacts": [{"logical_name": "driver.sys", "local_path": str(artifact), "retrieval_method": "local"}],
    })
    assert first["status"] == "SEND_BLOCKED"
    restarted = module.TestSubmissionController(
        config_path,
        config=config,
        mail_gateway=mail,
        product_gate=FakePreviewBridge(),
        now_fn=lambda: datetime(2026, 7, 17, 9, 31, tzinfo=timezone.utc),
        environ={"TEST_SUBMISSION_HMAC_KEY": "test-key"},
    )
    retry = restarted.run_once()
    assert retry == {"status": "ready", "retried": 1, "sent": 1}
    second_retry = restarted.run_once()
    assert second_retry == {"status": "ready", "retried": 0, "sent": 0}
