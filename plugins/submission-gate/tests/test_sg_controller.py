from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "submission_gate_core.py"
sys.path.insert(0, str(SRC_ROOT))


def _load_module():
    spec = importlib.util.spec_from_file_location("submission_gate_core", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeMailGateway:
    def __init__(self, body_text: str, request_digest: str) -> None:
        self.body_text = body_text
        self.request_digest = request_digest
        self.sent: list[dict[str, object]] = []

    def list_accounts(self):
        return {"accounts": [{"name": "gate-mail", "email": "submission-gate@example.com"}]}

    def search_messages(self, _payload):
        return {"messages": [{"uid": "42", "message_id": "<submission@example.com>"}]}

    def read_message(self, _payload):
        return {
            "uid": "42",
            "uidvalidity": "9",
            "message_id": "<submission@example.com>",
            "body_text": self.body_text,
            "from": [{"email": "submitter@example.com"}],
            "release_workflow_headers": {
                "event_id": "event-1",
                "round_id": "1",
                "task": "TASK-1",
                "module": "kernel",
                "request_digest": self.request_digest,
            },
            "evidence": {"raw_headers_sha256": "3" * 64},
        }

    def send_email(self, payload):
        self.sent.append(payload)
        return {"sent": True, "message_id": "<notice@example.com>", "refused": {}}


class FakeGateAdapter:
    def preflight(self):
        return {"ready": True}

    def evaluate(self, payload):
        return {
            "adapter_contract": "GitLabGateResult/v1",
            "provider": "gitlab",
            "verdict": "CLEAN",
            "event_id": payload["event_id"],
            "round_id": payload["round_id"],
            "request_digest": payload["request_digest"],
            "policy_digest": payload["policy_digest"],
            "manifest_digest": "sha256:" + "1" * 64,
            "material_sha256": "2" * 64,
            "evidence_refs": ["gitlab://pipeline/1", "gitlab://job/1"],
            "pipeline_ref": "gitlab://pipeline/1",
            "job_ref": "gitlab://job/1",
            "artifact_ref": "gitlab://artifact/1",
            "artifacts": [{"logical_name": "driver.sys"}],
            "lark_evidence_ref": "lark://doc/1",
        }


def _base_config(tmp_path: Path) -> dict[str, object]:
    return {
        "gate_mail_account": {"profile": "gate-mail", "email": "submission-gate@example.com"},
        "submission_group_address": "qa@example.com",
        "blocked_notice_address": "rd@example.com",
        "state_dir": str(tmp_path / "state"),
        "event_store_dir": str(tmp_path / "events"),
        "audit_log_path": str(tmp_path / "audit.jsonl"),
        "audit_key_path": str(tmp_path / "audit.key"),
        "dependency_lock": str(tmp_path / "dependency-lock.json"),
        "dependency_lock_sha256": "0" * 64,
        "product_gate_config": str(tmp_path / "product-release-gate.json"),
        "mailbox": "INBOX",
        "scan_limit": 100,
    }


def _signed_body(module, *, event_id: str = "event-1", task_name: str = "TASK-1", enabled_optional_checks=None):
    request = {
        "schema": "ProductMaterialSubmission/v1",
        "event_id": event_id,
        "round_id": 1,
        "task_name": task_name,
        "module": "kernel",
        "change_summary": "fix",
        "submitter_email": "submitter@example.com",
        "expected_delivery_at": "2026-07-18T18:00:00+08:00",
        "enabled_optional_checks": [] if enabled_optional_checks is None else enabled_optional_checks,
        "artifacts": [{"logical_name": "driver.sys", "local_path": "C:/tmp/driver.sys", "source_ref": "rev-1"}],
    }
    request["request_digest"] = module.hashlib.sha256(module.canonical_json(request).encode("utf-8")).hexdigest()
    block = dict(request)
    block["contract"] = "rd.test-submission.v1"
    block["hmac_sha256"] = module.hmac.new(
        b"tttttttttttttttttttttttttttttttt",
        module.canonical_json({k: v for k, v in block.items() if k != "hmac_sha256"}).encode("utf-8"),
        module.hashlib.sha256,
    ).hexdigest()
    body_text = "summary\n-----BEGIN RD TEST SUBMISSION BLOCK-----\n" + json.dumps(block) + "\n-----END RD TEST SUBMISSION BLOCK-----\n"
    return request, body_text


def test_run_once_scans_mail_idempotently_and_passes_submission(tmp_path: Path) -> None:
    module = _load_module()
    request, body_text = _signed_body(module)
    mail = FakeMailGateway(body_text, request["request_digest"])
    config_path = tmp_path / "config.json"
    base_config = _base_config(tmp_path)
    config_path.write_text(json.dumps(base_config), encoding="utf-8")
    controller = module.SubmissionGateController(
        config_path,
        mail_gateway=mail,
        gate_adapter=FakeGateAdapter(),
        environ={"TEST_SUBMISSION_HMAC_KEY": "tttttttttttttttttttttttttttttttt"},
    )
    result = controller.run_once()
    assert result["passed"] == 1
    assert mail.sent[0]["subject"].startswith("【提测】")
    assert mail.sent[0]["headers"]["X-RD-Submitter-Email"] == "submitter@example.com"
    assert "提测人邮箱：submitter@example.com" in mail.sent[0]["text"]


def test_run_once_is_idempotent_across_restart_and_zero_checks_block(tmp_path: Path) -> None:
    module = _load_module()
    request, body_text = _signed_body(module)
    mail = FakeMailGateway(body_text, request["request_digest"])
    config_path = tmp_path / "config.json"
    config = _base_config(tmp_path)
    config_path.write_text(json.dumps(config), encoding="utf-8")
    controller = module.SubmissionGateController(
        config_path,
        config={**config, "mandatory_checks_by_module": {"kernel": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required", "must-keep"], "client": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"], "server": ["artifacts_present", "hashes_match", "source_revision_present", "package_digest_present", "cloud_scan_required"]}},
        mail_gateway=mail,
        gate_adapter=FakeGateAdapter(),
        environ={"TEST_SUBMISSION_HMAC_KEY": "tttttttttttttttttttttttttttttttt"},
    )
    first = controller.run_once()
    assert first["passed"] == 1
    restarted = module.SubmissionGateController(
        config_path,
        config={**config, "mandatory_checks_by_module": {"kernel": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required", "must-keep"], "client": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"], "server": ["artifacts_present", "hashes_match", "source_revision_present", "package_digest_present", "cloud_scan_required"]}},
        mail_gateway=mail,
        gate_adapter=FakeGateAdapter(),
        environ={"TEST_SUBMISSION_HMAC_KEY": "tttttttttttttttttttttttttttttttt"},
    )
    second = restarted.run_once()
    assert second["skipped"] == 1
    assert second["processed"] == 0

    blocking_mail = FakeMailGateway(body_text, request["request_digest"])
    blocking = module.SubmissionGateController(
        config_path,
        config={**config, "state_dir": str(tmp_path / "state-block"), "mandatory_checks_by_module": {"kernel": ["artifacts_present", "hashes_match", "version_present", "cloud_scan_required"], "client": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"], "server": ["artifacts_present", "hashes_match", "source_revision_present", "package_digest_present", "cloud_scan_required"]}},
        mail_gateway=blocking_mail,
        gate_adapter=FakeGateAdapter(),
        environ={"TEST_SUBMISSION_HMAC_KEY": "tttttttttttttttttttttttttttttttt"},
    )
    blocked = blocking.run_once()
    assert blocked["blocked"] == 1
    assert blocking_mail.sent[0]["subject"].startswith("【提测阻断】")
