from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TEST_SUBMISSION_ROOT = Path(__file__).resolve().parents[1]
TEST_SUBMISSION_SRC = TEST_SUBMISSION_ROOT / "src"
SUBMISSION_GATE_ROOT = TEST_SUBMISSION_ROOT.parent / "submission-gate"
SUBMISSION_GATE_SRC = SUBMISSION_GATE_ROOT / "src"
sys.path.insert(0, str(TEST_SUBMISSION_SRC))
sys.path.insert(0, str(SUBMISSION_GATE_SRC))


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OutboundSubmissionMail:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    def send_email(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(payload)
        return {"sent": True, "message_id": "<submission@example.test>", "refused": {}}


class SubmissionGateMailbox:
    def __init__(self, submission_mail: dict[str, Any]) -> None:
        self.submission_mail = submission_mail
        self.sent: list[dict[str, Any]] = []

    def list_accounts(self) -> dict[str, Any]:
        return {"accounts": [{"name": "gate-mail", "email": "submission-gate@example.test"}]}

    def search_messages(self, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"messages": [{"uid": "42", "message_id": "<submission@example.test>"}]}

    def read_message(self, _payload: dict[str, Any]) -> dict[str, Any]:
        headers = self.submission_mail["headers"]
        return {
            "uid": "42",
            "uidvalidity": "9",
            "message_id": "<submission@example.test>",
            "body_text": self.submission_mail["text"],
            "from": [{"email": "submitter@example.test"}],
            "release_workflow_headers": {
                "event_id": headers["X-RD-Event-Id"],
                "round_id": headers["X-RD-Round-Id"],
                "task": headers["X-RD-Task"],
                "module": headers["X-RD-Module"],
                "request_digest": headers["X-RD-Request-Digest"],
            },
            "evidence": {"raw_headers_sha256": "3" * 64},
        }

    def send_email(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(payload)
        return {"sent": True, "message_id": "<gate-pass@example.test>", "refused": {}}


class ProtectedGitLabGateAdapter:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def preflight(self) -> dict[str, Any]:
        return {"ready": True}

    def evaluate(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(payload)
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
            "artifacts": [{"logical_name": "retrieved-client.pkg"}],
            "lark_evidence_ref": "lark://doc/1",
        }


class LocalPreviewMustNotRun:
    def preflight(self) -> dict[str, Any]:
        return {"ready": False}

    def preview_submission(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        raise AssertionError("SVN submission must not create a local Manifest-S")


def test_fixed_revision_svn_submission_reaches_submission_gate_ci_adapter(tmp_path: Path) -> None:
    test_submission = _load(TEST_SUBMISSION_SRC / "test_submission_core.py", "test_submission_core_svn_integration")
    submission_gate = _load(SUBMISSION_GATE_SRC / "submission_gate_core.py", "submission_gate_core_svn_integration")
    hmac_key = "t" * 32
    outbound = OutboundSubmissionMail()
    submit_config = {
        "mail_account": {"profile": "submitter-mail", "email": "submitter@example.test"},
        "submission_gate_address": "submission-gate@example.test",
        "state_dir": str(tmp_path / "submit-state"),
        "event_store_dir": str(tmp_path / "submit-events"),
        "dependency_lock": str(tmp_path / "submit-lock.json"),
        "dependency_lock_sha256": "0" * 64,
        "product_gate_preview_config": str(tmp_path / "preview.json"),
        "svn_mandatory_checks": [
            "provenance_locator_present",
            "fixed_revision_present",
            "trusted_retrieval_succeeded",
            "retrieved_nonempty",
            "audit_recorded",
        ],
    }
    submit_config_path = tmp_path / "submit-config.json"
    submit_config_path.write_text(json.dumps(submit_config), encoding="utf-8")
    submitter = test_submission.TestSubmissionController(
        submit_config_path,
        config=submit_config,
        mail_gateway=outbound,
        product_gate=LocalPreviewMustNotRun(),
        now_fn=lambda: datetime(2026, 7, 22, 9, 30, tzinfo=timezone.utc),
        environ={"TEST_SUBMISSION_HMAC_KEY": hmac_key},
    )

    submitted = submitter.submit(
        {
            "event_id": "svn-integration-1",
            "round_id": 1,
            "task_name": "TASK-SVN-INTEGRATION",
            "module": "client",
            "retrieval_method": "svn",
            "source_locator": "https://svn.example.test/repos/rd/client",
            "revision": "12345",
            "version": "8.2.0",
            "artifacts": [],
        }
    )
    assert submitted["status"] == "SUBMITTED"
    assert len(outbound.sent) == 1

    mailbox = SubmissionGateMailbox(outbound.sent[0])
    adapter = ProtectedGitLabGateAdapter()
    gate_config = {
        "gate_mail_account": {"profile": "gate-mail", "email": "submission-gate@example.test"},
        "submission_group_address": "qa@example.test",
        "blocked_notice_address": "rd@example.test",
        "state_dir": str(tmp_path / "gate-state"),
        "event_store_dir": str(tmp_path / "gate-events"),
        "audit_log_path": str(tmp_path / "audit.jsonl"),
        "audit_key_path": str(tmp_path / "audit.key"),
        "dependency_lock": str(tmp_path / "gate-lock.json"),
        "dependency_lock_sha256": "0" * 64,
        "product_gate_config": str(tmp_path / "product-release-gate.json"),
        "mailbox": "INBOX",
        "scan_limit": 100,
        "svn_mandatory_checks": [
            "provenance_locator_present",
            "fixed_revision_present",
            "trusted_retrieval_succeeded",
            "retrieved_nonempty",
            "audit_recorded",
        ],
    }
    gate_config_path = tmp_path / "gate-config.json"
    gate_config_path.write_text(json.dumps(gate_config), encoding="utf-8")
    gate = submission_gate.SubmissionGateController(
        gate_config_path,
        config=gate_config,
        mail_gateway=mailbox,
        gate_adapter=adapter,
        environ={"TEST_SUBMISSION_HMAC_KEY": hmac_key},
    )

    result = gate.run_once()

    assert result["passed"] == 1
    assert adapter.requests[0]["retrieval_method"] == "svn"
    assert adapter.requests[0]["source_locator"] == "https://svn.example.test/repos/rd/client"
    assert adapter.requests[0]["revision"] == "12345"
    assert adapter.requests[0]["sender_artifact_declarations"] == []
    assert mailbox.sent[0]["subject"].startswith("【提测】TASK-SVN-INTEGRATION-client-")
