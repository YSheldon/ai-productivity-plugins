from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = ROOT / "shared"
if str(SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(SHARED_ROOT))

from release_workflow_core.audit import AuditError, JsonlAuditLog
from release_workflow_core.gate_adapter_contract import GateAdapterContractError, validate_gitlab_gate_result
from release_workflow_core.mail_contract import MailContractError, encode_machine_payload, parse_message, render_message
from release_workflow_core.manifest import bind_material_file, build_manifest_r, build_manifest_s, combined_manifest_digest
from release_workflow_core.models import validate_submission_payload, validate_workflow_payload
from release_workflow_core.policy import effective_checks, freeze_policy
from release_workflow_core.states import (
    CAPABILITY_BLOCKED,
    PENDING_TEST_RESULT,
    PRERELEASE_REQUESTED,
    RELEASE_READY,
    RELEASE_READY_NOTIFIED,
    WorkflowTransitionError,
    can_transition,
    freeze_capability_blocked,
    require_transition,
)


def _submission_payload() -> dict[str, object]:
    return {
        "schema": "ProductMaterialSubmission/v1",
        "event_id": "evt-release-1",
        "round_id": 1,
        "task": "Task A",
        "module": "client",
        "submitter_email": "submitter@example.com",
        "created_at": "2026-07-17T10:00:00Z",
        "policy_profile": "submission-client/v1",
        "effective_checks": [
            "artifacts_present",
            "hashes_match",
            "version_present",
            "signature_present",
            "cloud_scan_required",
            "lint_clean",
        ],
        "change_summary": "stable release candidate",
        "expected_delivery_at": "2026-07-18T03:00:00Z",
        "evidence_refs": ["feishu://doc/a", "gitlab://pipeline/1"],
        "artifacts": [
            {
                "logical_name": "client.zip",
                "material_sha256": "a" * 64,
                "material_sha1": "b" * 40,
                "size": 128,
                "source_ref": "git:abcd1234",
            }
        ],
    }


def _workflow_payload() -> dict[str, object]:
    return {
        "schema": "ProductMaterialWorkflow/v1",
        "event_id": "evt-release-1",
        "round_id": 2,
        "event_type": "PRERELEASE_REQUEST",
        "state": "PRERELEASE_REQUESTED",
        "task": "Task A",
        "module": "client",
        "submitter_email": "submitter@example.com",
        "created_at": "2026-07-17T11:00:00Z",
        "policy_profile": "release-gate/v1",
        "policy_digest": "sha256:" + "c" * 64,
        "parent_event_id": "evt-release-1",
        "parent_round_id": 1,
        "manifest_s_digest": "sha256:" + "d" * 64,
        "manifest_r_digest": "sha256:" + "e" * 64,
        "manifest_digest": "sha256:" + "f" * 64,
        "request_digest": "sha256:" + "1" * 64,
        "evidence_refs": ["gitlab://pipeline/1", "imap://mail/uid/2"],
        "test_result": "PASS",
        "gate_verdict": "CLEAN",
    }


def test_submission_model_validation_accepts_canonical_payload() -> None:
    model = validate_submission_payload(_submission_payload())
    assert model.schema == "ProductMaterialSubmission/v1"
    assert model.module == "client"
    assert model.effective_checks[-1] == "lint_clean"
    assert model.submitter_email == "submitter@example.com"
    assert model.artifacts[0].material_sha256 == "a" * 64


def test_workflow_model_validation_requires_parent_pair() -> None:
    payload = _workflow_payload()
    payload.pop("parent_round_id")
    with pytest.raises(ValueError, match="parent_event_id and parent_round_id"):
        validate_workflow_payload(payload)


def test_state_machine_enforces_release_ready_notification_boundary() -> None:
    assert can_transition(PRERELEASE_REQUESTED, RELEASE_READY)
    require_transition(PRERELEASE_REQUESTED, RELEASE_READY)
    require_transition(RELEASE_READY, RELEASE_READY_NOTIFIED)
    assert not can_transition(CAPABILITY_BLOCKED, RELEASE_READY_NOTIFIED)
    with pytest.raises(WorkflowTransitionError, match="workflow transition is invalid"):
        require_transition(CAPABILITY_BLOCKED, RELEASE_READY_NOTIFIED)
    checkpoint = freeze_capability_blocked(PENDING_TEST_RESULT, "mailbox not configured")
    assert checkpoint.state == PENDING_TEST_RESULT
    assert checkpoint.replayable is True


def test_policy_freeze_produces_deterministic_effective_checks_and_digest() -> None:
    policy = freeze_policy(
        "client",
        policy_profile="submission-client/v1",
        configured_mandatory=(
            "artifacts_present",
            "hashes_match",
            "version_present",
            "signature_present",
            "cloud_scan_required",
            "hashes_match",
        ),
        enabled_optional=("lint_clean", "smoke_passed", "lint_clean"),
    )
    assert policy["effective_checks"] == [
        "artifacts_present",
        "hashes_match",
        "version_present",
        "signature_present",
        "cloud_scan_required",
        "lint_clean",
        "smoke_passed",
    ]
    assert policy["policy_digest"].startswith("sha256:")
    assert effective_checks(
        "client",
        configured_mandatory=policy["configured_mandatory"],
        enabled_optional=policy["enabled_optional"],
    ) == tuple(policy["effective_checks"])


def test_manifest_builders_are_deterministic_and_bind_file_hashes(tmp_path: Path) -> None:
    first = tmp_path / "client-a.bin"
    second = tmp_path / "client-b.bin"
    first.write_bytes(b"alpha")
    second.write_bytes(b"beta")
    submission = validate_submission_payload(_submission_payload())
    policy = freeze_policy(
        "client",
        policy_profile=submission.policy_profile,
        configured_mandatory=submission.effective_checks[:5],
        enabled_optional=submission.effective_checks[5:],
    )

    unordered = [
        bind_material_file(second, logical_name="client-b.bin", source_ref="git:def"),
        bind_material_file(first, logical_name="client-a.bin", source_ref="git:abc"),
    ]
    manifest_s_a = build_manifest_s(submission, policy_digest=policy["policy_digest"], file_bindings=unordered)
    manifest_s_b = build_manifest_s(
        submission,
        policy_digest=policy["policy_digest"],
        file_bindings=list(reversed(unordered)),
    )
    assert manifest_s_a["manifest_s_digest"] == manifest_s_b["manifest_s_digest"]
    assert manifest_s_a["artifacts"][0]["logical_name"] == "client-a.bin"

    workflow = validate_workflow_payload(_workflow_payload())
    manifest_r = build_manifest_r(
        workflow,
        manifest_s_digest=manifest_s_a["manifest_s_digest"],
        material_files=unordered,
        evidence_refs=["imap://mail/uid/2", "gitlab://pipeline/1"],
    )
    combined = combined_manifest_digest(manifest_s_a["manifest_s_digest"], manifest_r["manifest_r_digest"])
    assert manifest_r["manifest_r_digest"].startswith("sha256:")
    assert combined.startswith("sha256:")


def test_mail_contract_renders_and_parses_hmac_bound_machine_payload() -> None:
    secret = b"m" * 32
    payload = _workflow_payload()
    message = render_message(
        "release_application",
        payload,
        secret=secret,
        when="2026-07-17",
        summary_lines=("任务：Task A", "模块：client"),
    )
    parsed = parse_message(
        message["body_text"],
        secret=secret,
        headers=message["headers"],
        expected_bindings={"event_id": "evt-release-1", "round_id": 2, "policy_digest": payload["policy_digest"]},
    )
    assert parsed["event_type"] == "PRERELEASE_REQUEST"
    assert parsed["submitter_email"] == "submitter@example.com"
    assert message["headers"]["X-RD-Manifest-Digest"] == payload["manifest_digest"]
    assert message["headers"]["X-RD-Submitter-Email"] == "submitter@example.com"

    tampered_payload = dict(message["signed_payload"])
    tampered_payload["event_id"] = "evt-release-x"
    tampered = message["body_text"].replace(encode_machine_payload(message["signed_payload"]), encode_machine_payload(tampered_payload))
    with pytest.raises(MailContractError):
        parse_message(tampered, secret=secret)


def test_audit_log_verifies_head_chain_and_fails_after_tamper(tmp_path: Path) -> None:
    audit = JsonlAuditLog(tmp_path / "audit.jsonl", audit_key=b"k" * 32)
    first = audit.append({"event_id": "evt-release-1", "state": "SUBMITTED"}, recorded_at="2026-07-17T10:00:00Z")
    second = audit.append(
        {"event_id": "evt-release-1", "state": "PRERELEASE_REQUESTED"},
        recorded_at="2026-07-17T11:00:00Z",
    )
    checkpoint = audit.verify()
    assert checkpoint == {"count": 2, "head_hash": second["head_hash"]}
    audit.verify_audit_checkpoint(2, second["head_hash"])
    assert first["head_hash"] != second["head_hash"]

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[-1])
    payload["record"]["state"] = "RELEASE_READY_NOTIFIED"
    lines[-1] = json.dumps(payload, ensure_ascii=False)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditError, match="record digest"):
        audit.verify()


def test_gate_adapter_contract_requires_clean_gitlab_verdict_and_bindings() -> None:
    payload = {
        "adapter_contract": "GitLabGateResult/v1",
        "provider": "gitlab",
        "verdict": "CLEAN",
        "event_id": "evt-release-1",
        "round_id": 2,
        "request_digest": "sha256:" + "1" * 64,
        "policy_digest": "sha256:" + "2" * 64,
        "manifest_digest": "sha256:" + "3" * 64,
        "material_sha256": "4" * 64,
        "evidence_refs": ["gitlab://pipeline/1", "gitlab://job/2"],
        "pipeline_ref": "gitlab://pipeline/1",
        "job_ref": "gitlab://job/2",
        "artifact_ref": "gitlab://artifact/3",
    }
    evidence = validate_gitlab_gate_result(
        payload,
        expected_bindings={
            "event_id": "evt-release-1",
            "round_id": 2,
            "request_digest": payload["request_digest"],
            "policy_digest": payload["policy_digest"],
            "manifest_digest": payload["manifest_digest"],
            "material_sha256": payload["material_sha256"],
            "evidence_refs": payload["evidence_refs"],
        },
    )
    assert evidence.verdict == "CLEAN"
    bad = dict(payload)
    bad["verdict"] = "BLOCKED"
    with pytest.raises(GateAdapterContractError, match="verdict must be CLEAN"):
        validate_gitlab_gate_result(bad)
