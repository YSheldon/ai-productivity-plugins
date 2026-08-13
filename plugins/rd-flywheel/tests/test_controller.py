import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_config import load_config  # noqa: E402
from rd_flywheel_controller import RDFlywheelController  # noqa: E402
from rd_flywheel_decision import parse_decision_role_snapshot  # noqa: E402
from rd_flywheel_lock import KernelRunLock  # noqa: E402
from rd_flywheel_protocol import (  # noqa: E402
    PRODUCTION_EVIDENCE_TYPES,
    canonical_json,
    compute_idempotency_key,
)
from rd_flywheel_store import RDFlywheelStore  # noqa: E402


def make_config(
    tmp_path: Path,
    *,
    agent_profile="approved-agent",
    tools=None,
    decision_roles=False,
):
    payload = {
        "schema_version": 2,
        "governance_inbox": str(tmp_path / "inbox"),
        "state_dir": str(tmp_path / "state"),
        "poll_minutes": 60,
        "timezone": "Asia/Shanghai",
        "tool_profiles": tools or ["imap-smtp-mail", "gitlab", "lark-cli"],
        "approved_agent_profiles": ["approved-agent"],
        "agent_profile": agent_profile,
        "protected_merge": {
            "tool_profile": "gitlab",
            "protected_branch_required": True,
        },
        "notification": {
            "mail_profile": "corp-mail",
            "recipients": ["governance@example.com"],
        },
        "decision_role_source": (
            {
                "type": "feishu",
                "document_url": "https://example.feishu.cn/docx/roles",
                "heading": "## 决策角色",
            }
            if decision_roles
            else None
        ),
        "dependency_lock": str(tmp_path / "dependency-lock.json"),
        "dependency_lock_sha256": "0" * 64,
        "decision_verifier_config": str(tmp_path / "verifier-config.json"),
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_config(path)


def event_payload(*, allowed_tools=None):
    payload = {
        "schema": "CapabilityGapEvent/v1",
        "originating_plugin": "release-approval",
        "originating_event_id": "release-event-1",
        "originating_round_id": 1,
        "checkpoint_digest": "a" * 64,
        "missing_capability": "mail.raw_thread_headers",
        "required_evidence": list(PRODUCTION_EVIDENCE_TYPES),
        "allowed_tool_profiles": allowed_tools or ["imap-smtp-mail", "gitlab"],
        "created_at": "2026-07-16T08:00:00Z",
    }
    payload["idempotency_key"] = compute_idempotency_key(payload)
    return payload


def write_event(config, payload=None, name="event.json"):
    config.governance_inbox.mkdir(parents=True, exist_ok=True)
    path = config.governance_inbox / name
    path.write_text(json.dumps(payload or event_payload()), encoding="utf-8")
    return path


def agent_result(with_evidence=True):
    evidence = []
    if with_evidence:
        evidence = [
            {
                "kind": kind,
                "uri": f"file:///evidence/{kind}.json",
                "sha256": hashlib.sha256(kind.encode()).hexdigest(),
            }
            for kind in PRODUCTION_EVIDENCE_TYPES
        ]
    return {
        "candidate_id": "candidate-1",
        "status": "merged",
        "exit_code": 0,
        "evidence": evidence,
    }


def decision_snapshot():
    return parse_decision_role_snapshot(
        """## 决策角色
| role_id | email | required | enabled |
| --- | --- | --- | --- |
| director | director@example.com | true | true |
| security | security@example.com | true | true |
""",
        document_url="https://example.feishu.cn/docx/roles",
        heading="## 决策角色",
    )


def verified_decision(request):
    return {
        "verified": True,
        "verifier": "release-approval-verifier",
        "receipt": {
            "contract": "ApprovalVerificationReceipt/v1",
            "authority_scope": "RD_FLYWHEEL_GOVERNANCE",
            "status": "APPROVAL_VERIFIED",
            "event_id": request["event_id"],
            "round_id": request["round_id"],
            "manifest_s_digest": request["manifest_s_digest"],
            "manifest_r_digest": request["manifest_r_digest"],
            "manifest_digest": request["manifest_digest"],
            "request_digest": request["request_digest"],
            "role_snapshot_digest": request["role_snapshot_digest"],
            "expires_at": request["expires_at"],
            "required_roles": list(request["required_roles"]),
            "current_decisions": [
                {
                    "role_id": role["role_id"],
                    "decision_id": f"decision-{role['role_id']}",
                    "decision": "APPROVE",
                    "approver_email": role["email"],
                    "authentication_path": "dkim",
                    "source_message_id": f"<{role['role_id']}@example.com>",
                    "decided_at": "2026-07-16T09:00:00Z",
                }
                for role in request["required_role_bindings"]
            ],
            "receipt_id": "receipt-governance",
            "receipt_hmac": "base64:independently-verified",
        },
    }


def decision_services(*, verifier=verified_decision, presentations=None):
    presentations = presentations if presentations is not None else []

    def presenter(payload):
        presentations.append(payload)
        return {
            "status": "accepted",
            "message_id": payload["request"]["original_message_id"],
            "refused": {},
            "atomic_recipients": True,
            "data_submitted": True,
            "recipients": payload["recipients"],
            "accepted_at": "2026-07-16T08:01:00Z",
        }

    return {
        "role_snapshot_fetcher": lambda source: decision_snapshot(),
        "decision_presenter": presenter,
        "decision_verifier": verifier,
    }


def test_missing_agent_fails_closed_and_preserves_originating_checkpoint(tmp_path):
    config = make_config(tmp_path)
    write_event(config)
    notifications = []
    controller = RDFlywheelController(
        config,
        agent_adapters={},
        evidence_verifiers={},
        notifier=notifications.append,
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"
    stored = controller.get_event(event_payload()["idempotency_key"])
    assert stored["state"] == "CAPABILITY_BLOCKED"
    assert stored["checkpoint_digest"] == "a" * 64
    assert stored["missing_capability"] == "mail.raw_thread_headers"
    assert notifications and notifications[0]["status"] == "CAPABILITY_BLOCKED"


def test_missing_allowlisted_tool_blocks_before_agent_invocation(tmp_path):
    config = make_config(tmp_path, tools=["gitlab"])
    write_event(config)
    calls = []
    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: calls.append(payload)},
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert calls == []
    assert "imap-smtp-mail" in result["blocked_reasons"][0]


def test_ai_output_and_zero_exit_are_evidence_only_not_authority(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result(with_evidence=False)},
        evidence_verifiers={},
        **decision_services(),
    )

    assert controller.run_once()["status"] == "DECISION_PENDING"
    result = controller.run_once()
    stored = controller.get_event(event_payload()["idempotency_key"])

    assert result["status"] == "EVIDENCE_PENDING"
    assert stored["state"] == "EVIDENCE_PENDING"
    assert stored["state"] != "COMPLETE"


def test_complete_requires_every_independent_evidence_verifier(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    seen = []
    verifiers = {
        kind: (lambda reference, event, kind=kind: seen.append((kind, reference.uri)) or True)
        for kind in PRODUCTION_EVIDENCE_TYPES
    }
    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        evidence_verifiers=verifiers,
        **decision_services(),
    )

    assert controller.run_once()["status"] == "DECISION_PENDING"
    result = controller.run_once()
    stored = controller.get_event(event_payload()["idempotency_key"])

    assert result["status"] == "COMPLETE"
    assert stored["state"] == "COMPLETE"
    assert {kind for kind, _ in seen} == set(PRODUCTION_EVIDENCE_TYPES)
    evidence = stored["evidence"]
    for kind in PRODUCTION_EVIDENCE_TYPES:
        assert any(item["kind"] == kind and item["verified"] for item in evidence)


def test_one_failed_verifier_keeps_event_evidence_pending(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    verifiers = {kind: (lambda reference, event: True) for kind in PRODUCTION_EVIDENCE_TYPES}
    verifiers["protected_merge"] = lambda reference, event: False
    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        evidence_verifiers=verifiers,
        **decision_services(),
    )

    assert controller.run_once()["status"] == "DECISION_PENDING"
    result = controller.run_once()

    assert result["status"] == "EVIDENCE_PENDING"
    assert "protected_merge" in result["missing_evidence"]


def test_run_once_takes_kernel_lock_before_store_or_inbox_side_effects(tmp_path):
    config = make_config(tmp_path)
    write_event(config)
    lock = KernelRunLock(config.run_lock_path)
    assert lock.acquire() is True
    try:
        controller = RDFlywheelController(config)
        result = controller.run_once()
    finally:
        lock.release()

    assert result == {"status": "RUN_ALREADY_ACTIVE", "busy": True}
    assert not config.database_path.exists()


def test_orphan_metadata_is_recovered_only_after_kernel_lock_is_acquired(tmp_path):
    config = make_config(tmp_path)
    config.state_dir.mkdir(parents=True)
    config.run_lock_path.write_text(
        json.dumps({"pid": 999999, "started_at": "2020-01-01T00:00:00Z"}),
        encoding="utf-8",
    )
    controller = RDFlywheelController(config)

    result = controller.run_once()

    assert result["status"] in {"ready", "CAPABILITY_BLOCKED"}
    store = RDFlywheelStore(config.database_path)
    rows = store.audit_events()
    assert any(row["event_type"] == "orphan_lock_metadata_recovered" for row in rows)


def test_invalid_input_is_rejected_and_audited_once(tmp_path):
    config = make_config(tmp_path)
    config.governance_inbox.mkdir(parents=True)
    (config.governance_inbox / "invalid.json").write_text('{"schema":"wrong"}', encoding="utf-8")
    controller = RDFlywheelController(config)

    first = controller.run_once()
    second = controller.run_once()

    assert first["rejected"] == 1
    assert second["rejected"] == 0
    store = RDFlywheelStore(config.database_path)
    assert sum(row["event_type"] == "input_rejected" for row in store.audit_events()) == 1


def test_retry_replays_same_frozen_event_after_adapter_becomes_available(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    blocked = RDFlywheelController(config)
    blocked.run_once()
    key = event_payload()["idempotency_key"]

    verifiers = {kind: (lambda reference, event: True) for kind in PRODUCTION_EVIDENCE_TYPES}
    resumed = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        evidence_verifiers=verifiers,
        **decision_services(),
    )
    assert resumed.retry_event(key)["status"] == "DECISION_PENDING"
    result = resumed.run_once()

    assert result["status"] == "COMPLETE"
    assert resumed.get_event(key)["checkpoint_digest"] == "a" * 64


def test_preflight_persists_and_notifies_missing_agent_capability(tmp_path):
    config = make_config(tmp_path)
    notices = []
    controller = RDFlywheelController(config, notifier=notices.append)

    result = controller.preflight()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert "approved agent adapter" in " ".join(result["blocked_reasons"])
    store = RDFlywheelStore(config.database_path)
    assert any(row["event_type"] == "preflight_capability_blocked" for row in store.audit_events())
    assert notices


def test_preflight_requires_live_governance_decision_dependencies(tmp_path):
    config = make_config(tmp_path)
    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
    )

    result = controller.preflight()

    assert result["status"] == "CAPABILITY_BLOCKED"
    reasons = " ".join(result["blocked_reasons"])
    assert "decision role source" in reasons
    assert "role snapshot fetcher" in reasons
    assert "decision presenter" in reasons
    assert "decision verifier" in reasons


def test_partial_smtp_refusal_blocks_before_agent_and_freezes_no_acceptance_receipt(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    calls = []

    def partially_refused(payload):
        return {
            "status": "accepted",
            "message_id": payload["request"]["original_message_id"],
            "refused": {"security@example.com": "550 rejected"},
            "recipients": payload["recipients"],
            "accepted_at": "2026-07-16T08:01:00Z",
        }

    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: calls.append(payload)},
        role_snapshot_fetcher=lambda source: decision_snapshot(),
        decision_presenter=partially_refused,
        decision_verifier=verified_decision,
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert calls == []
    decision_dir = config.audit_dir / "decisions" / event_payload()["idempotency_key"]
    assert (decision_dir / "governance-decision-request.json").is_file()
    assert not (decision_dir / "presentation-receipt.json").exists()


def test_presentation_runtime_failure_becomes_audited_blocked_state(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    agent_calls = []

    def failing_presenter(_payload):
        raise RuntimeError("mail adapter unavailable")

    controller = RDFlywheelController(
        config,
        agent_adapters={
            "approved-agent": lambda payload: agent_calls.append(payload) or agent_result()
        },
        role_snapshot_fetcher=lambda source: decision_snapshot(),
        decision_presenter=failing_presenter,
        decision_verifier=verified_decision,
    )

    result = controller.run_once()
    stored = controller.get_event(event_payload()["idempotency_key"])

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert stored["state"] == "CAPABILITY_BLOCKED"
    assert "RuntimeError" in stored["last_detail"]
    assert agent_calls == []


def test_verifier_runtime_failure_becomes_audited_blocked_state(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    agent_calls = []

    def failing_verifier(_request):
        raise RuntimeError("verifier adapter unavailable")

    controller = RDFlywheelController(
        config,
        agent_adapters={
            "approved-agent": lambda payload: agent_calls.append(payload) or agent_result()
        },
        **decision_services(verifier=failing_verifier),
    )

    assert controller.run_once()["status"] == "DECISION_PENDING"
    result = controller.run_once()
    stored = controller.get_event(event_payload()["idempotency_key"])

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert stored["state"] == "CAPABILITY_BLOCKED"
    assert "RuntimeError" in stored["last_detail"]
    assert agent_calls == []


def test_failed_smtp_presentation_retries_exact_frozen_decision_package(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    first = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        role_snapshot_fetcher=lambda source: decision_snapshot(),
        decision_presenter=lambda payload: {
            "status": "rejected",
            "message_id": payload["request"]["original_message_id"],
            "refused": {payload["recipients"][0]: "451 temporary failure"},
            "recipients": payload["recipients"],
            "accepted_at": "2026-07-16T08:01:00Z",
        },
        decision_verifier=verified_decision,
    )
    assert first.run_once()["status"] == "CAPABILITY_BLOCKED"
    key = event_payload()["idempotency_key"]
    request_path = config.audit_dir / "decisions" / key / "governance-decision-request.json"
    frozen_before = request_path.read_bytes()

    resumed = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        **decision_services(),
    )
    result = resumed.retry_event(key)

    assert result["status"] == "DECISION_PENDING"
    assert request_path.read_bytes() == frozen_before


def test_decision_presentation_requires_timestamp_and_freezes_receipt(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)

    missing_timestamp = decision_services()
    missing_timestamp["decision_presenter"] = lambda payload: {
        "status": "accepted",
        "message_id": payload["request"]["original_message_id"],
        "refused": {},
        "atomic_recipients": True,
        "data_submitted": True,
        "recipients": payload["recipients"],
    }
    blocked = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        **missing_timestamp,
    )
    assert blocked.run_once()["status"] == "CAPABILITY_BLOCKED"

    key = event_payload()["idempotency_key"]
    accepted = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        **decision_services(),
    )
    assert accepted.retry_event(key)["status"] == "DECISION_PENDING"
    receipt_path = config.audit_dir / "decisions" / key / "presentation-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["accepted_at"] == "2026-07-16T08:01:00Z"
    assert receipt["message_id"].startswith("<rd-flywheel-")


def test_tampered_visual_companion_blocks_pending_decision(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    pending = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        **decision_services(
            verifier=lambda request: {
                "verified": False,
                "status": "APPROVAL_PAUSED",
            }
        ),
    )
    assert pending.run_once()["status"] == "DECISION_PENDING"
    key = event_payload()["idempotency_key"]
    screen_path = config.audit_dir / "decisions" / key / "visual-companion.html"
    screen_path.write_text("tampered", encoding="utf-8")

    verifier_called = []
    resumed = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        role_snapshot_fetcher=lambda source: decision_snapshot(),
        decision_presenter=lambda payload: {},
        decision_verifier=lambda request: verifier_called.append(request)
        or verified_decision(request),
    )
    result = resumed.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert verifier_called == []


def test_rehashed_governance_context_tamper_cannot_escape_event_binding(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    pending = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        **decision_services(
            verifier=lambda request: {
                "verified": False,
                "status": "APPROVAL_PAUSED",
            }
        ),
    )
    assert pending.run_once()["status"] == "DECISION_PENDING"
    key = event_payload()["idempotency_key"]
    request_path = (
        config.audit_dir / "decisions" / key / "governance-decision-request.json"
    )
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["governance_context"]["missing_capability"] = "different.capability"
    request["request_digest"] = "sha256:" + hashlib.sha256(
        canonical_json(
            {name: value for name, value in request.items() if name != "request_digest"}
        ).encode("utf-8")
    ).hexdigest()
    request_path.write_text(canonical_json(request) + "\n", encoding="utf-8")

    verifier_called = []
    resumed = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        role_snapshot_fetcher=lambda source: decision_snapshot(),
        decision_presenter=lambda payload: {},
        decision_verifier=lambda request: verifier_called.append(request)
        or verified_decision(request),
    )
    result = resumed.run_once()
    stored = resumed.get_event(key)

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert "governance_context" in stored["last_detail"]
    assert verifier_called == []


def test_pending_decision_is_presented_only_once(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    presentations = []
    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        **decision_services(
            presentations=presentations,
            verifier=lambda request: {
                "verified": False,
                "status": "APPROVAL_PAUSED",
            },
        ),
    )

    assert controller.run_once()["status"] == "DECISION_PENDING"
    assert controller.run_once()["status"] == "DECISION_PENDING"
    assert controller.run_once()["status"] == "DECISION_PENDING"
    assert len(presentations) == 1


def test_controller_waits_for_verified_multi_role_decision_before_agent(tmp_path):
    config = make_config(tmp_path, decision_roles=True)
    write_event(config)
    presented = []
    agent_calls = []

    def presenter(payload):
        presented.append(payload)
        return {
            "status": "accepted",
            "message_id": payload["request"]["original_message_id"],
            "refused": {},
            "atomic_recipients": True,
            "data_submitted": True,
            "recipients": payload["recipients"],
            "accepted_at": "2026-07-16T08:01:00Z",
        }

    pending = RDFlywheelController(
        config,
        agent_adapters={
            "approved-agent": lambda payload: agent_calls.append(payload) or agent_result()
        },
        evidence_verifiers={
            kind: (lambda reference, event: True)
            for kind in PRODUCTION_EVIDENCE_TYPES
        },
        role_snapshot_fetcher=lambda source: decision_snapshot(),
        decision_presenter=presenter,
        decision_verifier=lambda request: {
            "verified": False,
            "status": "APPROVAL_PAUSED",
        },
    )

    first = pending.run_once()

    assert first["status"] == "DECISION_PENDING"
    assert agent_calls == []
    assert len(presented) == 1
    key = event_payload()["idempotency_key"]
    assert pending.get_event(key)["state"] == "DECISION_PENDING"
    assert Path(presented[0]["screen_path"]).is_file()
    assert Path(presented[0]["request_path"]).is_file()

    approved = RDFlywheelController(
        config,
        agent_adapters={
            "approved-agent": lambda payload: agent_calls.append(payload) or agent_result()
        },
        evidence_verifiers={
            kind: (lambda reference, event: True)
            for kind in PRODUCTION_EVIDENCE_TYPES
        },
        role_snapshot_fetcher=lambda source: decision_snapshot(),
        decision_presenter=presenter,
        decision_verifier=verified_decision,
    )

    second = approved.run_once()

    assert second["status"] == "COMPLETE"
    assert len(agent_calls) == 1
    stored = approved.get_event(key)
    assert [item["to_state"] for item in stored["transitions"]] == [
        "RECEIVED",
        "VALIDATED",
        "DECISION_PENDING",
        "WAITING_AGENT",
        "BUILDING",
        "EVIDENCE_PENDING",
        "COMPLETE",
    ]
