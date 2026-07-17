import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_config import load_config  # noqa: E402
from rd_flywheel_controller import RDFlywheelController  # noqa: E402
from rd_flywheel_lock import KernelRunLock  # noqa: E402
from rd_flywheel_protocol import PRODUCTION_EVIDENCE_TYPES, compute_idempotency_key  # noqa: E402
from rd_flywheel_store import RDFlywheelStore  # noqa: E402


def make_config(tmp_path: Path, *, agent_profile="approved-agent", tools=None):
    payload = {
        "schema_version": 1,
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
        "decision_role_source": None,
        "dependency_lock": str(tmp_path / "dependency-lock.json"),
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
    config = make_config(tmp_path)
    write_event(config)
    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result(with_evidence=False)},
        evidence_verifiers={},
    )

    result = controller.run_once()
    stored = controller.get_event(event_payload()["idempotency_key"])

    assert result["status"] == "EVIDENCE_PENDING"
    assert stored["state"] == "EVIDENCE_PENDING"
    assert stored["state"] != "COMPLETE"


def test_complete_requires_every_independent_evidence_verifier(tmp_path):
    config = make_config(tmp_path)
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
    )

    result = controller.run_once()
    stored = controller.get_event(event_payload()["idempotency_key"])

    assert result["status"] == "COMPLETE"
    assert stored["state"] == "COMPLETE"
    assert {kind for kind, _ in seen} == set(PRODUCTION_EVIDENCE_TYPES)
    evidence = stored["evidence"]
    for kind in PRODUCTION_EVIDENCE_TYPES:
        assert any(item["kind"] == kind and item["verified"] for item in evidence)


def test_one_failed_verifier_keeps_event_evidence_pending(tmp_path):
    config = make_config(tmp_path)
    write_event(config)
    verifiers = {kind: (lambda reference, event: True) for kind in PRODUCTION_EVIDENCE_TYPES}
    verifiers["protected_merge"] = lambda reference, event: False
    controller = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        evidence_verifiers=verifiers,
    )

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
    config = make_config(tmp_path)
    write_event(config)
    blocked = RDFlywheelController(config)
    blocked.run_once()
    key = event_payload()["idempotency_key"]

    verifiers = {kind: (lambda reference, event: True) for kind in PRODUCTION_EVIDENCE_TYPES}
    resumed = RDFlywheelController(
        config,
        agent_adapters={"approved-agent": lambda payload: agent_result()},
        evidence_verifiers=verifiers,
    )
    result = resumed.retry_event(key)

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
