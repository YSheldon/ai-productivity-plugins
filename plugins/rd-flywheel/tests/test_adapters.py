import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_adapters import (  # noqa: E402
    AdapterError,
    discover_adapter_profiles,
    load_runtime_adapters,
)
from rd_flywheel_config import load_config  # noqa: E402
from rd_flywheel_protocol import CapabilityGapEvent, EvidenceReference, PRODUCTION_EVIDENCE_TYPES, compute_idempotency_key  # noqa: E402


def config(tmp_path):
    payload = {
        "schema_version": 1,
        "governance_inbox": str(tmp_path / "inbox"),
        "state_dir": str(tmp_path / "state"),
        "poll_minutes": 60,
        "timezone": "Asia/Shanghai",
        "tool_profiles": ["gitlab"],
        "approved_agent_profiles": ["agent-a"],
        "agent_profile": "agent-a",
        "protected_merge": {"tool_profile": "gitlab", "protected_branch_required": True},
        "notification": None,
        "decision_role_source": None,
        "dependency_lock": str(tmp_path / "lock.json"),
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_config(path)


def event():
    payload = {
        "schema": "CapabilityGapEvent/v1",
        "originating_plugin": "release-approval",
        "originating_event_id": "event-1",
        "originating_round_id": 1,
        "checkpoint_digest": "a" * 64,
        "missing_capability": "mail.headers",
        "required_evidence": list(PRODUCTION_EVIDENCE_TYPES),
        "allowed_tool_profiles": ["gitlab"],
        "created_at": "2026-07-16T08:00:00Z",
    }
    payload["idempotency_key"] = compute_idempotency_key(payload)
    return CapabilityGapEvent.from_mapping(payload)


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, args, *, input_text=None, encoding=None):
        self.calls.append((list(args), input_text, encoding))
        if args[0] == "agent":
            output = {"candidate_id": "c1", "evidence": []}
        else:
            output = {"verified": True}
        return subprocess.CompletedProcess(args, 0, json.dumps(output), "")


def test_environment_registry_discovers_profile_names_not_credentials():
    environ = {
        "RD_FLYWHEEL_AGENT_COMMANDS_JSON": json.dumps({"agent-b": ["b"], "agent-a": ["a"]}),
        "RD_FLYWHEEL_VERIFIER_COMMANDS_JSON": json.dumps({"tests": ["verify"]}),
    }
    discovered = discover_adapter_profiles(environ)
    assert discovered == ("agent-a", "agent-b")


def test_only_approved_agent_profile_is_loaded_and_commands_use_shell_free_argv(tmp_path):
    runner = Runner()
    environ = {
        "RD_FLYWHEEL_AGENT_COMMANDS_JSON": json.dumps(
            {"agent-a": ["agent", "--json"], "unapproved": ["bad"]}
        ),
        "RD_FLYWHEEL_VERIFIER_COMMANDS_JSON": json.dumps({"tests": ["verify-tests"]}),
    }
    agents, verifiers = load_runtime_adapters(config(tmp_path), environ=environ, runner=runner)

    result = agents["agent-a"](dict(event().payload))
    assert result["candidate_id"] == "c1"
    assert "unapproved" not in agents
    assert runner.calls[0][0] == ["agent", "--json"]
    assert json.loads(runner.calls[0][1])["schema"] == "CapabilityGapEvent/v1"

    reference = EvidenceReference(
        kind="tests",
        uri="file:///tests.json",
        sha256="b" * 64,
        verifier="agent-output",
        verified=False,
    )
    assert verifiers["tests"](reference, event()) == {"verified": True}


def test_invalid_or_nonzero_adapter_configuration_fails_closed(tmp_path):
    with pytest.raises(AdapterError):
        load_runtime_adapters(
            config(tmp_path),
            environ={"RD_FLYWHEEL_AGENT_COMMANDS_JSON": '{"agent-a":"shell string"}'},
        )

    def failing(args, **kwargs):
        return subprocess.CompletedProcess(args, 9, "", "provider unavailable")

    agents, _ = load_runtime_adapters(
        config(tmp_path),
        environ={"RD_FLYWHEEL_AGENT_COMMANDS_JSON": '{"agent-a":["agent"]}'},
        runner=failing,
    )
    with pytest.raises(AdapterError, match="provider unavailable"):
        agents["agent-a"](dict(event().payload))
