import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import rd_flywheel_mcp as mcp  # noqa: E402
from rd_flywheel_config import ConfigError  # noqa: E402


EXPECTED_TOOLS = {
    "rd_flywheel_setup",
    "rd_flywheel_preflight",
    "rd_flywheel_run_once",
    "rd_flywheel_status",
    "rd_flywheel_doctor",
    "rd_flywheel_list_events",
    "rd_flywheel_get_event",
    "rd_flywheel_retry_event",
    "rd_flywheel_verify_audit",
    "rd_flywheel_scheduler",
}


class FakeController:
    def preflight(self):
        return {"status": "ready", "operation": "preflight"}

    def run_once(self):
        return {"status": "ready", "operation": "run-once"}

    def status(self):
        return {"status": "ready", "operation": "status"}

    def doctor(self):
        return {"status": "ready", "operation": "doctor"}

    def list_events(self, state=None):
        return {"status": "ready", "events": [], "state_filter": state}

    def get_event(self, event_id):
        return {"status": "ready", "event": {"idempotency_key": event_id}}

    def retry_event(self, event_id):
        return {"status": "EVIDENCE_PENDING", "idempotency_key": event_id}

    def verify_audit(self):
        return {"status": "ready", "ok": True}


class FakeScheduler:
    def install(self, *, mode):
        return {"status": "ready", "action": "install", "mode": mode}

    def status(self, *, mode):
        return {"status": "ready", "action": "status", "mode": mode}

    def remove(self, *, mode):
        return {"status": "ready", "action": "remove", "mode": mode}


def test_mcp_exposes_every_required_operation():
    assert set(mcp.TOOLS) == EXPECTED_TOOLS


def test_mcp_common_operations_use_one_controller(tmp_path):
    created = []

    def factory(path):
        created.append(path)
        return FakeController()

    result = mcp.handle_tool_call(
        "rd_flywheel_run_once",
        {},
        config_path=tmp_path / "config.json",
        controller_factory=factory,
    )

    assert result == {"status": "ready", "operation": "run-once"}
    assert created == [tmp_path / "config.json"]


def test_mcp_setup_cold_starts_without_loading_existing_config(tmp_path):
    calls = []

    def setup_runner(**kwargs):
        calls.append(kwargs)
        return {"status": "CAPABILITY_BLOCKED", "config_path": str(kwargs["config_path"])}

    result = mcp.handle_tool_call(
        "rd_flywheel_setup",
        {"non_interactive": True, "scheduler_mode": "auto"},
        config_path=tmp_path / "missing.json",
        controller_factory=lambda path: pytest.fail("setup must not load controller config"),
        setup_runner=setup_runner,
    )

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert calls[0]["non_interactive"] is True


def test_mcp_rejects_per_call_config_override(tmp_path):
    with pytest.raises(ConfigError, match="cannot be supplied per call"):
        mcp.handle_tool_call(
            "rd_flywheel_status",
            {"config_path": "other.json"},
            config_path=tmp_path / "config.json",
            controller_factory=lambda path: FakeController(),
        )


def test_scheduler_action_is_explicit_and_uses_same_config(tmp_path):
    result = mcp.handle_tool_call(
        "rd_flywheel_scheduler",
        {"action": "install", "mode": "cron"},
        config_path=tmp_path / "config.json",
        scheduler_factory=lambda path: FakeScheduler(),
    )
    assert result == {"status": "ready", "action": "install", "mode": "cron"}


def test_json_rpc_stdio_envelope_contains_structured_json(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp, "default_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(mcp, "_controller_factory", lambda path: FakeController())
    response = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "rd_flywheel_status", "arguments": {}},
        }
    )
    assert response["id"] == 7
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["operation"] == "status"
