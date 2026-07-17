import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import rd_flywheel_cli as cli  # noqa: E402


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
    def __init__(self):
        self.calls = []

    def install(self, *, mode):
        self.calls.append(("install", mode))
        return {"status": "ready", "action": "install", "mode": mode}

    def status(self, *, mode):
        self.calls.append(("status", mode))
        return {"status": "ready", "action": "status", "mode": mode}

    def remove(self, *, mode):
        self.calls.append(("remove", mode))
        return {"status": "ready", "action": "remove", "mode": mode}


def invoke(args, tmp_path, *, setup_runner=None, scheduler=None):
    output = io.StringIO()
    code = cli.run_cli(
        ["--config", str(tmp_path / "config.json"), *args],
        controller_factory=lambda path: FakeController(),
        setup_runner=setup_runner or (lambda **kwargs: {"status": "ready"}),
        scheduler_factory=lambda path: scheduler or FakeScheduler(),
        stdout=output,
    )
    return code, json.loads(output.getvalue())


def test_cli_exposes_required_commands_as_json(tmp_path):
    for command in ["preflight", "run-once", "status", "doctor", "list-events", "verify-audit"]:
        code, payload = invoke([command], tmp_path)
        assert code == 0
        assert isinstance(payload, dict)


def test_cli_setup_uses_same_shared_setup_payload_as_mcp(tmp_path):
    expected = {"status": "CAPABILITY_BLOCKED", "reason": "no approved agent"}

    def setup_runner(**kwargs):
        assert kwargs["non_interactive"] is True
        return expected

    code, payload = invoke(["setup", "--non-interactive"], tmp_path, setup_runner=setup_runner)
    assert code == cli.EXIT_BLOCKED
    assert payload == expected


def test_cli_scheduler_has_no_policy_override(tmp_path):
    scheduler = FakeScheduler()
    code, payload = invoke(["scheduler", "install", "--mode", "cron"], tmp_path, scheduler=scheduler)
    assert code == 0
    assert scheduler.calls == [("install", "cron")]

    code, payload = invoke(
        ["scheduler", "install", "--mode", "cron", "--poll-minutes", "5"],
        tmp_path,
        scheduler=scheduler,
    )
    assert code == cli.EXIT_USAGE
    assert payload["error"]["code"] == "INVALID_ARGUMENT"


def test_cli_get_and_retry_event(tmp_path):
    code, payload = invoke(["get-event", "gap-1"], tmp_path)
    assert code == 0
    assert payload["event"]["idempotency_key"] == "gap-1"

    code, payload = invoke(["retry-event", "gap-1"], tmp_path)
    assert code == cli.EXIT_PENDING
    assert payload["status"] == "EVIDENCE_PENDING"


def test_cli_busy_and_blocked_have_stable_exit_codes(tmp_path):
    class Busy(FakeController):
        def run_once(self):
            return {"status": "RUN_ALREADY_ACTIVE", "busy": True}

    out = io.StringIO()
    code = cli.run_cli(
        ["--config", str(tmp_path / "config.json"), "run-once"],
        controller_factory=lambda path: Busy(),
        stdout=out,
    )
    assert code == cli.EXIT_BUSY


def test_cli_has_no_codex_runtime_import():
    source = (ROOT / "src" / "rd_flywheel_cli.py").read_text(encoding="utf-8").casefold()
    assert "import codex" not in source
    assert "from codex" not in source
