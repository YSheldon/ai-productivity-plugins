import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_config import load_config  # noqa: E402
from rd_flywheel_setup import DiscoveryResult, RDFlywheelSetup  # noqa: E402


class FakeController:
    def __init__(self, calls):
        self.calls = calls

    def preflight(self):
        self.calls.append("preflight")
        return {"status": "ready"}

    def run_once(self):
        self.calls.append("run-once")
        return {"status": "ready", "processed": 0}

    def status(self):
        self.calls.append("status")
        return {"status": "ready"}


class FakeScheduler:
    def __init__(self, calls):
        self.calls = calls

    def install(self, *, mode):
        self.calls.append(("scheduler-install", mode))
        return {"status": "ready", "mode": "cron"}

    def status(self, *, mode):
        self.calls.append(("scheduler-status", mode))
        return {"status": "ready", "mode": "cron"}


def discovery(*agents):
    return DiscoveryResult(
        tool_profiles=(
            "imap-smtp-mail",
            "gitlab",
            "lark-cli",
            "ssh",
            "product-release-gate",
        ),
        agent_profiles=tuple(agents),
        scheduler_mode="cron",
        timezone="Asia/Shanghai",
    )


def make_setup(tmp_path, found, prompts, calls):
    return RDFlywheelSetup(
        config_path=tmp_path / "config.json",
        discoverer=lambda: found,
        prompt=lambda label, default: prompts.append((label, default)) or default,
        controller_factory=lambda config: FakeController(calls),
        scheduler_factory=lambda config, path: FakeScheduler(calls),
    )


def test_setup_uses_at_most_three_prompts_and_activates_in_order(tmp_path):
    prompts = []
    calls = []
    setup = make_setup(tmp_path, discovery("agent-a", "agent-b"), prompts, calls)

    result = setup.run(non_interactive=False)

    assert len(prompts) == 3
    assert result["status"] == "ready"
    assert calls == [
        "preflight",
        ("scheduler-install", "cron"),
        "run-once",
        "status",
        ("scheduler-status", "cron"),
    ]
    config = load_config(tmp_path / "config.json")
    assert config.agent_profile == "agent-a"


def test_setup_rerun_is_zero_prompt_and_reuses_single_config(tmp_path):
    prompts = []
    calls = []
    setup = make_setup(tmp_path, discovery("agent-a"), prompts, calls)
    setup.run(non_interactive=False)
    prompts.clear()

    result = setup.run(non_interactive=False)

    assert prompts == []
    assert result["config_reused"] is True


def test_noninteractive_setup_is_deterministic_and_fails_closed_on_ambiguous_agent(tmp_path):
    prompts = []
    calls = []
    setup = make_setup(tmp_path, discovery("agent-b", "agent-a"), prompts, calls)

    result = setup.run(non_interactive=True)

    assert prompts == []
    config = load_config(tmp_path / "config.json")
    assert config.agent_profile is None
    assert result["preflight"]["status"] in {"ready", "CAPABILITY_BLOCKED"}


def test_single_agent_and_default_paths_need_no_noninteractive_input(tmp_path):
    setup = make_setup(tmp_path, discovery("agent-a"), [], [])

    setup.run(non_interactive=True)

    config = load_config(tmp_path / "config.json")
    assert config.agent_profile == "agent-a"
    assert config.governance_inbox == (tmp_path / "inbox").resolve()
    assert config.state_dir == (tmp_path / "state").resolve()


def test_setup_does_not_copy_credentials_or_authorization_material(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    monkeypatch.setenv("GITLAB_TOKEN", "secret")
    setup = make_setup(tmp_path, discovery("agent-a"), [], [])

    setup.run(non_interactive=True)

    text = (tmp_path / "config.json").read_text(encoding="utf-8").casefold()
    assert "secret" not in text
    assert "password" not in text
    assert "token" not in text
    assert "authorization" not in text


def test_setup_returns_status_doctor_remove_and_rollback_commands(tmp_path):
    setup = make_setup(tmp_path, discovery(), [], [])

    result = setup.run(non_interactive=True)

    commands = result["commands"]
    assert set(commands) == {"status", "doctor", "scheduler_remove", "rollback"}
    assert all("rd_flywheel_cli.py" in command for command in commands.values())
    assert result["first_run"]["status"] == "ready"
