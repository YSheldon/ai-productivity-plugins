import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_config import load_config  # noqa: E402
from rd_flywheel_setup import DiscoveryResult, RDFlywheelSetup, SetupError  # noqa: E402


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
    lock = tmp_path / "dependency-lock.rd-flywheel.json"
    lock.write_text('{"plugins":[]}\n', encoding="utf-8")
    answers = {
        "Configured enterprise mail profile": "corp-mail",
        "R&D governance decision mail group": "governance@example.com",
        "Feishu decision role document URL": "https://example.feishu.cn/docx/roles",
    }
    return RDFlywheelSetup(
        config_path=tmp_path / "config.json",
        discoverer=lambda: found,
        prompt=lambda label, default: prompts.append((label, default)) or answers[label],
        dependency_bootstrapper=lambda: {
            "dependency_lock": str(lock),
            "fresh_task_required": False,
        },
        controller_factory=lambda config: FakeController(calls),
        scheduler_factory=lambda config, path: FakeScheduler(calls),
    )


def test_setup_uses_at_most_three_prompts_and_activates_in_order(tmp_path):
    prompts = []
    calls = []
    setup = make_setup(tmp_path, discovery("agent-a", "agent-b"), prompts, calls)

    result = setup.run(non_interactive=False, agent_profile="agent-a")

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

    result = setup.run(
        non_interactive=True,
        mail_profile="corp-mail",
        governance_group="governance@example.com",
        role_document_url="https://example.feishu.cn/docx/roles",
    )

    assert prompts == []
    config = load_config(tmp_path / "config.json")
    assert config.agent_profile is None
    assert result["preflight"]["status"] in {"ready", "CAPABILITY_BLOCKED"}


def test_single_agent_and_default_paths_need_no_noninteractive_input(tmp_path):
    setup = make_setup(tmp_path, discovery("agent-a"), [], [])

    setup.run(
        non_interactive=True,
        mail_profile="corp-mail",
        governance_group="governance@example.com",
        role_document_url="https://example.feishu.cn/docx/roles",
    )

    config = load_config(tmp_path / "config.json")
    assert config.agent_profile == "agent-a"
    assert config.governance_inbox == (tmp_path / "inbox").resolve()
    assert config.state_dir == (tmp_path / "state").resolve()


def test_setup_does_not_copy_credentials_or_authorization_material(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    monkeypatch.setenv("GITLAB_TOKEN", "secret")
    setup = make_setup(tmp_path, discovery("agent-a"), [], [])

    setup.run(
        non_interactive=True,
        mail_profile="corp-mail",
        governance_group="governance@example.com",
        role_document_url="https://example.feishu.cn/docx/roles",
    )

    text = (tmp_path / "config.json").read_text(encoding="utf-8").casefold()
    assert "secret" not in text
    assert "password" not in text
    assert "token" not in text
    assert "authorization" not in text


def test_setup_returns_status_doctor_remove_and_rollback_commands(tmp_path):
    setup = make_setup(tmp_path, discovery(), [], [])

    result = setup.run(
        non_interactive=True,
        mail_profile="corp-mail",
        governance_group="governance@example.com",
        role_document_url="https://example.feishu.cn/docx/roles",
    )

    commands = result["commands"]
    assert set(commands) == {"status", "doctor", "scheduler_remove", "rollback"}
    assert all("rd_flywheel_cli.py" in command for command in commands.values())
    assert result["first_run"]["status"] == "ready"


def test_setup_migrates_v1_config_with_frozen_dependency_lock_and_no_prompt(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "governance_inbox": str(tmp_path / "legacy-inbox"),
                "state_dir": str(tmp_path / "legacy-state"),
                "poll_minutes": 30,
                "timezone": "Asia/Shanghai",
                "tool_profiles": ["gitlab"],
                "approved_agent_profiles": ["agent-a"],
                "agent_profile": "agent-a",
                "protected_merge": {
                    "tool_profile": "gitlab",
                    "protected_branch_required": True,
                },
                "notification": {
                    "mail_profile": "corp-mail",
                    "recipients": ["governance@example.com"],
                },
                "decision_role_source": {
                    "type": "feishu",
                    "document_url": "https://example.feishu.cn/docx/roles",
                    "heading": "## Frozen Roles",
                },
                "dependency_lock": str(tmp_path / "obsolete-lock.json"),
            }
        ),
        encoding="utf-8",
    )
    lock = tmp_path / "dependency-lock.rd-flywheel.json"
    lock.write_text('{"plugins":[]}\n', encoding="utf-8")
    calls = []
    setup = RDFlywheelSetup(
        config_path=config_path,
        discoverer=lambda: discovery("agent-a"),
        prompt=lambda *_: pytest.fail("migration must not prompt when v1 values exist"),
        dependency_bootstrapper=lambda: {
            "dependency_lock": str(lock),
            "fresh_task_required": False,
        },
        controller_factory=lambda config: FakeController(calls),
        scheduler_factory=lambda config, path: FakeScheduler(calls),
    )

    result = setup.run(non_interactive=True)

    assert result["status"] == "ready"
    assert result["config_reused"] is True
    assert result["config_migrated"] is True
    assert result["prompt_count"] == 0
    config = load_config(config_path)
    assert config.schema_version == 2
    assert config.dependency_lock == lock.resolve()
    assert config.dependency_lock_sha256 == __import__("hashlib").sha256(
        lock.read_bytes()
    ).hexdigest()
    assert config.notification.recipients == ("governance@example.com",)
    assert config.decision_role_source.heading == "## Frozen Roles"


def test_v1_migration_fails_closed_without_required_noninteractive_values(tmp_path):
    config_path = tmp_path / "config.json"
    original = {
        "schema_version": 1,
        "governance_inbox": str(tmp_path / "inbox"),
        "state_dir": str(tmp_path / "state"),
        "poll_minutes": 60,
        "timezone": "Asia/Shanghai",
        "tool_profiles": ["gitlab"],
        "approved_agent_profiles": [],
        "agent_profile": None,
        "protected_merge": {
            "tool_profile": "gitlab",
            "protected_branch_required": True,
        },
        "notification": None,
        "decision_role_source": None,
        "dependency_lock": str(tmp_path / "obsolete-lock.json"),
    }
    config_path.write_text(json.dumps(original), encoding="utf-8")
    setup = RDFlywheelSetup(
        config_path=config_path,
        discoverer=lambda: discovery(),
        prompt=lambda *_: pytest.fail("non-interactive migration must not prompt"),
        dependency_bootstrapper=lambda: pytest.fail(
            "missing governance values must block before dependency changes"
        ),
    )

    with pytest.raises(SetupError) as caught:
        setup.run(non_interactive=True)

    assert caught.value.code == "SETUP_INPUT_REQUIRED"
    assert json.loads(config_path.read_text(encoding="utf-8")) == original


def test_v1_migration_validation_failure_preserves_original_config(tmp_path):
    config_path = tmp_path / "config.json"
    original = {
        "schema_version": 1,
        "governance_inbox": str(tmp_path / "inbox"),
        "state_dir": str(tmp_path / "state"),
        "poll_minutes": 1,
        "timezone": "Asia/Shanghai",
        "tool_profiles": ["gitlab"],
        "approved_agent_profiles": [],
        "agent_profile": None,
        "protected_merge": {
            "tool_profile": "gitlab",
            "protected_branch_required": True,
        },
        "notification": {
            "mail_profile": "corp-mail",
            "recipients": ["governance@example.com"],
        },
        "decision_role_source": {
            "type": "feishu",
            "document_url": "https://example.feishu.cn/docx/roles",
            "heading": "## Frozen Roles",
        },
        "dependency_lock": str(tmp_path / "obsolete-lock.json"),
    }
    original_text = json.dumps(original)
    config_path.write_text(original_text, encoding="utf-8")
    lock = tmp_path / "dependency-lock.rd-flywheel.json"
    lock.write_text('{"plugins":[]}\n', encoding="utf-8")
    setup = RDFlywheelSetup(
        config_path=config_path,
        discoverer=lambda: discovery(),
        prompt=lambda *_: pytest.fail("complete v1 input must not prompt"),
        dependency_bootstrapper=lambda: {
            "dependency_lock": str(lock),
            "fresh_task_required": False,
        },
    )

    with pytest.raises(SetupError) as caught:
        setup.run(non_interactive=True)

    assert caught.value.code == "CONFIG_ERROR"
    assert config_path.read_text(encoding="utf-8") == original_text
    assert list(tmp_path.glob(".config.json.*.candidate")) == []


def test_setup_reports_missing_dependency_lock_as_capability_blocked(tmp_path):
    setup = RDFlywheelSetup(
        config_path=tmp_path / "config.json",
        discoverer=lambda: discovery(),
        dependency_bootstrapper=lambda: {"fresh_task_required": False},
    )

    with pytest.raises(SetupError) as caught:
        setup.run(
            non_interactive=True,
            mail_profile="corp-mail",
            governance_group="governance@example.com",
            role_document_url="https://example.feishu.cn/docx/roles",
        )

    assert caught.value.code == "CAPABILITY_BLOCKED"
    assert not (tmp_path / "config.json").exists()
