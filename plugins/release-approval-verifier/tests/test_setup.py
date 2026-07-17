from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "verifier_setup.py"


def _load_module():
    assert MODULE_PATH.is_file(), f"missing setup module: {MODULE_PATH}"
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("verifier_setup", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("verifier_setup", module)
    spec.loader.exec_module(module)
    return module


class FakeController:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def preflight(self) -> dict[str, Any]:
        self.calls.append("preflight")
        return {"status": "ready"}

    def run_once(self) -> dict[str, Any]:
        self.calls.append("run_once")
        return {"status": "ready", "processed": 0}

    def status(self) -> dict[str, Any]:
        self.calls.append("status")
        return {"status": "ready", "missing_roles": 0}

    def doctor(self) -> dict[str, Any]:
        self.calls.append("doctor")
        return {"status": "ready", "checks": []}


class FakeScheduler:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def install(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("install", kwargs))
        return {"status": "ready", "mode": kwargs["mode"], "installed": True}

    def status(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("status", kwargs))
        return {"status": "ready", "mode": kwargs["mode"], "installed": True}


def _bootstrap(tmp_path: Path, calls: list[tuple[str, Path]]):
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text("{}\n", encoding="utf-8")

    def run(profile: str, *, repo_root: Path) -> dict[str, Any]:
        calls.append((profile, repo_root))
        return {
            "status": "ready",
            "fresh_task_required": False,
            "dependency_lock": str(dependency_lock),
        }

    return run


def test_setup_creates_one_config_with_at_most_four_prompts(tmp_path: Path) -> None:
    module = _load_module()
    config_path = tmp_path / "config" / "release-approval-verifier.json"
    prompts: list[str] = []
    answers = iter(
        (
            "release-group@example.com",
            "https://open.feishu.cn/docx/release-roles",
            "https://open.feishu.cn/wiki/release-audit",
            "mx.example.com",
        )
    )
    bootstrap_calls: list[tuple[str, Path]] = []
    controller = FakeController()
    scheduler = FakeScheduler()

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return next(answers)

    setup = module.VerifierSetup(
        config_path=config_path,
        repo_root=REPO_ROOT,
        bootstrap_runner=_bootstrap(tmp_path, bootstrap_calls),
        account_discoverer=lambda _lock, _digest: {
            "accounts": [{"name": "mail-primary", "email": "verifier@example.com"}]
        },
        controller_factory=lambda _config, _path: controller,
        scheduler_factory=lambda _config, _path: scheduler,
        input_fn=ask,
        timezone_detector=lambda: "Asia/Shanghai",
    )

    result = setup.run(non_interactive=False, scheduler_mode="auto")

    assert result["status"] == "ready"
    assert len(prompts) == 4
    assert len(prompts) <= 4
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["verifier_mail_account"] == {
        "profile": "mail-primary",
        "email": "verifier@example.com",
    }
    assert payload["release_group"] == "release-group@example.com"
    assert payload["role_source"] == {
        "type": "feishu",
        "document_url": "https://open.feishu.cn/docx/release-roles",
        "heading": "## 审批角色",
    }
    assert payload["audit_document"]["url"] == "https://open.feishu.cn/wiki/release-audit"
    assert payload["authentication_policy"]["allowed_authserv_ids"] == [
        "mx.example.com"
    ]
    assert payload["dependency_lock_sha256"] == module.sha256_file(
        Path(payload["dependency_lock"])
    )
    assert "password" not in json.dumps(payload).lower()
    assert bootstrap_calls == [("release-approval-verifier", REPO_ROOT)]
    assert controller.calls == ["preflight", "run_once", "status", "doctor"]
    assert scheduler.calls == [
        ("install", {"mode": "auto"}),
        ("status", {"mode": "auto"}),
    ]
    assert "scheduler remove" in result["rollback_command"]


def test_setup_rerun_uses_existing_config_with_zero_prompts(tmp_path: Path) -> None:
    module = _load_module()
    config_path = tmp_path / "release-approval-verifier.json"
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text("{}\n", encoding="utf-8")
    payload = {
        "mode": "production",
        "role_source": {"type": "feishu", "document_url": "https://open.feishu.cn/docx/roles"},
        "release_group": "release@example.com",
        "verifier_mail_account": {"profile": "mail-primary", "email": "verifier@example.com"},
        "event_expiry_hours": 24,
        "poll_minutes": 60,
        "timezone": "UTC",
        "working_hours": {"days": ["Mon"], "start": "09:00", "end": "18:00"},
        "reminder_policy": {"initial_delay_minutes": 60, "repeat_minutes": 240, "maximum": 3},
        "authentication_policy": {
            "accepted_paths": ["dmarc", "dkim", "spf"],
            "allowed_authserv_ids": ["mx.example.com"],
            "trusted_internal_header": "X-Trusted-Relay",
            "trusted_internal_value": "release-gateway",
        },
        "state_dir": str(tmp_path / "state"),
        "dependency_lock": str(dependency_lock),
        "dependency_lock_sha256": module.sha256_file(dependency_lock),
        "audit_document": {"url": "https://open.feishu.cn/wiki/audit"},
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    setup = module.VerifierSetup(
        config_path=config_path,
        repo_root=REPO_ROOT,
        bootstrap_runner=lambda _profile, *, repo_root: {
            "status": "ready",
            "fresh_task_required": False,
            "dependency_lock": str(dependency_lock),
            "repo_root": str(repo_root),
        },
        account_discoverer=lambda _lock, _digest: (_ for _ in ()).throw(AssertionError("must not rediscover")),
        controller_factory=lambda _config, _path: FakeController(),
        scheduler_factory=lambda _config, _path: FakeScheduler(),
        input_fn=lambda _prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
        timezone_detector=lambda: "UTC",
    )

    assert setup.run(non_interactive=False, scheduler_mode="auto")["prompt_count"] == 0
    assert setup.run(non_interactive=False, scheduler_mode="auto")["prompt_count"] == 0


def test_non_interactive_setup_fails_before_partial_write_when_input_is_missing(tmp_path: Path) -> None:
    module = _load_module()
    config_path = tmp_path / "release-approval-verifier.json"
    calls: list[tuple[str, Path]] = []
    setup = module.VerifierSetup(
        config_path=config_path,
        repo_root=REPO_ROOT,
        bootstrap_runner=_bootstrap(tmp_path, calls),
        account_discoverer=lambda _lock, _digest: {"accounts": []},
        controller_factory=lambda _config, _path: FakeController(),
        scheduler_factory=lambda _config, _path: FakeScheduler(),
        input_fn=lambda _prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
        timezone_detector=lambda: "UTC",
    )

    with pytest.raises(module.SetupError) as excinfo:
        setup.run(non_interactive=True, scheduler_mode="auto")

    assert excinfo.value.code == "SETUP_INPUT_REQUIRED"
    assert not config_path.exists()
