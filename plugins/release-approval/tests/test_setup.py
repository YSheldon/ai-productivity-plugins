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
MODULE_PATH = SRC_ROOT / "release_approval_setup.py"


def _load_module():
    assert MODULE_PATH.is_file(), f"missing setup module: {MODULE_PATH}"
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("release_approval_setup", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("release_approval_setup", module)
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
        return {"status": "ready", "matched_events": 0}

    def status(self) -> dict[str, Any]:
        self.calls.append("status")
        return {"status": "ready", "pending_count": 0}

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


def test_setup_creates_one_config_with_no_json_editing_and_at_most_four_prompts(
    tmp_path: Path,
) -> None:
    module = _load_module()
    config_path = tmp_path / "config" / "release-approval.json"
    prompts: list[str] = []
    answers = iter(
        (
            "release-manager",
            "release-group@example.com",
            "release-gate@example.com",
            "mx.example.com",
        )
    )
    bootstrap_calls: list[tuple[str, Path]] = []
    controller = FakeController()
    scheduler = FakeScheduler()

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return next(answers)

    setup = module.ReleaseApprovalSetup(
        config_path=config_path,
        repo_root=REPO_ROOT,
        bootstrap_runner=_bootstrap(tmp_path, bootstrap_calls),
        account_discoverer=lambda _lock: {
            "accounts": [{"name": "mail-primary", "email": "approver@example.com"}]
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
    assert config_path.is_file()
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["role_id"] == "release-manager"
    assert payload["role_email"] == "approver@example.com"
    assert payload["mail_account"] == {
        "profile": "mail-primary",
        "email": "approver@example.com",
    }
    assert payload["release_group"] == "release-group@example.com"
    assert payload["request_authentication"] == {
        "allowed_sender_emails": ["release-gate@example.com"],
        "allowed_authserv_ids": ["mx.example.com"],
        "accepted_paths": ["dmarc", "dkim", "spf"],
    }
    assert payload["timezone"] == "Asia/Shanghai"
    assert "password" not in json.dumps(payload).lower()
    assert bootstrap_calls == [("release-approval", REPO_ROOT)]
    assert controller.calls == ["preflight", "run_once", "status", "doctor"]
    assert scheduler.calls == [
        ("install", {"mode": "auto"}),
        ("status", {"mode": "auto"}),
    ]
    assert "scheduler remove" in result["rollback_command"]


def test_setup_rerun_uses_existing_config_with_zero_prompts(tmp_path: Path) -> None:
    module = _load_module()
    config_path = tmp_path / "release-approval.json"
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text("{}\n", encoding="utf-8")
    config_path.write_text(
        json.dumps(
            {
                "role_id": "release-manager",
                "role_email": "approver@example.com",
                "mail_account": {
                    "profile": "mail-primary",
                    "email": "approver@example.com",
                },
                "release_group": "release-group@example.com",
                "request_authentication": {
                    "allowed_sender_emails": ["release-gate@example.com"],
                    "allowed_authserv_ids": ["mx.example.com"],
                    "accepted_paths": ["dmarc", "dkim", "spf"],
                },
                "mailbox": "INBOX",
                "page": {"host": "127.0.0.1", "port": 8765},
                "poll_minutes": 60,
                "timezone": "UTC",
                "working_hours": {
                    "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
                    "start": "09:00",
                    "end": "18:00",
                },
                "state_dir": str(tmp_path / "state"),
                "dependency_lock": str(dependency_lock),
                "audit": {"verify_chain_on_startup": True, "retention_days": 3650},
            }
        ),
        encoding="utf-8",
    )
    prompt_count = 0

    def unexpected_prompt(_prompt: str) -> str:
        nonlocal prompt_count
        prompt_count += 1
        raise AssertionError("rerun must not prompt")

    setup = module.ReleaseApprovalSetup(
        config_path=config_path,
        repo_root=REPO_ROOT,
        bootstrap_runner=lambda _profile, *, repo_root: {
            "status": "ready",
            "fresh_task_required": False,
            "dependency_lock": str(dependency_lock),
            "repo_root": str(repo_root),
        },
        account_discoverer=lambda _lock: (_ for _ in ()).throw(
            AssertionError("existing config must not rediscover accounts")
        ),
        controller_factory=lambda _config, _path: FakeController(),
        scheduler_factory=lambda _config, _path: FakeScheduler(),
        input_fn=unexpected_prompt,
        timezone_detector=lambda: "UTC",
    )

    first = setup.run(non_interactive=False, scheduler_mode="auto")
    second = setup.run(non_interactive=False, scheduler_mode="auto")

    assert first["status"] == "ready"
    assert second["status"] == "ready"
    assert prompt_count == 0


def test_non_interactive_setup_fails_before_partial_write_when_input_is_missing(
    tmp_path: Path,
) -> None:
    module = _load_module()
    config_path = tmp_path / "release-approval.json"
    bootstrap_calls: list[tuple[str, Path]] = []

    setup = module.ReleaseApprovalSetup(
        config_path=config_path,
        repo_root=REPO_ROOT,
        bootstrap_runner=_bootstrap(tmp_path, bootstrap_calls),
        account_discoverer=lambda _lock: {"accounts": []},
        controller_factory=lambda _config, _path: FakeController(),
        scheduler_factory=lambda _config, _path: FakeScheduler(),
        input_fn=lambda _prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
        timezone_detector=lambda: "UTC",
    )

    with pytest.raises(module.SetupError) as excinfo:
        setup.run(non_interactive=True, scheduler_mode="auto")

    assert excinfo.value.code == "SETUP_INPUT_REQUIRED"
    assert not config_path.exists()

def test_non_interactive_setup_persists_optional_cloud_audit_url_without_prompt(
    tmp_path: Path,
) -> None:
    module = _load_module()
    config_path = tmp_path / "release-approval.json"
    setup = module.ReleaseApprovalSetup(
        config_path=config_path,
        repo_root=REPO_ROOT,
        bootstrap_runner=_bootstrap(tmp_path, []),
        account_discoverer=lambda _lock: {
            "accounts": [{"name": "mail-primary", "email": "approver@example.com"}]
        },
        controller_factory=lambda _config, _path: FakeController(),
        scheduler_factory=lambda _config, _path: FakeScheduler(),
        input_fn=lambda _prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
        timezone_detector=lambda: "UTC",
        environ={},
    )

    result = setup.run(
        non_interactive=True,
        scheduler_mode="auto",
        provided={
            "role_id": "release-manager",
            "role_email": "approver@example.com",
            "mail_profile": "mail-primary",
            "release_group": "release-group@example.com",
            "request_sender_email": "release-gate@example.com",
            "trusted_authserv_ids": "mx1.example.com,mx2.example.com",
            "audit_document_url": "https://example.com/audit/doc",
        },
    )

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert result["prompt_count"] == 0
    assert payload["request_authentication"]["allowed_authserv_ids"] == [
        "mx1.example.com",
        "mx2.example.com",
    ]
    assert payload["audit"]["document_url"] == "https://example.com/audit/doc"
