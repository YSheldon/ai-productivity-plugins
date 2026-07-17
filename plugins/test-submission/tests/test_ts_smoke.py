from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
CLI_PATH = SRC_ROOT / "test_submission_cli.py"
SCHEDULER_PATH = SRC_ROOT / "test_submission_scheduler.py"
SETUP_PATH = SRC_ROOT / "test_submission_setup.py"
sys.path.insert(0, str(SRC_ROOT))


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_setup_run_once_and_scheduler_smoke_without_codex_in_path(tmp_path: Path, monkeypatch) -> None:
    cli = _load(CLI_PATH, "test_submission_cli_smoke")
    setup_module = _load(SETUP_PATH, "test_submission_setup_smoke")
    scheduler_module = _load(SCHEDULER_PATH, "test_submission_scheduler_smoke")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", r"C:\Windows\System32")
    config_path = tmp_path / "config.json"
    dependency_lock = tmp_path / "dependency-lock.json"
    dependency_lock.write_text(json.dumps({"plugins": []}), encoding="utf-8")

    class FakeController:
        def preflight(self):
            return {"ready": True}

        def run_once(self):
            return {"status": "ready", "retried": 0, "sent": 0}

        def doctor(self):
            return {"ready": True}

        def status(self):
            return {"status": "ready", "events": 0, "pending_mail": 0}

    class FakeScheduler:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def install(self, *, mode: str):
            self.calls.append(("install", mode))
            return {"status": "ready", "mode": mode, "installed": True}

        def status(self, *, mode: str):
            self.calls.append(("status", mode))
            return {"status": "ready", "mode": mode, "installed": True}

        def remove(self, *, mode: str):
            self.calls.append(("remove", mode))
            return {"status": "ready", "mode": mode, "removed": True}

    scheduler = FakeScheduler()
    setup = setup_module.TestSubmissionSetup(
        config_path=config_path,
        repo_root=tmp_path,
        bootstrap_runner=lambda profile, *, repo_root: {"status": "ready", "dependency_lock": str(dependency_lock), "profile": profile, "repo_root": str(repo_root)},
        account_discoverer=lambda _lock, _digest: {"accounts": [{"name": "mail-primary", "email": "submitter@example.com"}]},
        controller_factory=lambda _path: FakeController(),
        scheduler_factory=lambda _path: scheduler,
        input_fn=lambda _prompt: "submission-gate@example.com",
    )
    setup_result = setup.run(non_interactive=True, scheduler_mode="auto", provided={"submission_gate_address": "submission-gate@example.com", "feishu_directory_url": ""})
    assert setup_result["status"] == "ready"
    assert "codex" not in os.environ["PATH"].lower()

    scheduler_for_cli = FakeScheduler()
    run_once_code = cli.run_cli(
        ["--config", str(config_path), "run-once"],
        controller_factory=lambda _path: FakeController(),
        scheduler_factory=lambda _path: scheduler_for_cli,
        setup_runner=lambda **_kwargs: {"status": "ready"},
    )
    assert run_once_code == cli.EXIT_OK

    commands: list[list[str]] = []

    def runner(command: list[str], cwd: str | None = None, input_text: str | None = None):
        del cwd, input_text
        commands.append(command)
        if command[:2] == ["schtasks", "/Create"]:
            return scheduler_module.subprocess.CompletedProcess(command, 0, stdout="SUCCESS", stderr="")
        if command[:2] == ["schtasks", "/Query"]:
            return scheduler_module.subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    '<?xml version="1.0" encoding="UTF-16"?>'
                    '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                    "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
                    "<StartWhenAvailable>false</StartWhenAvailable></Settings></Task>"
                ),
                stderr="",
            )
        if command[:2] == ["schtasks", "/Delete"]:
            return scheduler_module.subprocess.CompletedProcess(command, 0, stdout="SUCCESS", stderr="")
        raise AssertionError(command)

    os_scheduler = scheduler_module.TestSubmissionScheduler(config_path=config_path, state_dir=tmp_path / "state", poll_minutes=60, platform="win32", runner=runner)
    assert os_scheduler.install(mode="auto")["verification"]["installed"] is True
    assert os_scheduler.status(mode="windows")["installed"] is True
    assert os_scheduler.remove(mode="windows")["removed"] is True
    assert all(command[0].lower() != "codex" and not command[0].lower().endswith("\\codex.exe") for command in commands)
