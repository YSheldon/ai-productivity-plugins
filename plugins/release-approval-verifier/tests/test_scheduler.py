from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "verifier_scheduler.py"


def _load_module():
    assert MODULE_PATH.is_file(), f"missing scheduler module: {MODULE_PATH}"
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("verifier_scheduler", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("verifier_scheduler", module)
    spec.loader.exec_module(module)
    return module


def _build_scheduler(module: Any, tmp_path: Path, **overrides: Any):
    config_path = tmp_path / "config" / "release-approval-verifier.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("{}", encoding="utf-8")
    state_dir = tmp_path / "state"
    defaults = {
        "plugin_name": "release-approval-verifier",
        "role_id": "runtime",
        "config_path": config_path,
        "state_dir": state_dir,
        "poll_minutes": 60,
        "platform": "linux",
        "which": lambda name: None,
    }
    defaults.update(overrides)
    return module.VerifierScheduler(**defaults)


def test_scheduler_module_exists_and_default_runner_uses_argument_arrays_without_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    seen: dict[str, Any] = {}

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0, stdout="{}", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    command = ["py", "-3", "verifier_cli.py", "run-once"]

    module.run_command(command, cwd="C:\\state", input_text="payload")

    assert seen["args"][0] == command
    assert isinstance(seen["args"][0], list)
    assert seen["kwargs"]["cwd"] == "C:\\state"
    assert seen["kwargs"]["input"] == "payload"
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["check"] is False
    assert seen["kwargs"]["capture_output"] is True
    assert seen["kwargs"]["text"] is True


def test_default_runner_decodes_windows_task_xml_once_as_utf16(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    seen: dict[str, Any] = {}

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0, stdout="<Task />", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module.run_command(["schtasks", "/Query", "/TN", "task", "/XML"])

    assert seen["kwargs"]["encoding"] == "utf-16"
    assert "text" not in seen["kwargs"]


def test_builds_absolute_run_once_command_and_safe_identity(tmp_path: Path) -> None:
    module = _load_module()
    scheduler = _build_scheduler(module, tmp_path)

    assert scheduler.identity == "release-approval-verifier.runtime"
    assert scheduler.scheduled_command == [
        sys.executable,
        str((SRC_ROOT / "verifier_cli.py").resolve()),
        "--config",
        str((tmp_path / "config" / "release-approval-verifier.json").resolve()),
        "run-once",
    ]
    assert scheduler.metadata_path == (tmp_path / "state" / "setup" / "scheduler-install.json").resolve()


@pytest.mark.parametrize(
    ("plugin_name", "role_id"),
    [
        ("release approval", "runtime"),
        ("release-approval-verifier", "bad/role"),
        ("release-approval-verifier", "x" * 81),
    ],
)
def test_rejects_invalid_scheduler_identity_inputs_with_stable_code(
    tmp_path: Path,
    plugin_name: str,
    role_id: str,
) -> None:
    module = _load_module()

    with pytest.raises(module.SchedulerError) as excinfo:
        _build_scheduler(module, tmp_path, plugin_name=plugin_name, role_id=role_id)

    assert excinfo.value.code == "INVALID_SCHEDULER_IDENTITY"


def test_auto_mode_prefers_windows_then_systemd_then_cron_and_never_codex(tmp_path: Path) -> None:
    module = _load_module()

    windows = _build_scheduler(
        module,
        tmp_path / "windows",
        platform="win32",
        which=lambda name: "/usr/bin/systemctl",
    )
    assert windows.resolve_mode("auto") == "windows"

    systemd = _build_scheduler(
        module,
        tmp_path / "systemd",
        platform="linux",
        which=lambda name: "/usr/bin/systemctl" if name == "systemctl" else None,
        runner=lambda command, cwd, input_text: subprocess.CompletedProcess(
            command,
            0 if command == ["systemctl", "--user", "show-environment"] else 1,
            stdout="",
            stderr="",
        ),
    )
    assert systemd.resolve_mode("auto") == "systemd"

    cron = _build_scheduler(module, tmp_path / "cron", platform="linux", which=lambda name: None)
    assert cron.resolve_mode("auto") == "cron"
    assert cron.resolve_mode("codex") == "codex"


def test_auto_mode_falls_back_to_cron_when_systemd_user_manager_is_unavailable(
    tmp_path: Path,
) -> None:
    module = _load_module()

    scheduler = _build_scheduler(
        module,
        tmp_path,
        platform="linux",
        which=lambda name: "/usr/bin/systemctl" if name == "systemctl" else None,
        runner=lambda command, cwd, input_text: subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="Failed to connect to bus",
        ),
    )

    assert scheduler.resolve_mode("auto") == "cron"


def test_windows_install_status_and_remove_use_schtasks_and_persist_metadata(tmp_path: Path) -> None:
    module = _load_module()
    commands: list[tuple[list[str], str | None, str | None]] = []

    def runner(
        command: list[str],
        cwd: str | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        commands.append((command, cwd, input_text))
        if command[:2] == ["schtasks", "/Create"]:
            return subprocess.CompletedProcess(command, 0, stdout="SUCCESS\n", stderr="")
        if command[:2] == ["schtasks", "/Query"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    '<?xml version="1.0" encoding="UTF-16"?>'
                    '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                    '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
                    '<StartWhenAvailable>false</StartWhenAvailable></Settings></Task>'
                ),
                stderr="",
            )
        if command[:2] == ["schtasks", "/Delete"]:
            return subprocess.CompletedProcess(command, 0, stdout="SUCCESS\n", stderr="")
        raise AssertionError(f"unexpected command: {command}")

    scheduler = _build_scheduler(
        module,
        tmp_path,
        platform="win32",
        runner=runner,
        poll_minutes=15,
    )

    install_result = scheduler.install(mode="auto")

    assert install_result["status"] == "ready"
    assert install_result["mode"] == "windows"
    assert install_result["verification"]["misfire_policy_verified"] is True
    assert install_result["verification"]["overlap_policy_verified"] is True
    assert commands[0][0][:4] == ["schtasks", "/Create", "/TN", scheduler.identity]
    assert commands[0][0][commands[0][0].index("/SC") : commands[0][0].index("/SC") + 4] == [
        "/SC",
        "MINUTE",
        "/MO",
        "15",
    ]
    assert commands[0][0][commands[0][0].index("/TR") + 1] == subprocess.list2cmdline(scheduler.scheduled_command)
    metadata = json.loads(scheduler.metadata_path.read_text(encoding="utf-8"))
    assert metadata["mode"] == "windows"
    assert metadata["identity"] == scheduler.identity
    assert metadata["poll_minutes"] == 15
    assert metadata["config_path"] == str((tmp_path / "config" / "release-approval-verifier.json").resolve())
    assert "password" not in json.dumps(metadata).lower()

    status_result = scheduler.status(mode="windows")
    assert status_result["installed"] is True
    assert status_result["misfire_policy_verified"] is True
    assert status_result["overlap_policy_verified"] is True
    query = next(command for command, _cwd, _input in commands if command[:2] == ["schtasks", "/Query"])
    assert "/XML" in query

    remove_result = scheduler.remove(mode="windows")
    assert remove_result["removed"] is True
    assert any(command[:2] == ["schtasks", "/Delete"] for command, _cwd, _input in commands)



def test_windows_uses_daily_schedule_for_1440_minutes_and_fails_closed_on_remove_error(
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []
    module = _load_module()

    def runner(
        command: list[str],
        cwd: str | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, input_text
        commands.append(command)
        if command[:2] == ["schtasks", "/Create"]:
            return subprocess.CompletedProcess(command, 0, stdout="SUCCESS\n", stderr="")
        if command[:2] == ["schtasks", "/Query"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                    '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
                    '<StartWhenAvailable>false</StartWhenAvailable></Settings></Task>'
                ),
                stderr="",
            )
        if command[:2] == ["schtasks", "/Delete"]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="Access is denied.")
        raise AssertionError(f"unexpected command: {command}")

    scheduler = _build_scheduler(
        module,
        tmp_path,
        platform="win32",
        runner=runner,
        poll_minutes=1440,
    )
    scheduler.install(mode="windows")
    create = commands[0]

    assert create[create.index("/SC") : create.index("/SC") + 4] == [
        "/SC",
        "DAILY",
        "/MO",
        "1",
    ]
    with pytest.raises(module.SchedulerError) as excinfo:
        scheduler.remove(mode="windows")
    assert excinfo.value.code == "SCHEDULER_REMOVE_FAILED"


def test_systemd_install_writes_user_units_and_queries_external_state(tmp_path: Path) -> None:
    module = _load_module()
    commands: list[tuple[list[str], str | None, str | None]] = []

    def runner(
        command: list[str],
        cwd: str | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        commands.append((command, cwd, input_text))
        if command == ["systemctl", "--user", "show-environment"]:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[:3] == ["systemctl", "--user", "daemon-reload"]:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[:4] == ["systemctl", "--user", "enable", "--now"]:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[:3] == ["systemctl", "--user", "is-active"]:
            return subprocess.CompletedProcess(command, 0, stdout="active\n", stderr="")
        if command[:3] == ["systemctl", "--user", "is-enabled"]:
            return subprocess.CompletedProcess(command, 0, stdout="enabled\n", stderr="")
        if command[:4] == ["systemctl", "--user", "disable", "--now"]:
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected command: {command}")

    user_config_root = tmp_path / "user-config"
    scheduler = _build_scheduler(
        module,
        tmp_path,
        platform="linux",
        which=lambda name: "/usr/bin/systemctl" if name == "systemctl" else None,
        user_config_root=user_config_root,
        runner=runner,
        poll_minutes=30,
    )

    install_result = scheduler.install(mode="auto")

    assert install_result["mode"] == "systemd"
    service_path = user_config_root / "systemd" / "user" / f"{scheduler.identity}.service"
    timer_path = user_config_root / "systemd" / "user" / f"{scheduler.identity}.timer"
    service_text = service_path.read_text(encoding="utf-8")
    timer_text = timer_path.read_text(encoding="utf-8")
    assert f"Description=Release approval scheduler for {scheduler.identity}" in service_text
    assert str((SRC_ROOT / "verifier_cli.py").resolve()) in service_text
    assert "OnUnitActiveSec=30min" in timer_text
    assert "Persistent=false" in timer_text
    assert ["systemctl", "--user", "daemon-reload"] in [
        command for command, _cwd, _input in commands
    ]
    assert ["systemctl", "--user", "is-active", f"{scheduler.identity}.timer"] in [command for command, _cwd, _input in commands]
    assert ["systemctl", "--user", "is-enabled", f"{scheduler.identity}.timer"] in [command for command, _cwd, _input in commands]
    status_result = scheduler.status(mode="systemd")
    assert status_result["misfire_policy_verified"] is True
    assert status_result["overlap_policy"] == "kernel_run_lock"

    remove_result = scheduler.remove(mode="systemd")
    assert remove_result["removed"] is True
    assert not service_path.exists()
    assert not timer_path.exists()


def test_cron_fallback_preserves_unrelated_lines_and_owns_one_unique_marker(tmp_path: Path) -> None:
    module = _load_module()
    commands: list[tuple[list[str], str | None, str | None]] = []
    current_crontab = "MAILTO=ops@example.com\n0 1 * * * /usr/bin/backup\n"

    def runner(
        command: list[str],
        cwd: str | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal current_crontab
        commands.append((command, cwd, input_text))
        if command == ["crontab", "-l"]:
            return subprocess.CompletedProcess(command, 0, stdout=current_crontab, stderr="")
        if command == ["crontab", "-"]:
            current_crontab = input_text or ""
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected command: {command}")

    scheduler = _build_scheduler(
        module,
        tmp_path,
        platform="linux",
        which=lambda name: None,
        runner=runner,
        poll_minutes=15,
    )

    install_result = scheduler.install(mode="auto")
    assert install_result["mode"] == "cron"
    marker = scheduler.cron_marker
    assert "MAILTO=ops@example.com" in current_crontab
    assert current_crontab.count(marker) == 1
    assert "*/15 * * * *" in current_crontab

    scheduler.install(mode="cron")
    assert current_crontab.count(marker) == 1

    status_result = scheduler.status(mode="cron")
    assert status_result["installed"] is True
    assert status_result["entry_count"] == 1
    assert status_result["misfire_policy_verified"] is True
    assert status_result["overlap_policy"] == "kernel_run_lock"
    assert any(command == ["crontab", "-l"] for command, _cwd, _input in commands)

    remove_result = scheduler.remove(mode="cron")
    assert remove_result["removed"] is True
    assert marker not in current_crontab
    assert "MAILTO=ops@example.com" in current_crontab
