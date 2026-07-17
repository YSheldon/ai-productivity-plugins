import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_scheduler import RDFlywheelScheduler, SchedulerError  # noqa: E402


WINDOWS_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>false</StartWhenAvailable>
  </Settings>
</Task>
"""


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.crontab = "# unrelated\n"
        self.fail_delete = False
        self.systemd_user_usable = True

    def __call__(self, args, *, encoding=None, input_text=None):
        args = list(args)
        self.calls.append((args, encoding, input_text))
        if args[:3] == ["schtasks", "/Query", "/TN"]:
            return subprocess.CompletedProcess(args, 0, WINDOWS_XML, "")
        if args[:2] == ["schtasks", "/Delete"]:
            if self.fail_delete:
                return subprocess.CompletedProcess(args, 1, "", "Access is denied")
            return subprocess.CompletedProcess(args, 0, "SUCCESS", "")
        if args[:2] == ["systemctl", "--user"] and "show-environment" in args:
            code = 0 if self.systemd_user_usable else 1
            return subprocess.CompletedProcess(args, code, "", "no user bus" if code else "")
        if args[:2] == ["systemctl", "--user"]:
            return subprocess.CompletedProcess(args, 0, "enabled\n", "")
        if args == ["crontab", "-l"]:
            return subprocess.CompletedProcess(args, 0, self.crontab, "")
        if args and args[0] == "crontab" and len(args) == 2:
            self.crontab = Path(args[1]).read_text(encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")


def scheduler(tmp_path, *, platform_name="win32", poll_minutes=60, runner=None, which=None):
    return RDFlywheelScheduler(
        config_path=tmp_path / "config.json",
        cli_path=ROOT / "src" / "rd_flywheel_cli.py",
        state_dir=tmp_path / "state",
        poll_minutes=poll_minutes,
        platform_name=platform_name,
        python_executable=Path(sys.executable),
        command_runner=runner or FakeRunner(),
        which=which or (lambda name: name),
        home=tmp_path / "home",
    )


def test_scheduled_command_is_absolute_cli_run_once_without_codex(tmp_path):
    instance = scheduler(tmp_path)
    command = instance.run_command
    assert command[0] == str(Path(sys.executable).resolve())
    assert command[1] == str((ROOT / "src" / "rd_flywheel_cli.py").resolve())
    assert command[-1] == "run-once"
    assert "--config" in command
    assert command[0].casefold().endswith("python.exe")
    assert not command[0].casefold().endswith("codex")


def test_windows_uses_daily_for_1440_and_verifies_skip_missed_policy(tmp_path):
    runner = FakeRunner()
    instance = scheduler(tmp_path, poll_minutes=1440, runner=runner)

    result = instance.install(mode="windows")

    create = next(call for call, _, _ in runner.calls if call[:2] == ["schtasks", "/Create"])
    assert "/SC" in create and create[create.index("/SC") + 1] == "DAILY"
    assert "/MO" in create and create[create.index("/MO") + 1] == "1"
    query = next(item for item in runner.calls if item[0][:3] == ["schtasks", "/Query", "/TN"])
    assert query[1] == "utf-16"
    assert result["policy"] == {
        "overlap": "IgnoreNew",
        "missed_intervals": "skip_all",
        "start_when_available": False,
    }


def test_windows_delete_failure_is_not_reported_as_removed(tmp_path):
    runner = FakeRunner()
    runner.fail_delete = True
    instance = scheduler(tmp_path, runner=runner)
    with pytest.raises(SchedulerError, match="Access is denied"):
        instance.remove(mode="windows")


def test_auto_falls_back_to_cron_when_systemd_user_bus_is_unusable(tmp_path):
    runner = FakeRunner()
    runner.systemd_user_usable = False
    instance = scheduler(
        tmp_path,
        platform_name="linux",
        runner=runner,
        which=lambda name: f"/usr/bin/{name}",
    )

    assert instance.resolve_mode("auto") == "cron"


def test_systemd_timer_is_nonpersistent_and_ignore_new_is_kernel_locked(tmp_path):
    runner = FakeRunner()
    instance = scheduler(
        tmp_path,
        platform_name="linux",
        runner=runner,
        which=lambda name: f"/usr/bin/{name}",
    )

    result = instance.install(mode="systemd")

    timer = (tmp_path / "home" / ".config" / "systemd" / "user" / "rd-flywheel.timer")
    service = timer.with_suffix(".service")
    assert "Persistent=false" in timer.read_text(encoding="utf-8")
    assert "ExecStart=" in service.read_text(encoding="utf-8")
    assert result["policy"]["missed_intervals"] == "skip_all"
    assert result["policy"]["overlap"] == "kernel_lock"


def test_cron_install_is_idempotent_and_preserves_unrelated_entries(tmp_path):
    runner = FakeRunner()
    instance = scheduler(
        tmp_path,
        platform_name="linux",
        runner=runner,
        which=lambda name: f"/usr/bin/{name}",
    )

    first = instance.install(mode="cron")
    second = instance.install(mode="cron")

    assert runner.crontab.startswith("# unrelated\n")
    assert runner.crontab.count(instance.cron_marker) == 1
    assert first["status"] == second["status"] == "ready"
    assert first["policy"]["missed_intervals"] == "skip_all"


def test_cron_status_fails_closed_when_missing_or_duplicated(tmp_path):
    runner = FakeRunner()
    instance = scheduler(
        tmp_path,
        platform_name="linux",
        runner=runner,
        which=lambda name: f"/usr/bin/{name}",
    )
    assert instance.status(mode="cron")["status"] == "CAPABILITY_BLOCKED"
    entry = instance.render_cron_entry()
    runner.crontab = entry + "\n" + entry + "\n"
    assert instance.status(mode="cron")["status"] == "CAPABILITY_BLOCKED"


@pytest.mark.parametrize("poll_minutes", [61, 90, 1439])
def test_cron_rejects_intervals_it_cannot_represent_exactly(tmp_path, poll_minutes):
    instance = scheduler(
        tmp_path,
        platform_name="linux",
        poll_minutes=poll_minutes,
        which=lambda name: f"/usr/bin/{name}",
    )
    with pytest.raises(SchedulerError, match="cannot represent"):
        instance.install(mode="cron")


def test_scheduler_has_no_per_install_poll_override(tmp_path):
    instance = scheduler(tmp_path)
    with pytest.raises(TypeError):
        instance.install(mode="windows", poll_minutes=5)
