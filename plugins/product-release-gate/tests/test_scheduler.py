from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_scheduler import ReleaseGateScheduler, SchedulerError


def completed(
    command: list[str],
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


WINDOWS_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>false</StartWhenAvailable>
  </Settings>
</Task>
"""


class SchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.calls: list[tuple[list[str], str | None]] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _scheduler(self, **overrides: object) -> ReleaseGateScheduler:
        values = {
            "config_path": self.root / "config.json",
            "state_dir": self.root / "state",
            "poll_minutes": 60,
            "platform": "win32",
            "which": lambda _name: None,
            "runner": self._windows_runner,
            "user_config_root": self.root / "config-root",
        }
        values.update(overrides)
        return ReleaseGateScheduler(**values)

    def _windows_runner(
        self,
        command: list[str],
        cwd: str | None,
        input_text: str | None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(command), input_text))
        if command[:2] == ["schtasks", "/Query"]:
            return completed(command, stdout=WINDOWS_XML)
        return completed(command)

    def test_windows_install_proves_ignore_new_and_skip_missed(self) -> None:
        scheduler = self._scheduler()

        result = scheduler.install(mode="windows")

        create = next(command for command, _ in self.calls if command[:2] == ["schtasks", "/Create"])
        self.assertIn("MINUTE", create)
        self.assertIn("60", create)
        self.assertTrue(result["verification"]["overlap_policy_verified"])
        self.assertTrue(result["verification"]["misfire_policy_verified"])
        self.assertEqual("skip_all_missed", result["metadata"]["misfire_policy"])
        self.assertTrue(scheduler.scheduled_command[0].lower().endswith("python.exe"))
        self.assertFalse(scheduler.scheduled_command[0].lower().endswith("codex"))
        self.assertEqual("run-once", scheduler.scheduled_command[-1])

    def test_windows_uses_daily_for_1440_minutes_and_remove_fails_closed(self) -> None:
        scheduler = self._scheduler(poll_minutes=1440)
        scheduler.install(mode="windows")
        create = next(command for command, _ in self.calls if command[:2] == ["schtasks", "/Create"])
        self.assertEqual("DAILY", create[create.index("/SC") + 1])
        self.assertEqual("1", create[create.index("/MO") + 1])

        def denied(command: list[str], cwd: str | None, input_text: str | None) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["schtasks", "/Delete"]:
                return completed(command, 1, stderr="Access is denied")
            return self._windows_runner(command, cwd, input_text)

        scheduler.runner = denied
        with self.assertRaisesRegex(SchedulerError, "Access is denied"):
            scheduler.remove(mode="windows")

    def test_systemd_timer_is_nonpersistent_and_auto_probes_user_bus(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], cwd: str | None, input_text: str | None) -> subprocess.CompletedProcess[str]:
            calls.append(list(command))
            return completed(command, stdout="active\n")

        scheduler = self._scheduler(
            platform="linux",
            which=lambda name: f"/usr/bin/{name}" if name in {"systemctl", "crontab"} else None,
            runner=runner,
        )
        result = scheduler.install(mode="auto")

        self.assertEqual("systemd", result["mode"])
        timer_path = Path(result["timer_path"])
        timer = timer_path.read_text(encoding="utf-8")
        self.assertIn("Persistent=false", timer)
        self.assertIn("OnUnitActiveSec=60min", timer)
        self.assertNotIn("OnCalendar", timer)
        self.assertIn(["systemctl", "--user", "show-environment"], calls)

    def test_auto_falls_back_to_cron_when_systemd_user_bus_is_unavailable(self) -> None:
        crontab = {"text": "MAILTO=ops@example.com\n"}

        def runner(command: list[str], cwd: str | None, input_text: str | None) -> subprocess.CompletedProcess[str]:
            if command == ["systemctl", "--user", "show-environment"]:
                return completed(command, 1, stderr="Failed to connect to bus")
            if command == ["crontab", "-l"]:
                return completed(command, stdout=crontab["text"])
            if command == ["crontab", "-"]:
                crontab["text"] = input_text or ""
                return completed(command)
            return completed(command)

        scheduler = self._scheduler(
            platform="linux",
            which=lambda name: f"/usr/bin/{name}" if name in {"systemctl", "crontab"} else None,
            runner=runner,
        )

        first = scheduler.install(mode="auto")
        second = scheduler.install(mode="auto")

        self.assertEqual("cron", first["mode"])
        self.assertEqual(1, crontab["text"].count(scheduler.cron_marker))
        self.assertIn("MAILTO=ops@example.com", crontab["text"])
        self.assertTrue(second["verification"]["installed"])

    def test_poll_interval_is_configuration_only_and_validated(self) -> None:
        with self.assertRaisesRegex(SchedulerError, "5 to 1440"):
            self._scheduler(poll_minutes=1)


if __name__ == "__main__":
    unittest.main()
