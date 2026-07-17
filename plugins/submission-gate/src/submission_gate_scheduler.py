from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable


class SchedulerError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


Runner = Callable[[list[str], str | None, str | None], subprocess.CompletedProcess[str]]


def run_command(command: list[str], cwd: str | None = None, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    options: dict[str, Any] = {
        "cwd": cwd,
        "input": input_text,
        "capture_output": True,
        "check": False,
        "shell": False,
    }
    if command[:2] == ["schtasks", "/Query"] and "/XML" in command:
        options["encoding"] = "utf-16"
    else:
        options["text"] = True
    return subprocess.run(command, **options)


class SubmissionGateScheduler:
    identity = "submission-gate.scan"

    def __init__(
        self,
        *,
        config_path: str | Path,
        state_dir: str | Path,
        poll_minutes: int,
        platform: str | None = None,
        which: Callable[[str], str | None] = shutil.which,
        runner: Runner = run_command,
        user_config_root: str | Path | None = None,
    ) -> None:
        self.config_path = Path(config_path).resolve(strict=False)
        self.state_dir = Path(state_dir).resolve(strict=False)
        self.poll_minutes = poll_minutes
        self.platform = platform or sys.platform
        self.which = which
        self.runner = runner
        self.user_config_root = Path(
            user_config_root if user_config_root is not None else os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
        ).resolve(strict=False)
        self.cli_path = (Path(__file__).resolve().parent / "submission_gate_cli.py").resolve()
        self.scheduled_command = [
            sys.executable,
            str(self.cli_path),
            "--config",
            str(self.config_path),
            "run-once",
        ]
        self.metadata_path = self.state_dir / "setup" / "scheduler-install.json"

    def resolve_mode(self, mode: str) -> str:
        normalized = str(mode or "").strip().lower()
        if normalized not in {"auto", "windows", "systemd", "cron"}:
            raise SchedulerError("INVALID_SCHEDULER_MODE", f"unsupported scheduler mode: {mode}")
        if normalized != "auto":
            return normalized
        if self.platform.startswith("win"):
            return "windows"
        if self.which("systemctl"):
            return "systemd"
        return "cron"

    def install(self, *, mode: str = "auto") -> dict[str, Any]:
        resolved = self.resolve_mode(mode)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if resolved == "windows":
            details = self._install_windows()
        elif resolved == "systemd":
            details = self._install_systemd()
        else:
            details = self._install_cron()
        verification = self.status(mode=resolved)
        metadata = {
            "identity": self.identity,
            "mode": resolved,
            "poll_minutes": self.poll_minutes,
            "config_path": str(self.config_path),
            "scheduled_command": list(self.scheduled_command),
            "overlap_policy": "ignore_new",
            "misfire_policy": "skip_all_missed",
            "start_when_available": False,
        }
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        self.metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"status": "ready", "mode": resolved, **details, "verification": verification}

    def status(self, *, mode: str = "auto") -> dict[str, Any]:
        resolved = self.resolve_mode(mode)
        if resolved == "windows":
            return self._status_windows()
        if resolved == "systemd":
            return self._status_systemd()
        return self._status_cron()

    def remove(self, *, mode: str = "auto") -> dict[str, Any]:
        resolved = self.resolve_mode(mode)
        if resolved == "windows":
            self.runner(["schtasks", "/Delete", "/TN", self.identity, "/F"], str(self.state_dir), None)
        elif resolved == "systemd":
            self.runner(["systemctl", "--user", "disable", "--now", f"{self.identity}.timer"], None, None)
        else:
            current = self.runner(["crontab", "-l"], None, None)
            lines = [line for line in (current.stdout or "").splitlines() if self.identity not in line]
            self.runner(["crontab", "-"], None, "\n".join(lines) + ("\n" if lines else ""))
        if self.metadata_path.exists():
            self.metadata_path.unlink()
        return {"status": "ready", "mode": resolved, "removed": True}

    def _install_windows(self) -> dict[str, Any]:
        command = [
            "schtasks",
            "/Create",
            "/TN",
            self.identity,
            "/TR",
            subprocess.list2cmdline(self.scheduled_command),
            "/SC",
            "MINUTE",
            "/MO",
            str(self.poll_minutes),
            "/F",
        ]
        completed = self.runner(command, str(self.state_dir), None)
        if completed.returncode != 0:
            raise SchedulerError("SCHEDULER_INSTALL_FAILED", (completed.stderr or completed.stdout).strip())
        return {"installed": True, "task_name": self.identity}

    def _status_windows(self) -> dict[str, Any]:
        completed = self.runner(["schtasks", "/Query", "/TN", self.identity, "/XML"], str(self.state_dir), None)
        if completed.returncode != 0:
            return {"status": "CAPABILITY_BLOCKED", "mode": "windows", "installed": False}
        root = ET.fromstring(completed.stdout)
        settings = {element.tag.rsplit("}", 1)[-1]: (element.text or "").strip() for element in root.iter()}
        return {
            "status": "ready",
            "mode": "windows",
            "installed": settings.get("MultipleInstancesPolicy") == "IgnoreNew" and settings.get("StartWhenAvailable", "false").lower() == "false",
            "overlap_policy": "ignore_new",
            "misfire_policy": "skip_all_missed",
            "multiple_instances_policy": settings.get("MultipleInstancesPolicy", ""),
            "start_when_available": settings.get("StartWhenAvailable", "false").lower() == "true",
            "overlap_policy_verified": settings.get("MultipleInstancesPolicy") == "IgnoreNew",
            "misfire_policy_verified": settings.get("StartWhenAvailable", "false").lower() == "false",
        }

    def _systemd_paths(self) -> tuple[Path, Path]:
        root = self.user_config_root / "systemd" / "user"
        return root / f"{self.identity}.service", root / f"{self.identity}.timer"

    def _install_systemd(self) -> dict[str, Any]:
        service_path, timer_path = self._systemd_paths()
        service_path.parent.mkdir(parents=True, exist_ok=True)
        service_path.write_text(
            "\n".join((["[Unit]", "Description=Submission gate scan", "", "[Service]", "Type=oneshot", f"ExecStart={shlex.join(self.scheduled_command)}", ""])),
            encoding="utf-8",
        )
        timer_path.write_text(
            "\n".join((["[Unit]", "Description=Submission gate scan timer", "", "[Timer]", f"OnUnitActiveSec={self.poll_minutes}min", "Persistent=false", f"Unit={self.identity}.service", "", "[Install]", "WantedBy=timers.target", ""])),
            encoding="utf-8",
        )
        self.runner(["systemctl", "--user", "daemon-reload"], None, None)
        self.runner(["systemctl", "--user", "enable", "--now", f"{self.identity}.timer"], None, None)
        return {"installed": True, "service_path": str(service_path), "timer_path": str(timer_path)}

    def _status_systemd(self) -> dict[str, Any]:
        _service, timer_path = self._systemd_paths()
        text = timer_path.read_text(encoding="utf-8") if timer_path.is_file() else ""
        return {
            "status": "ready" if "Persistent=false" in text else "CAPABILITY_BLOCKED",
            "mode": "systemd",
            "installed": "Persistent=false" in text,
            "misfire_policy": "skip_all_missed",
            "misfire_policy_verified": "Persistent=false" in text,
            "overlap_policy": "kernel_run_lock",
        }

    def _install_cron(self) -> dict[str, Any]:
        current = self.runner(["crontab", "-l"], None, None)
        lines = [] if current.returncode != 0 else [line for line in (current.stdout or "").splitlines() if self.identity not in line]
        lines.append(f"*/{self.poll_minutes} * * * * {' '.join(shlex.quote(part) for part in self.scheduled_command)} # {self.identity}")
        self.runner(["crontab", "-"], None, "\n".join(lines) + "\n")
        return {"installed": True, "misfire_policy": "skip_all_missed", "overlap_policy": "kernel_run_lock"}

    def _status_cron(self) -> dict[str, Any]:
        current = self.runner(["crontab", "-l"], None, None)
        installed = current.returncode == 0 and self.identity in (current.stdout or "")
        return {
            "status": "ready" if installed else "CAPABILITY_BLOCKED",
            "mode": "cron",
            "installed": installed,
            "misfire_policy": "skip_all_missed",
            "overlap_policy": "kernel_run_lock",
        }
