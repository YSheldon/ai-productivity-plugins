from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Sequence


class SchedulerError(RuntimeError):
    """Raised when an OS scheduler cannot enforce unattended-run policy."""

    def __init__(self, message: str, *, code: str = "SCHEDULER_ERROR") -> None:
        super().__init__(message)
        self.code = code


def run_command(
    args: Sequence[str],
    *,
    encoding: str | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        encoding=encoding,
        input=input_text,
    )


class RDFlywheelScheduler:
    def __init__(
        self,
        *,
        config_path: str | Path,
        cli_path: str | Path,
        state_dir: str | Path,
        poll_minutes: int,
        platform_name: str | None = None,
        python_executable: str | Path | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = run_command,
        which: Callable[[str], str | None] = shutil.which,
        home: str | Path | None = None,
    ) -> None:
        if type(poll_minutes) is not int or not 5 <= poll_minutes <= 1440:
            raise SchedulerError(
                "poll_minutes must be an integer in 5..1440.",
                code="INVALID_INTERVAL",
            )
        self.config_path = Path(config_path).expanduser().resolve(strict=False)
        self.cli_path = Path(cli_path).expanduser().resolve(strict=False)
        self.state_dir = Path(state_dir).expanduser().resolve(strict=False)
        self.poll_minutes = poll_minutes
        self.platform_name = platform_name or sys.platform
        self.python_executable = Path(
            python_executable or sys.executable
        ).expanduser().resolve(strict=False)
        self.command_runner = command_runner
        self.which = which
        self.home = Path(home or Path.home()).expanduser().resolve(strict=False)
        identity = hashlib.sha256(str(self.config_path).encode("utf-8")).hexdigest()[:12]
        self.identity = identity
        self.task_name = f"RDFlywheel-{self.identity}"
        self.cron_marker = f"rd-flywheel:{self.identity}"

    @property
    def run_command(self) -> list[str]:
        return [
            str(self.python_executable),
            str(self.cli_path),
            "--config",
            str(self.config_path),
            "run-once",
        ]

    @property
    def policy(self) -> dict[str, object]:
        return {
            "overlap": "kernel_lock",
            "missed_intervals": "skip_all",
            "start_when_available": False,
        }

    def resolve_mode(self, mode: str) -> str:
        normalized = mode.casefold()
        if normalized not in {"auto", "windows", "systemd", "cron"}:
            raise SchedulerError(
                f"unsupported scheduler mode: {mode}",
                code="SCHEDULER_MODE_UNSUPPORTED",
            )
        if normalized != "auto":
            return normalized
        if self.platform_name.startswith("win"):
            return "windows"
        if self.which("systemctl"):
            probe = self.command_runner(
                ["systemctl", "--user", "show-environment"],
                encoding=None,
                input_text=None,
            )
            if probe.returncode == 0:
                return "systemd"
        if self.which("crontab"):
            return "cron"
        raise SchedulerError(
            "no supported OS scheduler is available.",
            code="SCHEDULER_UNAVAILABLE",
        )

    def install(self, *, mode: str = "auto") -> dict[str, object]:
        resolved = self.resolve_mode(mode)
        if resolved == "windows":
            result = self._install_windows()
        elif resolved == "systemd":
            result = self._install_systemd()
        else:
            result = self._install_cron()
        status = self.status(mode=resolved)
        if status.get("status") != "ready":
            raise SchedulerError(
                f"scheduler installation could not be externally verified: {status}",
                code="SCHEDULER_POLICY_UNVERIFIED",
            )
        self._write_metadata(resolved, status)
        return {**result, **status}

    def status(self, *, mode: str = "auto") -> dict[str, object]:
        resolved = self.resolve_mode(mode)
        if resolved == "windows":
            return self._status_windows()
        if resolved == "systemd":
            return self._status_systemd()
        return self._status_cron()

    def remove(self, *, mode: str = "auto") -> dict[str, object]:
        resolved = self.resolve_mode(mode)
        if resolved == "windows":
            return self._remove_windows()
        if resolved == "systemd":
            return self._remove_systemd()
        return self._remove_cron()

    def _install_windows(self) -> dict[str, object]:
        command_line = subprocess.list2cmdline(self.run_command)
        if self.poll_minutes == 1440:
            schedule = ["DAILY", "1"]
        else:
            schedule = ["MINUTE", str(self.poll_minutes)]
        args = [
            "schtasks",
            "/Create",
            "/TN",
            self.task_name,
            "/TR",
            command_line,
            "/SC",
            schedule[0],
            "/MO",
            schedule[1],
            "/F",
        ]
        completed = self.command_runner(args, encoding=None, input_text=None)
        self._require_success(completed, "create Windows scheduled task")
        return {"status": "ready", "mode": "windows", "installed": True}

    def _status_windows(self) -> dict[str, object]:
        args = ["schtasks", "/Query", "/TN", self.task_name, "/XML"]
        completed = self.command_runner(args, encoding="utf-16", input_text=None)
        if completed.returncode != 0:
            return {
                "status": "CAPABILITY_BLOCKED",
                "mode": "windows",
                "installed": False,
                "policy": self.policy,
                "detail": (completed.stderr or completed.stdout or "").strip(),
            }
        try:
            root = ET.fromstring((completed.stdout or "").lstrip("\ufeff\x00"))
        except ET.ParseError as exc:
            return {
                "status": "CAPABILITY_BLOCKED",
                "mode": "windows",
                "installed": False,
                "policy": self.policy,
                "detail": f"cannot parse Task Scheduler XML: {exc}",
            }
        values = {
            element.tag.rsplit("}", 1)[-1]: (element.text or "").strip()
            for element in root.iter()
        }
        overlap = values.get("MultipleInstancesPolicy")
        start_when_available = values.get("StartWhenAvailable", "").casefold()
        valid = overlap == "IgnoreNew" and start_when_available == "false"
        policy = {
            "overlap": overlap or "unknown",
            "missed_intervals": "skip_all" if start_when_available == "false" else "unknown",
            "start_when_available": start_when_available == "true",
        }
        return {
            "status": "ready" if valid else "CAPABILITY_BLOCKED",
            "mode": "windows",
            "installed": valid,
            "policy": policy,
        }

    def _remove_windows(self) -> dict[str, object]:
        args = ["schtasks", "/Delete", "/TN", self.task_name, "/F"]
        completed = self.command_runner(args, encoding=None, input_text=None)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            lowered = detail.casefold()
            if not any(
                token in lowered
                for token in ("cannot find", "not found", "does not exist", "找不到")
            ):
                raise SchedulerError(
                    f"cannot remove Windows scheduled task: {detail}",
                    code="SCHEDULER_REMOVE_FAILED",
                )
            return {
                "status": "ready",
                "mode": "windows",
                "removed": False,
                "detail": detail,
            }
        return {"status": "ready", "mode": "windows", "removed": True}

    @property
    def _systemd_dir(self) -> Path:
        return self.home / ".config" / "systemd" / "user"

    @property
    def _service_path(self) -> Path:
        return self._systemd_dir / "rd-flywheel.service"

    @property
    def _timer_path(self) -> Path:
        return self._systemd_dir / "rd-flywheel.timer"

    def _install_systemd(self) -> dict[str, object]:
        self._systemd_dir.mkdir(parents=True, exist_ok=True)
        service = "\n".join(
            (
                "[Unit]",
                "Description=R&D Flywheel capability-gap scan",
                "",
                "[Service]",
                "Type=oneshot",
                f"ExecStart={shlex.join(self.run_command)}",
                "",
            )
        )
        timer = "\n".join(
            (
                "[Unit]",
                "Description=R&D Flywheel capability-gap schedule",
                "",
                "[Timer]",
                f"OnUnitActiveSec={self.poll_minutes}min",
                "Persistent=false",
                "AccuracySec=1min",
                "",
                "[Install]",
                "WantedBy=timers.target",
                "",
            )
        )
        self._atomic_write(self._service_path, service)
        self._atomic_write(self._timer_path, timer)
        reload_result = self.command_runner(
            ["systemctl", "--user", "daemon-reload"],
            encoding=None,
            input_text=None,
        )
        self._require_success(reload_result, "reload systemd user units")
        enable_result = self.command_runner(
            ["systemctl", "--user", "enable", "--now", "rd-flywheel.timer"],
            encoding=None,
            input_text=None,
        )
        self._require_success(enable_result, "enable systemd user timer")
        return {"status": "ready", "mode": "systemd", "installed": True}

    def _status_systemd(self) -> dict[str, object]:
        files_present = self._service_path.is_file() and self._timer_path.is_file()
        timer_text = (
            self._timer_path.read_text(encoding="utf-8")
            if self._timer_path.is_file()
            else ""
        )
        persistent_false = "Persistent=false" in timer_text
        enabled = self.command_runner(
            ["systemctl", "--user", "is-enabled", "rd-flywheel.timer"],
            encoding=None,
            input_text=None,
        )
        active = self.command_runner(
            ["systemctl", "--user", "is-active", "rd-flywheel.timer"],
            encoding=None,
            input_text=None,
        )
        valid = (
            files_present
            and persistent_false
            and enabled.returncode == 0
            and active.returncode == 0
        )
        return {
            "status": "ready" if valid else "CAPABILITY_BLOCKED",
            "mode": "systemd",
            "installed": valid,
            "policy": self.policy,
        }

    def _remove_systemd(self) -> dict[str, object]:
        disabled = self.command_runner(
            ["systemctl", "--user", "disable", "--now", "rd-flywheel.timer"],
            encoding=None,
            input_text=None,
        )
        detail = (disabled.stderr or disabled.stdout or "").strip()
        if disabled.returncode != 0 and not any(
            token in detail.casefold()
            for token in ("not loaded", "not found", "does not exist")
        ):
            raise SchedulerError(
                f"cannot disable systemd timer: {detail}",
                code="SCHEDULER_REMOVE_FAILED",
            )
        removed = False
        for path in (self._timer_path, self._service_path):
            if path.exists():
                path.unlink()
                removed = True
        reload_result = self.command_runner(
            ["systemctl", "--user", "daemon-reload"],
            encoding=None,
            input_text=None,
        )
        self._require_success(reload_result, "reload systemd after removal")
        return {"status": "ready", "mode": "systemd", "removed": removed}

    def render_cron_entry(self) -> str:
        if self.poll_minutes == 1440:
            schedule = "0 0 * * *"
        elif self.poll_minutes == 60:
            schedule = "0 * * * *"
        elif self.poll_minutes < 60 and 60 % self.poll_minutes == 0:
            schedule = f"*/{self.poll_minutes} * * * *"
        else:
            raise SchedulerError(
                f"cron cannot represent an exact {self.poll_minutes}-minute interval without drift.",
                code="SCHEDULER_INTERVAL_UNREPRESENTABLE",
            )
        return f"{schedule} {shlex.join(self.run_command)} # {self.cron_marker}"

    def _read_crontab(self) -> str:
        completed = self.command_runner(
            ["crontab", "-l"],
            encoding=None,
            input_text=None,
        )
        if completed.returncode == 0:
            return completed.stdout or ""
        detail = (completed.stderr or completed.stdout or "").casefold()
        if "no crontab" in detail or not detail.strip():
            return ""
        raise SchedulerError(
            f"cannot read crontab: {(completed.stderr or completed.stdout or '').strip()}",
            code="SCHEDULER_STATUS_FAILED",
        )

    def _install_cron(self) -> dict[str, object]:
        current = self._read_crontab()
        lines = [
            line
            for line in current.splitlines()
            if self.cron_marker not in line
        ]
        lines.append(self.render_cron_entry())
        text = "\n".join(lines).rstrip() + "\n"
        self._write_crontab(text)
        return {"status": "ready", "mode": "cron", "installed": True}

    def _status_cron(self) -> dict[str, object]:
        current = self._read_crontab()
        count = sum(self.cron_marker in line for line in current.splitlines())
        valid = count == 1
        return {
            "status": "ready" if valid else "CAPABILITY_BLOCKED",
            "mode": "cron",
            "installed": valid,
            "entry_count": count,
            "policy": self.policy,
        }

    def _remove_cron(self) -> dict[str, object]:
        current = self._read_crontab()
        lines = [
            line
            for line in current.splitlines()
            if self.cron_marker not in line
        ]
        removed = len(lines) != len(current.splitlines())
        text = "\n".join(lines)
        if text:
            text += "\n"
        self._write_crontab(text)
        status = self._status_cron()
        if status["entry_count"] != 0:
            raise SchedulerError(
                "cron entry remained after removal.",
                code="SCHEDULER_REMOVE_FAILED",
            )
        return {"status": "ready", "mode": "cron", "removed": removed}

    def _write_crontab(self, text: str) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(
            prefix="rd-flywheel-crontab-",
            suffix=".txt",
            dir=self.state_dir,
            text=True,
        )
        path = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            completed = self.command_runner(
                ["crontab", str(path)],
                encoding=None,
                input_text=None,
            )
            self._require_success(completed, "install crontab")
        finally:
            path.unlink(missing_ok=True)

    def _write_metadata(
        self,
        mode: str,
        status: dict[str, object],
    ) -> None:
        payload = {
            "schema_version": 1,
            "mode": mode,
            "config_path": str(self.config_path),
            "run_command": self.run_command,
            "poll_minutes": self.poll_minutes,
            "policy": status.get("policy", self.policy),
        }
        path = self.state_dir / "scheduler" / "metadata.json"
        self._atomic_write(path, json.dumps(payload, sort_keys=True, indent=2) + "\n")

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(text, encoding="utf-8", newline="\n")
        os.replace(temporary, path)

    @staticmethod
    def _require_success(
        completed: subprocess.CompletedProcess[str],
        operation: str,
    ) -> None:
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise SchedulerError(
                f"cannot {operation}: {detail}",
                code="SCHEDULER_COMMAND_FAILED",
            )
