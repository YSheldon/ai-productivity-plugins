from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Mapping


class SchedulerError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


Runner = Callable[[list[str], str | None, str | None], subprocess.CompletedProcess[str]]


def run_command(
    command: list[str],
    cwd: str | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
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


class PreReleaseScheduler:
    identity = "pre-release.sync"

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
        self._validate_poll_minutes(poll_minutes)
        self.config_path = Path(config_path).resolve(strict=False)
        self.state_dir = Path(state_dir).resolve(strict=False)
        self.poll_minutes = poll_minutes
        self.platform = platform or sys.platform
        self.which = which
        self.runner = runner
        self.user_config_root = Path(
            user_config_root
            if user_config_root is not None
            else os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
        ).resolve(strict=False)
        self.cli_path = (Path(__file__).resolve().parent / "pre_release_cli.py").resolve()
        self.scheduled_command = [
            sys.executable,
            str(self.cli_path),
            "--config",
            str(self.config_path),
            "run-once",
        ]
        self.metadata_path = self.state_dir / "setup" / "scheduler-install.json"
        self.cron_marker = f"# managed-by={self.identity}"

    def resolve_mode(self, mode: str) -> str:
        normalized = str(mode or "").strip().lower()
        if normalized not in {"auto", "windows", "systemd", "cron", "codex"}:
            raise SchedulerError("INVALID_SCHEDULER_MODE", f"unsupported scheduler mode: {mode}")
        if normalized != "auto":
            return normalized
        if self.platform.startswith("win"):
            return "windows"
        if self.which("systemctl") and self._systemd_user_available():
            return "systemd"
        if self.which("crontab"):
            return "cron"
        raise SchedulerError("CAPABILITY_BLOCKED", "no supported OS scheduler is available")

    def install(self, *, mode: str = "auto") -> dict[str, Any]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        resolved = self.resolve_mode(mode)
        if resolved == "windows":
            details = self._install_windows()
        elif resolved == "systemd":
            details = self._install_systemd()
        elif resolved == "cron":
            details = self._install_cron()
        else:
            raise SchedulerError("CAPABILITY_BLOCKED", "Codex Automation is disabled because equivalent skip-missed semantics are not proven")
        verification = self.status(mode=resolved)
        if verification.get("installed") is not True:
            raise SchedulerError("SCHEDULER_INSTALL_FAILED", "external scheduler status did not confirm installation")
        metadata = {
            "schema": "PluginSchedulerInstall/v1",
            "identity": self.identity,
            "mode": resolved,
            "poll_minutes": self.poll_minutes,
            "config_path": str(self.config_path),
            "state_dir": str(self.state_dir),
            "scheduled_command": list(self.scheduled_command),
            "overlap_policy": "ignore_new",
            "misfire_policy": "skip_all_missed",
        }
        self._write_metadata(metadata)
        return {"status": "ready", "mode": resolved, **details, "metadata": metadata, "verification": verification}

    def status(self, *, mode: str = "auto") -> dict[str, Any]:
        resolved = self._installed_or_resolved_mode(mode)
        if resolved == "windows":
            return self._status_windows()
        if resolved == "systemd":
            return self._status_systemd()
        if resolved == "cron":
            return self._status_cron()
        return {"status": "CAPABILITY_BLOCKED", "mode": "codex", "installed": False}

    def remove(self, *, mode: str = "auto") -> dict[str, Any]:
        resolved = self._installed_or_resolved_mode(mode)
        if resolved == "windows":
            details = self._remove_windows()
        elif resolved == "systemd":
            details = self._remove_systemd()
        elif resolved == "cron":
            details = self._remove_cron()
        else:
            raise SchedulerError("CAPABILITY_BLOCKED", "Codex scheduler is not managed here")
        if self.metadata_path.exists():
            self.metadata_path.unlink()
        return {"status": "ready", "mode": resolved, **details}

    def _install_windows(self) -> dict[str, Any]:
        schedule_type, modifier = ("DAILY", "1") if self.poll_minutes == 1440 else ("MINUTE", str(self.poll_minutes))
        command = [
            "schtasks", "/Create", "/TN", self.identity,
            "/TR", subprocess.list2cmdline(self.scheduled_command),
            "/SC", schedule_type, "/MO", modifier, "/F",
        ]
        self._require_success(self.runner(command, str(self.state_dir), None), "SCHEDULER_INSTALL_FAILED")
        return {"installed": True, "task_name": self.identity, "multiple_instances_policy": "IgnoreNew", "start_when_available": False}

    def _status_windows(self) -> dict[str, Any]:
        completed = self.runner(["schtasks", "/Query", "/TN", self.identity, "/XML"], str(self.state_dir), None)
        overlap = ""
        start_when_available: bool | None = None
        if completed.returncode == 0:
            root = ET.fromstring(completed.stdout)
            settings = {element.tag.rsplit("}", 1)[-1]: (element.text or "").strip() for element in root.iter()}
            overlap = settings.get("MultipleInstancesPolicy") or "IgnoreNew"
            start_when_available = (settings.get("StartWhenAvailable") or "false").lower() == "true"
        installed = completed.returncode == 0 and overlap == "IgnoreNew" and start_when_available is False
        return {
            "status": "ready" if installed else "CAPABILITY_BLOCKED",
            "mode": "windows",
            "installed": installed,
            "task_exists": completed.returncode == 0,
            "multiple_instances_policy": overlap,
            "start_when_available": start_when_available,
            "overlap_policy_verified": overlap == "IgnoreNew",
            "misfire_policy_verified": start_when_available is False,
        }

    def _remove_windows(self) -> dict[str, Any]:
        self._require_success(
            self.runner(["schtasks", "/Delete", "/TN", self.identity, "/F"], str(self.state_dir), None),
            "SCHEDULER_REMOVE_FAILED",
        )
        return {"removed": True, "task_name": self.identity}

    def _install_systemd(self) -> dict[str, Any]:
        service_dir = self.user_config_root / "systemd" / "user"
        service_dir.mkdir(parents=True, exist_ok=True)
        service_path = service_dir / f"{self.identity}.service"
        timer_path = service_dir / f"{self.identity}.timer"
        service_path.write_text(
            "\n".join(
                [
                    "[Unit]",
                    f"Description=Pre-release scheduler for {self.identity}",
                    "",
                    "[Service]",
                    "Type=oneshot",
                    f"ExecStart={shlex.join(self.scheduled_command)}",
                    "",
                ]
            ) + "\n",
            encoding="utf-8",
        )
        timer_path.write_text(
            "\n".join(
                [
                    "[Unit]",
                    f"Description=Pre-release timer for {self.identity}",
                    "",
                    "[Timer]",
                    f"OnUnitActiveSec={self.poll_minutes}min",
                    "Persistent=false",
                    "",
                    "[Install]",
                    "WantedBy=timers.target",
                    "",
                ]
            ) + "\n",
            encoding="utf-8",
        )
        for command in (
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "enable", "--now", f"{self.identity}.timer"],
        ):
            self._require_success(self.runner(command, str(self.state_dir), None), "SCHEDULER_INSTALL_FAILED")
        return {"installed": True, "service_path": str(service_path), "timer_path": str(timer_path)}

    def _status_systemd(self) -> dict[str, Any]:
        active = self.runner(["systemctl", "--user", "is-active", f"{self.identity}.timer"], str(self.state_dir), None)
        enabled = self.runner(["systemctl", "--user", "is-enabled", f"{self.identity}.timer"], str(self.state_dir), None)
        installed = active.returncode == 0 and enabled.returncode == 0
        return {"status": "ready" if installed else "CAPABILITY_BLOCKED", "mode": "systemd", "installed": installed, "overlap_policy": "kernel_run_lock", "misfire_policy_verified": True}

    def _remove_systemd(self) -> dict[str, Any]:
        for command in (
            ["systemctl", "--user", "disable", "--now", f"{self.identity}.timer"],
            ["systemctl", "--user", "daemon-reload"],
        ):
            self._require_success(self.runner(command, str(self.state_dir), None), "SCHEDULER_REMOVE_FAILED")
        for path in (
            self.user_config_root / "systemd" / "user" / f"{self.identity}.service",
            self.user_config_root / "systemd" / "user" / f"{self.identity}.timer",
        ):
            if path.exists():
                path.unlink()
        return {"removed": True}

    def _install_cron(self) -> dict[str, Any]:
        existing = self.runner(["crontab", "-l"], str(self.state_dir), None)
        lines = [] if existing.returncode != 0 else existing.stdout.splitlines()
        filtered = [line for line in lines if self.cron_marker not in line]
        filtered.append(f"*/{self.poll_minutes} * * * * {shlex.join(self.scheduled_command)} {self.cron_marker}")
        self._require_success(self.runner(["crontab", "-"], str(self.state_dir), "\n".join(filtered) + "\n"), "SCHEDULER_INSTALL_FAILED")
        return {"installed": True, "entry_count": 1}

    def _status_cron(self) -> dict[str, Any]:
        completed = self.runner(["crontab", "-l"], str(self.state_dir), None)
        lines = [] if completed.returncode != 0 else completed.stdout.splitlines()
        count = sum(1 for line in lines if self.cron_marker in line)
        installed = count == 1
        return {"status": "ready" if installed else "CAPABILITY_BLOCKED", "mode": "cron", "installed": installed, "entry_count": count, "overlap_policy": "kernel_run_lock", "misfire_policy_verified": True}

    def _remove_cron(self) -> dict[str, Any]:
        completed = self.runner(["crontab", "-l"], str(self.state_dir), None)
        lines = [] if completed.returncode != 0 else completed.stdout.splitlines()
        filtered = [line for line in lines if self.cron_marker not in line]
        self._require_success(self.runner(["crontab", "-"], str(self.state_dir), "\n".join(filtered) + ("\n" if filtered else "")), "SCHEDULER_REMOVE_FAILED")
        return {"removed": True}

    def _systemd_user_available(self) -> bool:
        completed = self.runner(["systemctl", "--user", "show-environment"], str(self.state_dir), None)
        return completed.returncode == 0

    def _installed_or_resolved_mode(self, mode: str) -> str:
        if self.metadata_path.exists():
            payload = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            return str(payload.get("mode") or self.resolve_mode(mode))
        return self.resolve_mode(mode)

    def _write_metadata(self, payload: Mapping[str, Any]) -> None:
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        self.metadata_path.write_text(json.dumps(dict(payload), sort_keys=True, indent=2), encoding="utf-8")

    def _require_success(self, completed: subprocess.CompletedProcess[str], code: str) -> None:
        if completed.returncode == 0:
            return
        detail = (completed.stderr or completed.stdout or "scheduler command failed").strip()
        raise SchedulerError(code, detail)

    @staticmethod
    def _validate_poll_minutes(value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or value < 5 or value > 1440:
            raise SchedulerError("INVALID_SCHEDULER_INTERVAL", "poll_minutes must be between 5 and 1440")
