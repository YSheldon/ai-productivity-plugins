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


class ReleaseGateScheduler:
    """Install one non-overlapping schedule that skips every missed run."""

    identity = "product-release-gate.unified-approval"

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
        self.cli_path = (Path(__file__).resolve().parent / "release_gate_cli.py").resolve()
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
        raise SchedulerError(
            "CAPABILITY_BLOCKED",
            "no supported OS scheduler is available",
        )

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
            raise SchedulerError(
                "CAPABILITY_BLOCKED",
                "Codex Automation is disabled because equivalent skip-missed semantics are not proven",
            )
        verification = self.status(mode=resolved)
        if verification.get("installed") is not True:
            raise SchedulerError(
                "SCHEDULER_INSTALL_FAILED",
                "external scheduler status did not prove ignore-new and skip-all-missed semantics",
            )
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
        return {
            "status": "ready",
            "mode": resolved,
            **details,
            "metadata": metadata,
            "verification": verification,
        }

    def status(self, *, mode: str = "auto") -> dict[str, Any]:
        resolved = self._installed_or_resolved_mode(mode)
        if resolved == "windows":
            return self._status_windows()
        if resolved == "systemd":
            return self._status_systemd()
        if resolved == "cron":
            return self._status_cron()
        return {
            "status": "CAPABILITY_BLOCKED",
            "mode": "codex",
            "installed": False,
            "reason": "equivalent misfire and overlap semantics are not proven",
        }

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
        schedule_type, modifier = (
            ("DAILY", "1")
            if self.poll_minutes == 1440
            else ("MINUTE", str(self.poll_minutes))
        )
        command = [
            "schtasks", "/Create", "/TN", self.identity,
            "/TR", subprocess.list2cmdline(self.scheduled_command),
            "/SC", schedule_type, "/MO", modifier, "/F",
        ]
        self._require_success(
            self.runner(command, str(self.state_dir), None),
            "SCHEDULER_INSTALL_FAILED",
        )
        return {
            "installed": True,
            "task_name": self.identity,
            "multiple_instances_policy": "IgnoreNew",
            "start_when_available": False,
        }

    def _status_windows(self) -> dict[str, Any]:
        completed = self.runner(
            ["schtasks", "/Query", "/TN", self.identity, "/XML"],
            str(self.state_dir),
            None,
        )
        overlap = ""
        start_when_available: bool | None = None
        policy_error = ""
        if completed.returncode == 0:
            try:
                root = ET.fromstring(completed.stdout)
                settings = {
                    element.tag.rsplit("}", 1)[-1]: (element.text or "").strip()
                    for element in root.iter()
                }
                overlap = settings.get("MultipleInstancesPolicy") or "IgnoreNew"
                start_when_available = (
                    settings.get("StartWhenAvailable") or "false"
                ).lower() == "true"
            except (ET.ParseError, UnicodeError) as exc:
                policy_error = str(exc)
        overlap_ok = overlap == "IgnoreNew"
        misfire_ok = start_when_available is False
        installed = completed.returncode == 0 and overlap_ok and misfire_ok
        return {
            "status": "ready" if installed else "CAPABILITY_BLOCKED",
            "mode": "windows",
            "installed": installed,
            "task_exists": completed.returncode == 0,
            "multiple_instances_policy": overlap,
            "start_when_available": start_when_available,
            "overlap_policy_verified": overlap_ok,
            "misfire_policy_verified": misfire_ok,
            "policy_error": policy_error,
            "detail": (completed.stderr or "").strip(),
        }

    def _remove_windows(self) -> dict[str, Any]:
        completed = self.runner(
            ["schtasks", "/Delete", "/TN", self.identity, "/F"],
            str(self.state_dir),
            None,
        )
        if completed.returncode != 0 and not self._is_not_found_error(completed):
            self._require_success(completed, "SCHEDULER_REMOVE_FAILED")
        return {"removed": True, "task_name": self.identity}

    def _install_systemd(self) -> dict[str, Any]:
        service_path, timer_path = self._systemd_paths()
        service_path.parent.mkdir(parents=True, exist_ok=True)
        service_path.write_text(
            "\n".join(
                (
                    "[Unit]",
                    "Description=Product release gate reconciliation",
                    "",
                    "[Service]",
                    "Type=oneshot",
                    f"WorkingDirectory={self.state_dir}",
                    f"ExecStart={shlex.join(self.scheduled_command)}",
                    "",
                )
            ),
            encoding="utf-8",
        )
        timer_path.write_text(
            "\n".join(
                (
                    "[Unit]",
                    "Description=Product release gate timer",
                    "",
                    "[Timer]",
                    "OnBootSec=1min",
                    f"OnUnitActiveSec={self.poll_minutes}min",
                    "Persistent=false",
                    "AccuracySec=1min",
                    f"Unit={self.identity}.service",
                    "",
                    "[Install]",
                    "WantedBy=timers.target",
                    "",
                )
            ),
            encoding="utf-8",
        )
        self._require_success(
            self.runner(["systemctl", "--user", "daemon-reload"], None, None),
            "SCHEDULER_INSTALL_FAILED",
        )
        self._require_success(
            self.runner(
                ["systemctl", "--user", "enable", "--now", f"{self.identity}.timer"],
                None,
                None,
            ),
            "SCHEDULER_INSTALL_FAILED",
        )
        return {
            "installed": True,
            "service_path": str(service_path),
            "timer_path": str(timer_path),
        }

    def _status_systemd(self) -> dict[str, Any]:
        timer = f"{self.identity}.timer"
        active = self.runner(["systemctl", "--user", "is-active", timer], None, None)
        enabled = self.runner(["systemctl", "--user", "is-enabled", timer], None, None)
        _service, timer_path = self._systemd_paths()
        timer_text = timer_path.read_text(encoding="utf-8") if timer_path.is_file() else ""
        misfire_ok = (
            "Persistent=false" in timer_text
            and "OnUnitActiveSec=" in timer_text
            and "OnCalendar=" not in timer_text
        )
        installed = active.returncode == 0 and enabled.returncode == 0 and misfire_ok
        return {
            "status": "ready" if installed else "CAPABILITY_BLOCKED",
            "mode": "systemd",
            "installed": installed,
            "misfire_policy_verified": misfire_ok,
            "overlap_policy": "kernel_run_lock",
        }

    def _remove_systemd(self) -> dict[str, Any]:
        timer = f"{self.identity}.timer"
        completed = self.runner(
            ["systemctl", "--user", "disable", "--now", timer],
            None,
            None,
        )
        if completed.returncode != 0 and not self._is_not_found_error(completed):
            self._require_success(completed, "SCHEDULER_REMOVE_FAILED")
        for path in self._systemd_paths():
            if path.exists():
                path.unlink()
        self._require_success(
            self.runner(["systemctl", "--user", "daemon-reload"], None, None),
            "SCHEDULER_REMOVE_FAILED",
        )
        return {"removed": True}

    def _install_cron(self) -> dict[str, Any]:
        current = self._read_crontab()
        retained = [line for line in current.splitlines() if self.cron_marker not in line]
        retained.append(
            f"{self._cron_expression()} {shlex.join(self.scheduled_command)} {self.cron_marker}"
        )
        updated = "\n".join(retained).rstrip() + "\n"
        self._require_success(
            self.runner(["crontab", "-"], None, updated),
            "SCHEDULER_INSTALL_FAILED",
        )
        return {"installed": True, "marker": self.cron_marker}

    def _status_cron(self) -> dict[str, Any]:
        current = self._read_crontab()
        count = sum(1 for line in current.splitlines() if self.cron_marker in line)
        return {
            "status": "ready" if count == 1 else "CAPABILITY_BLOCKED",
            "mode": "cron",
            "installed": count == 1,
            "entry_count": count,
            "misfire_policy_verified": count == 1,
            "misfire_policy": "cron_has_no_catchup",
            "overlap_policy": "kernel_run_lock",
        }

    def _remove_cron(self) -> dict[str, Any]:
        current = self._read_crontab()
        updated = "\n".join(
            line for line in current.splitlines() if self.cron_marker not in line
        ).rstrip()
        if updated:
            updated += "\n"
        self._require_success(
            self.runner(["crontab", "-"], None, updated),
            "SCHEDULER_REMOVE_FAILED",
        )
        return {"removed": True, "marker": self.cron_marker}

    def _read_crontab(self) -> str:
        completed = self.runner(["crontab", "-l"], None, None)
        if completed.returncode == 0:
            return completed.stdout
        detail = (completed.stderr or completed.stdout or "").strip().lower()
        if completed.returncode == 1 and (not detail or "no crontab" in detail):
            return ""
        raise SchedulerError("SCHEDULER_STATUS_FAILED", detail or "crontab -l failed")

    def _systemd_paths(self) -> tuple[Path, Path]:
        root = self.user_config_root / "systemd" / "user"
        return root / f"{self.identity}.service", root / f"{self.identity}.timer"

    def _systemd_user_available(self) -> bool:
        try:
            completed = self.runner(
                ["systemctl", "--user", "show-environment"],
                None,
                None,
            )
        except OSError:
            return False
        return completed.returncode == 0

    def _installed_or_resolved_mode(self, mode: str) -> str:
        if str(mode).strip().lower() != "auto":
            return self.resolve_mode(mode)
        metadata = self._read_metadata()
        installed = str(metadata.get("mode") or "").strip()
        if installed in {"windows", "systemd", "cron", "codex"}:
            return installed
        return self.resolve_mode("auto")

    def _read_metadata(self) -> Mapping[str, Any]:
        if not self.metadata_path.is_file():
            return {}
        try:
            payload = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, Mapping) else {}

    def _write_metadata(self, payload: Mapping[str, Any]) -> None:
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.metadata_path.with_name(f".{self.metadata_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(dict(payload), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.metadata_path)

    def _cron_expression(self) -> str:
        minutes = self.poll_minutes
        if minutes < 60 and 60 % minutes == 0:
            return f"*/{minutes} * * * *"
        if minutes == 60:
            return "0 * * * *"
        if minutes % 60 == 0 and 24 % (minutes // 60) == 0:
            return f"0 */{minutes // 60} * * *"
        raise SchedulerError(
            "INVALID_POLL_INTERVAL",
            "cron fallback requires an interval that evenly divides one hour or one day",
        )

    @staticmethod
    def _validate_poll_minutes(value: Any) -> None:
        if not isinstance(value, int) or isinstance(value, bool) or not 5 <= value <= 1440:
            raise SchedulerError(
                "INVALID_POLL_INTERVAL",
                "poll_minutes must be an integer from 5 to 1440",
            )

    @staticmethod
    def _is_not_found_error(completed: subprocess.CompletedProcess[str]) -> bool:
        detail = (completed.stderr or completed.stdout or "").strip().lower()
        return any(
            marker in detail
            for marker in ("not found", "does not exist", "could not be found", "cannot find")
        )

    @staticmethod
    def _require_success(
        completed: subprocess.CompletedProcess[str],
        code: str,
    ) -> None:
        if completed.returncode == 0:
            return
        detail = (completed.stderr or completed.stdout or "").strip() or "scheduler command failed"
        raise SchedulerError(code, detail)
