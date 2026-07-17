from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from submission_gate_core import default_config, sha256_file

_SOURCE_ROOT = Path(__file__).resolve().parent
_PLUGIN_ROOT = _SOURCE_ROOT.parent
_REPO_ROOT = _PLUGIN_ROOT.parents[1]
if str(_PLUGIN_ROOT) not in os.sys.path:
    os.sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile  # noqa: E402


class SetupError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


BootstrapRunner = Callable[..., Mapping[str, Any]]


def _command_array(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            parsed = json.loads(text)
            if not isinstance(parsed, list):
                raise SetupError("SETUP_INPUT_INVALID", "gate adapter command JSON must be an array")
            return [str(item) for item in parsed if str(item)]
        return [text]
    raise SetupError("SETUP_INPUT_INVALID", "gate adapter command must be an argument array")


class SubmissionGateSetup:
    def __init__(
        self,
        config_path: str | Path,
        *,
        repo_root: str | Path = _REPO_ROOT,
        bootstrap_runner: BootstrapRunner = bootstrap_profile,
        account_discoverer: Callable[[Path, str], Mapping[str, Any]] | None = None,
        controller_factory: Callable[[Path], Any] | None = None,
        scheduler_factory: Callable[[Path], Any] | None = None,
        input_fn: Callable[[str], str] = input,
    ) -> None:
        self.config_path = Path(config_path).resolve(strict=False)
        self.repo_root = Path(repo_root).resolve(strict=False)
        self.bootstrap_runner = bootstrap_runner
        self.account_discoverer = account_discoverer or (lambda _lock, _digest: {"accounts": []})
        self.controller_factory = controller_factory
        self.scheduler_factory = scheduler_factory
        self.input_fn = input_fn

    def run(
        self,
        *,
        non_interactive: bool,
        scheduler_mode: str,
        provided: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        values = dict(provided or {})
        bootstrap = dict(self.bootstrap_runner("submission-gate", repo_root=self.repo_root))
        dependency_lock = Path(str(bootstrap.get("dependency_lock") or "")).resolve(strict=True)
        dependency_lock_sha256 = sha256_file(dependency_lock)
        if self.config_path.is_file():
            config = json.loads(self.config_path.read_text(encoding="utf-8"))
            prompt_count = 0
        else:
            prompt_count = 0
            accounts = list(self.account_discoverer(dependency_lock, dependency_lock_sha256).get("accounts") or [])
            if not accounts:
                raise SetupError("SETUP_INPUT_REQUIRED", "no locked mail accounts are available")
            if values.get("mail_profile") and values.get("mail_email"):
                profile = str(values["mail_profile"])
                email = str(values["mail_email"])
            else:
                first = accounts[0]
                profile = str(first["name"])
                email = str(first["email"])
            submission_group = str(values.get("submission_group_address") or "").strip()
            if not submission_group:
                if non_interactive:
                    raise SetupError("SETUP_INPUT_REQUIRED", "submission_group_address is required")
                submission_group = self.input_fn("Submission group address: ").strip()
                prompt_count += 1
            blocked_notice = str(values.get("blocked_notice_address") or "").strip()
            if not blocked_notice:
                if non_interactive:
                    raise SetupError("SETUP_INPUT_REQUIRED", "blocked_notice_address is required")
                blocked_notice = self.input_fn("Blocked notice address: ").strip()
                prompt_count += 1
            config = default_config()
            config["gate_mail_account"] = {"profile": profile, "email": email}
            config["submission_group_address"] = submission_group
            config["blocked_notice_address"] = blocked_notice

        command_supplied = values.get("gate_adapter_command")
        if command_supplied not in (None, [], ""):
            config.setdefault("gate_adapter", {})["command"] = _command_array(command_supplied)
        if values.get("gate_adapter_entrypoint"):
            config.setdefault("gate_adapter", {})["entrypoint_path"] = str(values["gate_adapter_entrypoint"])
        if values.get("gate_adapter_entrypoint_sha256"):
            config.setdefault("gate_adapter", {})["entrypoint_sha256"] = str(
                values["gate_adapter_entrypoint_sha256"]
            ).strip().lower()
        config["scheduler_mode"] = scheduler_mode
        config["dependency_lock"] = str(dependency_lock)
        config["dependency_lock_sha256"] = dependency_lock_sha256
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.config_path.with_name(self.config_path.name + ".tmp")
        temp_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temp_path, self.config_path)

        scheduler = self.scheduler_factory(self.config_path) if self.scheduler_factory else None
        scheduler_result = (
            scheduler.install(mode=scheduler_mode)
            if scheduler is not None
            else {"status": "ready", "mode": scheduler_mode}
        )
        controller = self.controller_factory(self.config_path) if self.controller_factory else None
        preflight = controller.preflight() if controller is not None else {"ready": True}
        first_run = controller.run_once() if controller is not None else {"status": "ready", "processed": 0}
        doctor = controller.doctor() if controller is not None else {"ready": True}
        return {
            "status": "ready",
            "config_path": str(self.config_path),
            "prompt_count": prompt_count,
            "credential_boundary": "Mail credentials stay in imap-smtp-mail; SVN and GitLab credentials stay on the GitLab runner.",
            "bootstrap": bootstrap,
            "preflight": preflight,
            "first_run": first_run,
            "doctor": doctor,
            "scheduler": scheduler_result,
            "commands": {
                "status": f"{os.sys.executable} {(_SOURCE_ROOT / 'submission_gate_cli.py').resolve()} --config {self.config_path} status",
                "verify_audit": f"{os.sys.executable} {(_SOURCE_ROOT / 'submission_gate_cli.py').resolve()} --config {self.config_path} verify-audit",
                "scheduler_remove": f"{os.sys.executable} {(_SOURCE_ROOT / 'submission_gate_cli.py').resolve()} --config {self.config_path} scheduler remove",
            },
        }


def run_setup_operation(
    *,
    config_path: str | Path,
    non_interactive: bool,
    scheduler_mode: str,
    provided: Mapping[str, Any] | None = None,
    repo_root: str | Path = _REPO_ROOT,
) -> dict[str, Any]:
    return SubmissionGateSetup(config_path, repo_root=repo_root).run(
        non_interactive=non_interactive,
        scheduler_mode=scheduler_mode,
        provided=provided,
    )
