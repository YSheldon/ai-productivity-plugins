from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from test_submission_core import default_config, sha256_file

_SOURCE_ROOT = Path(__file__).resolve().parent
_PLUGIN_ROOT = _SOURCE_ROOT.parent
_REPO_ROOT = _PLUGIN_ROOT.parents[1]
if str(_PLUGIN_ROOT) not in os.sys.path:
    os.sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile  # noqa: E402

# Credentials stay in the locked mail bridge; this config stores no secret material.


class SetupError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


BootstrapRunner = Callable[..., Mapping[str, Any]]


class TestSubmissionSetup:
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

    def run(self, *, non_interactive: bool, scheduler_mode: str, provided: Mapping[str, Any] | None = None) -> dict[str, Any]:
        values = dict(provided or {})
        bootstrap = dict(self.bootstrap_runner("test-submission", repo_root=self.repo_root))
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
            if "mail_profile" in values and "mail_email" in values:
                profile = str(values["mail_profile"])
                email = str(values["mail_email"])
            else:
                first = accounts[0]
                profile = str(first["name"])
                email = str(first["email"])
            gate_address = str(values.get("submission_gate_address") or "").strip()
            if not gate_address:
                if non_interactive:
                    raise SetupError("SETUP_INPUT_REQUIRED", "submission_gate_address is required")
                gate_address = self.input_fn("Submission gate address: ").strip()
                prompt_count += 1
            feishu_directory_url = str(values.get("feishu_directory_url") or "").strip()
            if not feishu_directory_url and not non_interactive:
                feishu_directory_url = self.input_fn("Feishu directory URL (optional): ").strip()
                prompt_count += 1
            config = default_config()
            config["mail_account"] = {"profile": profile, "email": email}
            config["submission_gate_address"] = gate_address
            config["feishu_directory_url"] = feishu_directory_url
        config["scheduler_mode"] = scheduler_mode
        config["dependency_lock"] = str(dependency_lock)
        config["dependency_lock_sha256"] = dependency_lock_sha256
        preview_config = self.config_path.parent / "product-release-gate.preview.json"
        preview_config.parent.mkdir(parents=True, exist_ok=True)
        if not preview_config.exists():
            preview_config.write_text(
                json.dumps(
                    {
                        "storage_dir": str((self.config_path.parent / "preview-events").resolve(strict=False)),
                        "policy": {"require_signature": False, "require_cloud_scan": False},
                        "test": {"command": ["cmd", "/c", "exit", "0"], "timeout_seconds": 1},
                    },
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
        config["product_gate_preview_config"] = str(preview_config)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        scheduler = self.scheduler_factory(self.config_path) if self.scheduler_factory else None
        scheduler_result = scheduler.install(mode=scheduler_mode) if scheduler is not None else {"status": "ready", "mode": scheduler_mode}
        controller = self.controller_factory(self.config_path) if self.controller_factory else None
        preflight = controller.preflight() if controller is not None else {"ready": True}
        first_run = controller.run_once() if controller is not None else {"status": "ready", "retried": 0, "sent": 0}
        doctor = controller.doctor() if controller is not None else {"ready": True}
        return {
            "status": "ready",
            "config_path": str(self.config_path),
            "prompt_count": prompt_count,
            "bootstrap": bootstrap,
            "preflight": preflight,
            "first_run": first_run,
            "doctor": doctor,
            "scheduler": scheduler_result,
            "commands": {
                "status": f"{os.sys.executable} {(_SOURCE_ROOT / 'test_submission_cli.py').resolve()} --config {self.config_path} status",
                "scheduler_remove": f"{os.sys.executable} {(_SOURCE_ROOT / 'test_submission_cli.py').resolve()} --config {self.config_path} scheduler remove",
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
    return TestSubmissionSetup(config_path, repo_root=repo_root).run(
        non_interactive=non_interactive,
        scheduler_mode=scheduler_mode,
        provided=provided,
    )
