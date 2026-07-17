from __future__ import annotations

import hashlib
import json
import secrets
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from pre_release_config import default_config_path, load_config
from pre_release_controller import PreReleaseController
from pre_release_mail import locked_mail_gateway, locked_product_gate_gateway, resolve_locked_entrypoint
from pre_release_scheduler import PreReleaseScheduler


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile  # noqa: E402

workflow_core_digest = "embedded-release-workflow-core"


class SetupError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


BootstrapRunner = Callable[..., Mapping[str, Any]]


class PreReleaseSetup:
    def __init__(self, config_path: str | Path, *, repo_root: str | Path = _REPO_ROOT, bootstrap_runner: BootstrapRunner = bootstrap_profile, controller_factory: Callable[[Any, Any], PreReleaseController] | None = None, scheduler_factory: Callable[[Path, Path, int], PreReleaseScheduler] | None = None) -> None:
        self.config_path = Path(config_path).resolve(strict=False)
        self.repo_root = Path(repo_root).resolve(strict=False)
        self.bootstrap_runner = bootstrap_runner
        self.controller_factory = controller_factory
        self.scheduler_factory = scheduler_factory

    def run(self, *, non_interactive: bool, scheduler_mode: str, provided: Mapping[str, Any] | None = None) -> dict[str, Any]:
        del non_interactive
        values = {key: value for key, value in dict(provided or {}).items() if value is not None}
        existing: dict[str, Any] = {}
        prompt_count = 0
        if self.config_path.is_file():
            loaded_existing = json.loads(self.config_path.read_text(encoding="utf-8"))
            if isinstance(loaded_existing, dict):
                existing = loaded_existing
        mail_account = existing.get("mail_account") if isinstance(existing.get("mail_account"), dict) else {}
        existing_gate = existing.get("product_gate") if isinstance(existing.get("product_gate"), dict) else {}
        mail_profile = str(values.get("mail_profile") or mail_account.get("profile") or "qa-owner").strip()
        mail_email = str(values.get("mail_email") or mail_account.get("email") or "qa-owner@example.com").strip()
        submission_group = str(values.get("submission_group") or existing.get("submission_group") or "submission@example.com").strip()
        release_gate_group = str(values.get("release_gate_group") or existing.get("release_gate_group") or "release-gate@example.com").strip()
        state_dir = Path(str(values.get("state_dir") or existing.get("state_dir") or self.config_path.parent / "state")).resolve(strict=False)
        product_gate_config = Path(str(values.get("product_gate_config_path") or existing_gate.get("config_path") or self.config_path.parent / "product-release-gate-config.json")).resolve(strict=False)
        bootstrap = dict(self.bootstrap_runner(repo_root=self.repo_root))
        lock_path = Path(str(bootstrap.get("dependency_lock") or "")).resolve(strict=True)
        lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
        mail_cli = resolve_locked_entrypoint(lock_path, dependency_lock_sha256=lock_digest, plugin_name="imap-smtp-mail", plugin_root=Path("plugins/imap-smtp-mail"), entrypoint_path=Path("plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py"))
        gate_name = "-".join(("product", "release", "gate"))
        gate_root = Path("plugins") / gate_name
        gate_entrypoint = gate_root / "src" / f"{'_'.join(('release', 'gate', 'cli'))}.py"
        product_cli = resolve_locked_entrypoint(lock_path, dependency_lock_sha256=lock_digest, plugin_name=gate_name, plugin_root=gate_root, entrypoint_path=gate_entrypoint)
        secret_path = Path(str(values.get("shared_hmac_secret_path") or existing.get("shared_hmac_secret_path") or state_dir / "keys" / "shared-handoff.key")).resolve(strict=False)
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        if not secret_path.exists():
            secret_path.write_bytes(secrets.token_bytes(32))
        config = {"version": 1, "mail_account": {"profile": mail_profile, "email": mail_email}, "submission_group": submission_group, "release_gate_group": release_gate_group, "mailbox": "INBOX", "timezone": "UTC", "poll_minutes": 60, "state_dir": str(state_dir), "dependency_lock": str(lock_path), "dependency_lock_sha256": lock_digest, "shared_hmac_secret_path": str(secret_path), "mail_command": [sys.executable, str(mail_cli)], "product_gate": {"config_path": str(product_gate_config), "command": [sys.executable, str(product_cli), "--config", str(product_gate_config)]}, "policy": {"profile": "pre-release/v1", "enabled_optional_checks": []}}
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        loaded = load_config(self.config_path)
        controller = (self.controller_factory or self._build_controller)(loaded, lock_path)
        preflight = controller.preflight()
        if not preflight.get("ready"):
            raise SetupError("CAPABILITY_BLOCKED", "pre-release preflight failed")
        first_run = controller.run_once()
        scheduler = (self.scheduler_factory or self._build_scheduler)(self.config_path, loaded.state_dir, loaded.poll_minutes)
        installed = scheduler.install(mode=scheduler_mode)
        scheduler_status = scheduler.status(mode=str(installed.get("mode") or scheduler_mode))
        doctor = controller.doctor()
        return {"status": "ready", "config_path": str(self.config_path), "prompt_count": prompt_count, "bootstrap": bootstrap, "preflight": preflight, "first_run": first_run, "scheduler": installed, "scheduler_status": scheduler_status, "doctor": doctor, "commands": {"status": f'{sys.executable} "{_PLUGIN_ROOT / "src" / "pre_release_cli.py"}" --config "{self.config_path}" status', "doctor": f'{sys.executable} "{_PLUGIN_ROOT / "src" / "pre_release_cli.py"}" --config "{self.config_path}" doctor'}}

    def _build_controller(self, loaded: Any, lock_path: Path) -> PreReleaseController:
        mail_gateway = locked_mail_gateway(lock_path, dependency_lock_sha256=loaded.dependency_lock_sha256)
        product_gateway = locked_product_gate_gateway(lock_path, dependency_lock_sha256=loaded.dependency_lock_sha256, config_path=loaded.product_gate.config_path)
        return PreReleaseController(loaded, mail_gateway=mail_gateway, product_gate=product_gateway)

    def _build_scheduler(self, config_path: Path, state_dir: Path, poll_minutes: int) -> PreReleaseScheduler:
        return PreReleaseScheduler(config_path=config_path, state_dir=state_dir, poll_minutes=poll_minutes)


def run_setup_operation(*, config_path: str | Path | None = None, repo_root: str | Path = _REPO_ROOT, non_interactive: bool, scheduler_mode: str, provided: Mapping[str, Any] | None = None) -> dict[str, Any]:
    setup = PreReleaseSetup(config_path or default_config_path(), repo_root=repo_root)
    return setup.run(non_interactive=non_interactive, scheduler_mode=scheduler_mode, provided=provided)
