from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from release_gate_config import CANONICAL_REQUIRED_CHECKS, default_config_path, load_config
from release_gate_controller import ReleaseGateController
from release_gate_mail import locked_mail_gateway, locked_product_gate_gateway, resolve_locked_entrypoint
from release_workflow_gate_scheduler import ReleaseGateScheduler


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile  # noqa: E402


_PRODUCT_GATE_PLUGIN_NAME = "-".join(("product", "release", "gate"))
_PRODUCT_GATE_PLUGIN_ROOT = Path("plugins") / _PRODUCT_GATE_PLUGIN_NAME
_PRODUCT_GATE_ENTRYPOINT = _PRODUCT_GATE_PLUGIN_ROOT / "src" / "release_gate_cli.py"


class SetupError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


BootstrapRunner = Callable[..., Mapping[str, Any]]


class ReleaseGateSetup:
    def __init__(
        self,
        config_path: str | Path,
        *,
        repo_root: str | Path = _REPO_ROOT,
        bootstrap_runner: BootstrapRunner = bootstrap_profile,
        controller_factory: Callable[[Any, Any], ReleaseGateController] | None = None,
        scheduler_factory: Callable[[Path, Path, int], ReleaseGateScheduler] | None = None,
    ) -> None:
        self.config_path = Path(config_path).resolve(strict=False)
        self.repo_root = Path(repo_root).resolve(strict=False)
        self.bootstrap_runner = bootstrap_runner
        self.controller_factory = controller_factory
        self.scheduler_factory = scheduler_factory

    def run(self, *, non_interactive: bool, scheduler_mode: str, provided: Mapping[str, Any] | None = None) -> dict[str, Any]:
        del non_interactive
        values = {key: value for key, value in dict(provided or {}).items() if value is not None}
        bootstrap: dict[str, Any] = {}
        if self.config_path.is_file():
            loaded = load_config(self.config_path)
            lock_path = loaded.dependency_lock
            if not loaded.shared_hmac_secret_path.exists():
                loaded.shared_hmac_secret_path.parent.mkdir(parents=True, exist_ok=True)
                loaded.shared_hmac_secret_path.write_bytes(secrets.token_bytes(32))
        else:
            mail_profile = str(values.get("mail_profile") or "release-gate").strip()
            mail_email = str(values.get("mail_email") or "release-gate@example.com").strip()
            release_gate_group = str(values.get("release_gate_group") or "release-gate@example.com").strip()
            release_group = str(values.get("release_group") or "release@example.com").strip()
            state_dir = Path(str(values.get("state_dir") or self.config_path.parent / "state")).resolve(strict=False)
            product_gate_config = Path(str(values.get("product_gate_config_path") or self.config_path.parent / "product-release-gate-config.json")).resolve(strict=False)
            bootstrap = dict(self.bootstrap_runner(profile="release-gate", repo_root=self.repo_root))
            lock_path = Path(str(bootstrap.get("dependency_lock") or "")).resolve(strict=True)
            lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
            mail_cli = resolve_locked_entrypoint(
                lock_path,
                dependency_lock_sha256=lock_digest,
                plugin_name="imap-smtp-mail",
                plugin_root=Path("plugins/imap-smtp-mail"),
                entrypoint_path=Path("plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py"),
            )
            product_cli = resolve_locked_entrypoint(
                lock_path,
                dependency_lock_sha256=lock_digest,
                plugin_name=_PRODUCT_GATE_PLUGIN_NAME,
                plugin_root=_PRODUCT_GATE_PLUGIN_ROOT,
                entrypoint_path=_PRODUCT_GATE_ENTRYPOINT,
            )
            secret_path = Path(str(values.get("shared_hmac_secret_path") or state_dir / "keys" / "shared-handoff.key")).resolve(strict=False)
            secret_path.parent.mkdir(parents=True, exist_ok=True)
            if not secret_path.exists():
                secret_path.write_bytes(secrets.token_bytes(32))
            config = {
                "version": 1,
                "mail_account": {"profile": mail_profile, "email": mail_email},
                "release_gate_group": release_gate_group,
                "release_group": release_group,
                "mailbox": "INBOX",
                "timezone": "UTC",
                "poll_minutes": 60,
                "state_dir": str(state_dir),
                "dependency_lock": str(lock_path),
                "dependency_lock_sha256": lock_digest,
                "shared_hmac_secret_path": str(secret_path),
                "mail_command": [sys.executable, str(mail_cli)],
                "product_gate": {
                    "config_path": str(product_gate_config),
                    "command": [sys.executable, str(product_cli), "--config", str(product_gate_config)],
                },
                "policy": {
                    "profile": "release-gate/v1",
                    "required_checks": list(CANONICAL_REQUIRED_CHECKS),
                    "enabled_optional_checks": [],
                },
            }
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self.config_path.with_name(f".{self.config_path.name}.tmp-{os.getpid()}")
            temporary_path.write_text(json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(temporary_path, self.config_path)
            loaded = load_config(self.config_path)
        controller = (self.controller_factory or self._build_controller)(loaded, lock_path)
        preflight = controller.preflight()
        if not preflight.get("ready"):
            raise SetupError("CAPABILITY_BLOCKED", "release-gate preflight failed")
        first_run = controller.run_once()
        scheduler = (self.scheduler_factory or self._build_scheduler)(self.config_path, loaded.state_dir, loaded.poll_minutes)
        installed = scheduler.install(mode=scheduler_mode)
        scheduler_status = scheduler.status(mode=str(installed.get("mode") or scheduler_mode))
        doctor = controller.doctor()
        return {"status": "ready", "config_path": str(self.config_path), "prompt_count": 0, "bootstrap": bootstrap, "preflight": preflight, "first_run": first_run, "scheduler": installed, "scheduler_status": scheduler_status, "doctor": doctor}

    def _build_controller(self, loaded: Any, lock_path: Path) -> ReleaseGateController:
        mail_gateway = locked_mail_gateway(lock_path, dependency_lock_sha256=loaded.dependency_lock_sha256)
        product_gateway = locked_product_gate_gateway(lock_path, dependency_lock_sha256=loaded.dependency_lock_sha256, config_path=loaded.product_gate.config_path)
        return ReleaseGateController(loaded, mail_gateway=mail_gateway, product_gate=product_gateway)

    def _build_scheduler(self, config_path: Path, state_dir: Path, poll_minutes: int) -> ReleaseGateScheduler:
        return ReleaseGateScheduler(config_path=config_path, state_dir=state_dir, poll_minutes=poll_minutes)


def run_setup_operation(
    *,
    config_path: str | Path | None = None,
    repo_root: str | Path = _REPO_ROOT,
    non_interactive: bool,
    scheduler_mode: str,
    provided: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    setup = ReleaseGateSetup(config_path or default_config_path(), repo_root=repo_root)
    return setup.run(non_interactive=non_interactive, scheduler_mode=scheduler_mode, provided=provided)
