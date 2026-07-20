from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from release_gate_approval_mail import (
    LockedImapSmtpMailCliGateway,
    resolve_locked_entrypoint,
)
from release_gate_core import default_config
from release_gate_production import ProductionReleaseController
from release_gate_runtime import ReleaseGateWorkflowRuntime
from release_gate_scheduler import ReleaseGateScheduler


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile  # noqa: E402


_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAIL_PLUGIN_ROOT = Path("plugins/imap-smtp-mail")
_MAIL_CLI_PATH = _MAIL_PLUGIN_ROOT / "src" / "imap_smtp_mail_cli.py"
_VERIFIER_PLUGIN_ROOT = Path("plugins/release-approval-verifier")
_VERIFIER_BRIDGE_PATH = (
    _VERIFIER_PLUGIN_ROOT / "src" / "verifier_product_gate_bridge.py"
)
_FORBIDDEN_KEYS = {
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "authorization_code",
    "auth_code",
}


class SetupError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


BootstrapRunner = Callable[..., Mapping[str, Any]]
MailGatewayFactory = Callable[[Path, str], Any]


def _default_verifier_config_path(
    environ: Mapping[str, str] | None = None,
) -> Path:
    environment = os.environ if environ is None else environ
    explicit = str(
        environment.get("RELEASE_APPROVAL_VERIFIER_CONFIG") or ""
    ).strip()
    if explicit:
        return Path(os.path.expandvars(explicit)).expanduser().resolve(strict=False)
    if sys.platform.startswith("win"):
        local = str(environment.get("LOCALAPPDATA") or "").strip()
        root = Path(local) if local else Path.home() / "AppData" / "Local"
    else:
        xdg = str(environment.get("XDG_CONFIG_HOME") or "").strip()
        root = Path(xdg) if xdg else Path.home() / ".config"
    return (root / "release-approval-verifier" / "config.json").resolve(
        strict=False
    )


class ReleaseGateSetup:
    """Install and bind the managed production release-gate runtime."""

    def __init__(
        self,
        config_path: str | Path,
        *,
        repo_root: str | Path = _REPO_ROOT,
        prompt: Callable[[str], str] = input,
        controller_factory: Callable[[Path], Any] | None = None,
        scheduler_factory: Callable[[Any, Path], Any] | None = None,
        runtime_factory: Callable[[Any, Path], Any] | None = None,
        bootstrap_runner: BootstrapRunner = bootstrap_profile,
        mail_gateway_factory: MailGatewayFactory | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.config_path = Path(config_path).resolve(strict=False)
        self.repo_root = Path(repo_root).resolve(strict=False)
        self.prompt = prompt
        self.controller_factory = controller_factory or (
            lambda path: ProductionReleaseController(str(path))
        )
        self.scheduler_factory = scheduler_factory or self._scheduler_factory
        self.runtime_factory = runtime_factory or (
            lambda controller, path: ReleaseGateWorkflowRuntime(controller, path)
        )
        self.bootstrap_runner = bootstrap_runner
        self.mail_gateway_factory = mail_gateway_factory or (
            lambda lock_path, lock_digest: LockedImapSmtpMailCliGateway(
                lock_path,
                dependency_lock_sha256=lock_digest,
            )
        )
        self.environ = dict(os.environ if environ is None else environ)

    def run(
        self,
        *,
        non_interactive: bool,
        scheduler_mode: str,
        provided: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        values = dict(provided or {})
        prompt_count = 0
        if prompt_count > 4:
            raise SetupError(
                "PROMPT_LIMIT_EXCEEDED",
                "setup exceeded the supported prompt budget.",
            )
        self._reject_secrets(values)
        bootstrap = dict(
            self.bootstrap_runner(
                "product-release-gate",
                repo_root=self.repo_root,
            )
        )
        lock_text = str(bootstrap.get("dependency_lock") or "").strip()
        if not lock_text:
            raise SetupError(
                "DEPENDENCY_BOOTSTRAP_FAILED",
                "dependency bootstrap did not return an authoritative lock path",
            )
        dependency_lock = Path(lock_text).resolve(strict=True)
        dependency_lock_sha256 = self._sha256_file(dependency_lock)

        verifier_config_path = self._provided_verifier_config(values)
        verifier = self._read_verifier_binding(verifier_config_path)
        module = self._safe_module(values.get("module") or "all")

        bridge_path = resolve_locked_entrypoint(
            dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            plugin_name="release-approval-verifier",
            plugin_root=_VERIFIER_PLUGIN_ROOT,
            entrypoint_path=_VERIFIER_BRIDGE_PATH,
        )
        mail_cli_path = resolve_locked_entrypoint(
            dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            plugin_name="imap-smtp-mail",
            plugin_root=_MAIL_PLUGIN_ROOT,
            entrypoint_path=_MAIL_CLI_PATH,
        )
        self._validate_mail_account(
            dependency_lock,
            dependency_lock_sha256,
            profile=verifier["profile"],
            email=verifier["email"],
        )

        verify_command = [
            sys.executable,
            str(bridge_path),
            "--config",
            str(verifier_config_path),
            "--verification-ref",
            "{verification_ref}",
        ]
        mail_command = [sys.executable, str(mail_cli_path)]
        if self.config_path.is_file():
            config = self._read_existing()
            config = self._refresh_runtime_binding(
                config,
                dependency_lock=dependency_lock,
                dependency_lock_sha256=dependency_lock_sha256,
                verifier_config_path=verifier_config_path,
                verify_command=verify_command,
                mail_command=mail_command,
                verifier=verifier,
                module=module,
                scheduler_mode=scheduler_mode,
            )
        else:
            config = self._new_config(
                dependency_lock=dependency_lock,
                dependency_lock_sha256=dependency_lock_sha256,
                verifier_config_path=verifier_config_path,
                verify_command=verify_command,
                mail_command=mail_command,
                verifier=verifier,
                module=module,
                scheduler_mode=scheduler_mode,
            )
        self._write_config(config)

        controller = self.controller_factory(self.config_path)
        preflight = controller.unified_approval_preflight()
        if not preflight.get("ready"):
            missing = ", ".join(preflight.get("missing_capabilities") or [])
            raise SetupError(
                "CAPABILITY_BLOCKED",
                f"unified approval preflight failed: {missing or 'unknown capability'}",
            )
        runtime_config = config.get("runtime") or {}
        configured_mode = str(
            runtime_config.get("scheduler_mode") or scheduler_mode or "auto"
        )
        scheduler = self.scheduler_factory(controller, self.config_path)
        installed = scheduler.install(mode=configured_mode)
        runtime = self.runtime_factory(controller, self.config_path)
        first_run = runtime.run_once()
        if first_run.get("status") not in {"ready", "RUN_ALREADY_ACTIVE"}:
            raise SetupError(
                "FIRST_RUN_FAILED",
                f"first reconciliation failed: {first_run.get('status')}",
            )
        installed_mode = str(installed.get("mode") or configured_mode)
        scheduler_status = scheduler.status(mode=installed_mode)
        if scheduler_status.get("installed") is not True:
            raise SetupError(
                "SCHEDULER_STATUS_FAILED",
                "external scheduler status did not confirm installation",
            )
        cli = [
            sys.executable,
            str(_PLUGIN_ROOT / "src" / "release_gate_cli.py"),
            "--config",
            str(self.config_path),
        ]
        return {
            "status": "ready",
            "config_path": str(self.config_path),
            "prompt_count": 0,
            "dependencies_changed": bootstrap.get("fresh_task_required") is True,
            "bootstrap": bootstrap,
            "preflight": preflight,
            "scheduler": installed,
            "first_run": first_run,
            "scheduler_status": scheduler_status,
            "commands": {
                "status": subprocess.list2cmdline(cli + ["status"]),
                "doctor": subprocess.list2cmdline(cli + ["doctor"]),
                "remove_scheduler": subprocess.list2cmdline(
                    cli + ["scheduler", "remove"]
                ),
            },
        }

    def _new_config(
        self,
        *,
        dependency_lock: Path,
        dependency_lock_sha256: str,
        verifier_config_path: Path,
        verify_command: list[str],
        mail_command: list[str],
        verifier: Mapping[str, str],
        module: str,
        scheduler_mode: str,
    ) -> dict[str, Any]:
        config = default_config()
        root = self.config_path.parent
        config["storage_dir"] = str((root / "events").resolve(strict=False))
        config["runtime"] = {
            "state_dir": str((root / "state").resolve(strict=False)),
            "poll_minutes": 60,
            "scheduler_mode": scheduler_mode,
            "auto_authorize_verified_pre_release": True,
            "auto_deploy_authorized_releases": False,
            "auto_generate_production_report": False,
            "auto_deliver_production_report": False,
            "authorization_requester": "rd-flywheel",
        }
        production = config.setdefault("production", {})
        production["enabled"] = True
        production["audit"] = {"key_env": "PRODUCT_RELEASE_GATE_AUDIT_KEY"}
        production["approval_workflow"] = self._workflow_binding(
            dependency_lock=dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            verifier_config_path=verifier_config_path,
            verify_command=verify_command,
            mail_command=mail_command,
            verifier=verifier,
            module=module,
        )
        production["report_delivery"] = self._report_delivery_binding(
            dependency_lock=dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            mail_command=mail_command,
            verifier=verifier,
            module=module,
        )
        return config

    def _refresh_runtime_binding(
        self,
        config: dict[str, Any],
        *,
        dependency_lock: Path,
        dependency_lock_sha256: str,
        verifier_config_path: Path,
        verify_command: list[str],
        mail_command: list[str],
        verifier: Mapping[str, str],
        module: str,
        scheduler_mode: str,
    ) -> dict[str, Any]:
        production = config.setdefault("production", {})
        production["enabled"] = True
        production.setdefault(
            "audit", {"key_env": "PRODUCT_RELEASE_GATE_AUDIT_KEY"}
        )
        production["approval_workflow"] = self._workflow_binding(
            dependency_lock=dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            verifier_config_path=verifier_config_path,
            verify_command=verify_command,
            mail_command=mail_command,
            verifier=verifier,
            module=module,
        )
        managed_delivery = self._report_delivery_binding(
            dependency_lock=dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            mail_command=mail_command,
            verifier=verifier,
            module=module,
        )
        delivery = production.setdefault("report_delivery", {})
        for key, value in managed_delivery.items():
            if key in {"dependency_lock", "dependency_lock_sha256", "command"}:
                delivery[key] = value
            else:
                delivery.setdefault(key, value)
        runtime = config.setdefault("runtime", {})
        runtime.setdefault(
            "state_dir",
            str((self.config_path.parent / "state").resolve(strict=False)),
        )
        runtime.setdefault("poll_minutes", 60)
        runtime["scheduler_mode"] = str(
            runtime.get("scheduler_mode") or scheduler_mode
        )
        runtime["auto_authorize_verified_pre_release"] = True
        runtime.setdefault("auto_deploy_authorized_releases", False)
        runtime.setdefault("auto_generate_production_report", False)
        runtime.setdefault("auto_deliver_production_report", False)
        runtime.setdefault("authorization_requester", "rd-flywheel")
        return config

    @staticmethod
    def _workflow_binding(
        *,
        dependency_lock: Path,
        dependency_lock_sha256: str,
        verifier_config_path: Path,
        verify_command: list[str],
        mail_command: list[str],
        verifier: Mapping[str, str],
        module: str,
    ) -> dict[str, Any]:
        return {
            "mode": "unified_multi_role",
            "dependency_lock": str(dependency_lock),
            "dependency_lock_sha256": dependency_lock_sha256,
            "verifier_config_path": str(verifier_config_path),
            "verify_command": verify_command,
            "timeout_seconds": 120,
            "mail": {
                "profile": verifier["profile"],
                "release_group": verifier["release_group"],
                "module": module,
                "dependency_lock": str(dependency_lock),
                "dependency_lock_sha256": dependency_lock_sha256,
                "command": mail_command,
                "timeout_seconds": 120,
            },
        }

    @staticmethod
    def _report_delivery_binding(
        *,
        dependency_lock: Path,
        dependency_lock_sha256: str,
        mail_command: list[str],
        verifier: Mapping[str, str],
        module: str,
    ) -> dict[str, Any]:
        return {
            "enabled": False,
            "profile": verifier["profile"],
            "sender_email": verifier["email"],
            "recipients": [verifier["release_group"]],
            "module": module,
            "mailbox": "INBOX",
            "dependency_lock": str(dependency_lock),
            "dependency_lock_sha256": dependency_lock_sha256,
            "command": mail_command,
            "timeout_seconds": 120,
            "readback_timeout_seconds": 86400,
        }

    def _provided_verifier_config(self, values: Mapping[str, Any]) -> Path:
        explicit = str(values.get("verifier_config_path") or "").strip()
        path = (
            Path(os.path.expandvars(explicit)).expanduser().resolve(strict=False)
            if explicit
            else _default_verifier_config_path(self.environ)
        )
        if not path.is_file():
            raise SetupError(
                "VERIFIER_CONFIG_REQUIRED",
                "release-approval-verifier must be configured before product-release-gate setup",
            )
        return path.resolve(strict=True)

    def _read_verifier_binding(self, path: Path) -> dict[str, str]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SetupError(
                "INVALID_VERIFIER_CONFIG",
                f"verifier config is invalid JSON: {exc}",
            ) from exc
        if not isinstance(payload, Mapping):
            raise SetupError(
                "INVALID_VERIFIER_CONFIG",
                "verifier config must be one JSON object",
            )
        account = payload.get("verifier_mail_account")
        release_group = str(payload.get("release_group") or "").strip().lower()
        profile = (
            str(account.get("profile") or "").strip()
            if isinstance(account, Mapping)
            else ""
        )
        email = (
            str(account.get("email") or "").strip().lower()
            if isinstance(account, Mapping)
            else ""
        )
        if (
            not profile
            or not _EMAIL_PATTERN.fullmatch(email)
            or not _EMAIL_PATTERN.fullmatch(release_group)
        ):
            raise SetupError(
                "INVALID_VERIFIER_CONFIG",
                "verifier config must define one mail profile, account email, and release group",
            )
        return {
            "profile": profile,
            "email": email,
            "release_group": release_group,
        }

    def _validate_mail_account(
        self,
        dependency_lock: Path,
        dependency_lock_sha256: str,
        *,
        profile: str,
        email: str,
    ) -> None:
        gateway = self.mail_gateway_factory(
            dependency_lock,
            dependency_lock_sha256,
        )
        accounts = gateway.list_accounts()
        matches = [
            item
            for item in accounts
            if str(item.get("name") or "").strip() == profile
            and str(item.get("email") or "").strip().lower() == email
        ]
        if len(matches) != 1:
            raise SetupError(
                "MAIL_ACCOUNT_MISMATCH",
                "verifier mail profile and email were not found exactly once in imap-smtp-mail",
            )

    @staticmethod
    def _safe_module(value: Any) -> str:
        module = str(value or "").strip()
        if not module or len(module) > 80 or any(ord(char) < 32 for char in module):
            raise SetupError(
                "INVALID_MODULE",
                "module must contain 1-80 safe characters",
            )
        return module

    def _read_existing(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SetupError(
                "INVALID_CONFIG",
                f"configuration is invalid JSON: {exc}",
            ) from exc
        if not isinstance(payload, dict):
            raise SetupError("INVALID_CONFIG", "configuration must be one JSON object")
        return payload

    def _write_config(self, payload: Mapping[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config_path.with_name(
            f".{self.config_path.name}.{os.getpid()}.tmp"
        )
        temporary.write_text(
            json.dumps(dict(payload), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.config_path)

    def _scheduler_factory(
        self,
        controller: Any,
        path: Path,
    ) -> ReleaseGateScheduler:
        runtime = controller.config.get("runtime") or {}
        return ReleaseGateScheduler(
            config_path=path,
            state_dir=(
                runtime.get("state_dir")
                or controller.storage_dir.parent / "state"
            ),
            poll_minutes=runtime.get("poll_minutes", 60),
        )

    @staticmethod
    def _sha256_file(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @classmethod
    def _reject_secrets(cls, value: Any, path: str = "provided") -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                normalized = str(key).strip().lower()
                if normalized in _FORBIDDEN_KEYS:
                    raise SetupError(
                        "SECRET_INPUT_FORBIDDEN",
                        f"setup does not accept credential field: {path}.{key}",
                    )
                cls._reject_secrets(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                cls._reject_secrets(child, f"{path}[{index}]")


def run_setup_operation(
    *,
    config_path: str | Path,
    non_interactive: bool,
    scheduler_mode: str,
    provided: Mapping[str, Any] | None = None,
    repo_root: str | Path = _REPO_ROOT,
) -> dict[str, Any]:
    return ReleaseGateSetup(
        config_path,
        repo_root=repo_root,
    ).run(
        non_interactive=non_interactive,
        scheduler_mode=scheduler_mode,
        provided=provided,
    )
