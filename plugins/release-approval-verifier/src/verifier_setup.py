from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from verifier_config import (
    VerifierConfig,
    default_product_gate_config_path,
    load_config,
)
from verifier_dependency_lock import sha256_file
from verifier_mail import MailGateway
from verifier_scheduler import VerifierScheduler


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile


_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_FORBIDDEN_INPUT_FRAGMENTS = (
    "auth_code",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)


class SetupError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _parse_authserv_ids(value: str) -> list[str]:
    candidates = [item.strip().lower() for item in value.split(",")]
    if not candidates or any(
        not item or any(character.isspace() for character in item) or ";" in item
        for item in candidates
    ):
        raise SetupError(
            "INVALID_SETUP_INPUT",
            "trusted_authserv_ids must be a comma-separated list of authserv-id tokens.",
        )
    if len(set(candidates)) != len(candidates):
        raise SetupError(
            "INVALID_SETUP_INPUT",
            "trusted_authserv_ids must not contain duplicates.",
        )
    return candidates


BootstrapRunner = Callable[..., Mapping[str, Any]]
AccountDiscoverer = Callable[[Path, str], Mapping[str, Any]]
ControllerFactory = Callable[[VerifierConfig, Path], Any]
SchedulerFactory = Callable[[VerifierConfig, Path], VerifierScheduler | Any]


def _default_account_discoverer(
    dependency_lock: Path, dependency_lock_sha256: str
) -> Mapping[str, Any]:
    return MailGateway(
        dependency_lock,
        dependency_lock_sha256=dependency_lock_sha256,
    ).list_accounts()


def _default_controller_factory(config: VerifierConfig, config_path: Path) -> Any:
    from verifier_controller import VerifierController

    return VerifierController(config=config, config_path=config_path)


def _default_scheduler_factory(config: VerifierConfig, config_path: Path) -> VerifierScheduler:
    return VerifierScheduler(
        plugin_name="release-approval-verifier",
        role_id="runtime",
        config_path=config_path,
        state_dir=config.state_dir,
        poll_minutes=config.poll_minutes,
    )


class VerifierSetup:
    def __init__(
        self,
        *,
        config_path: str | Path,
        repo_root: str | Path,
        bootstrap_runner: BootstrapRunner = bootstrap_profile,
        account_discoverer: AccountDiscoverer = _default_account_discoverer,
        controller_factory: ControllerFactory = _default_controller_factory,
        scheduler_factory: SchedulerFactory = _default_scheduler_factory,
        input_fn: Callable[[str], str] = input,
        timezone_detector: Callable[[], str] | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.config_path = Path(config_path).expanduser().resolve(strict=False)
        self.repo_root = Path(repo_root).expanduser().resolve(strict=False)
        self.bootstrap_runner = bootstrap_runner
        self.account_discoverer = account_discoverer
        self.controller_factory = controller_factory
        self.scheduler_factory = scheduler_factory
        self.input_fn = input_fn
        self.timezone_detector = timezone_detector or self._detect_timezone
        self.environ = dict(os.environ if environ is None else environ)
        self.prompt_count = 0

    def run(
        self,
        *,
        non_interactive: bool,
        scheduler_mode: str,
        provided: Mapping[str, str | None] | None = None,
    ) -> dict[str, Any]:
        values = self._provided_values(provided or {})
        self.prompt_count = 0
        existed = self.config_path.is_file()
        bootstrap = dict(
            self.bootstrap_runner(
                "release-approval-verifier",
                repo_root=self.repo_root,
            )
        )
        dependency_lock_text = str(bootstrap.get("dependency_lock") or "").strip()
        if not dependency_lock_text:
            raise SetupError(
                "DEPENDENCY_BOOTSTRAP_FAILED",
                "dependency bootstrap did not return an authoritative lock path.",
            )
        try:
            dependency_lock = Path(dependency_lock_text).resolve(strict=True)
            dependency_lock_sha256 = sha256_file(dependency_lock)
        except OSError as exc:
            raise SetupError(
                "DEPENDENCY_BOOTSTRAP_FAILED",
                "authoritative dependency lock is unavailable.",
            ) from exc

        if existed:
            config = load_config(self.config_path)
            if config.dependency_lock != dependency_lock:
                raise SetupError(
                    "DEPENDENCY_LOCK_MISMATCH",
                    "existing config does not reference the authoritative dependency lock.",
                )
            if config.dependency_lock_sha256 != dependency_lock_sha256:
                raise SetupError(
                    "DEPENDENCY_LOCK_MISMATCH",
                    "existing config does not pin the authoritative dependency lock digest.",
                )
        else:
            accounts = self._accounts(
                self.account_discoverer(dependency_lock, dependency_lock_sha256)
            )
            payload = self._build_config_payload(
                dependency_lock=dependency_lock,
                dependency_lock_sha256=dependency_lock_sha256,
                accounts=accounts,
                non_interactive=non_interactive,
                provided=values,
            )
            if self.prompt_count > 4:
                raise SetupError(
                    "SETUP_PROMPT_BUDGET_EXCEEDED",
                    "standard verifier setup must not exceed four prompts.",
                )
            self._write_config(payload)
            config = load_config(self.config_path)

        controller = self.controller_factory(config, self.config_path)
        scheduler = self.scheduler_factory(config, self.config_path)
        preflight = controller.preflight()
        if str(preflight.get("status") or "") != "ready":
            raise SetupError(
                "PREFLIGHT_FAILED",
                "release approval verifier preflight did not reach ready state.",
            )
        schedule = scheduler.install(mode=scheduler_mode)
        first_run = controller.run_once()
        runtime_status = controller.status()
        doctor = controller.doctor()
        schedule_status = scheduler.status(mode=scheduler_mode)
        cli_prefix = [
            sys.executable,
            str((Path(__file__).resolve().parent / "verifier_cli.py").resolve()),
            "--config",
            str(self.config_path),
        ]
        return {
            "status": "ready",
            "config_path": str(self.config_path),
            "config_created": not existed,
            "prompt_count": self.prompt_count,
            "dependencies_changed": bootstrap.get("fresh_task_required") is True,
            "bootstrap": bootstrap,
            "preflight": preflight,
            "scheduler": schedule,
            "first_run": first_run,
            "runtime_status": runtime_status,
            "doctor": doctor,
            "scheduler_status": schedule_status,
            "status_command": subprocess.list2cmdline(cli_prefix + ["status"]),
            "doctor_command": subprocess.list2cmdline(cli_prefix + ["doctor"]),
            "rollback_command": subprocess.list2cmdline(
                cli_prefix + ["scheduler", "remove", "--mode", scheduler_mode]
            ),
        }

    def _build_config_payload(
        self,
        *,
        dependency_lock: Path,
        dependency_lock_sha256: str,
        accounts: list[dict[str, str]],
        non_interactive: bool,
        provided: Mapping[str, str],
    ) -> dict[str, Any]:
        account = self._select_account(
            accounts=accounts,
            non_interactive=non_interactive,
            provided=provided,
        )
        release_group = self._value_or_prompt(
            "release_group",
            "Release approval mail group: ",
            provided,
            non_interactive,
        ).lower()
        if not _EMAIL_PATTERN.fullmatch(release_group):
            raise SetupError("INVALID_SETUP_INPUT", "release_group must be a valid email address.")

        role_document_url = self._value_or_prompt(
            "role_document_url",
            "Feishu approval-role document URL: ",
            provided,
            non_interactive,
        )
        audit_document_url = self._value_or_prompt(
            "audit_document_url",
            "Feishu release-audit document URL: ",
            provided,
            non_interactive,
        )
        for field_name, value in (
            ("role_document_url", role_document_url),
            ("audit_document_url", audit_document_url),
        ):
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise SetupError(
                    "INVALID_SETUP_INPUT",
                    f"{field_name} must be an absolute HTTP(S) URL.",
                )

        trusted_authserv_ids = _parse_authserv_ids(
            self._value_or_prompt(
                "trusted_authserv_ids",
                "Trusted Authentication-Results authserv-id(s), comma separated: ",
                provided,
                non_interactive,
            )
        )

        product_gate_config_text = str(
            provided.get("product_gate_config_path") or ""
        ).strip()
        product_gate_config_path = (
            Path(product_gate_config_text).expanduser().resolve(strict=False)
            if product_gate_config_text
            else default_product_gate_config_path()
        )
        state_dir_text = str(provided.get("state_dir") or "").strip()
        state_dir = (
            Path(state_dir_text).expanduser().resolve(strict=False)
            if state_dir_text
            else (self.config_path.parent / "state").resolve(strict=False)
        )
        return {
            "mode": "production",
            "role_source": {
                "type": "feishu",
                "document_url": role_document_url,
                "heading": "## 审批角色",
            },
            "release_group": release_group,
            "verifier_mail_account": account,
            "mailbox": "INBOX",
            "event_expiry_hours": 24,
            "poll_minutes": 60,
            "timezone": self.timezone_detector(),
            "working_hours": {
                "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
                "start": "09:00",
                "end": "18:00",
            },
            "reminder_policy": {
                "initial_delay_minutes": 60,
                "repeat_minutes": 240,
                "maximum": 3,
            },
            "authentication_policy": {
                "accepted_paths": ["dmarc", "dkim", "spf"],
                "allowed_authserv_ids": trusted_authserv_ids,
                "trusted_internal_header": "X-Trusted-Relay",
                "trusted_internal_value": "release-gateway",
            },
            "state_dir": str(state_dir),
            "dependency_lock": str(dependency_lock),
            "dependency_lock_sha256": dependency_lock_sha256,
            "audit_document": {"url": audit_document_url},
            "product_gate": {"config_path": str(product_gate_config_path)},
        }

    def _select_account(
        self,
        *,
        accounts: list[dict[str, str]],
        non_interactive: bool,
        provided: Mapping[str, str],
    ) -> dict[str, str]:
        profile = str(provided.get("mail_profile") or "").strip()
        if not profile and len(accounts) == 1:
            return dict(accounts[0])
        if not profile:
            choices = ", ".join(account["profile"] for account in accounts)
            profile = self._value_or_prompt(
                "mail_profile",
                f"Verifier mail profile ({choices}): " if choices else "Verifier mail profile: ",
                provided,
                non_interactive,
            )
        matches = [account for account in accounts if account["profile"] == profile]
        if len(matches) != 1:
            raise SetupError(
                "MAIL_ACCOUNT_MISMATCH",
                "selected verifier mail profile was not found exactly once.",
            )
        return dict(matches[0])

    def _value_or_prompt(
        self,
        key: str,
        prompt: str,
        provided: Mapping[str, str],
        non_interactive: bool,
    ) -> str:
        value = str(provided.get(key) or "").strip()
        if value:
            return value
        if non_interactive:
            raise SetupError("SETUP_INPUT_REQUIRED", f"{key} is required for non-interactive setup.")
        self.prompt_count += 1
        value = self.input_fn(prompt).strip()
        if not value:
            raise SetupError("SETUP_INPUT_REQUIRED", f"{key} is required.")
        return value

    def _provided_values(self, provided: Mapping[str, str | None]) -> dict[str, str]:
        for key in provided:
            normalized = str(key).casefold()
            if any(fragment in normalized for fragment in _FORBIDDEN_INPUT_FRAGMENTS):
                raise SetupError("SECRET_INPUT_FORBIDDEN", "setup never accepts credentials or secrets.")
        mappings = {
            "mail_profile": "RELEASE_APPROVAL_VERIFIER_MAIL_PROFILE",
            "release_group": "RELEASE_APPROVAL_VERIFIER_RELEASE_GROUP",
            "role_document_url": "RELEASE_APPROVAL_VERIFIER_ROLE_DOCUMENT_URL",
            "audit_document_url": "RELEASE_APPROVAL_VERIFIER_AUDIT_DOCUMENT_URL",
            "trusted_authserv_ids": "RELEASE_APPROVAL_VERIFIER_TRUSTED_AUTHSERV_IDS",
            "state_dir": "RELEASE_APPROVAL_VERIFIER_STATE_DIR",
        }
        values: dict[str, str] = {}
        for key, environment_name in mappings.items():
            value = provided.get(key)
            values[key] = str(
                value if value is not None else self.environ.get(environment_name, "")
            ).strip()
        return values

    def _write_config(self, payload: Mapping[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config_path.with_name(f".{self.config_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(dict(payload), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.config_path)

    @staticmethod
    def _accounts(payload: Mapping[str, Any]) -> list[dict[str, str]]:
        accounts: list[dict[str, str]] = []
        for item in payload.get("accounts") or []:
            if not isinstance(item, Mapping):
                continue
            profile = str(item.get("name") or "").strip()
            email = str(item.get("email") or "").strip().lower()
            if profile and _EMAIL_PATTERN.fullmatch(email):
                accounts.append({"profile": profile, "email": email})
        return accounts

    @staticmethod
    def _detect_timezone() -> str:
        current = datetime.now().astimezone()
        return str(getattr(current.tzinfo, "key", "") or current.tzname() or "UTC")


def run_setup_operation(
    *,
    config_path: str | Path,
    repo_root: str | Path,
    non_interactive: bool,
    scheduler_mode: str,
    provided: Mapping[str, str | None] | None = None,
) -> dict[str, Any]:
    return VerifierSetup(config_path=config_path, repo_root=repo_root).run(
        non_interactive=non_interactive,
        scheduler_mode=scheduler_mode,
        provided=provided,
    )
