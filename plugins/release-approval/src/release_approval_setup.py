from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from release_approval_config import ReleaseApprovalConfig, load_config
from release_approval_mail import MailGateway
from release_approval_scheduler import ReleaseApprovalScheduler


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile


_SAFE_ROLE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_FORBIDDEN_INPUT_KEYS = {
    "password",
    "authorization",
    "authorization_code",
    "auth_code",
    "token",
    "secret",
}


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
AccountDiscoverer = Callable[[Path], Mapping[str, Any]]
ControllerFactory = Callable[[ReleaseApprovalConfig, Path], Any]
SchedulerFactory = Callable[[ReleaseApprovalConfig, Path], ReleaseApprovalScheduler | Any]


def _default_account_discoverer(dependency_lock: Path) -> Mapping[str, Any]:
    return MailGateway(dependency_lock).list_accounts()


def _default_controller_factory(config: ReleaseApprovalConfig, config_path: Path) -> Any:
    from release_approval_mcp import ReleaseApprovalController

    return ReleaseApprovalController(config=config, config_path=config_path)


def _default_scheduler_factory(
    config: ReleaseApprovalConfig,
    config_path: Path,
) -> ReleaseApprovalScheduler:
    return ReleaseApprovalScheduler(
        plugin_name="release-approval",
        role_id=config.role_id,
        config_path=config_path,
        state_dir=config.state_dir,
        poll_minutes=config.poll_minutes,
    )


class ReleaseApprovalSetup:
    """Create or reuse one credential-free config and activate one scheduler."""

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
        bootstrap = dict(
            self.bootstrap_runner("release-approval", repo_root=self.repo_root)
        )
        dependency_lock_text = str(bootstrap.get("dependency_lock") or "").strip()
        if not dependency_lock_text:
            raise SetupError(
                "DEPENDENCY_BOOTSTRAP_FAILED",
                "dependency bootstrap did not return an authoritative lock path.",
            )
        dependency_lock = Path(dependency_lock_text).resolve(strict=False)

        if self.config_path.is_file():
            config = load_config(self.config_path)
            if config.dependency_lock != dependency_lock:
                raise SetupError(
                    "DEPENDENCY_LOCK_MISMATCH",
                    "existing config does not reference the authoritative dependency lock.",
                )
        else:
            accounts = self._accounts(self.account_discoverer(dependency_lock))
            payload = self._build_config_payload(
                dependency_lock=dependency_lock,
                accounts=accounts,
                non_interactive=non_interactive,
                provided=values,
            )
            if self.prompt_count > 4:
                raise SetupError(
                    "SETUP_PROMPT_BUDGET_EXCEEDED",
                    "standard release-approval setup must not exceed four prompts.",
                )
            self._write_config(payload)
            config = load_config(self.config_path)

        controller = self.controller_factory(config, self.config_path)
        scheduler = self.scheduler_factory(config, self.config_path)
        preflight = controller.preflight()
        if str(preflight.get("status") or "") != "ready":
            raise SetupError(
                "PREFLIGHT_FAILED",
                "release approval preflight did not reach ready state.",
            )
        schedule = scheduler.install(mode=scheduler_mode)
        first_run = controller.run_once()
        runtime_status = controller.status()
        doctor = controller.doctor()
        schedule_status = scheduler.status(mode=scheduler_mode)
        cli_prefix = [
            sys.executable,
            str((Path(__file__).resolve().parent / "release_approval_cli.py").resolve()),
            "--config",
            str(self.config_path),
        ]
        return {
            "status": "ready",
            "config_path": str(self.config_path),
            "config_created": not bool(values.get("_existing")),
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
        accounts: list[dict[str, str]],
        non_interactive: bool,
        provided: Mapping[str, str],
    ) -> dict[str, Any]:
        role_id = self._value_or_prompt(
            "role_id",
            "Approver role ID: ",
            provided,
            non_interactive,
        )
        if not _SAFE_ROLE_PATTERN.fullmatch(role_id):
            raise SetupError(
                "INVALID_SETUP_INPUT",
                "role_id must use 1-80 letters, digits, dot, underscore, or hyphen characters.",
            )

        role_email = str(provided.get("role_email") or "").strip()
        if not role_email and len(accounts) == 1:
            role_email = accounts[0]["email"]
        if not role_email:
            role_email = self._value_or_prompt(
                "role_email",
                "Approver email: ",
                provided,
                non_interactive,
            )
        if not _EMAIL_PATTERN.fullmatch(role_email):
            raise SetupError("INVALID_SETUP_INPUT", "role_email must be a valid email address.")

        mail_profile = str(provided.get("mail_profile") or "").strip()
        candidates = [account for account in accounts if account["email"] == role_email]
        if not mail_profile and len(candidates) == 1:
            mail_profile = candidates[0]["name"]
        if not mail_profile:
            choices = ", ".join(account["name"] for account in candidates or accounts)
            prompt = "Mail profile"
            if choices:
                prompt += f" ({choices})"
            mail_profile = self._value_or_prompt(
                "mail_profile",
                f"{prompt}: ",
                provided,
                non_interactive,
            )
        matching_profiles = [
            account
            for account in accounts
            if account["name"] == mail_profile and account["email"] == role_email
        ]
        if accounts and not matching_profiles:
            raise SetupError(
                "MAIL_ACCOUNT_MISMATCH",
                "selected mail profile does not match the approver email.",
            )

        release_group = self._value_or_prompt(
            "release_group",
            "Release approval mail group: ",
            provided,
            non_interactive,
        )
        if not _EMAIL_PATTERN.fullmatch(release_group):
            raise SetupError(
                "INVALID_SETUP_INPUT",
                "release_group must be a valid email address.",
            )

        request_sender_email = self._value_or_prompt(
            "request_sender_email",
            "Release request sender email: ",
            provided,
            non_interactive,
        ).lower()
        if not _EMAIL_PATTERN.fullmatch(request_sender_email):
            raise SetupError(
                "INVALID_SETUP_INPUT",
                "request_sender_email must be a valid email address.",
            )

        trusted_authserv_ids = _parse_authserv_ids(
            self._value_or_prompt(
                "trusted_authserv_ids",
                "Trusted Authentication-Results authserv-id(s), comma separated: ",
                provided,
                non_interactive,
            )
        )

        state_dir_text = str(provided.get("state_dir") or "").strip()
        state_dir = (
            Path(state_dir_text).expanduser().resolve(strict=False)
            if state_dir_text
            else (self.config_path.parent / "state").resolve(strict=False)
        )
        return {
            "role_id": role_id,
            "role_email": role_email,
            "mail_account": {"profile": mail_profile, "email": role_email},
            "request_authentication": {
                "allowed_sender_emails": [request_sender_email],
                "allowed_authserv_ids": trusted_authserv_ids,
                "accepted_paths": ["dmarc", "dkim", "spf"],
            },
            "release_group": release_group,
            "mailbox": "INBOX",
            "page": {"host": "127.0.0.1", "port": 8765},
            "poll_minutes": 60,
            "timezone": self.timezone_detector(),
            "working_hours": {
                "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
                "start": "09:00",
                "end": "18:00",
            },
            "state_dir": str(state_dir),
            "dependency_lock": str(dependency_lock),
            "audit": {
                "verify_chain_on_startup": True,
                "retention_days": 3650,
                "document_url": str(provided.get("audit_document_url") or "").strip() or None,
            },
        }

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
            if key.lower() in _FORBIDDEN_INPUT_KEYS:
                raise SetupError("SECRET_INPUT_FORBIDDEN", "setup never accepts credentials or secrets.")
        mappings = {
            "role_id": "RELEASE_APPROVAL_ROLE_ID",
            "role_email": "RELEASE_APPROVAL_ROLE_EMAIL",
            "mail_profile": "RELEASE_APPROVAL_MAIL_PROFILE",
            "release_group": "RELEASE_APPROVAL_RELEASE_GROUP",
            "request_sender_email": "RELEASE_APPROVAL_REQUEST_SENDER_EMAIL",
            "trusted_authserv_ids": "RELEASE_APPROVAL_TRUSTED_AUTHSERV_IDS",
            "state_dir": "RELEASE_APPROVAL_STATE_DIR",
            "audit_document_url": "RELEASE_APPROVAL_AUDIT_DOCUMENT_URL",
        }
        values: dict[str, str] = {}
        for key, environment_name in mappings.items():
            value = provided.get(key)
            values[key] = str(value if value is not None else self.environ.get(environment_name, "")).strip()
        if self.config_path.is_file():
            values["_existing"] = "true"
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
            name = str(item.get("name") or "").strip()
            email = str(item.get("email") or "").strip()
            if name and _EMAIL_PATTERN.fullmatch(email):
                accounts.append({"name": name, "email": email})
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
    return ReleaseApprovalSetup(config_path=config_path, repo_root=repo_root).run(
        non_interactive=non_interactive,
        scheduler_mode=scheduler_mode,
        provided=provided,
    )
