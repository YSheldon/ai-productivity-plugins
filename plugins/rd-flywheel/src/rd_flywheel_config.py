from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UNEXPANDED_ENV_PATTERN = re.compile(r"%(?:[^%]+)%|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})")
_FORBIDDEN_SECRET_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "authorization_code",
    "auth_code",
    "client_secret",
    "clientsecret",
    "credential",
    "credentials",
    "gitlab_token",
    "mail_password",
    "password",
    "passwd",
    "private_key",
    "refresh_token",
    "secret",
    "smtp_password",
    "token",
}
_FORBIDDEN_SECRET_SUFFIXES = (
    "_api_key",
    "_authorization",
    "_credential",
    "_credentials",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)
_ROOT_KEYS = {
    "schema_version",
    "governance_inbox",
    "state_dir",
    "poll_minutes",
    "timezone",
    "tool_profiles",
    "approved_agent_profiles",
    "agent_profile",
    "protected_merge",
    "notification",
    "decision_role_source",
    "dependency_lock",
}


class ConfigError(ValueError):
    """Raised when the rd-flywheel runtime configuration is invalid."""


@dataclass(frozen=True)
class ProtectedMergeConfig:
    tool_profile: str
    protected_branch_required: bool


@dataclass(frozen=True)
class NotificationConfig:
    mail_profile: str
    recipients: tuple[str, ...]


@dataclass(frozen=True)
class RDFlywheelConfig:
    schema_version: int
    governance_inbox: Path
    state_dir: Path
    poll_minutes: int
    timezone: str
    tool_profiles: tuple[str, ...]
    approved_agent_profiles: tuple[str, ...]
    agent_profile: str | None
    protected_merge: ProtectedMergeConfig
    notification: NotificationConfig | None
    decision_role_source: str | None
    dependency_lock: Path

    @property
    def audit_dir(self) -> Path:
        return self.state_dir / "audit"

    @property
    def database_path(self) -> Path:
        return self.state_dir / "rd-flywheel.sqlite3"

    @property
    def run_lock_path(self) -> Path:
        return self.state_dir / "rd-flywheel.run.lock"


def default_config_path(
    environ: Mapping[str, str] | None = None,
    *,
    platform: str | None = None,
) -> Path:
    environment = os.environ if environ is None else environ
    explicit = str(environment.get("RD_FLYWHEEL_CONFIG") or "").strip()
    if explicit:
        return _expand_path(explicit)
    current_platform = platform or sys.platform
    if current_platform.startswith("win"):
        root = Path(
            str(
                environment.get("LOCALAPPDATA")
                or Path(str(environment.get("USERPROFILE") or Path.home()))
                / "AppData"
                / "Local"
            )
        )
    else:
        root = Path(
            str(
                environment.get("XDG_CONFIG_HOME")
                or Path(str(environment.get("HOME") or Path.home())) / ".config"
            )
        )
    return (root / "rd-flywheel" / "config.json").expanduser().resolve(strict=False)


def reject_per_call_config_override(arguments: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if arguments and "config_path" in arguments:
        raise ConfigError(
            "config_path cannot be supplied per call; restart the MCP server with the approved config."
        )
    return arguments or {}


def _normalize_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).casefold()).strip("_")


def _ensure_no_secrets(value: Any, *, path: str = "config") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = _normalize_key(key)
            if (
                normalized in _FORBIDDEN_SECRET_KEYS
                or normalized.endswith(_FORBIDDEN_SECRET_SUFFIXES)
            ):
                raise ConfigError(
                    f"{path} must not contain credentials, passwords, tokens, or authorization material."
                )
            _ensure_no_secrets(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _ensure_no_secrets(child, path=f"{path}[{index}]")


def _expand_path(value: str) -> Path:
    expanded = os.path.expandvars(value)
    if _UNEXPANDED_ENV_PATTERN.search(expanded):
        raise ConfigError("path contains an unexpanded environment variable.")
    return Path(expanded).expanduser().resolve(strict=False)


def _require_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} is required.")
    return value.strip()


def _unique_strings(value: Any, *, field_name: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        suffix = "a list" if allow_empty else "a non-empty list"
        raise ConfigError(f"{field_name} must be {suffix}.")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ConfigError(f"{field_name} must contain non-empty strings.")
    normalized = tuple(item.strip() for item in value)
    if len(set(normalized)) != len(normalized):
        raise ConfigError(f"{field_name} values must be unique.")
    return normalized


def _require_mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, Mapping):
        raise ConfigError(f"{key} must be an object.")
    return value


def load_config(path: str | Path) -> RDFlywheelConfig:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot load config: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ConfigError("config root must be an object.")
    _ensure_no_secrets(payload)
    unexpected = set(payload).difference(_ROOT_KEYS)
    if unexpected:
        raise ConfigError(f"unknown config fields: {', '.join(sorted(unexpected))}.")

    schema_version = payload.get("schema_version")
    if schema_version != 1 or type(schema_version) is not int:
        raise ConfigError("schema_version must be 1.")
    poll_minutes = payload.get("poll_minutes", 60)
    if type(poll_minutes) is not int or not 5 <= poll_minutes <= 1440:
        raise ConfigError("poll_minutes must be an integer in 5..1440.")
    timezone = _require_string(payload, "timezone")
    tool_profiles = _unique_strings(payload.get("tool_profiles"), field_name="tool_profiles")
    approved_agents = _unique_strings(
        payload.get("approved_agent_profiles", []),
        field_name="approved_agent_profiles",
        allow_empty=True,
    )
    raw_agent = payload.get("agent_profile")
    if raw_agent is None:
        agent_profile = None
    elif isinstance(raw_agent, str) and raw_agent.strip():
        agent_profile = raw_agent.strip()
    else:
        raise ConfigError("agent_profile must be null or a non-empty string.")
    if agent_profile is not None and agent_profile not in approved_agents:
        raise ConfigError("agent_profile must be present in approved_agent_profiles.")

    merge_payload = _require_mapping(payload, "protected_merge")
    merge_profile = _require_string(merge_payload, "tool_profile")
    protected_required = merge_payload.get("protected_branch_required")
    if type(protected_required) is not bool:
        raise ConfigError("protected_merge.protected_branch_required must be a bool.")
    if not protected_required:
        raise ConfigError("protected_merge.protected_branch_required must remain true.")
    if merge_profile not in tool_profiles:
        raise ConfigError("protected_merge tool profile must be present in tool_profiles.")

    notification_payload = payload.get("notification")
    notification: NotificationConfig | None
    if notification_payload is None:
        notification = None
    elif isinstance(notification_payload, Mapping):
        recipients = _unique_strings(
            notification_payload.get("recipients"),
            field_name="notification.recipients",
        )
        invalid = [item for item in recipients if not _EMAIL_PATTERN.fullmatch(item)]
        if invalid:
            raise ConfigError("notification.recipients must contain valid email addresses.")
        notification = NotificationConfig(
            mail_profile=_require_string(notification_payload, "mail_profile"),
            recipients=recipients,
        )
    else:
        raise ConfigError("notification must be null or an object.")

    role_source = payload.get("decision_role_source")
    if role_source is not None and (
        not isinstance(role_source, str) or not role_source.strip()
    ):
        raise ConfigError("decision_role_source must be null or a non-empty string.")

    return RDFlywheelConfig(
        schema_version=schema_version,
        governance_inbox=_expand_path(_require_string(payload, "governance_inbox")),
        state_dir=_expand_path(_require_string(payload, "state_dir")),
        poll_minutes=poll_minutes,
        timezone=timezone,
        tool_profiles=tool_profiles,
        approved_agent_profiles=approved_agents,
        agent_profile=agent_profile,
        protected_merge=ProtectedMergeConfig(
            tool_profile=merge_profile,
            protected_branch_required=protected_required,
        ),
        notification=notification,
        decision_role_source=role_source.strip() if isinstance(role_source, str) else None,
        dependency_lock=_expand_path(_require_string(payload, "dependency_lock")),
    )
