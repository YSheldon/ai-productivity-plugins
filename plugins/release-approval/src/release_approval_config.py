from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TIME_PATTERN = re.compile(r"^\d{2}:\d{2}$")
_UNEXPANDED_ENVIRONMENT_PATTERN = re.compile(r"%(?:[^%]+)%|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})")
_ALLOWED_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_SUPPORTED_REQUEST_AUTH_PATHS = {"dmarc", "dkim", "spf"}
_FORBIDDEN_SECRET_KEYS = {
    "api_key",
    "apikey",
    "auth_code",
    "authorization",
    "authorization_code",
    "client_secret",
    "credential",
    "credentials",
    "password",
    "passwd",
    "private_key",
    "refresh_token",
    "secret",
    "token",
}
_FORBIDDEN_SECRET_SUFFIXES = (
    "_api_key",
    "_credential",
    "_credentials",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)


class ConfigError(ValueError):
    """Raised when the release-approval runtime configuration is invalid."""


@dataclass(frozen=True)
class MailAccountConfig:
    profile: str
    email: str


@dataclass(frozen=True)
class RequestAuthenticationConfig:
    allowed_sender_emails: tuple[str, ...]
    allowed_authserv_ids: tuple[str, ...]
    accepted_paths: tuple[str, ...]


@dataclass(frozen=True)
class PageConfig:
    host: str
    port: int


@dataclass(frozen=True)
class WorkingHoursConfig:
    days: tuple[str, ...]
    start: str
    end: str


@dataclass(frozen=True)
class AuditConfig:
    verify_chain_on_startup: bool
    retention_days: int
    document_url: str | None = None


@dataclass(frozen=True)
class ReleaseApprovalConfig:
    role_id: str
    role_email: str
    mail_account: MailAccountConfig
    request_authentication: RequestAuthenticationConfig
    release_group: str
    mailbox: str
    page: PageConfig
    poll_minutes: int
    timezone: str
    working_hours: WorkingHoursConfig
    state_dir: Path
    dependency_lock: Path
    audit: AuditConfig


def default_config_path(
    environ: Mapping[str, str] | None = None,
    *,
    platform: str | None = None,
) -> Path:
    environment = os.environ if environ is None else environ
    explicit = str(environment.get("RELEASE_APPROVAL_CONFIG") or "").strip()
    if explicit:
        return Path(os.path.expandvars(explicit)).expanduser().resolve(strict=False)
    current_platform = platform or sys.platform
    if current_platform.startswith("win"):
        local_root = str(environment.get("LOCALAPPDATA") or "").strip()
        if local_root:
            root = Path(local_root)
        else:
            profile = str(environment.get("USERPROFILE") or Path.home()).strip()
            root = Path(profile) / "AppData" / "Local"
    else:
        xdg_root = str(environment.get("XDG_CONFIG_HOME") or "").strip()
        if xdg_root:
            root = Path(xdg_root)
        else:
            home = str(environment.get("HOME") or Path.home()).strip()
            root = Path(home) / ".config"
    return (root / "release-approval" / "config.json").expanduser().resolve(strict=False)


def reject_per_call_config_override(arguments: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if arguments and "config_path" in arguments:
        raise ConfigError("config_path cannot be supplied per call; restart the MCP server with approved config.")
    return arguments or {}


def _require_mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, Mapping):
        raise ConfigError(f"{key} must be an object.")
    return value


def _require_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} is required.")
    return value.strip()


def _require_email(value: str, *, field_name: str) -> str:
    if not _EMAIL_PATTERN.fullmatch(value):
        raise ConfigError(f"{field_name} must be a valid email address.")
    return value


def _require_email_list(
    payload: Mapping[str, Any],
    key: str,
    *,
    field_name: str,
) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{field_name} must be a non-empty list.")
    normalized: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ConfigError(f"{field_name}[{index}] must be a valid email address.")
        normalized.append(
            _require_email(item.strip().lower(), field_name=f"{field_name}[{index}]")
        )
    if len(set(normalized)) != len(normalized):
        raise ConfigError(f"{field_name} must not contain duplicate email addresses.")
    return tuple(normalized)


def _require_authserv_id_list(
    payload: Mapping[str, Any],
    key: str,
    *,
    field_name: str,
) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{field_name} must be a non-empty list.")
    normalized: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"{field_name}[{index}] must be a non-empty authserv-id.")
        candidate = item.strip().lower()
        if any(ch.isspace() for ch in candidate) or ";" in candidate:
            raise ConfigError(f"{field_name}[{index}] must be one authserv-id token.")
        normalized.append(candidate)
    if len(set(normalized)) != len(normalized):
        raise ConfigError(f"{field_name} must not contain duplicates.")
    return tuple(normalized)


def _require_authentication_paths(
    payload: Mapping[str, Any],
) -> tuple[str, ...]:
    value = payload.get("accepted_paths")
    if not isinstance(value, list) or not value:
        raise ConfigError(
            "request_authentication.accepted_paths must be a non-empty list."
        )
    normalized = tuple(
        item.strip().lower()
        for item in value
        if isinstance(item, str) and item.strip()
    )
    if len(normalized) != len(value):
        raise ConfigError(
            "request_authentication.accepted_paths must contain only non-empty strings."
        )
    if len(set(normalized)) != len(normalized):
        raise ConfigError(
            "request_authentication.accepted_paths must not contain duplicates."
        )
    unsupported = sorted(set(normalized) - _SUPPORTED_REQUEST_AUTH_PATHS)
    if unsupported:
        raise ConfigError(
            "request_authentication.accepted_paths contains unsupported paths: "
            + ", ".join(unsupported)
        )
    return normalized


def _require_exact_bool(value: Any, *, field_name: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{field_name} must be a bool.")
    return value


def _require_positive_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ConfigError(f"{field_name} must be a positive integer.")
    return value


def _expand_path(value: str) -> Path:
    expanded = os.path.expandvars(value)
    if _UNEXPANDED_ENVIRONMENT_PATTERN.search(expanded):
        raise ConfigError("path contains an unexpanded environment variable.")
    return Path(expanded).expanduser().resolve(strict=False)


def _is_loopback_host(host: str) -> bool:
    if host in _ALLOWED_LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_time(value: str, *, field_name: str) -> str:
    if not _TIME_PATTERN.fullmatch(value):
        raise ConfigError(f"{field_name} must use HH:MM.")
    hours, minutes = (int(part) for part in value.split(":", 1))
    if hours > 23 or minutes > 59:
        raise ConfigError(f"{field_name} must use HH:MM.")
    return value


def _optional_http_url(value: Any, *, field_name: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{field_name} must be an absolute HTTP(S) URL.")
    normalized = value.strip()
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"{field_name} must be an absolute HTTP(S) URL.")
    return normalized


def _ensure_no_secrets(value: Any, *, path: str = "config") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "_", str(key).casefold()).strip("_")
            if normalized in _FORBIDDEN_SECRET_KEYS or normalized.endswith(_FORBIDDEN_SECRET_SUFFIXES):
                raise ConfigError(
                    f"{path} must not contain passwords; config must not contain credentials or authorization codes."
                )
            _ensure_no_secrets(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _ensure_no_secrets(child, path=f"{path}[{index}]")


def load_config(path: str | Path) -> ReleaseApprovalConfig:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ConfigError("config root must be an object.")
    _ensure_no_secrets(payload)

    role_email = _require_email(_require_string(payload, "role_email"), field_name="role_email")
    mail_account_payload = _require_mapping(payload, "mail_account")
    mail_account_email = _require_email(
        _require_string(mail_account_payload, "email"),
        field_name="mail_account.email",
    )
    if mail_account_email != role_email:
        raise ConfigError("configured live mail-account email must match role_email.")

    request_authentication_payload = _require_mapping(
        payload, "request_authentication"
    )
    allowed_sender_emails = _require_email_list(
        request_authentication_payload,
        "allowed_sender_emails",
        field_name="request_authentication.allowed_sender_emails",
    )
    allowed_authserv_ids = _require_authserv_id_list(
        request_authentication_payload,
        "allowed_authserv_ids",
        field_name="request_authentication.allowed_authserv_ids",
    )
    accepted_paths = _require_authentication_paths(request_authentication_payload)

    page_payload = _require_mapping(payload, "page")
    page_host = _require_string(page_payload, "host")
    if not _is_loopback_host(page_host):
        raise ConfigError("page.host must resolve to a loopback host.")
    page_port = page_payload.get("port")
    if not isinstance(page_port, int) or not (1 <= page_port <= 65535):
        raise ConfigError("page.port must be an integer in 1..65535.")

    poll_minutes = payload.get("poll_minutes", 60)
    if not isinstance(poll_minutes, int) or not (5 <= poll_minutes <= 1440):
        raise ConfigError("poll_minutes must be within 5..1440.")

    working_hours_payload = _require_mapping(payload, "working_hours")
    days_value = working_hours_payload.get("days")
    if not isinstance(days_value, list) or not days_value:
        raise ConfigError("working_hours.days must be a non-empty list.")
    if not all(isinstance(day, str) and day.strip() for day in days_value):
        raise ConfigError("working_hours.days must contain non-empty strings.")
    days = tuple(day.strip() for day in days_value)

    audit_payload = _require_mapping(payload, "audit")

    return ReleaseApprovalConfig(
        role_id=_require_string(payload, "role_id"),
        role_email=role_email,
        mail_account=MailAccountConfig(
            profile=_require_string(mail_account_payload, "profile"),
            email=mail_account_email,
        ),
        request_authentication=RequestAuthenticationConfig(
            allowed_sender_emails=allowed_sender_emails,
            allowed_authserv_ids=allowed_authserv_ids,
            accepted_paths=accepted_paths,
        ),
        release_group=_require_string(payload, "release_group"),
        mailbox=_require_string(payload, "mailbox"),
        page=PageConfig(host=page_host, port=page_port),
        poll_minutes=poll_minutes,
        timezone=str(payload.get("timezone") or "Asia/Shanghai"),
        working_hours=WorkingHoursConfig(
            days=days,
            start=_validate_time(_require_string(working_hours_payload, "start"), field_name="working_hours.start"),
            end=_validate_time(_require_string(working_hours_payload, "end"), field_name="working_hours.end"),
        ),
        state_dir=_expand_path(_require_string(payload, "state_dir")),
        dependency_lock=_expand_path(_require_string(payload, "dependency_lock")),
        audit=AuditConfig(
            verify_chain_on_startup=_require_exact_bool(
                audit_payload.get("verify_chain_on_startup"),
                field_name="audit.verify_chain_on_startup",
            ),
            retention_days=_require_positive_int(
                audit_payload.get("retention_days"),
                field_name="audit.retention_days",
            ),
            document_url=_optional_http_url(
                audit_payload.get("document_url"),
                field_name="audit.document_url",
            ),
        ),
    )
