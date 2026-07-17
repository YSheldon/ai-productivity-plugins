from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from role_snapshot import RoleRecord


_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TIME_PATTERN = re.compile(r"^\d{2}:\d{2}$")
_UNEXPANDED_ENVIRONMENT_PATTERN = re.compile(r"%(?:[^%]+)%|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})")
_FORBIDDEN_SECRET_KEYS = {
    "api_key", "apikey", "auth_code", "authorization", "authorization_code",
    "client_secret", "credential", "credentials", "password", "passwd",
    "private_key", "refresh_token", "secret", "token",
}
_FORBIDDEN_SECRET_SUFFIXES = (
    "_api_key", "_credential", "_credentials", "_password", "_private_key",
    "_secret", "_token",
)
_SUPPORTED_AUTH_PATHS = {"dmarc", "dkim", "spf", "trusted_internal"}
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ConfigError(ValueError):
    """Raised when the release-approval-verifier runtime configuration is invalid."""


@dataclass(frozen=True)
class MailAccountConfig:
    profile: str
    email: str


@dataclass(frozen=True)
class WorkingHoursConfig:
    days: tuple[str, ...]
    start: str
    end: str


@dataclass(frozen=True)
class ReminderPolicyConfig:
    initial_delay_minutes: int
    repeat_minutes: int
    maximum: int


@dataclass(frozen=True)
class AuthenticationPolicyConfig:
    accepted_paths: tuple[str, ...]
    allowed_authserv_ids: tuple[str, ...]
    trusted_internal_header: str
    trusted_internal_value: str


@dataclass(frozen=True)
class AuditDocumentConfig:
    url: str


@dataclass(frozen=True)
class FeishuRoleSourceConfig:
    kind: str
    document_url: str
    heading: str


@dataclass(frozen=True)
class StaticRoleSourceConfig:
    kind: str
    roles: tuple[RoleRecord, ...]


@dataclass(frozen=True)
class VerifierConfig:
    mode: str
    role_source: FeishuRoleSourceConfig | StaticRoleSourceConfig
    release_group: str
    mailbox: str
    verifier_mail_account: MailAccountConfig
    event_expiry_hours: int
    poll_minutes: int
    timezone: str
    working_hours: WorkingHoursConfig
    reminder_policy: ReminderPolicyConfig
    authentication_policy: AuthenticationPolicyConfig
    state_dir: Path
    dependency_lock: Path
    dependency_lock_sha256: str
    audit_document: AuditDocumentConfig
    product_gate_config_path: Path | None = None


def default_config_path(
    environ: Mapping[str, str] | None = None,
    *,
    platform: str | None = None,
) -> Path:
    environment = os.environ if environ is None else environ
    explicit = str(environment.get("RELEASE_APPROVAL_VERIFIER_CONFIG") or "").strip()
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
    return (root / "release-approval-verifier" / "config.json").expanduser().resolve(strict=False)


def default_product_gate_config_path(
    environ: Mapping[str, str] | None = None,
    *,
    platform: str | None = None,
) -> Path:
    environment = os.environ if environ is None else environ
    explicit = str(environment.get("PRODUCT_RELEASE_GATE_CONFIG") or "").strip()
    if explicit:
        return Path(os.path.expandvars(explicit)).expanduser().resolve(strict=False)
    current_platform = platform or sys.platform
    if current_platform.startswith("win"):
        local_root = str(environment.get("LOCALAPPDATA") or "").strip()
        root = Path(local_root) if local_root else Path.home() / "AppData" / "Local"
    else:
        xdg_root = str(environment.get("XDG_CONFIG_HOME") or "").strip()
        root = Path(xdg_root) if xdg_root else Path.home() / ".config"
    return (root / "product-release-gate" / "config.json").resolve(strict=False)

def reject_per_call_config_override(arguments: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if arguments and "config_path" in arguments:
        raise ConfigError("config_path cannot be supplied per call; restart the verifier with approved config.")
    return arguments or {}


def _load_authserv_ids(payload: Mapping[str, Any]) -> tuple[str, ...]:
    value = payload.get("allowed_authserv_ids")
    if not isinstance(value, list) or not value:
        raise ConfigError("authentication_policy.allowed_authserv_ids must be a non-empty list.")
    normalized: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"authentication_policy.allowed_authserv_ids[{index}] must be a non-empty authserv-id.")
        candidate = item.strip().lower()
        if any(ch.isspace() for ch in candidate) or ";" in candidate:
            raise ConfigError(f"authentication_policy.allowed_authserv_ids[{index}] must be one authserv-id token.")
        normalized.append(candidate)
    if len(set(normalized)) != len(normalized):
        raise ConfigError("authentication_policy.allowed_authserv_ids must not contain duplicates.")
    return tuple(normalized)


def load_config(path: str | Path) -> VerifierConfig:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ConfigError("config root must be an object.")
    _ensure_no_secrets(payload)

    mode = _require_string(payload, "mode", default="production").lower()
    if mode not in {"production", "test"}:
        raise ConfigError("mode must be either production or test.")

    role_source = _load_role_source(payload, mode=mode)
    verifier_mail_payload = _require_mapping(payload, "verifier_mail_account")
    authentication_policy_payload = _require_mapping(payload, "authentication_policy")
    accepted_paths = _load_accepted_paths(authentication_policy_payload)
    allowed_authserv_ids = _load_authserv_ids(authentication_policy_payload)
    reminder_policy_payload = _require_mapping(payload, "reminder_policy")
    working_hours_payload = _require_mapping(payload, "working_hours")
    audit_document_payload = _require_mapping(payload, "audit_document")
    product_gate_payload = payload.get("product_gate")
    if product_gate_payload is None:
        product_gate_config_path = default_product_gate_config_path()
    elif isinstance(product_gate_payload, Mapping):
        product_gate_config_path = _expand_path(
            _require_string(product_gate_payload, "config_path")
        )
    else:
        raise ConfigError("product_gate must be an object.")

    return VerifierConfig(
        mode=mode,
        role_source=role_source,
        release_group=_require_email(_require_string(payload, "release_group"), field_name="release_group"),
        mailbox=_require_string(payload, "mailbox", default="INBOX"),
        verifier_mail_account=MailAccountConfig(
            profile=_require_string(verifier_mail_payload, "profile"),
            email=_require_email(_require_string(verifier_mail_payload, "email"), field_name="verifier_mail_account.email"),
        ),
        event_expiry_hours=_require_positive_int(payload.get("event_expiry_hours", 24), field_name="event_expiry_hours"),
        poll_minutes=_require_bounded_int(payload.get("poll_minutes", 60), field_name="poll_minutes", minimum=5, maximum=1440),
        timezone=_require_string(payload, "timezone", default="Asia/Shanghai"),
        working_hours=WorkingHoursConfig(
            days=_require_days(working_hours_payload),
            start=_validate_time(_require_string(working_hours_payload, "start"), field_name="working_hours.start"),
            end=_validate_time(_require_string(working_hours_payload, "end"), field_name="working_hours.end"),
        ),
        reminder_policy=ReminderPolicyConfig(
            initial_delay_minutes=_require_positive_int(
                reminder_policy_payload.get("initial_delay_minutes"),
                field_name="reminder_policy.initial_delay_minutes",
            ),
            repeat_minutes=_require_positive_int(
                reminder_policy_payload.get("repeat_minutes"),
                field_name="reminder_policy.repeat_minutes",
            ),
            maximum=_require_positive_int(
                reminder_policy_payload.get("maximum"),
                field_name="reminder_policy.maximum",
            ),
        ),
        authentication_policy=AuthenticationPolicyConfig(
            accepted_paths=accepted_paths,
            allowed_authserv_ids=allowed_authserv_ids,
            trusted_internal_header=_require_string(
                authentication_policy_payload,
                "trusted_internal_header",
            ),
            trusted_internal_value=_require_string(
                authentication_policy_payload,
                "trusted_internal_value",
            ),
        ),
        state_dir=_expand_path(_require_string(payload, "state_dir")),
        dependency_lock=_expand_path(_require_string(payload, "dependency_lock")),
        dependency_lock_sha256=_require_sha256(
            _require_string(payload, "dependency_lock_sha256"),
            field_name="dependency_lock_sha256",
        ),
        audit_document=AuditDocumentConfig(
            url=_require_absolute_http_url(
                _require_string(audit_document_payload, "url"),
                field_name="audit_document.url",
            )
        ),
        product_gate_config_path=product_gate_config_path,
    )


def _load_role_source(payload: Mapping[str, Any], *, mode: str) -> FeishuRoleSourceConfig | StaticRoleSourceConfig:
    role_source_payload = _require_mapping(payload, "role_source")
    source_type = _require_string(role_source_payload, "type").lower()
    if source_type == "feishu":
        return FeishuRoleSourceConfig(
            kind="feishu",
            document_url=_require_absolute_http_url(
                _require_string(role_source_payload, "document_url"),
                field_name="role_source.document_url",
            ),
            heading=_require_string(role_source_payload, "heading", default="## 审批角色"),
        )
    if source_type == "static":
        if mode != "test":
            raise ConfigError("static roles are test-only and cannot be used in production mode.")
        roles_value = role_source_payload.get("roles")
        if not isinstance(roles_value, list) or not roles_value:
            raise ConfigError("role_source.roles must be a non-empty list.")
        roles: list[RoleRecord] = []
        for index, raw_role in enumerate(roles_value):
            if not isinstance(raw_role, Mapping):
                raise ConfigError(f"role_source.roles[{index}] must be an object.")
            roles.append(
                RoleRecord(
                    role_id=_require_string(raw_role, "role_id"),
                    email=_require_email(_require_string(raw_role, "email"), field_name=f"role_source.roles[{index}].email"),
                    required=_require_exact_bool(raw_role.get("required"), field_name=f"role_source.roles[{index}].required"),
                    enabled=_require_exact_bool(raw_role.get("enabled"), field_name=f"role_source.roles[{index}].enabled"),
                )
            )
        return StaticRoleSourceConfig(kind="static", roles=tuple(roles))
    raise ConfigError("role_source.type must be either feishu or static.")


def _load_accepted_paths(payload: Mapping[str, Any]) -> tuple[str, ...]:
    accepted_paths = payload.get("accepted_paths")
    if not isinstance(accepted_paths, list) or not accepted_paths:
        raise ConfigError("authentication_policy.accepted_paths must be a non-empty list.")
    normalized = tuple(str(value).strip().lower() for value in accepted_paths if isinstance(value, str) and str(value).strip())
    if len(normalized) != len(accepted_paths):
        raise ConfigError("authentication_policy.accepted_paths must contain only non-empty strings.")
    unsupported = sorted(set(normalized) - _SUPPORTED_AUTH_PATHS)
    if unsupported:
        raise ConfigError(
            f"authentication_policy.accepted_paths contains unsupported paths: {', '.join(unsupported)}."
        )
    return normalized


def _require_absolute_http_url(value: str, *, field_name: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"{field_name} must be an absolute HTTP(S) URL.")
    return value


def _require_mapping(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, Mapping):
        raise ConfigError(f"{key} must be an object.")
    return value


def _require_string(payload: Mapping[str, Any], key: str, *, default: str | None = None) -> str:
    value = payload.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} is required.")
    return value.strip()


def _require_email(value: str, *, field_name: str) -> str:
    if not _EMAIL_PATTERN.fullmatch(value):
        raise ConfigError(f"{field_name} must be a valid email address.")
    return value.lower()


def _require_sha256(value: str, *, field_name: str) -> str:
    normalized = value.strip().lower()
    if not _SHA256_PATTERN.fullmatch(normalized):
        raise ConfigError(f"{field_name} must be a lowercase SHA-256 digest.")
    return normalized


def _require_exact_bool(value: Any, *, field_name: str) -> bool:
    if type(value) is not bool:
        raise ConfigError(f"{field_name} must be a bool.")
    return value


def _require_positive_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ConfigError(f"{field_name} must be a positive integer.")
    return value


def _require_bounded_int(value: Any, *, field_name: str, minimum: int, maximum: int) -> int:
    number = _require_positive_int(value, field_name=field_name)
    if not (minimum <= number <= maximum):
        raise ConfigError(f"{field_name} must be within {minimum}..{maximum}.")
    return number


def _require_days(payload: Mapping[str, Any]) -> tuple[str, ...]:
    value = payload.get("days")
    if not isinstance(value, list) or not value:
        raise ConfigError("working_hours.days must be a non-empty list.")
    if not all(isinstance(day, str) and day.strip() for day in value):
        raise ConfigError("working_hours.days must contain non-empty strings.")
    return tuple(day.strip() for day in value)


def _validate_time(value: str, *, field_name: str) -> str:
    if not _TIME_PATTERN.fullmatch(value):
        raise ConfigError(f"{field_name} must use HH:MM.")
    hours, minutes = (int(part) for part in value.split(":", 1))
    if hours > 23 or minutes > 59:
        raise ConfigError(f"{field_name} must use HH:MM.")
    return value


def _expand_path(value: str) -> Path:
    expanded = os.path.expandvars(value)
    if _UNEXPANDED_ENVIRONMENT_PATTERN.search(expanded):
        raise ConfigError("path contains an unexpanded environment variable.")
    return Path(expanded).expanduser().resolve(strict=False)


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
