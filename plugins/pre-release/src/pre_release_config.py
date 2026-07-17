from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class MailAccountConfig:
    profile: str
    email: str


@dataclass(frozen=True)
class ProductGateConfig:
    config_path: Path
    command: tuple[str, ...]


@dataclass(frozen=True)
class PreReleaseConfig:
    mail_account: MailAccountConfig
    submission_group: str
    release_gate_group: str
    mailbox: str
    timezone: str
    poll_minutes: int
    state_dir: Path
    dependency_lock: Path
    dependency_lock_sha256: str
    shared_hmac_secret_path: Path
    mail_command: tuple[str, ...]
    product_gate: ProductGateConfig
    policy_profile: str
    enabled_optional_checks: tuple[str, ...]


def default_config_path() -> Path:
    explicit = str(os.environ.get("PRE_RELEASE_CONFIG") or "").strip()
    if explicit:
        return Path(os.path.expandvars(explicit)).expanduser().resolve(strict=False)
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return (root / "pre-release" / "config.json").resolve(strict=False)


def load_config(path: str | Path) -> PreReleaseConfig:
    config_path = Path(path).expanduser().resolve(strict=False)
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"missing config: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid config json: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError("config root must be one object")
    mail = _object(payload, "mail_account")
    policy = _object(payload, "policy")
    product_gate = _object(payload, "product_gate")
    return PreReleaseConfig(
        mail_account=MailAccountConfig(
            profile=_string(mail, "profile"),
            email=_email(_string(mail, "email"), "mail_account.email"),
        ),
        submission_group=_email(_string(payload, "submission_group"), "submission_group"),
        release_gate_group=_email(_string(payload, "release_gate_group"), "release_gate_group"),
        mailbox=_string(payload, "mailbox"),
        timezone=_string(payload, "timezone"),
        poll_minutes=_int(payload, "poll_minutes", minimum=5, maximum=1440),
        state_dir=_path(payload, "state_dir"),
        dependency_lock=_path(payload, "dependency_lock"),
        dependency_lock_sha256=_sha256(_string(payload, "dependency_lock_sha256"), "dependency_lock_sha256"),
        shared_hmac_secret_path=_path(payload, "shared_hmac_secret_path"),
        mail_command=_command(payload, "mail_command"),
        product_gate=ProductGateConfig(
            config_path=_path(product_gate, "config_path"),
            command=_command(product_gate, "command"),
        ),
        policy_profile=_string(policy, "profile"),
        enabled_optional_checks=tuple(_string_list(policy, "enabled_optional_checks")),
    )


def _object(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be one object")
    return value


def _string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} must be one non-empty string")
    return value.strip()


def _path(payload: dict[str, Any], key: str) -> Path:
    return Path(_string(payload, key)).expanduser().resolve(strict=False)


def _email(value: str, field_name: str) -> str:
    if not _EMAIL_PATTERN.fullmatch(value):
        raise ConfigError(f"{field_name} must be one email address")
    return value


def _int(payload: dict[str, Any], key: str, *, minimum: int, maximum: int) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise ConfigError(f"{key} must be between {minimum} and {maximum}")
    return value


def _sha256(value: str, field_name: str) -> str:
    lowered = value.lower()
    if not _SHA256_PATTERN.fullmatch(lowered):
        raise ConfigError(f"{field_name} must be one lowercase SHA-256 digest")
    return lowered


def _command(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
        raise ConfigError(f"{key} must be one non-empty argument array")
    return tuple(item.strip() for item in value)


def _string_list(payload: dict[str, Any], key: str) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ConfigError(f"{key} must be an array of non-empty strings")
    return [item.strip() for item in value]
