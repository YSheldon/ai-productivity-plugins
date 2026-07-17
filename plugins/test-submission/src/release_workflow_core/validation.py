from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence


_SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_MODULES = frozenset(("kernel", "client", "server"))


class ValidationError(ValueError):
    """Raised when a canonical release-workflow payload is invalid."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def freeze_digest(payload: Mapping[str, Any], *, exclude: Iterable[str] = ()) -> str:
    excluded = set(exclude)
    frozen = {key: value for key, value in payload.items() if key not in excluded}
    return "sha256:" + hashlib.sha256(canonical_json(frozen).encode("utf-8")).hexdigest()


def require_schema(payload: Mapping[str, Any], *, field_name: str = "schema", expected: str) -> str:
    value = require_non_empty_string(payload, field_name)
    if value != expected:
        raise ValidationError(f"{field_name} must be the exact value {expected}.")
    return value


def require_non_empty_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{key} must be a non-empty string.")
    return value.strip()


def optional_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    return value.strip() if isinstance(value, str) else ""


def require_event_id(payload: Mapping[str, Any], key: str = "event_id") -> str:
    value = require_non_empty_string(payload, key)
    if not _EVENT_PATTERN.fullmatch(value):
        raise ValidationError(f"{key} must match the stable workflow identifier pattern.")
    return value


def require_positive_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if type(value) is not int or value <= 0:
        raise ValidationError(f"{key} must be a positive integer.")
    return value


def require_email(payload: Mapping[str, Any], key: str) -> str:
    value = require_non_empty_string(payload, key).lower()
    if not _EMAIL_PATTERN.fullmatch(value):
        raise ValidationError(f"{key} must be one RFC-like email address.")
    return value


def optional_email(payload: Mapping[str, Any], key: str) -> str:
    value = optional_string(payload, key).lower()
    if not value:
        return ""
    if not _EMAIL_PATTERN.fullmatch(value):
        raise ValidationError(f"{key} must be one RFC-like email address when present.")
    return value


def normalize_email(value: Any, *, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if not _EMAIL_PATTERN.fullmatch(text):
        raise ValidationError(f"{field_name} must be one RFC-like email address.")
    return text


def optional_positive_int(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if value in (None, ""):
        return None
    if type(value) is not int or value <= 0:
        raise ValidationError(f"{key} must be a positive integer when present.")
    return value


def require_module(payload: Mapping[str, Any], key: str = "module") -> str:
    value = require_non_empty_string(payload, key).lower()
    if value not in _MODULES:
        raise ValidationError(f"{key} must be one of: {', '.join(sorted(_MODULES))}.")
    return value


def require_sha1(value: Any, *, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA1_PATTERN.fullmatch(text):
        raise ValidationError(f"{field_name} must be a 40-hex SHA-1 digest.")
    return text


def require_sha256_hex(value: Any, *, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_HEX_PATTERN.fullmatch(text):
        raise ValidationError(f"{field_name} must be a 64-hex SHA-256 digest.")
    return text


def require_sha256_digest(payload: Mapping[str, Any], key: str) -> str:
    value = require_non_empty_string(payload, key).lower()
    if not _SHA256_PATTERN.fullmatch(value):
        raise ValidationError(f"{key} must be a sha256:<64-hex> digest.")
    return value


def optional_sha256_digest(payload: Mapping[str, Any], key: str) -> str:
    value = optional_string(payload, key).lower()
    if not value:
        return ""
    if not _SHA256_PATTERN.fullmatch(value):
        raise ValidationError(f"{key} must be a sha256:<64-hex> digest when present.")
    return value


def require_rfc3339(payload: Mapping[str, Any], key: str) -> str:
    value = require_non_empty_string(payload, key)
    if not _RFC3339_PATTERN.fullmatch(value):
        raise ValidationError(f"{key} must be an RFC 3339 timestamp.")
    return _normalize_rfc3339(value)


def optional_rfc3339(payload: Mapping[str, Any], key: str) -> str:
    value = optional_string(payload, key)
    if not value:
        return ""
    if not _RFC3339_PATTERN.fullmatch(value):
        raise ValidationError(f"{key} must be an RFC 3339 timestamp when present.")
    return _normalize_rfc3339(value)


def normalize_string_sequence(value: Any, *, field_name: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{field_name} must be a list of strings.")
    items = tuple(str(item).strip() for item in value if isinstance(item, str) and item.strip())
    if len(items) != len(value):
        raise ValidationError(f"{field_name} must contain only non-empty strings.")
    if not allow_empty and not items:
        raise ValidationError(f"{field_name} must not be empty.")
    return items


def require_mapping(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field_name} must be an object.")
    return value


def normalize_ref_list(value: Any, *, field_name: str) -> tuple[str, ...]:
    return tuple(sorted(dict.fromkeys(normalize_string_sequence(value, field_name=field_name, allow_empty=True))))


def utc_now_rfc3339(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("datetime values must be timezone-aware.")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_rfc3339(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError("timestamps must be timezone-aware.")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
