from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from lark_cli_command import resolve_lark_cli_command


SUPPORTED_EVENT_TYPES = frozenset(
    {
        "REQUEST_CREATED",
        "PAGE_DECISION",
        "MAIL_DECISION",
        "REMINDER_SENT",
        "APPROVAL_MESSAGE_QUARANTINED",
        "AGGREGATE_VERIFICATION",
        "APPROVAL_REVOKED",
        "RELEASE_HOLD_REQUESTED",
        "PRE_RELEASE_REQUESTED",
    }
)

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_KEY_NORMALIZER = re.compile(r"[^a-z0-9]+")
_SAFE_SCALAR_PATTERN = re.compile(r"^[A-Za-z0-9_.:+-]{1,256}$")
_OMIT = object()
_FORBIDDEN_KEY_PARTS = frozenset(
    {
        "authorization",
        "bearer",
        "cookie",
        "credential",
        "credentials",
        "display_name",
        "email",
        "localhost",
        "name",
        "password",
        "private_key",
        "raw_authentication_results",
        "raw_header",
        "raw_headers",
        "secret",
        "session_key",
        "token",
        "url",
        "uri",
    }
)
_RAW_AUTH_KEYS = frozenset(
    {
        "authentication_result",
        "authentication_results",
        "auth_result",
        "auth_results",
    }
)
_ALLOWED_EXACT_KEYS = frozenset(
    {
        "attempt",
        "decision",
        "decision_code",
        "imap_uid",
        "imap_uidvalidity",
        "next_state",
        "previous_state",
        "reason_code",
        "required",
        "role_id",
        "sequence",
        "state",
        "status",
        "uid",
        "uidvalidity",
    }
)
_ALLOWED_SUFFIXES = ("_at", "_count", "_digest", "_hash", "_sha256")


@dataclass(frozen=True)
class AuditRecord:
    event_id: str
    round_id: str
    event_type: str
    manifest_digest: str
    role_snapshot_digest: str
    state: str
    required_role_emails: Mapping[str, str]
    audit_payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _require_inline_value(self.event_id, field_name="event_id")
        _require_inline_value(self.round_id, field_name="round_id")
        _require_inline_value(self.state, field_name="state")
        if self.event_type not in SUPPORTED_EVENT_TYPES:
            raise ValueError(f"unsupported audit event type: {self.event_type}")
        _require_digest(self.manifest_digest, field_name="manifest_digest")
        _require_digest(self.role_snapshot_digest, field_name="role_snapshot_digest")
        if not isinstance(self.required_role_emails, Mapping):
            raise ValueError("required_role_emails must be a mapping")
        for role_id, email in self.required_role_emails.items():
            _require_inline_value(role_id, field_name="role_id")
            _require_inline_value(email, field_name="role_email")
            if not _EMAIL_PATTERN.fullmatch(email):
                raise ValueError("required role email is invalid")
        if not isinstance(self.audit_payload, Mapping):
            raise ValueError("audit_payload must be a mapping")


@dataclass(frozen=True)
class AuditWriteResult:
    status: str
    state_advance_allowed: bool
    cloud_readback_verified: bool
    audit_payload_digest: str
    recorded_state: str
    failure_reason: str | None = None


def canonical_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def minimize_audit_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    minimized = _minimize_mapping(payload)
    return minimized if minimized else {}


def audit_payload_digest(record: AuditRecord) -> str:
    payload = canonical_json(minimize_audit_payload(record.audit_payload)).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def render_audit_markdown(record: AuditRecord) -> str:
    minimized_payload = minimize_audit_payload(record.audit_payload)
    payload_digest = audit_payload_digest(record)
    lines = [
        "### Release approval audit",
        "",
        "- contract: `release-approval-audit/v1`",
        f"- event_id: `{record.event_id}`",
        f"- round_id: `{record.round_id}`",
        f"- event_type: `{record.event_type}`",
        f"- manifest_digest: `{record.manifest_digest}`",
        f"- role_snapshot_digest: `{record.role_snapshot_digest}`",
        f"- state: `{record.state}`",
        f"- audit_payload_digest: `{payload_digest}`",
        "- required_role_emails:",
    ]
    if record.required_role_emails:
        for role_id, email in sorted(record.required_role_emails.items()):
            lines.append(f"  - `{role_id}`: `{email.lower()}`")
    else:
        lines.append("  - none")
    lines.extend(
        [
            "- audit_payload:",
            f"    {canonical_json(minimized_payload)}",
            "",
        ]
    )
    return "\n".join(lines)


def build_lark_update_args(document_url: str, markdown: str) -> list[str]:
    return [
        *resolve_lark_cli_command(),
        "docs",
        "+update",
        "--api-version",
        "v2",
        "--doc",
        document_url,
        "--command",
        "append",
        "--doc-format",
        "markdown",
        "--content",
        markdown,
        "--as",
        "user",
    ]


def build_lark_fetch_args(document_url: str, payload_digest: str) -> list[str]:
    return [
        *resolve_lark_cli_command(),
        "docs",
        "+fetch",
        "--api-version",
        "v2",
        "--doc",
        document_url,
        "--doc-format",
        "markdown",
        "--scope",
        "keyword",
        "--keyword",
        payload_digest,
        "--context-before",
        "12",
        "--context-after",
        "4",
        "--format",
        "json",
        "--as",
        "user",
    ]


class LarkAuditAdapter:
    def __init__(
        self,
        document_url: str,
        *,
        required: bool,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        _require_inline_value(document_url, field_name="document_url")
        self.document_url = document_url
        self.required = required
        self.runner = runner

    def write(self, record: AuditRecord) -> AuditWriteResult:
        payload_digest = audit_payload_digest(record)
        markdown = render_audit_markdown(record)
        update = self._run(build_lark_update_args(self.document_url, markdown))
        if update is None or update.returncode != 0:
            return self._failure(record, payload_digest, "LARK_UPDATE_FAILED")

        fetch = self._run(build_lark_fetch_args(self.document_url, payload_digest))
        if fetch is None or fetch.returncode != 0:
            return self._failure(record, payload_digest, "LARK_READBACK_FAILED")

        cloud_text = _extract_cloud_text(fetch.stdout or "")
        if not _has_all_bindings(cloud_text, record, payload_digest):
            return self._failure(record, payload_digest, "LARK_READBACK_BINDING_MISMATCH")

        return AuditWriteResult(
            status="AUDIT_WRITTEN",
            state_advance_allowed=True,
            cloud_readback_verified=True,
            audit_payload_digest=payload_digest,
            recorded_state=record.state,
        )

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return self.runner(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError):
            return None

    def _failure(self, record: AuditRecord, payload_digest: str, reason: str) -> AuditWriteResult:
        return AuditWriteResult(
            status="CAPABILITY_BLOCKED" if self.required else "AUDIT_DEGRADED",
            state_advance_allowed=not self.required,
            cloud_readback_verified=False,
            audit_payload_digest=payload_digest,
            recorded_state=record.state,
            failure_reason=reason,
        )


def _minimize_mapping(payload: Mapping[str, Any]) -> dict[str, Any]:
    minimized: dict[str, Any] = {}
    for raw_key in sorted(payload, key=lambda value: str(value)):
        key = str(raw_key)
        normalized_key = _normalize_key(key)
        if _is_forbidden_key(normalized_key) or not _is_allowed_key(normalized_key):
            continue
        raw_value = payload[raw_key]
        if isinstance(raw_value, str) and not _SAFE_SCALAR_PATTERN.fullmatch(raw_value):
            continue
        value = _minimize_value(raw_value)
        if value is not _OMIT:
            minimized[key] = value
    return minimized


def _minimize_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if "localhost" in lowered or "127.0.0.1" in lowered or "?key=" in lowered:
            return _OMIT
        return value
    if isinstance(value, Mapping):
        return _minimize_mapping(value)
    if isinstance(value, (list, tuple)):
        items = []
        for item in value:
            minimized = _minimize_value(item)
            if minimized is not _OMIT:
                items.append(minimized)
        return items
    return _OMIT


def _normalize_key(value: str) -> str:
    return _KEY_NORMALIZER.sub("_", value.strip().lower()).strip("_")


def _is_forbidden_key(normalized_key: str) -> bool:
    if normalized_key in _RAW_AUTH_KEYS:
        return True
    parts = set(normalized_key.split("_"))
    for forbidden in _FORBIDDEN_KEY_PARTS:
        if forbidden in normalized_key or forbidden in parts:
            return True
    return normalized_key.endswith("_key") and not normalized_key.endswith("_key_digest")


def _is_allowed_key(normalized_key: str) -> bool:
    return normalized_key in _ALLOWED_EXACT_KEYS or normalized_key.endswith(_ALLOWED_SUFFIXES)


def _extract_cloud_text(stdout: str) -> str:
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return stdout
    contents: list[str] = []
    _collect_content_strings(payload, contents)
    return "\n".join(contents) if contents else ""


def _collect_content_strings(value: Any, contents: list[str], *, content_context: bool = False) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = _normalize_key(str(key))
            _collect_content_strings(
                child,
                contents,
                content_context=normalized in {"content", "markdown", "text"},
            )
        return
    if isinstance(value, list):
        for child in value:
            _collect_content_strings(child, contents, content_context=content_context)
        return
    if content_context and isinstance(value, str):
        contents.append(value)


def _has_all_bindings(cloud_text: str, record: AuditRecord, payload_digest: str) -> bool:
    expected = (
        "contract: `release-approval-audit/v1`",
        f"event_id: `{record.event_id}`",
        f"round_id: `{record.round_id}`",
        f"manifest_digest: `{record.manifest_digest}`",
        f"role_snapshot_digest: `{record.role_snapshot_digest}`",
        f"state: `{record.state}`",
        f"audit_payload_digest: `{payload_digest}`",
    )
    sections = cloud_text.split("### Release approval audit")[1:]
    return any(all(binding in section for binding in expected) for section in sections)


def _require_inline_value(value: str, *, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    if any(character in value for character in ("\r", "\n", "`")):
        raise ValueError(f"{field_name} must be a single safe line")


def _require_digest(value: str, *, field_name: str) -> None:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase sha256 digest")
