from __future__ import annotations

import email.utils
import hashlib
import re
from typing import Any, Mapping

from .mail_contract import _PROVENANCE_PLAIN, provenance_badge
from .policy import required_verdict
from .validation import ValidationError, canonical_json, normalize_email


_SUBJECT_RE = re.compile(
    r"^\[提测\]\[(?P<identifier>[^\]-]+)-(?P<task>[^\]]+)\](?P<submitted_at>\d{8}-\d{2}:\d{2}:\d{2})$"
)
_LINE_RE = re.compile(
    r"^\s*(?P<label>提测类型|提测标识|提测标题|标题|目录|SVN\s*地址|SVN\s*Revision|SVN[-_\s]*Revision|revision|文件数|修改说明)\s*[：:]\s*(?P<value>.*)$",
    re.IGNORECASE,
)
_REVISION_RE = re.compile(r"^[1-9]\d*$")
_MODULE_TOKEN_PATTERNS = {
    "kernel": re.compile(r"内核|(?<![A-Za-z0-9_])kernel(?![A-Za-z0-9_])", re.IGNORECASE),
    "client": re.compile(r"客户端|(?<![A-Za-z0-9_])client(?![A-Za-z0-9_])", re.IGNORECASE),
    "server": re.compile(r"服务端|(?<![A-Za-z0-9_])server(?![A-Za-z0-9_])", re.IGNORECASE),
}

DRAFT_STATE = "DRAFT"
UNTRUSTED_EVENT_TYPE = "PLAIN_EMAIL_UNVERIFIED_INTAKE"
BLOCKED_STATE = "CAPABILITY_BLOCKED"


class LegacyIntakeError(RuntimeError):
    """Raised when a legacy plain-text submission mail cannot be normalized safely."""


def parse_legacy_submission_mail(
    message: Mapping[str, Any],
    *,
    enabled_checks: tuple[str, ...] = (),
) -> dict[str, Any]:
    subject = str(message.get("subject") or "").strip()
    body_text = str(message.get("body_text") or "").strip()
    headers = message.get("headers") or {}
    header_digest = "sha256:" + hashlib.sha256(
        canonical_json(headers if isinstance(headers, Mapping) else {}).encode("utf-8")
    ).hexdigest()

    subject_match = _SUBJECT_RE.fullmatch(subject)
    if not subject_match:
        raise LegacyIntakeError("legacy intake subject does not match the approved compatibility pattern.")

    fields = _parse_body_fields(body_text)
    submitter_email = _extract_submitter_email(message, headers=headers)
    task = fields.get("提测标题") or fields.get("标题") or subject_match.group("task").strip()
    locator = fields.get("目录") or fields.get("SVN地址") or ""
    revision = _normalize_revision(fields.get("revision", ""))
    module, module_issue = _detect_module(subject=subject, fields=fields, locator=locator)

    required_inputs: list[str] = []
    if not locator:
        required_inputs.append("locator")
    if not revision:
        required_inputs.append("revision")
    if module_issue:
        required_inputs.append(module_issue)

    state = DRAFT_STATE if not required_inputs else BLOCKED_STATE
    checks = tuple(str(item).strip() for item in enabled_checks if str(item).strip())
    payload: dict[str, Any] = {
        "schema": "ProductMaterialWorkflow/v1",
        "event_type": UNTRUSTED_EVENT_TYPE,
        "state": state,
        "trust_level": "UNTRUSTED",
        "provenance_classification": _PROVENANCE_PLAIN,
        "provenance_badge": provenance_badge(_PROVENANCE_PLAIN),
        "task": task,
        "module": module,
        "legacy_submission_type": fields.get("提测类型", ""),
        "legacy_identifier": fields.get("提测标识", subject_match.group("identifier").strip()),
        "submitter_email": submitter_email,
        "submitter_email_status": "valid" if submitter_email else "missing_or_invalid",
        "locator": locator,
        "revision": revision,
        "file_count": fields.get("文件数", ""),
        "change_summary": fields.get("修改说明", ""),
        "submitted_at": subject_match.group("submitted_at"),
        "required_inputs": required_inputs,
        "source": {
            "uid": str(message.get("uid") or ""),
            "message_id": str(message.get("message_id") or ""),
            "headers_sha256": header_digest,
            "subject": subject,
            "submitter_email": submitter_email,
        },
        "promotion_requirements": {
            "independent_gate_allowed": not required_inputs,
            "trusted_pickup": "svn-or-gitlab-trusted-retrieval",
            "required_verdict": required_verdict(checks),
            "enabled_checks": list(checks),
            "machine_auth_optional": True,
        },
    }
    if required_inputs:
        if "module_conflict" in required_inputs:
            payload["failure_reason"] = "legacy intake contains conflicting module tokens"
        else:
            payload["failure_reason"] = "legacy intake requires locator, revision, and reliable module before gate promotion"
    return payload


def _extract_submitter_email(message: Mapping[str, Any], *, headers: Mapping[str, Any]) -> str:
    from_entries = message.get("from")
    if isinstance(from_entries, list):
        for entry in from_entries:
            if isinstance(entry, Mapping):
                candidate = str(entry.get("email") or "").strip()
                if candidate:
                    try:
                        return normalize_email(candidate, field_name="submitter_email")
                    except ValidationError:
                        return ""
    raw_from = str(headers.get("From") or headers.get("from") or "").strip()
    if not raw_from:
        return ""
    _display_name, candidate = email.utils.parseaddr(raw_from)
    if not candidate:
        return ""
    try:
        return normalize_email(candidate, field_name="submitter_email")
    except ValidationError:
        return ""


def _parse_body_fields(body_text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in body_text.splitlines():
        match = _LINE_RE.match(line)
        if not match:
            continue
        label = _normalize_label(match.group("label"))
        value = match.group("value").strip()
        if value and label not in parsed:
            parsed[label] = value
    return parsed


def _normalize_label(label: str) -> str:
    compact = re.sub(r"[-_\s]+", "", str(label or "").strip().lower())
    if compact == "svn地址":
        return "SVN地址"
    if compact in {"svnrevision", "revision"}:
        return "revision"
    if compact == "提测类型":
        return "提测类型"
    if compact == "提测标识":
        return "提测标识"
    if compact == "提测标题":
        return "提测标题"
    if compact == "标题":
        return "标题"
    if compact == "目录":
        return "目录"
    if compact == "文件数":
        return "文件数"
    if compact == "修改说明":
        return "修改说明"
    return label.strip()


def _normalize_revision(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if _REVISION_RE.fullmatch(text):
        return text
    return ""


def _detect_module(
    *,
    subject: str,
    fields: Mapping[str, str],
    locator: str,
) -> tuple[str, str]:
    sources = tuple(
        str(value).strip()
        for value in (
            subject,
            fields.get("提测类型", ""),
            fields.get("提测标题", ""),
            fields.get("标题", ""),
            locator,
        )
        if str(value).strip()
    )
    hits = {
        module
        for module, pattern in _MODULE_TOKEN_PATTERNS.items()
        if any(pattern.search(source) for source in sources)
    }
    if len(hits) == 1:
        return next(iter(hits)), ""
    if hits:
        return "", "module_conflict"
    return "", "module"
