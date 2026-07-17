from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping

from .auth import WorkflowAuthProvider
from .validation import require_sha256_digest


_BEGIN = "-----BEGIN PRODUCT MATERIAL WORKFLOW-----"
_END = "-----END PRODUCT MATERIAL WORKFLOW-----"
_MAIL_CONTRACT = "ProductMaterialMail/v1"
_PROVENANCE_VERIFIED = "COMPLIANT_PLUGIN_VERIFIED"
_PROVENANCE_PLAIN = "PLAIN_EMAIL_UNVERIFIED"
_PROVENANCE_STRUCTURED = "STRUCTURED_UNVERIFIED"
_PROVENANCE_AUTH_FAILED = "AUTHENTICATION_FAILED"
_SUBJECTS = {
    "test_submission": "【提测】",
    "release_gate_check": "【发布门禁检查】",
    "release_application": "【发布申请】",
    "blocked": "【发布阻断】",
}
_HEADER_MAP = {
    "event_id": "X-RD-Event-Id",
    "round_id": "X-RD-Round-Id",
    "parent_event_id": "X-RD-Parent-Event-Id",
    "parent_round_id": "X-RD-Parent-Round-Id",
    "manifest_s_digest": "X-RD-Manifest-S-Digest",
    "manifest_r_digest": "X-RD-Manifest-R-Digest",
    "manifest_digest": "X-RD-Manifest-Digest",
    "policy_digest": "X-RD-Policy-Digest",
    "submitter_email": "X-RD-Submitter-Email",
    "evidence_refs": "X-RD-Evidence-Refs",
    "state": "X-RD-Workflow-State",
    "event_type": "X-RD-Workflow-Event-Type",
}
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class MailContractError(RuntimeError):
    """Raised when a canonical release workflow mail payload is unsafe or invalid."""


class AuthenticationFailedError(MailContractError):
    """Raised when a message claims authentication but validation fails."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def render_subject(kind: str, *, task: str, module: str, when: date | datetime | str) -> str:
    prefix = _SUBJECTS.get(str(kind or "").strip())
    if not prefix:
        raise MailContractError(f"unsupported subject kind: {kind}")
    task_text = str(task or "").strip()
    module_text = str(module or "").strip()
    if not task_text or not module_text:
        raise MailContractError("task and module are required for rendered subjects.")
    stamp = _normalize_subject_date(when)
    return f"{prefix}{task_text}-{module_text}-{stamp}"


def render_message(
    kind: str,
    payload: Mapping[str, Any],
    *,
    secret: bytes | Mapping[str, bytes] | WorkflowAuthProvider | None = None,
    key_id: str = "default",
    identity_id: str = "",
    when: date | datetime | str,
    summary_lines: Iterable[str] = (),
    provenance_classification: str | None = None,
) -> dict[str, Any]:
    signed = sign_machine_payload(payload, secret=secret, key_id=key_id, identity_id=identity_id)
    classification = provenance_classification or classify_machine_payload(signed, secret=secret)
    task = str(payload.get("task") or "")
    module = str(payload.get("module") or "")
    subject = render_subject(kind, task=task, module=module, when=when)
    body_lines = [provenance_badge(classification)]
    body_lines.extend(str(line) for line in summary_lines if str(line).strip())
    body_lines.append(encode_machine_payload(signed))
    return {
        "subject": subject,
        "body_text": "\n".join(body_lines),
        "headers": binding_headers(payload, provenance_classification=classification),
        "signed_payload": signed,
    }


def parse_message(
    body_text: str,
    *,
    secret: bytes | Mapping[str, bytes] | WorkflowAuthProvider | None = None,
    headers: Mapping[str, Any] | None = None,
    expected_bindings: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload = decode_machine_payload(body_text)
    classification = classify_machine_payload(payload, secret=secret)
    if classification == _PROVENANCE_AUTH_FAILED:
        raise AuthenticationFailedError("message authentication failed.")
    if headers is not None:
        _verify_headers(payload, headers)
    if expected_bindings is not None:
        _verify_bindings(payload, expected_bindings)
    material = dict(payload)
    material.setdefault("provenance_classification", classification)
    material.setdefault("provenance_badge", provenance_badge(classification))
    return material


def binding_headers(payload: Mapping[str, Any], *, provenance_classification: str | None = None) -> dict[str, str]:
    classification = provenance_classification or str(payload.get("provenance_classification") or "") or _PROVENANCE_STRUCTURED
    headers = {
        "X-RD-Mail-Contract": _MAIL_CONTRACT,
        "X-RD-Intake-Provenance": classification,
        "X-RD-Intake-Badge": provenance_badge(classification),
    }
    for field_name, header_name in _HEADER_MAP.items():
        value = payload.get(field_name)
        if field_name == "evidence_refs":
            refs = [str(item).strip() for item in value or [] if str(item).strip()]
            if refs:
                headers[header_name] = ",".join(sorted(dict.fromkeys(refs)))
            continue
        if value in (None, ""):
            continue
        headers[header_name] = str(value)
    return headers


def provenance_badge(classification: str) -> str:
    mapping = {
        _PROVENANCE_VERIFIED: "发起来源：合规插件发起（已验证）",
        _PROVENANCE_PLAIN: "发起来源：普通邮件发起（未验证）",
        _PROVENANCE_STRUCTURED: "发起来源：结构化事件发起（未验证）",
        _PROVENANCE_AUTH_FAILED: "发起来源：认证失败（已阻断）",
    }
    return mapping.get(classification, mapping[_PROVENANCE_STRUCTURED])


def sign_machine_payload(
    payload: Mapping[str, Any],
    *,
    secret: bytes | Mapping[str, bytes] | WorkflowAuthProvider | None = None,
    key_id: str = "default",
    identity_id: str = "",
) -> dict[str, Any]:
    material = dict(payload)
    material["mail_contract"] = _MAIL_CONTRACT
    resolved = _resolve_secret(secret, key_id=key_id)
    if resolved is None:
        material.pop("auth", None)
        material.pop("hmac_sha256", None)
        return material
    if len(resolved) < 32:
        raise MailContractError("auth secret must contain at least 32 bytes.")
    auth = {
        "algorithm": "HMAC-SHA256",
        "key_id": key_id,
        "identity_id": str(identity_id or key_id).strip() or key_id,
        "value": "",
    }
    material["auth"] = auth
    auth["value"] = hmac.new(resolved, canonical_json(_auth_body(material)).encode("utf-8"), hashlib.sha256).hexdigest()
    material["hmac_sha256"] = auth["value"]
    return material


def classify_machine_payload(
    payload: Mapping[str, Any],
    *,
    secret: bytes | Mapping[str, bytes] | WorkflowAuthProvider | None = None,
) -> str:
    auth = payload.get("auth")
    legacy_hmac = str(payload.get("hmac_sha256") or "").strip().lower()
    if isinstance(auth, Mapping) or legacy_hmac:
        try:
            verify_machine_payload(payload, secret=secret)
        except MailContractError:
            return _PROVENANCE_AUTH_FAILED
        return _PROVENANCE_VERIFIED
    if payload.get("schema") == "ProductMaterialWorkflow/v1":
        return _PROVENANCE_STRUCTURED
    return _PROVENANCE_PLAIN


def verify_machine_payload(
    payload: Mapping[str, Any],
    *,
    secret: bytes | Mapping[str, bytes] | WorkflowAuthProvider | None = None,
) -> None:
    material = dict(payload)
    if material.get("mail_contract") != _MAIL_CONTRACT:
        raise MailContractError("signed machine payload uses an unsupported mail contract.")
    auth = material.get("auth")
    if isinstance(auth, Mapping):
        if str(auth.get("algorithm") or "") != "HMAC-SHA256":
            raise MailContractError("unsupported auth algorithm.")
        key_id = str(auth.get("key_id") or "").strip()
        signature = str(auth.get("value") or "").strip().lower()
        resolved = _resolve_secret(secret, key_id=key_id)
        if resolved is None:
            raise MailContractError("auth key is not available for verification.")
        if len(resolved) < 32:
            raise MailContractError("auth secret must contain at least 32 bytes.")
        actual = hmac.new(resolved, canonical_json(_auth_body(material)).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, actual):
            raise MailContractError("signed machine payload auth does not match.")
        return
    legacy_hmac = str(material.pop("hmac_sha256", "")).strip().lower()
    if legacy_hmac:
        resolved = _resolve_secret(secret, key_id="default")
        if resolved is None:
            raise MailContractError("auth key is not available for legacy verification.")
        actual = hmac.new(resolved, canonical_json(material).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(legacy_hmac, actual):
            raise MailContractError("legacy machine payload hmac does not match.")
        return
    raise MailContractError("machine payload does not declare auth.")


def encode_machine_payload(payload: Mapping[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(canonical_json(payload).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{_BEGIN}\n{encoded}\n{_END}"


def decode_machine_payload(body_text: str) -> dict[str, Any]:
    try:
        encoded = body_text.split(_BEGIN, 1)[1].split(_END, 1)[0].strip()
    except IndexError as exc:
        raise MailContractError("workflow machine block is missing or ambiguous.") from exc
    padding = "=" * (-len(encoded) % 4)
    try:
        decoded = base64.urlsafe_b64decode((encoded + padding).encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
    except Exception as exc:
        raise MailContractError("workflow machine block payload is invalid.") from exc
    if not isinstance(payload, dict):
        raise MailContractError("workflow machine block must decode to one object.")
    return payload


def _verify_headers(payload: Mapping[str, Any], headers: Mapping[str, Any]) -> None:
    expected = binding_headers(
        payload,
        provenance_classification=str(payload.get("provenance_classification") or headers.get("X-RD-Intake-Provenance") or _PROVENANCE_STRUCTURED),
    )
    for header_name, expected_value in expected.items():
        actual_value = headers.get(header_name)
        if actual_value is None:
            continue
        if str(actual_value).strip() != expected_value:
            raise MailContractError(f"mail header drift detected for {header_name}.")


def _verify_bindings(payload: Mapping[str, Any], expected_bindings: Mapping[str, Any]) -> None:
    for field_name in (
        "event_id",
        "round_id",
        "parent_event_id",
        "parent_round_id",
        "manifest_s_digest",
        "manifest_r_digest",
        "manifest_digest",
        "policy_digest",
        "state",
        "event_type",
    ):
        if field_name not in expected_bindings:
            continue
        if str(payload.get(field_name) or "") != str(expected_bindings.get(field_name) or ""):
            raise MailContractError(f"machine payload binding mismatch: {field_name}.")
    if "evidence_refs" in expected_bindings:
        current_refs = sorted(
            dict.fromkeys(str(item).strip() for item in payload.get("evidence_refs") or [] if str(item).strip())
        )
        expected_refs = sorted(
            dict.fromkeys(
                str(item).strip() for item in expected_bindings.get("evidence_refs") or [] if str(item).strip()
            )
        )
        if current_refs != expected_refs:
            raise MailContractError("machine payload binding mismatch: evidence_refs.")
    for digest_field in ("manifest_s_digest", "manifest_r_digest", "manifest_digest", "policy_digest"):
        if payload.get(digest_field):
            require_sha256_digest(payload, digest_field)


def _resolve_secret(
    secret: bytes | Mapping[str, bytes] | WorkflowAuthProvider | None,
    *,
    key_id: str,
) -> bytes | None:
    if secret is None:
        return None
    if isinstance(secret, bytes):
        return secret
    if isinstance(secret, Mapping):
        return secret.get(key_id) or secret.get("default")
    if hasattr(secret, "resolve_secret"):
        return secret.resolve_secret(key_id)
    raise MailContractError("unsupported secret provider type.")


def _auth_body(payload: Mapping[str, Any]) -> dict[str, Any]:
    material = {key: value for key, value in payload.items() if key not in {"auth", "hmac_sha256"}}
    if "auth" in payload and isinstance(payload.get("auth"), Mapping):
        auth = dict(payload["auth"])
        auth.pop("value", None)
        material["auth"] = auth
    return material


def _normalize_subject_date(value: date | datetime | str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise MailContractError("subject timestamps must be timezone-aware.")
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d")
    if isinstance(value, date):
        return value.isoformat()
    text = str(value or "").strip()
    if not _DATE_RE.fullmatch(text):
        raise MailContractError("subject date must be YYYY-MM-DD.")
    return text
