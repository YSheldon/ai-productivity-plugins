from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


class DecisionError(RuntimeError):
    """Raised when governance decision evidence cannot be trusted."""


@dataclass(frozen=True)
class DecisionRole:
    role_id: str
    email: str
    required: bool
    enabled: bool


@dataclass(frozen=True)
class DecisionRoleSnapshot:
    document_url: str
    heading: str
    roles: tuple[DecisionRole, ...]
    digest: str

    @property
    def required_role_ids(self) -> tuple[str, ...]:
        return tuple(role.role_id for role in self.roles if role.required)


@dataclass(frozen=True)
class GovernanceDecisionPackage:
    request: Mapping[str, Any]
    screen_html: str
    screen_sha256: str


_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ROLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_TRUE_VALUES = frozenset({"true", "yes", "1", "y"})
_FALSE_VALUES = frozenset({"false", "no", "0", "n"})


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _snapshot_digest(
    *,
    document_url: str,
    heading: str,
    roles: list[Mapping[str, Any]],
) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical_json(
            {
                "document_url": document_url,
                "heading": heading,
                "roles": roles,
            }
        ).encode("utf-8")
    ).hexdigest()


def decision_role_snapshot_payload(snapshot: DecisionRoleSnapshot) -> dict[str, Any]:
    roles = [
        {
            "email": role.email,
            "enabled": role.enabled,
            "required": role.required,
            "role_id": role.role_id,
        }
        for role in snapshot.roles
    ]
    return {
        "document_url": snapshot.document_url,
        "heading": snapshot.heading,
        "digest": snapshot.digest,
        "roles": roles,
    }


def decision_role_snapshot_from_mapping(payload: Mapping[str, Any]) -> DecisionRoleSnapshot:
    if not isinstance(payload, Mapping):
        raise DecisionError("frozen role snapshot is not an object")
    document_url = payload.get("document_url")
    heading = payload.get("heading")
    raw_roles = payload.get("roles")
    if not isinstance(document_url, str) or not document_url.strip():
        raise DecisionError("frozen role snapshot document_url is invalid")
    if not isinstance(heading, str) or not heading.strip():
        raise DecisionError("frozen role snapshot heading is invalid")
    if not isinstance(raw_roles, list) or not raw_roles:
        raise DecisionError("frozen role snapshot roles are invalid")
    roles: list[DecisionRole] = []
    canonical_roles: list[dict[str, Any]] = []
    role_ids: set[str] = set()
    emails: set[str] = set()
    for item in raw_roles:
        if not isinstance(item, Mapping):
            raise DecisionError("frozen role snapshot contains a malformed role")
        role_id = item.get("role_id")
        email = item.get("email")
        required = item.get("required")
        enabled = item.get("enabled")
        if not isinstance(role_id, str) or not _ROLE_ID_PATTERN.fullmatch(role_id):
            raise DecisionError("frozen role snapshot role_id is invalid")
        if not isinstance(email, str) or not _EMAIL_PATTERN.fullmatch(email):
            raise DecisionError("frozen role snapshot email is invalid")
        if type(required) is not bool or enabled is not True:
            raise DecisionError("frozen role snapshot flags are invalid")
        normalized_email = email.casefold()
        if role_id in role_ids or normalized_email in emails:
            raise DecisionError("frozen role snapshot contains duplicate roles")
        role_ids.add(role_id)
        emails.add(normalized_email)
        roles.append(DecisionRole(role_id, normalized_email, required, True))
        canonical_roles.append(
            {
                "email": normalized_email,
                "enabled": True,
                "required": required,
                "role_id": role_id,
            }
        )
    if not any(role.required for role in roles):
        raise DecisionError("frozen role snapshot has no required role")
    if [role.role_id for role in roles] != sorted(role.role_id for role in roles):
        raise DecisionError("frozen role snapshot roles are not canonical")
    expected = _snapshot_digest(
        document_url=document_url,
        heading=heading,
        roles=canonical_roles,
    )
    if payload.get("digest") != expected:
        raise DecisionError("frozen role snapshot digest is invalid")
    return DecisionRoleSnapshot(
        document_url=document_url,
        heading=heading,
        roles=tuple(roles),
        digest=expected,
    )


def _table_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        raise DecisionError("role source contains a malformed Markdown table row")
    return [cell.strip() for cell in stripped[1:-1].split("|")]


def _table_bool(value: str, *, field_name: str) -> bool:
    normalized = value.strip().casefold()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise DecisionError(f"role source {field_name} must be a boolean table cell")


def parse_decision_role_snapshot(
    markdown: str,
    *,
    document_url: str,
    heading: str,
) -> DecisionRoleSnapshot:
    lines = markdown.splitlines()
    target = heading.strip()
    section: list[str] = []
    inside = False
    for line in lines:
        stripped = line.strip()
        if not inside:
            if stripped == target:
                inside = True
            continue
        if stripped.startswith("## "):
            break
        section.append(line)
    if not inside:
        raise DecisionError(f"required decision role heading was not found: {heading}")

    table: list[str] = []
    collecting = False
    for line in section:
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            collecting = True
            table.append(line)
        elif collecting:
            break
    if len(table) < 3:
        raise DecisionError("decision role section must contain a non-empty Markdown table")
    header = [cell.casefold() for cell in _table_row(table[0])]
    if header != ["role_id", "email", "required", "enabled"]:
        raise DecisionError(
            "decision role table must use role_id, email, required, enabled columns"
        )

    roles: list[DecisionRole] = []
    role_ids: set[str] = set()
    emails: set[str] = set()
    for line in table[2:]:
        cells = _table_row(line)
        if len(cells) != 4:
            raise DecisionError("decision role table row must contain four cells")
        enabled = _table_bool(cells[3], field_name="enabled")
        if not enabled:
            continue
        role_id = cells[0].strip()
        email = cells[1].strip().casefold()
        required = _table_bool(cells[2], field_name="required")
        if not _ROLE_ID_PATTERN.fullmatch(role_id):
            raise DecisionError("enabled decision role_id is invalid")
        if not _EMAIL_PATTERN.fullmatch(email):
            raise DecisionError("enabled decision role email is invalid")
        if role_id in role_ids or email in emails:
            raise DecisionError("enabled decision roles contain duplicate role_id or email")
        role_ids.add(role_id)
        emails.add(email)
        roles.append(
            DecisionRole(
                role_id=role_id,
                email=email,
                required=required,
                enabled=True,
            )
        )
    roles.sort(key=lambda role: role.role_id)
    if not roles or not any(role.required for role in roles):
        raise DecisionError("at least one enabled required decision role is required")
    canonical_roles = [
        {
            "email": role.email,
            "enabled": role.enabled,
            "required": role.required,
            "role_id": role.role_id,
        }
        for role in roles
    ]
    digest = _snapshot_digest(
        document_url=document_url,
        heading=target,
        roles=canonical_roles,
    )
    return DecisionRoleSnapshot(
        document_url=document_url,
        heading=target,
        roles=tuple(roles),
        digest=digest,
    )


def build_governance_decision_request(
    event: Any,
    snapshot: Any,
    *,
    requested_at: str,
    expires_at: str,
    original_message_id: str,
) -> GovernanceDecisionPackage:
    if not isinstance(snapshot, DecisionRoleSnapshot):
        raise DecisionError("governance decision requires a frozen role snapshot")
    if not _MESSAGE_ID_PATTERN.fullmatch(original_message_id):
        raise DecisionError("original_message_id must be one exact RFC Message-ID")
    requested = _parse_timestamp(requested_at, field_name="requested_at")
    expires = _parse_timestamp(expires_at, field_name="expires_at")
    if expires <= requested:
        raise DecisionError("expires_at must be later than requested_at")

    required_roles = [role for role in snapshot.roles if role.required]
    if not required_roles:
        raise DecisionError("governance decision requires at least one required role")
    screen_html = _render_visual_companion(event, snapshot, requested_at, expires_at)
    screen_sha256 = hashlib.sha256(screen_html.encode("utf-8")).hexdigest()
    manifest_s_digest = "sha256:" + event.payload_digest
    manifest_r_digest = "sha256:" + screen_sha256
    manifest_digest = "sha256:" + hashlib.sha256(
        _canonical_json(
            {
                "manifest_s_digest": manifest_s_digest,
                "manifest_r_digest": manifest_r_digest,
            }
        ).encode("utf-8")
    ).hexdigest()
    request: dict[str, Any] = {
        "contract": "ReleaseAuthorizationRequest/v1",
        "schema": "ReleaseAuthorizationRequest/v1",
        "authority_scope": "RD_FLYWHEEL_GOVERNANCE",
        "event_id": event.idempotency_key,
        "round_id": event.originating_round_id,
        "target_scope": "rd-flywheel:capability-construction",
        "task_id": event.missing_capability,
        "task": event.missing_capability,
        "module": event.originating_plugin,
        "source_ref": event.originating_event_id,
        "checkpoint_digest": event.checkpoint_digest,
        "manifest_s_digest": manifest_s_digest,
        "manifest_r_digest": manifest_r_digest,
        "manifest_digest": manifest_digest,
        "role_snapshot_digest": snapshot.digest,
        "required_roles": [role.role_id for role in required_roles],
        "required_role_bindings": [
            {
                "role_id": role.role_id,
                "email": role.email,
                "required": True,
            }
            for role in required_roles
        ],
        "original_message_id": original_message_id,
        "references": [],
        "requested_at": requested_at,
        "expires_at": expires_at,
        "idempotency_key": (
            f"rd-flywheel-governance:{event.idempotency_key}:"
            f"{event.originating_round_id}"
        ),
        "visual_companion": {
            "html_sha256": "sha256:" + screen_sha256,
            "authority": "DESIGN_CONSENT_ONLY",
        },
        "governance_context": {
            "authority_boundary": "DESIGN_CONSENT_ONLY",
            "missing_capability": event.missing_capability,
            "originating_plugin": event.originating_plugin,
            "originating_event_id": event.originating_event_id,
            "checkpoint_digest": event.checkpoint_digest,
            "required_evidence": list(event.required_evidence),
            "visual_companion_html_sha256": "sha256:" + screen_sha256,
        },
    }
    request["request_digest"] = "sha256:" + hashlib.sha256(
        _canonical_json(request).encode("utf-8")
    ).hexdigest()
    return GovernanceDecisionPackage(
        request=request,
        screen_html=screen_html,
        screen_sha256=screen_sha256,
    )


def _render_visual_companion(
    event: Any,
    snapshot: DecisionRoleSnapshot,
    requested_at: str,
    expires_at: str,
) -> str:
    role_rows = "".join(
        "<tr><td>"
        + html.escape(role.role_id)
        + "</td><td>"
        + html.escape(role.email)
        + "</td><td>"
        + ("Required" if role.required else "Observer")
        + "</td></tr>"
        for role in snapshot.roles
    )
    evidence_items = "".join(
        "<li>" + html.escape(kind) + "</li>" for kind in event.required_evidence
    )
    return "\n".join(
        (
            "<!doctype html>",
            '<html lang="zh-CN">',
            '<head><meta charset="utf-8"><title>研发飞轮决策</title>',
            "<style>body{margin:0;background:#eef3f4;color:#102a32;font-family:'Segoe UI','Microsoft YaHei',sans-serif}"
            ".shell{max-width:920px;margin:36px auto;background:#fff;border:1px solid #c8d8da;border-radius:18px;overflow:hidden}"
            ".hero{padding:34px 42px;background:linear-gradient(120deg,#083d4b,#14766f);color:#fff}"
            ".body{padding:34px 42px}.notice{padding:18px;border-left:5px solid #e8a317;background:#fff7dd}"
            "table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #dce7e8;text-align:left}"
            ".meta{color:#547078}code{font-family:Consolas,monospace;word-break:break-all}</style></head>",
            '<body><main class="shell">',
            '<section class="hero"><div>Visual Companion</div><h1>研发飞轮治理决策</h1>',
            "<p>能力建设开始前的多角色确认</p></section>",
            '<section class="body">',
            '<div class="notice"><strong>权限边界：</strong>本页只证明治理与设计同意，'
            "不代表测试通过、发布授权、生产凭证或生产部署。</div>",
            "<h2>需要确认的能力缺口</h2>",
            "<p><strong>能力：</strong><code>"
            + html.escape(event.missing_capability)
            + "</code></p>",
            "<p><strong>来源：</strong>"
            + html.escape(event.originating_plugin)
            + " / "
            + html.escape(event.originating_event_id)
            + "</p>",
            "<p><strong>原始检查点：</strong><code>"
            + html.escape(event.checkpoint_digest)
            + "</code></p>",
            "<h2>生产完成证据</h2><ul>" + evidence_items + "</ul>",
            "<h2>冻结决策角色</h2><table><thead><tr><th>角色</th><th>邮箱</th><th>职责</th></tr></thead><tbody>"
            + role_rows
            + "</tbody></table>",
            '<p class="meta">请求时间：'
            + html.escape(requested_at)
            + "　有效期："
            + html.escape(expires_at)
            + "</p>",
            "</section></main></body></html>",
            "",
        )
    )


def _parse_timestamp(value: str, *, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise DecisionError(f"{field_name} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise DecisionError(f"{field_name} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DecisionError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_governance_decision_verification(
    request: Mapping[str, Any],
    verification: Mapping[str, Any],
) -> Mapping[str, Any]:
    if not isinstance(verification, Mapping) or verification.get("verified") is not True:
        raise DecisionError("governance decision receipt was not independently verified")
    if verification.get("verifier") != "release-approval-verifier":
        raise DecisionError("governance decision receipt used an unsupported verifier")
    receipt = verification.get("receipt")
    if not isinstance(receipt, Mapping):
        raise DecisionError("governance decision verification is missing its receipt")
    if receipt.get("contract") != "ApprovalVerificationReceipt/v1":
        raise DecisionError("governance decision receipt contract is unsupported")
    if receipt.get("authority_scope") != "RD_FLYWHEEL_GOVERNANCE":
        raise DecisionError("governance decision receipt authority_scope is invalid")
    if receipt.get("status") != "APPROVAL_VERIFIED":
        raise DecisionError("governance decision receipt is not fully approved")
    if not isinstance(receipt.get("receipt_hmac"), str) or not receipt["receipt_hmac"]:
        raise DecisionError("governance decision receipt has no verified HMAC evidence")

    binding_fields = (
        "event_id",
        "round_id",
        "manifest_s_digest",
        "manifest_r_digest",
        "manifest_digest",
        "request_digest",
        "role_snapshot_digest",
        "expires_at",
    )
    for field_name in binding_fields:
        if receipt.get(field_name) != request.get(field_name):
            raise DecisionError(
                f"governance decision receipt binding mismatch: {field_name}"
            )

    required_roles = request.get("required_roles")
    if (
        not isinstance(required_roles, list)
        or not required_roles
        or receipt.get("required_roles") != required_roles
    ):
        raise DecisionError("governance decision receipt required_roles drifted")
    role_bindings = request.get("required_role_bindings")
    if not isinstance(role_bindings, list):
        raise DecisionError("governance decision request has no frozen role bindings")
    expected_emails = {
        str(item.get("role_id")): str(item.get("email")).casefold()
        for item in role_bindings
        if isinstance(item, Mapping) and item.get("required") is True
    }
    if set(expected_emails) != set(required_roles):
        raise DecisionError("governance decision request role bindings are inconsistent")

    raw_decisions = receipt.get("current_decisions")
    if not isinstance(raw_decisions, list):
        raise DecisionError("governance decision receipt decisions must be a list")
    decisions_by_role: dict[str, list[Mapping[str, Any]]] = {}
    for item in raw_decisions:
        if not isinstance(item, Mapping):
            raise DecisionError("governance decision receipt contains a malformed decision")
        role_id = str(item.get("role_id") or "").strip()
        decisions_by_role.setdefault(role_id, []).append(item)
    for role_id in required_roles:
        decisions = decisions_by_role.get(role_id, [])
        if len(decisions) != 1:
            raise DecisionError(
                "governance decision receipt must contain one approval for all required role decisions"
            )
        decision = decisions[0]
        if str(decision.get("decision") or "").upper() != "APPROVE":
            raise DecisionError(
                "governance decision receipt must contain one approval for all required role decisions"
            )
        if str(decision.get("approver_email") or "").casefold() != expected_emails[role_id]:
            raise DecisionError(
                "governance decision receipt approver email differs from the frozen role"
            )
        for field_name in (
            "decision_id",
            "authentication_path",
            "source_message_id",
            "decided_at",
        ):
            if not isinstance(decision.get(field_name), str) or not decision[field_name].strip():
                raise DecisionError(
                    f"governance decision receipt decision is missing {field_name}"
                )

    normalized = dict(receipt)
    normalized["verification_digest"] = "sha256:" + hashlib.sha256(
        _canonical_json(receipt).encode("utf-8")
    ).hexdigest()
    return normalized
