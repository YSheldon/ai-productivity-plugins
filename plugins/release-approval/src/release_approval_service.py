from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from release_approval_config import ReleaseApprovalConfig
from release_approval_mail import MailCapabilityError, MailGateway, MailGatewayError, MailSendResult
from release_approval_protocol import ReleaseAuthorizationRequest, canonical_json
from release_approval_store import ReleaseApprovalStore


_SAFE_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9._-]+$")
_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_BEGIN_MARKER = "-----BEGIN APPROVAL DECISION-----"
_END_MARKER = "-----END APPROVAL DECISION-----"


class ReleaseApprovalServiceError(RuntimeError):
    """Raised when Task 5 service state cannot be produced safely."""


@dataclass(frozen=True)
class PageSession:
    artifact_dir: Path
    page_html_path: Path
    page_html_sha256: str
    page_state_path: Path
    browser_events_path: Path
    nonce: str
    nonce_sha256: str
    url_key: str
    created_at: str
    expires_at: str
    event_id: str
    round_id: int
    role_id: str


@dataclass(frozen=True)
class SubmissionResult:
    status: str
    response_text: str


class ReleaseApprovalService:
    def __init__(
        self,
        *,
        config: ReleaseApprovalConfig,
        store: ReleaseApprovalStore,
        mail_gateway: MailGateway | Any,
        now_fn: Callable[[], datetime] | None = None,
        token_bytes: Callable[[int], bytes] | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.mail_gateway = mail_gateway
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.token_bytes = token_bytes or secrets.token_bytes
        self._decision_cache: dict[tuple[str, int, str, str, str, str], dict[str, Any]] = {}

    def record_request(self, request: ReleaseAuthorizationRequest) -> None:
        self.store.record_request(request)

    def artifact_dir_for_request(self, request: ReleaseAuthorizationRequest) -> Path:
        audit_root = (self.config.state_dir / "audit").resolve(strict=False)
        event_component = self._safe_path_component(request.event_id)
        role_component = self._safe_path_component(request.installed_role_id)
        artifact_dir = (audit_root / event_component / f"round-{request.round_id}" / f"role-{role_component}").resolve(strict=False)
        try:
            artifact_dir.relative_to(audit_root)
        except ValueError as exc:
            raise ReleaseApprovalServiceError("safe path component required: final artifact path escaped audit root") from exc
        return artifact_dir

    def create_page_session(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        request_payload: Mapping[str, Any],
    ) -> PageSession:
        self.mail_gateway.require_thread_reply_capability(
            {
                "reply_subject": request_payload.get("reply_subject"),
                "original_message_id": request.original_message_id,
                "references": self._normalized_thread_references(request),
            }
        )
        artifact_dir = self.artifact_dir_for_request(request)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        created_at = self._isoformat(self.now_fn())
        nonce = self._random_token(32)
        url_key = self._random_token(32)
        persisted_html = self._render_page_html(request=request)
        page_html_path = artifact_dir / "page.html"
        page_html_path.write_text(persisted_html, encoding="utf-8")
        page_html_sha256 = self._sha256_prefixed(page_html_path.read_text(encoding="utf-8"))
        nonce_sha256 = self._sha256_prefixed(nonce)
        page_state_path = artifact_dir / "page-state.json"
        page_state_path.write_text(
            json.dumps(
                {
                    "event_id": request.event_id,
                    "round_id": request.round_id,
                    "role_id": request.installed_role_id,
                    "expires_at": request.expires_at,
                    "created_at": created_at,
                    "page_html_sha256": page_html_sha256,
                    "nonce_sha256": nonce_sha256,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        browser_events_path = artifact_dir / "browser-events.jsonl"
        self._append_jsonl(
            browser_events_path,
            {
                "event_type": "page_created",
                "recorded_at": created_at,
                "event_id": request.event_id,
                "round_id": request.round_id,
                "role_id": request.installed_role_id,
            },
        )
        self.store.record_page(
            event_id=request.event_id,
            round_id=request.round_id,
            role=request.installed_role_id,
            html_path=page_html_path,
            html_sha256=page_html_sha256,
            nonce_sha256=nonce_sha256,
            created_at=created_at,
        )
        self._write_sha256sums(artifact_dir)
        return PageSession(
            artifact_dir=artifact_dir,
            page_html_path=page_html_path,
            page_html_sha256=page_html_sha256,
            page_state_path=page_state_path,
            browser_events_path=browser_events_path,
            nonce=nonce,
            nonce_sha256=nonce_sha256,
            url_key=url_key,
            created_at=created_at,
            expires_at=request.expires_at,
            event_id=request.event_id,
            round_id=request.round_id,
            role_id=request.installed_role_id,
        )

    def build_decision_payload(
        self,
        request: ReleaseAuthorizationRequest,
        decision: str,
        comment: str,
        page_html_sha256: str,
        *,
        decided_at: str | None = None,
    ) -> dict[str, Any]:
        cache_key = (
            request.event_id,
            request.round_id,
            request.installed_role_id,
            decision,
            comment,
            page_html_sha256,
        )
        if decided_at is None and cache_key in self._decision_cache:
            return dict(self._decision_cache[cache_key])
        timestamp = decided_at or self._isoformat(self.now_fn())
        decision_id, idempotency_key = self._decision_identity(
            request=request,
            decision=decision,
            comment=comment,
            page_html_sha256=page_html_sha256,
        )
        payload = {
            "schema": "ApprovalDecision/v1",
            "decision_id": decision_id,
            "event_id": request.event_id,
            "round_id": request.round_id,
            "manifest_digest": request.manifest_digest,
            "role_snapshot_digest": request.role_snapshot_digest,
            "approver_email": request.installed_role_email,
            "decision": decision,
            "comment": comment,
            "source": "LOCAL_PAGE",
            "original_message_id": request.original_message_id,
            "page_html_sha256": page_html_sha256,
            "decided_at": timestamp,
            "idempotency_key": idempotency_key,
        }
        self._decision_cache[cache_key] = dict(payload)
        return payload

    def _decision_scope_payload(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        decision: str,
        comment: str,
        page_html_sha256: str,
    ) -> dict[str, Any]:
        return {
            "event_id": request.event_id,
            "round_id": request.round_id,
            "role_id": request.installed_role_id,
            "manifest_digest": request.manifest_digest,
            "role_snapshot_digest": request.role_snapshot_digest,
            "approver_email": request.installed_role_email,
            "decision": decision,
            "comment": comment,
            "source": "LOCAL_PAGE",
            "original_message_id": request.original_message_id,
            "page_html_sha256": page_html_sha256,
        }

    def _decision_identity(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        decision: str,
        comment: str,
        page_html_sha256: str,
    ) -> tuple[str, str]:
        decision_scope = self._decision_scope_payload(
            request=request,
            decision=decision,
            comment=comment,
            page_html_sha256=page_html_sha256,
        )
        stable_digest = self._decision_stable_digest(decision_scope)
        return (
            f"decision-{request.event_id}-round-{request.round_id}-{request.installed_role_id}-{stable_digest}",
            f"decision:{request.event_id}:{request.round_id}:{request.installed_role_id}:{stable_digest}",
        )

    @staticmethod
    def _decision_stable_digest(payload: Mapping[str, Any]) -> str:
        return hashlib.sha256(canonical_json(dict(payload)).encode("utf-8")).hexdigest()

    def _reusable_retry_decision_payload(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        decision: str,
        comment: str,
        page_html_sha256: str,
    ) -> dict[str, Any] | None:
        current = self.store.get_current_decision(request.event_id, request.round_id, request.installed_role_id)
        if current is None:
            return None
        decision_id, idempotency_key = self._decision_identity(
            request=request,
            decision=decision,
            comment=comment,
            page_html_sha256=page_html_sha256,
        )
        if current.idempotency_key != idempotency_key:
            return None
        expected_fields = {
            "decision_id": decision_id,
            "decision": decision,
            "approver_email": request.installed_role_email,
            "comment": comment,
            "source": "LOCAL_PAGE",
            "original_message_id": request.original_message_id,
            "page_html_sha256": page_html_sha256,
            "request_digest": request.request_digest,
        }
        mismatched = [
            key
            for key, value in expected_fields.items()
            if getattr(current, key) != value
        ]
        if mismatched:
            raise ReleaseApprovalServiceError("persisted retry decision state does not match the current request.")
        return {
            "schema": "ApprovalDecision/v1",
            "decision_id": current.decision_id,
            "event_id": request.event_id,
            "round_id": request.round_id,
            "manifest_digest": request.manifest_digest,
            "role_snapshot_digest": request.role_snapshot_digest,
            "approver_email": current.approver_email,
            "decision": current.decision,
            "comment": current.comment,
            "source": current.source,
            "original_message_id": current.original_message_id,
            "page_html_sha256": current.page_html_sha256,
            "decided_at": current.decided_at,
            "idempotency_key": current.idempotency_key,
        }

    def submit_local_decision(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        request_payload: Mapping[str, Any],
        page_session: PageSession,
        decision: str,
        comment: str,
        nonce: str,
        page_html_sha256: str,
    ) -> SubmissionResult:
        self._validate_page_submission(request=request, page_session=page_session, nonce=nonce, page_html_sha256=page_html_sha256)
        decision_payload = self._reusable_retry_decision_payload(
            request=request,
            decision=decision,
            comment=comment,
            page_html_sha256=page_session.page_html_sha256,
        )
        if decision_payload is None:
            decided_at = self._isoformat(self.now_fn())
            decision_payload = self.build_decision_payload(
                request,
                decision,
                comment,
                page_session.page_html_sha256,
                decided_at=decided_at,
            )
            self.store.record_decision(
                decision_id=str(decision_payload["decision_id"]),
                request_event_id=request.event_id,
                request_round_id=request.round_id,
                role=request.installed_role_id,
                approver_email=request.installed_role_email,
                decision=decision,
                comment=comment,
                source="LOCAL_PAGE",
                original_message_id=request.original_message_id,
                decided_at=str(decision_payload["decided_at"]),
                page_html_sha256=page_session.page_html_sha256,
                request_digest=request.request_digest,
                idempotency_key=str(decision_payload["idempotency_key"]),
            )
        decided_at = str(decision_payload["decided_at"])
        decision_path = page_session.artifact_dir / "decision.json"
        decision_path.write_text(json.dumps(decision_payload, indent=2) + "\n", encoding="utf-8")
        self._write_sha256sums(page_session.artifact_dir)
        self._append_jsonl(
            page_session.browser_events_path,
            {
                "event_type": "decision_submitted",
                "recorded_at": decided_at,
                "decision": decision,
            },
        )
        mail_arguments = self._build_mail_arguments(
            request=request,
            request_payload=request_payload,
            decision_payload=decision_payload,
        )
        smtp_result_path = page_session.artifact_dir / "smtp-result.json"
        try:
            send_result = self.mail_gateway.send_email(mail_arguments)
            smtp_result = self._smtp_result_payload(send_result=send_result, recorded_at=decided_at)
        except MailGatewayError as exc:
            smtp_result = {
                "status": "retry_queued",
                "recorded_at": decided_at,
                "message_id": "",
                "refused": {},
                "error": str(exc),
            }
            self.store.record_smtp_outcome(
                event_id=request.event_id,
                round_id=request.round_id,
                role=request.installed_role_id,
                smtp_message_id="",
                outcome="RETRY_QUEUED",
                detail=str(exc),
                recorded_at=decided_at,
            )
            smtp_result_path.write_text(json.dumps(smtp_result, indent=2) + "\n", encoding="utf-8")
            self._write_sha256sums(page_session.artifact_dir)
            return SubmissionResult(status="retry_queued", response_text="retry queued")

        smtp_result_path.write_text(json.dumps(smtp_result, indent=2) + "\n", encoding="utf-8")
        self.store.record_smtp_outcome(
            event_id=request.event_id,
            round_id=request.round_id,
            role=request.installed_role_id,
            smtp_message_id=str(smtp_result["message_id"]),
            outcome="SENT" if smtp_result["status"] == "sent" else "RETRY_QUEUED",
            detail=canonical_json(smtp_result),
            recorded_at=decided_at,
        )
        self._write_sha256sums(page_session.artifact_dir)
        return SubmissionResult(status=str(smtp_result["status"]), response_text="sent" if smtp_result["status"] == "sent" else "retry queued")

    def _build_mail_arguments(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        request_payload: Mapping[str, Any],
        decision_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        reply_subject = str(request_payload.get("reply_subject") or "").strip()
        normalized_references = self._normalized_thread_references(request)
        self.mail_gateway.require_thread_reply_capability(
            {
                "reply_subject": reply_subject,
                "original_message_id": request.original_message_id,
                "references": normalized_references,
            }
        )
        return {
            "account": self.config.mail_account.profile,
            "to": [self.config.release_group],
            "subject": reply_subject,
            "text": self._build_reply_text(decision_payload),
            "dry_run": False,
            "in_reply_to": request.original_message_id,
            "references": normalized_references,
            "headers": {
                "X-RD-Decision-Schema": "ApprovalDecision/v1",
                "X-RD-Event-Id": request.event_id,
                "X-RD-Round-Id": str(request.round_id),
                "X-RD-Manifest-Digest": request.manifest_digest,
                "X-RD-Role-Snapshot-Digest": request.role_snapshot_digest,
            },
        }

    def _build_reply_text(self, decision_payload: Mapping[str, Any]) -> str:
        encoded = base64.urlsafe_b64encode(canonical_json(dict(decision_payload)).encode("utf-8")).decode("ascii").rstrip("=")
        comment = str(decision_payload.get("comment") or "").strip()
        decision = str(decision_payload.get("decision") or "").strip()
        return "\n".join(
            [
                f"Decision: {decision}",
                comment,
                "",
                _BEGIN_MARKER,
                encoded,
                _END_MARKER,
                "",
            ]
        )

    def _normalized_thread_references(self, request: ReleaseAuthorizationRequest) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()
        for message_id in request.references:
            if not self._is_message_id(message_id) or message_id in seen:
                continue
            seen.add(message_id)
            ordered.append(message_id)
        if request.original_message_id not in seen:
            ordered.append(request.original_message_id)
        return ordered

    @staticmethod
    def _smtp_result_payload(*, send_result: MailSendResult, recorded_at: str) -> dict[str, Any]:
        status = "sent" if send_result.sent and not send_result.refused else "retry_queued"
        return {
            "status": status,
            "recorded_at": recorded_at,
            "message_id": send_result.message_id,
            "refused": send_result.refused,
        }

    def _validate_page_submission(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        page_session: PageSession,
        nonce: str,
        page_html_sha256: str,
    ) -> None:
        if request.event_id != page_session.event_id or request.round_id != page_session.round_id or request.installed_role_id != page_session.role_id:
            raise ReleaseApprovalServiceError("page session binding mismatch.")
        if self._sha256_prefixed(nonce) != page_session.nonce_sha256:
            raise ReleaseApprovalServiceError("page session nonce mismatch.")
        if page_html_sha256 != page_session.page_html_sha256:
            raise ReleaseApprovalServiceError("page session HTML binding mismatch.")
        if self._parse_timestamp(request.expires_at) <= self.now_fn().astimezone(timezone.utc):
            raise ReleaseApprovalServiceError("page session is expired.")

    def _render_page_html(self, *, request: ReleaseAuthorizationRequest) -> str:
        governance = request.authority_scope == "RD_FLYWHEEL_GOVERNANCE"
        title = "研发飞轮治理决策" if governance else "生产发布审批"
        boundary = (
            "本次确认仅授权治理设计与能力建设，不代表测试通过、发布授权、生产凭证或生产部署。"
            if governance
            else "本页只采集角色审批证据；最终发布授权必须由独立验证器和产品发布门禁共同签发。"
        )
        context = request.governance_context
        if governance and context is None:
            raise ReleaseApprovalServiceError(
                "governance confirmation page requires a frozen governance context."
            )
        context_html: list[str] = []
        if context is not None:
            evidence_items = "".join(
                f"<li><span>{index:02d}</span>{html.escape(kind)}</li>"
                for index, kind in enumerate(context.required_evidence, start=1)
            )
            context_html = [
                '<section class="panel visual-companion">',
                '<div class="eyebrow">VISUAL COMPANION</div>',
                "<h2>需要确认的能力建设边界</h2>",
                '<div class="facts">',
                '<div class="fact primary"><small>能力缺口</small><strong>'
                + html.escape(context.missing_capability)
                + "</strong></div>",
                '<div class="fact"><small>来源插件</small><strong>'
                + html.escape(context.originating_plugin)
                + "</strong></div>",
                '<div class="fact"><small>来源事件</small><code>'
                + html.escape(context.originating_event_id)
                + "</code></div>",
                '<div class="fact"><small>权限边界</small><strong>'
                + html.escape(context.authority_boundary)
                + "</strong></div>",
                "</div>",
                "<h3>完成后必须提供的生产证据</h3>",
                f'<ol class="evidence">{evidence_items}</ol>',
                '<div class="digest-grid">',
                '<div><small>原始检查点 SHA-256</small><code>'
                + html.escape(context.checkpoint_digest)
                + "</code></div>",
                '<div><small>Visual Companion SHA-256</small><code>'
                + html.escape(context.visual_companion_html_sha256)
                + "</code></div>",
                "</div>",
                "</section>",
            ]
        required_roles = " · ".join(html.escape(role) for role in request.required_roles)
        return "\n".join(
            [
                "<!doctype html>",
                '<html lang="zh-CN">',
                f'<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>',
                "<style>"
                ":root{--ink:#102b35;--muted:#577078;--teal:#0b6b69;--mint:#dcefee;--line:#c9dcdd;--amber:#d48b13;--paper:#f3f7f6}"
                "*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 5%,#d5ebe8 0,transparent 32%),var(--paper);color:var(--ink);font-family:'Segoe UI','Microsoft YaHei',sans-serif}"
                ".shell{width:min(980px,calc(100% - 32px));margin:32px auto 64px}.hero{position:relative;overflow:hidden;padding:40px 44px;border-radius:24px 24px 0 0;background:linear-gradient(125deg,#073844,#0b6b69 70%,#17867c);color:#fff}"
                ".hero:after{content:'';position:absolute;width:260px;height:260px;right:-65px;top:-110px;border:42px solid rgba(255,255,255,.09);border-radius:50%}.kicker,.eyebrow{font-size:12px;font-weight:800;letter-spacing:.16em}.hero h1{margin:10px 0 8px;font-size:34px}.hero p{margin:0;opacity:.85}.scope{display:inline-block;margin-top:20px;padding:8px 12px;border:1px solid rgba(255,255,255,.45);border-radius:999px;font:700 12px Consolas,monospace}"
                ".content{padding:28px;background:#fff;border:1px solid var(--line);border-top:0;border-radius:0 0 24px 24px;box-shadow:0 18px 55px rgba(20,57,64,.12)}"
                ".boundary{padding:16px 18px;border-left:5px solid var(--amber);background:#fff7e4;border-radius:8px;font-weight:700}.panel{margin-top:22px;padding:24px;border:1px solid var(--line);border-radius:16px;background:#fff}.visual-companion{background:linear-gradient(180deg,#f7fbfa,#fff)}"
                ".eyebrow{color:var(--teal)}h2{margin:7px 0 18px;font-size:23px}h3{margin:24px 0 10px}.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.fact{min-height:82px;padding:14px;background:#edf6f5;border-radius:12px}.fact.primary{grid-column:1/-1;background:var(--mint)}small{display:block;margin-bottom:7px;color:var(--muted);font-size:12px}strong,code{overflow-wrap:anywhere}code{font-family:Consolas,monospace;font-size:12px}"
                ".evidence{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;padding:0;list-style:none}.evidence li{display:flex;gap:9px;align-items:center;padding:10px 12px;border:1px solid #d8e5e5;border-radius:10px}.evidence span{color:var(--teal);font:700 11px Consolas,monospace}.digest-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:18px}.digest-grid>div{padding:12px;border-top:2px solid var(--teal);background:#f5f8f8}"
                ".meta-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.meta-grid div{padding:10px 0;border-bottom:1px solid #e5eeee}.decision-set{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:16px 0}.choice{display:block;padding:14px;border:1px solid var(--line);border-radius:12px;font-weight:700;cursor:pointer}.choice:has(input:checked){border-color:var(--teal);background:var(--mint)}textarea{width:100%;min-height:92px;padding:12px;border:1px solid var(--line);border-radius:10px;font:inherit}button{margin-top:14px;padding:12px 22px;border:0;border-radius:10px;background:var(--teal);color:#fff;font-weight:800;cursor:pointer}.audit{margin-top:16px;color:var(--muted);font-size:12px}"
                "@media(max-width:680px){.hero{padding:30px 24px}.hero h1{font-size:27px}.content{padding:18px}.facts,.evidence,.digest-grid,.meta-grid,.decision-set{grid-template-columns:1fr}.fact.primary{grid-column:auto}}"
                "</style></head>",
                '<body><main class="shell">',
                '<header class="hero"><div class="kicker">AUDITED DECISION PAGE</div>',
                f"<h1>{html.escape(title)}</h1>",
                f"<p>{html.escape(request.task)} · {html.escape(request.module)}</p>",
                f'<div class="scope">{html.escape(request.authority_scope)}</div></header>',
                '<div class="content">',
                f'<div class="boundary">{html.escape(boundary)}</div>',
                *context_html,
                '<section class="panel"><div class="eyebrow">FROZEN REQUEST</div><h2>本角色的冻结决策信息</h2><div class="meta-grid">',
                f'<div><small>事件</small><code>{html.escape(request.event_id)}</code></div>',
                f'<div><small>轮次</small><strong>{request.round_id}</strong></div>',
                f'<div><small>当前角色</small><strong>{html.escape(request.installed_role_id)}</strong></div>',
                f'<div><small>角色邮箱</small><strong>{html.escape(request.installed_role_email)}</strong></div>',
                f'<div><small>全部必审角色</small><strong>{required_roles}</strong></div>',
                f'<div><small>到期时间</small><code>{html.escape(request.expires_at)}</code></div>',
                f'<div><small>请求摘要</small><code>{html.escape(request.request_digest)}</code></div>',
                f'<div><small>角色快照摘要</small><code>{html.escape(request.role_snapshot_digest)}</code></div>',
                "</div></section>",
                '<section class="panel"><div class="eyebrow">YOUR DECISION</div><h2>请选择处理意见</h2>',
                '<form method="post">',
                f"<input type=\"hidden\" name=\"event_id\" value=\"{html.escape(request.event_id, quote=True)}\">",
                f"<input type=\"hidden\" name=\"round_id\" value=\"{request.round_id}\">",
                f"<input type=\"hidden\" name=\"role_id\" value=\"{html.escape(request.installed_role_id, quote=True)}\">",
                "<input type=\"hidden\" name=\"nonce\" value=\"__NONCE__\">",
                "<input type=\"hidden\" name=\"page_html_sha256\" value=\"__PAGE_HTML_SHA256__\">",
                '<div class="decision-set">',
                '<label class="choice"><input type="radio" name="decision" value="APPROVE" required> 同意 / APPROVE</label>',
                '<label class="choice"><input type="radio" name="decision" value="HOLD"> 待定 / HOLD</label>',
                '<label class="choice"><input type="radio" name="decision" value="REJECT"> 驳回 / REJECT</label>',
                "</div>",
                '<label><small>审批意见</small><textarea name="comment" maxlength="4000" placeholder="说明通过依据、待补证据或驳回原因"></textarea></label>',
                '<button type="submit">提交并邮件回执</button>',
                "</form></section>",
                '<p class="audit">本页、角色快照、请求机器块、审批结果和邮件回执均通过 SHA-256 与审计链绑定。</p>',
                "</div></main></body>",
                "</html>",
                "",
            ]
        )

    def _write_sha256sums(self, artifact_dir: Path) -> None:
        lines: list[str] = []
        for path in sorted(artifact_dir.iterdir()):
            if not path.is_file() or path.name in {"SHA256SUMS", "SHA256SUMS.tmp"}:
                continue
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()} *{path.name}")
        sums_path = artifact_dir / "SHA256SUMS"
        tmp_path = artifact_dir / "SHA256SUMS.tmp"
        tmp_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        tmp_path.replace(sums_path)

    def _append_jsonl(self, path: Path, payload: Mapping[str, Any]) -> None:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(dict(payload), separators=(",", ":")) + "\n")
        self._write_sha256sums(path.parent)

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)

    @staticmethod
    def _isoformat(value: datetime) -> str:
        return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _sha256_prefixed(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_path_component(value: str) -> str:
        if not isinstance(value, str) or not value or value in {".", ".."}:
            raise ReleaseApprovalServiceError(f"safe path component required: {value}")
        if not _SAFE_PATH_COMPONENT.fullmatch(value):
            raise ReleaseApprovalServiceError(f"safe path component required: {value}")
        normalized = value.rstrip(" .")
        if not normalized:
            raise ReleaseApprovalServiceError(f"safe path component required: {value}")
        if os.name == "nt":
            device_root = normalized.split(".", 1)[0].upper()
            if device_root in _WINDOWS_RESERVED_NAMES:
                raise ReleaseApprovalServiceError(f"reserved path component is not allowed: {value}")
        return value

    @staticmethod
    def _is_message_id(value: str) -> bool:
        return bool(_MESSAGE_ID_PATTERN.fullmatch(value))

    def _random_token(self, size: int) -> str:
        return base64.urlsafe_b64encode(self.token_bytes(size)).rstrip(b"=").decode("ascii")
