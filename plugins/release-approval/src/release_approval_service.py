from __future__ import annotations

import base64
import hashlib
import json
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
        return (
            self.config.state_dir
            / "audit"
            / self._safe_path_component(request.event_id)
            / f"round-{request.round_id}"
            / f"role-{self._safe_path_component(request.installed_role_id)}"
        )

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
        decision_id = f"decision-{request.event_id}-{request.installed_role_id}"
        payload = {
            "contract": "ApprovalDecision/v1",
            "decision_id": decision_id,
            "request_event_id": request.event_id,
            "request_round_id": request.round_id,
            "task": request.task,
            "module": request.module,
            "manifest_digest": request.manifest_digest,
            "request_digest": request.request_digest,
            "role": request.installed_role_id,
            "approver_email": request.installed_role_email,
            "decision": decision,
            "comment": comment,
            "source": "LOCAL_PAGE",
            "original_message_id": request.original_message_id,
            "decided_at": timestamp,
            "page_html_sha256": page_html_sha256,
            "idempotency_key": f"approval-decision-{request.event_id}-{request.installed_role_id}",
        }
        self._decision_cache[cache_key] = dict(payload)
        return payload

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
            decided_at=decided_at,
            page_html_sha256=page_session.page_html_sha256,
            request_digest=request.request_digest,
            idempotency_key=str(decision_payload["idempotency_key"]),
        )
        decision_path = page_session.artifact_dir / "decision.json"
        decision_path.write_text(json.dumps(decision_payload, indent=2) + "\n", encoding="utf-8")
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
        return "\n".join(
            [
                "<!doctype html>",
                "<html>",
                "<head><meta charset=\"utf-8\"><title>Release approval</title></head>",
                "<body>",
                f"<h1>Release approval for {request.event_id}</h1>",
                f"<p>Role: {request.installed_role_id}</p>",
                f"<p>Task: {request.task}</p>",
                "<form method=\"post\">",
                f"<input type=\"hidden\" name=\"event_id\" value=\"{request.event_id}\">",
                f"<input type=\"hidden\" name=\"round_id\" value=\"{request.round_id}\">",
                f"<input type=\"hidden\" name=\"role_id\" value=\"{request.installed_role_id}\">",
                "<input type=\"hidden\" name=\"nonce\" value=\"__NONCE__\">",
                "<input type=\"hidden\" name=\"page_html_sha256\" value=\"__PAGE_HTML_SHA256__\">",
                "<label>Decision <input name=\"decision\"></label>",
                "<label>Comment <textarea name=\"comment\"></textarea></label>",
                "</form>",
                "</body>",
                "</html>",
                "",
            ]
        )

    def _write_sha256sums(self, artifact_dir: Path) -> None:
        lines: list[str] = []
        for path in sorted(artifact_dir.iterdir()):
            if path.name == "SHA256SUMS" or not path.is_file():
                continue
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()} *{path.name}")
        (artifact_dir / "SHA256SUMS").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    @staticmethod
    def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(dict(payload), separators=(",", ":")) + "\n")

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
        if not _SAFE_PATH_COMPONENT.fullmatch(value):
            raise ReleaseApprovalServiceError(f"safe path component required: {value}")
        return value

    @staticmethod
    def _is_message_id(value: str) -> bool:
        return bool(_MESSAGE_ID_PATTERN.fullmatch(value))

    def _random_token(self, size: int) -> str:
        return base64.urlsafe_b64encode(self.token_bytes(size)).rstrip(b"=").decode("ascii")
