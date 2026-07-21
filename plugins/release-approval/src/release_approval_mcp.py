from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import traceback
import uuid
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

_SOURCE_ROOT = Path(__file__).resolve().parent
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from lark_audit import AuditRecord, LarkAuditAdapter
from release_approval_config import default_config_path, load_config, reject_per_call_config_override
from release_approval_lock import RunOnceLock
from release_approval_mail import MailCapabilityError, MailGateway, MailGatewayError
from release_approval_page import DecisionPageBinding, ReleaseApprovalPage
from release_approval_protocol import (
    ProtocolError,
    ReleaseAuthorizationRequest,
    canonical_json,
    validate_release_request,
)
from release_approval_scheduler import SchedulerError
from release_approval_service import PageSession, ReleaseApprovalService
from release_approval_setup import SetupError, run_setup_operation
from release_approval_store import AuditTamperError, ReleaseApprovalStore, StoreError

_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile

SERVER_NAME = "release-approval"
SERVER_VERSION = "0.2.4"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
_REQUEST_BEGIN_MARKER = "-----BEGIN RELEASE APPROVAL REQUEST-----"
_REQUEST_END_MARKER = "-----END RELEASE APPROVAL REQUEST-----"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReleaseApprovalMcpError(RuntimeError):
    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


@dataclass(frozen=True)
class CachedRequestContext:
    request: ReleaseAuthorizationRequest
    request_payload: dict[str, Any]
    reply_subject: str
    page_session: PageSession | None



def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


class ReleaseApprovalController:
    def __init__(
        self,
        *,
        config,
        config_path: str | Path | None = None,
        store: ReleaseApprovalStore | None = None,
        mail_gateway: MailGateway | Any | None = None,
        service: ReleaseApprovalService | None = None,
        bootstrap_runner: Callable[..., Mapping[str, Any]] = bootstrap_profile,
        scheduler: Any | None = None,
        browser_opener: Callable[[str], Any] | None = None,
        now_fn: Callable[[], datetime] | None = None,
        lark_audit_adapter: Any | None = None,
    ) -> None:
        self.config = config
        self.config_path = (
            None
            if config_path is None
            else Path(config_path).expanduser().resolve(strict=False)
        )
        self.store = store or ReleaseApprovalStore(self.config.state_dir / "state.sqlite3")
        self.mail_gateway = mail_gateway or MailGateway(self.config.dependency_lock)
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.service = service or ReleaseApprovalService(
            config=self.config,
            store=self.store,
            mail_gateway=self.mail_gateway,
            now_fn=self.now_fn,
        )
        self.bootstrap_runner = bootstrap_runner
        self.scheduler = scheduler
        self.browser_opener = browser_opener or webbrowser.open
        document_url = getattr(self.config.audit, "document_url", None)
        self.lark_audit_adapter = lark_audit_adapter or (
            LarkAuditAdapter(document_url, required=False) if document_url else None
        )
        self._contexts: dict[tuple[str, int, str], CachedRequestContext] = {}
        self._live_pages: dict[tuple[str, int, str], ReleaseApprovalPage] = {}
        self._setup_state_path = self.config.state_dir / "setup" / "runtime-setup.json"

    def preflight(self) -> dict[str, Any]:
        account = self._validate_configured_account()
        return {
            "status": "ready" if account["matched"] else "CAPABILITY_BLOCKED",
            "config": {
                "role_id": self.config.role_id,
                "role_email": self.config.role_email,
                "mail_account_profile": self.config.mail_account.profile,
                "mailbox": self.config.mailbox,
                "release_group": self.config.release_group,
                "allowed_request_senders": list(
                    self.config.request_authentication.allowed_sender_emails
                ),
                "request_authentication_paths": list(
                    self.config.request_authentication.accepted_paths
                ),
                "poll_minutes": self.config.poll_minutes,
                "page_host": self.config.page.host,
                "page_port": self.config.page.port,
                "state_dir": str(self.config.state_dir),
                "dependency_lock": str(self.config.dependency_lock),
            },
            "account_validation": account,
            "cloud_audit": {
                "configured": self.lark_audit_adapter is not None,
                "required": False,
                "status": "ready" if self.lark_audit_adapter is not None else "optional_not_configured",
            },
        }

    def start_setup(self) -> dict[str, Any]:
        bootstrap = dict(
            self.bootstrap_runner("release-approval", repo_root=_PLUGIN_ROOT.parents[1])
        )
        result: dict[str, Any] = {
            "recorded_at": self._isoformat(self.now_fn()),
            "dependency_lock": str(bootstrap.get("dependency_lock") or self.config.dependency_lock),
            "bootstrap": bootstrap,
        }
        if bootstrap.get("fresh_task_required") is True:
            result["status"] = "FRESH_TASK_REQUIRED"
            self._write_setup_record(result)
            return result
        account = self._validate_configured_account(require_match=True)
        scheduler = self._scheduler_adapter()
        schedule = scheduler.install(mode="auto")
        first_run = self.run_once()
        schedule_status = scheduler.status(mode="auto")
        result.update(
            {
                "status": "ready",
                "configured_account_email": account["discovered_email"],
                "scheduler": schedule,
                "first_run": first_run,
                "scheduler_status": schedule_status,
            }
        )
        self._write_setup_record(result)
        self.store.append_audit_event(
            "setup_completed",
            {
                "scheduler_mode": schedule["mode"],
                "dependency_lock": result["dependency_lock"],
                "codex_required": False,
            },
            created_at=self._isoformat(self.now_fn()),
        )
        return result
    def run_once(self) -> dict[str, Any]:
        run_lock = RunOnceLock(
            self.config.state_dir / "run-once.lock",
            owner=f"{os.getpid()}-{uuid.uuid4().hex}",
            now_fn=self.now_fn,
        )
        lock_result = run_lock.acquire()
        if lock_result["status"] != "acquired":
            return {"status": "RUN_ALREADY_ACTIVE", "busy": True}
        try:
            recovered_owner = lock_result.get("recovered_owner")
            if recovered_owner:
                self.store.append_audit_event(
                    "run_lock_orphan_recovered",
                    {
                        "recovered_owner": recovered_owner,
                        "current_owner": run_lock.owner,
                    },
                    created_at=self._isoformat(self.now_fn()),
                )
            return self._run_once_locked()
        finally:
            run_lock.release()

    def _run_once_locked(self) -> dict[str, Any]:
        search = self.mail_gateway.search_messages(
            {
                "account": self.config.mail_account.profile,
                "mailbox": self.config.mailbox,
                "query": {
                    "subject": "【发布申请】",
                    "since": (self.now_fn().astimezone(timezone.utc) - timedelta(days=7)).date().isoformat(),
                },
                "limit": 25,
                "scan_limit": 200,
            }
        )
        events: list[dict[str, Any]] = []
        created_pages = 0
        reused_pages = 0
        opened_pages = 0
        retried = 0
        blocked = 0
        summaries = list(search.get("messages") or [])
        for summary in summaries:
            uid = str(summary.get("uid") or "").strip()
            if not uid:
                continue
            message = self.mail_gateway.read_message(
                {"account": self.config.mail_account.profile, "mailbox": self.config.mailbox, "uid": uid}
            )
            try:
                request_payload = self._extract_request_machine_block(
                    str(message.get("body_text") or "")
                )
                request = validate_release_request(
                    request_payload,
                    installed_role_id=self.config.role_id,
                    installed_role_email=self.config.role_email,
                    now=self.now_fn(),
                )
            except (ReleaseApprovalMcpError, ProtocolError) as exc:
                payload = self._rejected_message_payload(
                    message,
                    self._quarantined_request_payload(message, exc),
                )
                if self._has_rejected_message_audit("request_quarantined", payload):
                    continue
                blocked += 1
                self._append_rejected_message_audit(
                    "request_quarantined",
                    payload,
                )
                events.append({**payload, "status": "QUARANTINED"})
                continue
            reply_subject = self._reply_subject(str(message.get("subject") or ""))
            key = (request.event_id, request.round_id, request.installed_role_id)
            if not self._has_authenticated_request_evidence(message, request):
                payload = self._blocked_event_payload(
                    request,
                    message_id=str(message.get("message_id") or ""),
                    reason="request source authentication failed",
                )
                payload = self._rejected_message_payload(message, payload)
                if self._has_rejected_message_audit("capability_blocked", payload):
                    continue
                blocked += 1
                self._append_rejected_message_audit(
                    "capability_blocked",
                    payload,
                )
                events.append({**payload, "status": "CAPABILITY_BLOCKED"})
                continue
            is_new_message = self._record_message_checkpoint(message)
            self._record_request_checkpoint(request)
            self._record_authenticated_request_checkpoint(request, message)
            cloud_audit = None
            if is_new_message:
                cloud_audit = self._write_cloud_audit(
                    request=request,
                    event_type="REQUEST_CREATED",
                    state="PENDING",
                    audit_payload={
                        "status": "PENDING",
                        "role_id": request.installed_role_id,
                        "uid": int(str(message.get("uid") or "0") or "0"),
                        "uidvalidity": int(str(message.get("uidvalidity") or "0") or "0"),
                    },
                )
            context = self._contexts.get(key)
            if context is None:
                self._contexts[key] = CachedRequestContext(
                    request,
                    {"reply_subject": reply_subject},
                    reply_subject,
                    None,
                )
            if is_new_message:
                status = "pending"
            else:
                reused_pages += 1
                status = "reused"
            retry_result = self._retry_unsent_decision(key, request, {"reply_subject": reply_subject})
            if retry_result is not None:
                retried += 1
            page_row = self._get_page_row(*key)
            events.append(
                {
                    "status": status,
                    "event_id": request.event_id,
                    "round_id": request.round_id,
                    "role_id": request.installed_role_id,
                    "message_id": str(message.get("message_id") or ""),
                    "uid": str(message.get("uid") or ""),
                    "uidvalidity": str(message.get("uidvalidity") or ""),
                    "page_html_path": None if page_row is None else page_row["html_path"],
                    "retry": retry_result,
                    "cloud_audit": cloud_audit,
                }
            )
        return {
            "status": "CAPABILITY_BLOCKED" if blocked else "ready",
            "scanned_messages": len(summaries),
            "matched_events": len(events),
            "created_pages": created_pages,
            "reused_pages": reused_pages,
            "opened_pages": opened_pages,
            "retried_decisions": retried,
            "events": events,
        }

    def status(self) -> dict[str, Any]:
        pending = self.list_pending()
        scheduler_status = self._scheduler_adapter().status(mode="auto")
        ready = (
            scheduler_status.get("status") == "ready"
            and scheduler_status.get("installed") is True
        )
        return {
            "status": "ready" if ready else "CAPABILITY_BLOCKED",
            "pending_count": len(pending["pending"]),
            "scheduler": scheduler_status,
            "state_db": str(self.store.path),
            "config_path": None if self.config_path is None else str(self.config_path),
            "codex_required": False,
        }

    def doctor(self) -> dict[str, Any]:
        preflight = self.preflight()
        runtime = self.status()
        audit_verified = False
        audit_error = ""
        try:
            self.store.verify_audit_chain()
            audit_verified = True
        except AuditTamperError as exc:
            audit_error = str(exc)
        ready = (
            preflight.get("status") == "ready"
            and runtime.get("status") == "ready"
            and audit_verified
        )
        return {
            "status": "ready" if ready else "CAPABILITY_BLOCKED",
            "codex_required": False,
            "checks": {
                "config_and_mail": preflight,
                "runtime": runtime,
                "audit_chain": {
                    "verified": audit_verified,
                    "error": audit_error,
                },
                "headless_run_once": True,
                "scheduler_command": "standalone CLI run-once",
            },
        }

    def list_pending(self) -> dict[str, Any]:
        rows = self.store.connection.execute(
            "SELECT event_id, round_id, role, expires_at FROM requests ORDER BY event_id, round_id, role"
        ).fetchall()
        pending: list[dict[str, Any]] = []
        for row in rows:
            key = (str(row["event_id"]), int(row["round_id"]), str(row["role"]))
            decision = self.store.get_current_decision(*key)
            smtp = self._get_latest_smtp_outcome(*key)
            status = "PENDING"
            if decision is not None and (smtp is None or smtp["outcome"] != "SENT"):
                status = "RETRY_QUEUED"
            elif decision is not None:
                continue
            page_row = self._get_page_row(*key)
            live_page = self._live_pages.get(key)
            pending.append(
                {
                    "event_id": key[0],
                    "round_id": key[1],
                    "role_id": key[2],
                    "expires_at": str(row["expires_at"]),
                    "status": status,
                    "page_html_path": None if page_row is None else page_row["html_path"],
                    "page_url": None if live_page is None else live_page.url,
                }
            )
        return {"status": "ready", "pending": pending}

    def open_page(self, *, event_id: str, round_id: int, role_id: str | None = None) -> dict[str, Any]:
        key = (event_id, round_id, role_id or self.config.role_id)
        self._rotate_page_session(key)
        page = self._ensure_live_page(key, True)
        page_row = self._get_page_row(*key)
        return {
            "status": "ready",
            "event_id": key[0],
            "round_id": key[1],
            "role_id": key[2],
            "page_url": page.url,
            "page_html_path": None if page_row is None else page_row["html_path"],
        }

    def get_event(self, *, event_id: str, round_id: int, role_id: str | None = None) -> dict[str, Any]:
        key = (event_id, round_id, role_id or self.config.role_id)
        request = self._get_request_row(*key)
        if request is None:
            raise ReleaseApprovalMcpError("EVENT_NOT_FOUND", "event checkpoint was not found.", details={"event_id": event_id, "round_id": round_id, "role_id": key[2]})
        page_row = self._get_page_row(*key)
        decision = self.store.get_current_decision(*key)
        smtp = self._get_latest_smtp_outcome(*key)
        live_page = self._live_pages.get(key)
        return {
            "status": "ready",
            "event": {
                "event_id": key[0],
                "round_id": key[1],
                "role_id": key[2],
                "request_digest": request["request_digest"],
                "manifest_digest": request["manifest_digest"],
                "role_snapshot_digest": request["role_snapshot_digest"],
                "original_message_id": request["original_message_id"],
                "expires_at": request["expires_at"],
                "page_html_path": None if page_row is None else page_row["html_path"],
                "page_url": None if live_page is None else live_page.url,
                "current_decision": None if decision is None else {"decision_id": decision.decision_id, "decision": decision.decision, "comment": decision.comment, "decided_at": decision.decided_at, "idempotency_key": decision.idempotency_key},
                "latest_smtp_outcome": None if smtp is None else {"outcome": smtp["outcome"], "smtp_message_id": smtp["smtp_message_id"], "recorded_at": smtp["recorded_at"]},
            },
        }

    def verify_audit_chain(self) -> dict[str, Any]:
        self.store.verify_audit_chain()
        return {"status": "ready", "verified": True, "state_db": str(self.store.path)}
    def _record_message_checkpoint(self, message: Mapping[str, Any]) -> bool:
        try:
            self.store.record_message(
                account=self.config.mail_account.profile,
                mailbox=self.config.mailbox,
                uidvalidity=int(str(message.get("uidvalidity") or "0") or "0"),
                uid=int(str(message.get("uid") or "0") or "0"),
                message_id=str(message.get("message_id") or ""),
            )
            return True
        except StoreError as exc:
            if "duplicate UID" not in str(exc) and "duplicate Message-ID" not in str(exc):
                raise
            return False

    def _record_request_checkpoint(self, request: ReleaseAuthorizationRequest) -> None:
        try:
            self.service.record_request(request)
        except StoreError as exc:
            if "already exists" not in str(exc) and "idempotency key" not in str(exc):
                raise

    def _record_authenticated_request_checkpoint(
        self,
        request: ReleaseAuthorizationRequest,
        message: Mapping[str, Any],
    ) -> None:
        key = (request.event_id, request.round_id, request.installed_role_id)
        if self._has_authenticated_request_checkpoint(key):
            return
        evidence = message.get("evidence")
        if not isinstance(evidence, Mapping):
            raise ReleaseApprovalMcpError(
                "CAPABILITY_BLOCKED",
                "authenticated request evidence is unavailable.",
            )
        authentication_path = self._authenticated_request_path(message)
        sender_email = self._request_sender_email(message)
        if authentication_path is None or sender_email is None:
            raise ReleaseApprovalMcpError(
                "CAPABILITY_BLOCKED",
                "authenticated request source evidence is unavailable.",
            )
        self.store.append_audit_event(
            "request_authenticated",
            {
                "event_id": request.event_id,
                "round_id": request.round_id,
                "role_id": request.installed_role_id,
                "message_id": str(message.get("message_id") or ""),
                "raw_headers_sha256": str(evidence.get("raw_headers_sha256") or ""),
                "sender_email": sender_email,
                "return_path": str(evidence.get("return_path") or "").lower(),
                "authentication_path": authentication_path,
            },
            created_at=self._isoformat(self.now_fn()),
        )

    def _has_authenticated_request_checkpoint(
        self,
        key: tuple[str, int, str],
    ) -> bool:
        rows = self.store.connection.execute(
            """
            SELECT payload_json
            FROM audit_events
            WHERE event_type = 'request_authenticated'
            ORDER BY id ASC
            """
        ).fetchall()
        for row in rows:
            try:
                payload = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError:
                continue
            if (
                payload.get("event_id") == key[0]
                and payload.get("round_id") == key[1]
                and payload.get("role_id") == key[2]
                and _SHA256_RE.fullmatch(
                    str(payload.get("raw_headers_sha256") or "")
                )
            ):
                return True
        return False

    def _retry_unsent_decision(self, key: tuple[str, int, str], request: ReleaseAuthorizationRequest, request_payload: Mapping[str, Any]) -> dict[str, Any] | None:
        decision = self.store.get_current_decision(*key)
        if decision is None:
            return None
        smtp = self._get_latest_smtp_outcome(*key)
        if smtp is not None and smtp["outcome"] == "SENT":
            return None
        decision_payload = {
            "schema": "ApprovalDecision/v1",
            "decision_id": decision.decision_id,
            "event_id": request.event_id,
            "round_id": request.round_id,
            "manifest_digest": request.manifest_digest,
            "role_snapshot_digest": request.role_snapshot_digest,
            "approver_email": decision.approver_email,
            "decision": decision.decision,
            "comment": decision.comment,
            "source": decision.source,
            "original_message_id": decision.original_message_id,
            "page_html_sha256": decision.page_html_sha256,
            "decided_at": decision.decided_at,
            "idempotency_key": decision.idempotency_key,
        }
        mail_arguments = self.service._build_mail_arguments(request=request, request_payload=request_payload, decision_payload=decision_payload)  # noqa: SLF001
        recorded_at = self._isoformat(self.now_fn())
        try:
            send_result = self.mail_gateway.send_email(mail_arguments)
            smtp_payload = self.service._smtp_result_payload(send_result=send_result, recorded_at=recorded_at)  # noqa: SLF001
        except MailGatewayError as exc:
            self.store.record_smtp_outcome(
                event_id=request.event_id,
                round_id=request.round_id,
                role=request.installed_role_id,
                smtp_message_id="",
                outcome="RETRY_QUEUED",
                detail=str(exc),
                recorded_at=recorded_at,
            )
            return {"status": "retry_queued", "error": str(exc)}
        self.store.record_smtp_outcome(
            event_id=request.event_id,
            round_id=request.round_id,
            role=request.installed_role_id,
            smtp_message_id=str(smtp_payload["message_id"]),
            outcome="SENT" if smtp_payload["status"] == "sent" else "RETRY_QUEUED",
            detail=canonical_json(smtp_payload),
            recorded_at=recorded_at,
        )
        return {"status": str(smtp_payload["status"]), "message_id": str(smtp_payload["message_id"])}

    def _submit_page_decision(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        request_payload: Mapping[str, Any],
        page_session: PageSession,
        form: Mapping[str, str],
    ):
        result = self.service.submit_local_decision(
            request=request,
            request_payload=request_payload,
            page_session=page_session,
            decision=form["decision"],
            comment=form["comment"],
            nonce=form["nonce"],
            page_html_sha256=form["page_html_sha256"],
        )
        self._write_cloud_audit(
            request=request,
            event_type="PAGE_DECISION",
            state=form["decision"].upper(),
            audit_payload={
                "decision_code": form["decision"].upper(),
                "role_id": request.installed_role_id,
                "status": result.status,
            },
        )
        return result

    def _write_cloud_audit(
        self,
        *,
        request: ReleaseAuthorizationRequest,
        event_type: str,
        state: str,
        audit_payload: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if self.lark_audit_adapter is None:
            return None
        result = self.lark_audit_adapter.write(
            AuditRecord(
                event_id=request.event_id,
                round_id=str(request.round_id),
                event_type=event_type,
                manifest_digest=request.manifest_digest,
                role_snapshot_digest=request.role_snapshot_digest,
                state=state,
                required_role_emails={
                    request.installed_role_id: request.installed_role_email,
                },
                audit_payload=dict(audit_payload),
            )
        )
        payload = {
            "status": result.status,
            "state_advance_allowed": result.state_advance_allowed,
            "cloud_readback_verified": result.cloud_readback_verified,
            "audit_payload_digest": result.audit_payload_digest,
            "recorded_state": result.recorded_state,
            "failure_reason": result.failure_reason,
        }
        if result.status == "AUDIT_DEGRADED":
            self.store.append_audit_event(
                "cloud_audit_degraded",
                {
                    "event_id": request.event_id,
                    "round_id": request.round_id,
                    "role_id": request.installed_role_id,
                    "reason_code": result.failure_reason or "LARK_AUDIT_FAILED",
                    "audit_payload_digest": result.audit_payload_digest,
                },
                created_at=self._isoformat(self.now_fn()),
            )
        if not result.state_advance_allowed:
            raise ReleaseApprovalMcpError(
                "CAPABILITY_BLOCKED",
                "required cloud audit writeback or readback failed.",
                details=payload,
            )
        return payload
    def _rotate_page_session(self, key: tuple[str, int, str]) -> None:
        if not self._has_authenticated_request_checkpoint(key):
            raise ReleaseApprovalMcpError(
                "CAPABILITY_BLOCKED",
                "approval page creation requires a durable authenticated-request checkpoint.",
                details={"event_id": key[0], "round_id": key[1], "role_id": key[2]},
            )
        live = self._live_pages.pop(key, None)
        if live is not None:
            live.close()
        context = self._contexts.get(key)
        if context is None:
            self._restore_page_context(key)
            return
        page_session = self.service.create_page_session(
            request=context.request,
            request_payload=context.request_payload,
        )
        self._contexts[key] = CachedRequestContext(
            request=context.request,
            request_payload=context.request_payload,
            reply_subject=context.reply_subject,
            page_session=page_session,
        )

    def _ensure_live_page(self, key: tuple[str, int, str], open_browser_now: bool) -> ReleaseApprovalPage:
        live = self._live_pages.get(key)
        if live is not None:
            if open_browser_now:
                self.browser_opener(live.url)
            return live
        context = self._contexts.get(key)
        if context is None or context.page_session is None:
            context = self._restore_page_context(key)
        page = ReleaseApprovalPage.from_page_session(
            host=self.config.page.host,
            artifact_dir=context.page_session.artifact_dir,
            binding=DecisionPageBinding(event_id=context.request.event_id, round_id=context.request.round_id, role_id=context.request.installed_role_id, expires_at=context.request.expires_at, page_html_sha256=context.page_session.page_html_sha256),
            page_session=context.page_session,
            submit_decision=lambda form: self._submit_page_decision(
                request=context.request,
                request_payload=context.request_payload,
                page_session=context.page_session,
                form=form,
            ),
            open_browser=self.browser_opener,
            now_fn=self.now_fn,
        )
        page.start()
        self._live_pages[key] = page
        return page

    def _restore_page_context(
        self,
        key: tuple[str, int, str],
    ) -> CachedRequestContext:
        if not self._has_authenticated_request_checkpoint(key):
            raise ReleaseApprovalMcpError(
                "CAPABILITY_BLOCKED",
                "stored request lacks a durable authenticated-request checkpoint.",
                details={"event_id": key[0], "round_id": key[1], "role_id": key[2]},
            )
        if key[2] != self.config.role_id:
            raise ReleaseApprovalMcpError(
                "EVENT_ROLE_MISMATCH",
                "the requested role does not match this plugin installation.",
                details={"requested_role_id": key[2], "configured_role_id": self.config.role_id},
            )
        row = self._get_request_row(*key)
        if row is None:
            raise ReleaseApprovalMcpError(
                "EVENT_NOT_FOUND",
                "event checkpoint was not found.",
                details={"event_id": key[0], "round_id": key[1], "role_id": key[2]},
            )
        if str(row["installed_role_email"]) != self.config.role_email:
            raise ReleaseApprovalMcpError(
                "EVENT_ROLE_MISMATCH",
                "the stored approver email does not match this plugin installation.",
                details={"event_id": key[0], "round_id": key[1], "role_id": key[2]},
            )
        try:
            payload = {
                "contract": "ReleaseAuthorizationRequest/v1",
                "event_id": str(row["event_id"]),
                "round_id": int(row["round_id"]),
                "task": str(row["task"]),
                "module": str(row["module"]),
                "manifest_s_digest": str(row["manifest_s_digest"]),
                "manifest_r_digest": str(row["manifest_r_digest"]),
                "manifest_digest": str(row["manifest_digest"]),
                "request_digest": str(row["request_digest"]),
                "role_snapshot_digest": str(row["role_snapshot_digest"]),
                "required_roles": json.loads(str(row["required_roles_json"])),
                "original_message_id": str(row["original_message_id"]),
                "references": json.loads(str(row["references_json"])),
                "expires_at": str(row["expires_at"]),
                "idempotency_key": str(row["idempotency_key"]),
            }
            request = validate_release_request(
                payload,
                installed_role_id=self.config.role_id,
                installed_role_email=self.config.role_email,
                now=self.now_fn(),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ReleaseApprovalMcpError(
                "EVENT_STATE_INVALID",
                "stored request state failed integrity validation.",
                details={"event_id": key[0], "round_id": key[1], "role_id": key[2]},
            ) from exc
        reply_subject = f"Re: 【发布申请】{request.task}-{request.module}"
        request_payload = {"reply_subject": reply_subject}
        page_session = self.service.create_page_session(
            request=request,
            request_payload=request_payload,
        )
        context = CachedRequestContext(
            request=request,
            request_payload=request_payload,
            reply_subject=reply_subject,
            page_session=page_session,
        )
        self._contexts[key] = context
        return context

    def _validate_configured_account(self, *, require_match: bool = False) -> dict[str, Any]:
        payload = self.mail_gateway.list_accounts()
        discovered_email = ""
        accounts = payload.get("accounts")
        if isinstance(accounts, list):
            for item in accounts:
                if isinstance(item, Mapping) and str(item.get("name") or "") == self.config.mail_account.profile:
                    discovered_email = str(item.get("email") or "").strip()
                    break
        matched = discovered_email == self.config.mail_account.email
        if require_match and not matched:
            raise ReleaseApprovalMcpError("CAPABILITY_BLOCKED", "configured mail account email does not match the locked account inventory.", details={"profile": self.config.mail_account.profile, "configured_email": self.config.mail_account.email, "discovered_email": discovered_email})
        return {"profile": self.config.mail_account.profile, "configured_email": self.config.mail_account.email, "discovered_email": discovered_email, "matched": matched}

    def _scheduler_adapter(self) -> Any:
        if self.scheduler is not None:
            return self.scheduler
        if self.config_path is None:
            raise ReleaseApprovalMcpError(
                "STARTUP_CONFIG_ERROR",
                "the authoritative config path is required to manage the scheduler.",
            )
        from release_approval_scheduler import ReleaseApprovalScheduler

        self.scheduler = ReleaseApprovalScheduler(
            plugin_name="release-approval",
            role_id=self.config.role_id,
            config_path=self.config_path,
            state_dir=self.config.state_dir,
            poll_minutes=self.config.poll_minutes,
        )
        return self.scheduler

    def _write_setup_record(self, payload: Mapping[str, Any]) -> None:
        self._setup_state_path.parent.mkdir(parents=True, exist_ok=True)
        self._setup_state_path.write_text(json.dumps(dict(payload), indent=2) + "\n", encoding="utf-8")

    def _extract_request_machine_block(self, body_text: str) -> dict[str, Any]:
        if _REQUEST_BEGIN_MARKER not in body_text or _REQUEST_END_MARKER not in body_text:
            raise ReleaseApprovalMcpError("REQUEST_BLOCK_MISSING", "release request machine block is missing.")
        encoded = body_text.split(_REQUEST_BEGIN_MARKER, 1)[1].split(_REQUEST_END_MARKER, 1)[0].strip()
        padded = encoded + "=" * (-len(encoded) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseApprovalMcpError("REQUEST_BLOCK_INVALID", "release request machine block is invalid.") from exc
        if not isinstance(payload, dict):
            raise ReleaseApprovalMcpError("REQUEST_BLOCK_INVALID", "release request machine block must decode to an object.")
        return payload

    def _has_authenticated_request_evidence(
        self,
        message: Mapping[str, Any],
        request: ReleaseAuthorizationRequest,
    ) -> bool:
        evidence = message.get("evidence")
        if not isinstance(evidence, Mapping):
            return False
        if not _SHA256_RE.fullmatch(
            str(evidence.get("raw_headers_sha256") or "").strip()
        ):
            return False
        references = evidence.get("references")
        if not isinstance(references, list) or references != list(request.references):
            return False
        message_id = str(message.get("message_id") or "").strip()
        if message_id != request.original_message_id:
            return False
        if str(evidence.get("message_id") or "").strip() != request.original_message_id:
            return False
        workflow_headers = message.get("release_workflow_headers")
        if not isinstance(workflow_headers, Mapping):
            return False
        authentication_path = self._authenticated_request_path(message)
        if authentication_path is None:
            return False
        expected_headers = {
            "contract": request.contract,
            "event_id": request.event_id,
            "round_id": str(request.round_id),
            "task": request.task,
            "module": request.module,
            "manifest_s_digest": request.manifest_s_digest,
            "manifest_r_digest": request.manifest_r_digest,
            "manifest_digest": request.manifest_digest,
            "request_digest": request.request_digest,
            "role_snapshot_digest": request.role_snapshot_digest,
            "required_roles": ",".join(request.required_roles),
            "expires_at": request.expires_at,
        }
        return all(
            str(workflow_headers.get(key) or "").strip() == value
            for key, value in expected_headers.items()
        )

    def _authenticated_request_path(
        self, message: Mapping[str, Any]
    ) -> str | None:
        sender_email = self._request_sender_email(message)
        if sender_email is None:
            return None
        allowed = set(self.config.request_authentication.allowed_sender_emails)
        if sender_email not in allowed:
            return None
        evidence = message.get("evidence")
        if not isinstance(evidence, Mapping):
            return None
        raw_authentication_results = str(
            evidence.get("authentication_results") or ""
        )
        authentication_results = self._trusted_authentication_results(
            raw_authentication_results,
            self.config.request_authentication.allowed_authserv_ids,
        ).lower()
        if not authentication_results:
            return None
        received_spf = str(evidence.get("received_spf") or "").lower()
        return_path = str(evidence.get("return_path") or "").strip().lower()
        sender_domain = sender_email.rsplit("@", 1)[1]
        for path_name in self.config.request_authentication.accepted_paths:
            if (
                path_name == "dmarc"
                and self._authentication_method_passed(
                    authentication_results, "dmarc"
                )
                and self._authentication_parameter(
                    authentication_results, "header.from"
                )
                == sender_domain
            ):
                return "dmarc"
            if (
                path_name == "dkim"
                and self._authentication_method_passed(
                    authentication_results, "dkim"
                )
                and self._authentication_parameter(
                    authentication_results, "header.d"
                )
                == sender_domain
            ):
                return "dkim"
            if path_name == "spf" and return_path == sender_email:
                if self._authentication_method_passed(
                    authentication_results, "spf"
                ) and received_spf.strip().startswith("pass"):
                    return "spf"
        return None

    @staticmethod
    def _trusted_authentication_results(
        value: str,
        allowed_authserv_ids: tuple[str, ...],
    ) -> str:
        allowed = set(allowed_authserv_ids)
        trusted: list[str] = []
        for line in value.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            authserv_id = candidate.split(";", 1)[0].strip().lower()
            if authserv_id in allowed:
                trusted.append(candidate)
        return "\n".join(trusted)

    @staticmethod
    def _request_sender_email(message: Mapping[str, Any]) -> str | None:
        senders = message.get("from")
        if not isinstance(senders, list) or len(senders) != 1:
            return None
        sender = senders[0]
        if not isinstance(sender, Mapping):
            return None
        email_address = str(sender.get("email") or "").strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email_address):
            return None
        return email_address

    @staticmethod
    def _authentication_method_passed(value: str, method: str) -> bool:
        return bool(
            re.search(
                rf"(?:^|[;\s]){re.escape(method)}\s*=\s*pass(?:[;\s]|$)",
                value,
                flags=re.IGNORECASE,
            )
        )

    @staticmethod
    def _authentication_parameter(value: str, name: str) -> str:
        match = re.search(
            rf"(?:^|[;\s]){re.escape(name)}\s*=\s*([A-Za-z0-9.-]+)",
            value,
            flags=re.IGNORECASE,
        )
        return "" if match is None else match.group(1).lower()

    def _quarantined_request_payload(
        self,
        message: Mapping[str, Any],
        exc: Exception,
    ) -> dict[str, Any]:
        return {
            "message_id": str(message.get("message_id") or ""),
            "uid": str(message.get("uid") or ""),
            "uidvalidity": str(message.get("uidvalidity") or ""),
            "reason": f"invalid release request: {exc}",
            "error_code": str(getattr(exc, "code", "INVALID_REQUEST")),
            "checkpoint_preserved": True,
        }

    def _rejected_message_payload(
        self,
        message: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        evidence = message.get("evidence")
        raw_headers_sha256 = (
            str(evidence.get("raw_headers_sha256") or "").strip()
            if isinstance(evidence, Mapping)
            else ""
        )
        checkpoint_source = {
            "account": self.config.mail_account.profile,
            "mailbox": self.config.mailbox,
            "uidvalidity": str(message.get("uidvalidity") or ""),
            "uid": str(message.get("uid") or ""),
            "message_id": str(message.get("message_id") or ""),
            "raw_headers_sha256": raw_headers_sha256,
        }
        transport_checkpoint = hashlib.sha256(
            canonical_json(checkpoint_source).encode("utf-8")
        ).hexdigest()
        return {
            **dict(payload),
            **checkpoint_source,
            "transport_checkpoint": transport_checkpoint,
        }

    def _has_rejected_message_audit(
        self,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> bool:
        checkpoint = str(payload.get("transport_checkpoint") or "")
        rows = self.store.connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_type = ? ORDER BY id ASC",
            (event_type,),
        ).fetchall()
        for row in rows:
            try:
                existing = json.loads(str(row[0]))
            except json.JSONDecodeError:
                continue
            if isinstance(existing, Mapping) and existing.get("transport_checkpoint") == checkpoint:
                return True
        return False


    def _append_rejected_message_audit(
        self,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> bool:
        checkpoint = str(payload.get("transport_checkpoint") or "")
        rows = self.store.connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_type = ? ORDER BY id ASC",
            (event_type,),
        ).fetchall()
        for row in rows:
            try:
                existing = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError:
                continue
            if existing.get("transport_checkpoint") == checkpoint:
                return False
        self.store.append_audit_event(
            event_type,
            dict(payload),
            created_at=self._isoformat(self.now_fn()),
        )
        return True

    def _blocked_event_payload(
        self,
        request: ReleaseAuthorizationRequest,
        *,
        message_id: str,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "event_id": request.event_id,
            "round_id": request.round_id,
            "role_id": request.installed_role_id,
            "message_id": message_id,
            "reason": reason,
            "checkpoint_preserved": True,
        }

    def _reply_subject(self, subject: str) -> str:
        subject = subject.strip()
        if not subject:
            return "Re: 【发布申请】"
        return subject if subject.lower().startswith("re:") else f"Re: {subject}"

    def _get_request_row(self, event_id: str, round_id: int, role: str):
        return self.store.connection.execute("SELECT * FROM requests WHERE event_id = ? AND round_id = ? AND role = ?", (event_id, round_id, role)).fetchone()

    def _get_page_row(self, event_id: str, round_id: int, role: str):
        return self.store.connection.execute("SELECT html_path, html_sha256, nonce_sha256, created_at FROM pages WHERE event_id = ? AND round_id = ? AND role = ?", (event_id, round_id, role)).fetchone()

    def _get_latest_smtp_outcome(self, event_id: str, round_id: int, role: str):
        return self.store.connection.execute("SELECT smtp_message_id, outcome, detail, recorded_at FROM smtp_outcomes WHERE event_id = ? AND round_id = ? AND role = ? ORDER BY id DESC LIMIT 1", (event_id, round_id, role)).fetchone()

    @staticmethod
    def _isoformat(value: datetime) -> str:
        return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

_STARTUP_CONTROLLER: ReleaseApprovalController | None = None
_STARTUP_ERROR: ReleaseApprovalMcpError | None = None


def startup_controller(arguments: Mapping[str, Any] | None) -> ReleaseApprovalController:
    global _STARTUP_CONTROLLER, _STARTUP_ERROR
    reject_per_call_config_override(arguments)
    if _STARTUP_CONTROLLER is not None:
        return _STARTUP_CONTROLLER
    if _STARTUP_ERROR is not None:
        raise _STARTUP_ERROR
    config_path = default_config_path()
    try:
        _STARTUP_CONTROLLER = ReleaseApprovalController(
            config=load_config(config_path),
            config_path=config_path,
        )
        return _STARTUP_CONTROLLER
    except ReleaseApprovalMcpError as exc:
        _STARTUP_ERROR = exc
        raise
    except Exception as exc:
        _STARTUP_ERROR = ReleaseApprovalMcpError("STARTUP_CONFIG_ERROR", str(exc))
        raise _STARTUP_ERROR from exc


def tool_result(payload: Any) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}], "structuredContent": payload}


def error_result(code: str, message: str, *, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
    payload = {"ok": False, "error_code": code, "message": message}
    if details:
        payload["details"] = dict(details)
    return {"content": [{"type": "text", "text": message}], "structuredContent": payload, "isError": True}


def preflight(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).preflight()


def start_setup(args: dict[str, Any]) -> dict[str, Any]:
    global _STARTUP_CONTROLLER, _STARTUP_ERROR
    reject_per_call_config_override(args)
    if args.get("non_interactive", True) is not True:
        raise ReleaseApprovalMcpError(
            "INVALID_ARGUMENT",
            "MCP setup is non-interactive; omit non_interactive or set it to true.",
        )
    scheduler_mode = str(args.get("scheduler_mode") or "auto").strip().lower()
    if scheduler_mode not in {"auto", "windows", "systemd", "cron", "codex"}:
        raise ReleaseApprovalMcpError("INVALID_ARGUMENT", "unsupported scheduler_mode.")
    provided_keys = (
        "role_id",
        "role_email",
        "mail_profile",
        "release_group",
        "request_sender_email",
        "trusted_authserv_ids",
        "state_dir",
        "audit_document_url",
    )
    payload = dict(
        run_setup_operation(
            config_path=default_config_path(),
            repo_root=_PLUGIN_ROOT.parents[1],
            non_interactive=True,
            scheduler_mode=scheduler_mode,
            provided={key: args.get(key) for key in provided_keys},
        )
    )
    _STARTUP_CONTROLLER = None
    _STARTUP_ERROR = None
    return payload


def run_once(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).run_once()


def status(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).status()


def doctor(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).doctor()


def list_pending(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).list_pending()


def open_page(args: dict[str, Any]) -> dict[str, Any]:
    event_id = str(args.get("event_id") or "").strip()
    round_id = args.get("round_id")
    role_id = args.get("role_id")
    if not event_id:
        raise ReleaseApprovalMcpError("INVALID_ARGUMENT", "event_id is required.")
    if not isinstance(round_id, int) or round_id <= 0:
        raise ReleaseApprovalMcpError("INVALID_ARGUMENT", "round_id must be a positive integer.")
    if role_id is not None and (not isinstance(role_id, str) or not role_id.strip()):
        raise ReleaseApprovalMcpError("INVALID_ARGUMENT", "role_id must be a non-empty string when supplied.")
    return startup_controller(args).open_page(event_id=event_id, round_id=round_id, role_id=role_id)


def get_event(args: dict[str, Any]) -> dict[str, Any]:
    event_id = str(args.get("event_id") or "").strip()
    round_id = args.get("round_id")
    role_id = args.get("role_id")
    if not event_id:
        raise ReleaseApprovalMcpError("INVALID_ARGUMENT", "event_id is required.")
    if not isinstance(round_id, int) or round_id <= 0:
        raise ReleaseApprovalMcpError("INVALID_ARGUMENT", "round_id must be a positive integer.")
    if role_id is not None and (not isinstance(role_id, str) or not role_id.strip()):
        raise ReleaseApprovalMcpError("INVALID_ARGUMENT", "role_id must be a non-empty string when supplied.")
    return startup_controller(args).get_event(event_id=event_id, round_id=round_id, role_id=role_id)


def verify_audit_chain(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).verify_audit_chain()


TOOLS: dict[str, dict[str, Any]] = {
    "release_approval_preflight": {"description": "Check the startup-locked configuration, locked mail account binding, dependency lock path, and loopback page boundary.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "handler": preflight},
    "release_approval_start_setup": {"description": "Cold-start the shared non-interactive setup flow, create the authoritative config when needed, install one OS scheduler, and execute the first headless run.", "inputSchema": {"type": "object", "properties": {"non_interactive": {"type": "boolean", "const": True, "default": True}, "scheduler_mode": {"type": "string", "enum": ["auto", "windows", "systemd", "cron", "codex"], "default": "auto"}, "role_id": {"type": "string"}, "role_email": {"type": "string"}, "mail_profile": {"type": "string"}, "release_group": {"type": "string"}, "request_sender_email": {"type": "string", "format": "email"}, "trusted_authserv_ids": {"type": "string", "description": "Comma-separated trusted Authentication-Results authserv-id values."}, "state_dir": {"type": "string"}, "audit_document_url": {"type": "string", "format": "uri"}}, "additionalProperties": False}, "handler": start_setup},
    "release_approval_run_once": {"description": "Headlessly scan recent release-request mail, validate the frozen machine block, record pending state, and retry known-unsent decisions.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "handler": run_once},
    "release_approval_status": {"description": "Read pending state and verify the externally installed unattended scheduler.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "handler": status},
    "release_approval_doctor": {"description": "Diagnose mail binding, scheduler state, headless execution, and the audit chain without requiring Codex.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "handler": doctor},
    "release_approval_list_pending": {"description": "List pending or retry-queued release approval checkpoints for the configured role.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "handler": list_pending},
    "release_approval_open_page": {"description": "Open the existing loopback approval page for one event/round/role binding.", "inputSchema": {"type": "object", "properties": {"event_id": {"type": "string"}, "round_id": {"type": "integer", "minimum": 1}, "role_id": {"type": "string"}}, "required": ["event_id", "round_id"], "additionalProperties": False}, "handler": open_page},
    "release_approval_get_event": {"description": "Read the stored checkpoint, page artifact path, current decision, and latest SMTP outcome for one release approval event.", "inputSchema": {"type": "object", "properties": {"event_id": {"type": "string"}, "round_id": {"type": "integer", "minimum": 1}, "role_id": {"type": "string"}}, "required": ["event_id", "round_id"], "additionalProperties": False}, "handler": get_event},
    "release_approval_verify_audit_chain": {"description": "Verify the append-only local audit hash chain for the configured role state store.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "handler": verify_audit_chain},
}


def response(request_id: Any, value: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if request_id is None:
        return None
    try:
        if method == "initialize":
            return response(request_id, {"protocolVersion": params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION, "capabilities": {"tools": {}}, "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}})
        if method == "ping":
            return response(request_id, {})
        if method == "tools/list":
            return response(request_id, {"tools": [{"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]} for name, spec in TOOLS.items()]})
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if tool_name not in TOOLS:
                raise ReleaseApprovalMcpError("UNKNOWN_TOOL", f"Unknown tool: {tool_name}")
            handler: Callable[[dict[str, Any]], dict[str, Any]] = TOOLS[tool_name]["handler"]
            return response(request_id, tool_result(handler(arguments)))
        return error_response(request_id, -32601, f"Method not found: {method}")
    except ReleaseApprovalMcpError as exc:
        return response(request_id, error_result(exc.code, str(exc), details=exc.details))
    except (SetupError, SchedulerError) as exc:
        return response(request_id, error_result(exc.code, str(exc)))
    except (MailGatewayError, MailCapabilityError, StoreError, AuditTamperError, ValueError, TypeError, KeyError) as exc:
        code = "CAPABILITY_BLOCKED" if "CAPABILITY_BLOCKED" in str(exc) else "TOOL_FAILED"
        return response(request_id, error_result(code, str(exc)))
    except Exception as exc:
        eprint(traceback.format_exc())
        return response(request_id, error_result("UNEXPECTED_ERROR", f"Unexpected {type(exc).__name__}: {exc}"))


def send_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run_stdio_server() -> None:
    eprint("Release Approval MCP stdio server started")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            send_message(error_response(None, -32700, f"Parse error: {exc}"))
            continue
        result_value = handle_request(message)
        if result_value is not None:
            send_message(result_value)


if __name__ == "__main__":
    run_stdio_server()
