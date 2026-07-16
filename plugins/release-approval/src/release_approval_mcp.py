from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import traceback
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from release_approval_config import load_config, reject_per_call_config_override
from release_approval_mail import MailCapabilityError, MailGateway, MailGatewayError
from release_approval_page import DecisionPageBinding, ReleaseApprovalPage
from release_approval_protocol import ReleaseAuthorizationRequest, canonical_json, validate_release_request
from release_approval_service import PageSession, ReleaseApprovalService
from release_approval_store import AuditTamperError, ReleaseApprovalStore, StoreError

_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.bootstrap_dependencies import bootstrap_profile

SERVER_NAME = "release-approval"
SERVER_VERSION = "0.1.0"
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


Runner = Callable[[list[str], str | None], subprocess.CompletedProcess[str]]


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def _run_command(command: list[str], cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False, shell=False)


class ReleaseApprovalController:
    def __init__(
        self,
        *,
        config,
        store: ReleaseApprovalStore | None = None,
        mail_gateway: MailGateway | Any | None = None,
        service: ReleaseApprovalService | None = None,
        bootstrap_runner: Callable[..., Mapping[str, Any]] = bootstrap_profile,
        automation_runner: Runner = _run_command,
        browser_opener: Callable[[str], Any] | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
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
        self.automation_runner = automation_runner
        self.browser_opener = browser_opener or webbrowser.open
        self._contexts: dict[tuple[str, int, str], CachedRequestContext] = {}
        self._live_pages: dict[tuple[str, int, str], ReleaseApprovalPage] = {}
        self._setup_state_path = self.config.state_dir / "setup" / "hourly-automation.json"

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
                "poll_minutes": self.config.poll_minutes,
                "page_host": self.config.page.host,
                "page_port": self.config.page.port,
                "state_dir": str(self.config.state_dir),
                "dependency_lock": str(self.config.dependency_lock),
            },
            "account_validation": account,
        }

    def start_setup(self) -> dict[str, Any]:
        bootstrap = dict(self.bootstrap_runner("release-approval"))
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
        automation = self._ensure_hourly_automation()
        first_run = self.run_once()
        result.update(
            {
                "status": "ready",
                "configured_account_email": account["discovered_email"],
                "automation": automation,
                "first_run": first_run,
            }
        )
        self._write_setup_record(result)
        self.store.append_audit_event(
            "setup_completed",
            {"automation_id": automation["automation_id"], "dependency_lock": result["dependency_lock"]},
            created_at=self._isoformat(self.now_fn()),
        )
        return result
    def run_once(self) -> dict[str, Any]:
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
            request_payload = self._extract_request_machine_block(str(message.get("body_text") or ""))
            request = validate_release_request(
                request_payload,
                installed_role_id=self.config.role_id,
                installed_role_email=self.config.role_email,
                now=self.now_fn(),
            )
            reply_subject = self._reply_subject(str(message.get("subject") or ""))
            key = (request.event_id, request.round_id, request.installed_role_id)
            self._record_message_checkpoint(message)
            self._record_request_checkpoint(request)
            if not self._has_authenticated_request_evidence(message):
                blocked += 1
                payload = self._blocked_event_payload(request, message_id=str(message.get("message_id") or ""))
                self.store.append_audit_event("capability_blocked", payload, created_at=self._isoformat(self.now_fn()))
                self._contexts[key] = CachedRequestContext(request, {"reply_subject": reply_subject}, reply_subject, None)
                events.append({**payload, "status": "CAPABILITY_BLOCKED"})
                continue
            context = self._contexts.get(key)
            stored_page = self._get_page_row(*key)
            if context is None and stored_page is None:
                page_session = self.service.create_page_session(request=request, request_payload={"reply_subject": reply_subject})
                self._contexts[key] = CachedRequestContext(request, {"reply_subject": reply_subject}, reply_subject, page_session)
                self._ensure_live_page(key, True)
                created_pages += 1
                opened_pages += 1
                status = "created"
            else:
                if context is None:
                    self._contexts[key] = CachedRequestContext(request, {"reply_subject": reply_subject}, reply_subject, None)
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
    def _record_message_checkpoint(self, message: Mapping[str, Any]) -> None:
        try:
            self.store.record_message(
                account=self.config.mail_account.profile,
                mailbox=self.config.mailbox,
                uidvalidity=int(str(message.get("uidvalidity") or "0") or "0"),
                uid=int(str(message.get("uid") or "0") or "0"),
                message_id=str(message.get("message_id") or ""),
            )
        except StoreError as exc:
            if "duplicate UID" not in str(exc) and "duplicate Message-ID" not in str(exc):
                raise

    def _record_request_checkpoint(self, request: ReleaseAuthorizationRequest) -> None:
        try:
            self.service.record_request(request)
        except StoreError as exc:
            if "already exists" not in str(exc) and "idempotency key" not in str(exc):
                raise

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

    def _ensure_live_page(self, key: tuple[str, int, str], open_browser_now: bool) -> ReleaseApprovalPage:
        live = self._live_pages.get(key)
        if live is not None:
            if open_browser_now:
                self.browser_opener(live.url)
            return live
        context = self._contexts.get(key)
        if context is None or context.page_session is None:
            raise ReleaseApprovalMcpError("PAGE_SESSION_UNAVAILABLE", "page session is unavailable in the current startup controller; rerun release_approval_run_once first.", details={"event_id": key[0], "round_id": key[1], "role_id": key[2]})
        page = ReleaseApprovalPage.from_page_session(
            host=self.config.page.host,
            artifact_dir=context.page_session.artifact_dir,
            binding=DecisionPageBinding(event_id=context.request.event_id, round_id=context.request.round_id, role_id=context.request.installed_role_id, expires_at=context.request.expires_at, page_html_sha256=context.page_session.page_html_sha256),
            page_session=context.page_session,
            submit_decision=lambda form: self.service.submit_local_decision(request=context.request, request_payload=context.request_payload, page_session=context.page_session, decision=form["decision"], comment=form["comment"], nonce=form["nonce"], page_html_sha256=form["page_html_sha256"]),
            open_browser=self.browser_opener,
            now_fn=self.now_fn,
        )
        page.start()
        self._live_pages[key] = page
        return page

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

    def _ensure_hourly_automation(self) -> dict[str, Any]:
        if self._setup_state_path.is_file():
            existing = json.loads(self._setup_state_path.read_text(encoding="utf-8"))
            automation = existing.get("automation")
            if isinstance(automation, Mapping) and automation.get("schedule") == "hourly":
                return dict(automation)
        command = ["codex", "automation", "create", "--name", f"release-approval-{self.config.role_id}", "--schedule", "hourly", "--tool", "release_approval_run_once", "--json"]
        completed = self.automation_runner(command, str(self.config.state_dir))
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip() or "codex automation create failed"
            raise ReleaseApprovalMcpError("AUTOMATION_CREATE_FAILED", detail)
        try:
            payload = json.loads(completed.stdout.strip() or "{}")
        except json.JSONDecodeError as exc:
            raise ReleaseApprovalMcpError("AUTOMATION_CREATE_FAILED", "automation creation returned invalid JSON.") from exc
        automation_id = str(payload.get("automation_id") or payload.get("id") or "").strip()
        if not automation_id:
            raise ReleaseApprovalMcpError("AUTOMATION_CREATE_FAILED", "automation creation did not return an automation_id.")
        return {"automation_id": automation_id, "schedule": "hourly", "command": command}

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
        except (ValueError, json.JSONDecodeError) as exc:
            raise ReleaseApprovalMcpError("REQUEST_BLOCK_INVALID", "release request machine block is invalid.") from exc
        if not isinstance(payload, dict):
            raise ReleaseApprovalMcpError("REQUEST_BLOCK_INVALID", "release request machine block must decode to an object.")
        return payload

    def _has_authenticated_request_evidence(self, message: Mapping[str, Any]) -> bool:
        evidence = message.get("evidence")
        if not isinstance(evidence, Mapping):
            return False
        if not _SHA256_RE.fullmatch(str(evidence.get("raw_headers_sha256") or "").strip()):
            return False
        references = evidence.get("references")
        return isinstance(references, list) and bool(references) and bool(str(message.get("message_id") or "").strip())

    def _blocked_event_payload(self, request: ReleaseAuthorizationRequest, *, message_id: str) -> dict[str, Any]:
        return {"event_id": request.event_id, "round_id": request.round_id, "role_id": request.installed_role_id, "message_id": message_id, "reason": "missing thread/readback capability", "checkpoint_preserved": True}

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
    config_path = os.environ.get("RELEASE_APPROVAL_CONFIG", "").strip()
    if not config_path:
        _STARTUP_ERROR = ReleaseApprovalMcpError("STARTUP_CONFIG_ERROR", "RELEASE_APPROVAL_CONFIG must be set before starting the release-approval MCP server.")
        raise _STARTUP_ERROR
    try:
        _STARTUP_CONTROLLER = ReleaseApprovalController(config=load_config(config_path))
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
    return startup_controller(args).start_setup()


def run_once(args: dict[str, Any]) -> dict[str, Any]:
    return startup_controller(args).run_once()


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
    "release_approval_start_setup": {"description": "Run the fixed allowlisted bootstrap, create exactly one hourly Codex automation, and execute the first run immediately unless a fresh task is required.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "handler": start_setup},
    "release_approval_run_once": {"description": "Scan recent release-request mail, validate the frozen machine block, create or reuse one durable page, and retry known-unsent decisions.", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}, "handler": run_once},
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
