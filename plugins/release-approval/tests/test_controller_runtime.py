from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_config import (  # noqa: E402
    AuditConfig,
    MailAccountConfig,
    PageConfig,
    RequestAuthenticationConfig,
    ReleaseApprovalConfig,
    WorkingHoursConfig,
)
from release_approval_mcp import (  # noqa: E402
    ReleaseApprovalController,
    ReleaseApprovalMcpError,
)
from release_approval_lock import RunOnceLock  # noqa: E402
from release_approval_protocol import (  # noqa: E402
    ReleaseAuthorizationRequest,
    build_request_digest,
    canonical_json,
    validate_release_request,
)
from release_approval_store import ReleaseApprovalStore  # noqa: E402


FIXED_NOW = datetime(2026, 7, 16, 1, 2, 3, tzinfo=timezone.utc)
BEGIN_MARKER = "-----BEGIN RELEASE APPROVAL REQUEST-----"
END_MARKER = "-----END RELEASE APPROVAL REQUEST-----"


def _config(tmp_path: Path) -> ReleaseApprovalConfig:
    return ReleaseApprovalConfig(
        role_id="release-manager",
        role_email="release-manager@example.com",
        mail_account=MailAccountConfig(
            profile="release-manager",
            email="release-manager@example.com",
        ),
        request_authentication=RequestAuthenticationConfig(
            allowed_sender_emails=("release-gate@example.com",),
            allowed_authserv_ids=("mx.example.com",),
            accepted_paths=("dmarc", "dkim", "spf"),
        ),
        release_group="release-approvers@example.com",
        mailbox="INBOX",
        page=PageConfig(host="127.0.0.1", port=8765),
        poll_minutes=60,
        timezone="UTC",
        working_hours=WorkingHoursConfig(
            days=("Mon", "Tue", "Wed", "Thu", "Fri"),
            start="09:00",
            end="18:00",
        ),
        state_dir=tmp_path,
        dependency_lock=REPO_ROOT / "dependency-lock.json",
        audit=AuditConfig(verify_chain_on_startup=True, retention_days=3650),
    )


def _request_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "contract": "ReleaseAuthorizationRequest/v1",
        "event_id": "release-event-1",
        "round_id": 1,
        "task": "Release task",
        "module": "client",
        "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64,
        "manifest_digest": "sha256:" + "3" * 64,
        "role_snapshot_digest": "sha256:" + "4" * 64,
        "required_roles": ["release-manager"],
        "original_message_id": "<request-1@example.com>",
        "references": ["<root@example.com>"],
        "expires_at": "2099-07-16T00:00:00Z",
        "idempotency_key": "request:release-event-1:1",
    }
    payload["request_digest"] = build_request_digest(payload)
    return payload


def _request() -> ReleaseAuthorizationRequest:
    return validate_release_request(
        _request_payload(),
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
        now=FIXED_NOW,
    )


def _workflow_headers(payload: dict[str, object]) -> dict[str, str]:
    required_roles = payload["required_roles"]
    assert isinstance(required_roles, list)
    return {
        "contract": str(payload["contract"]),
        "event_id": str(payload["event_id"]),
        "round_id": str(payload["round_id"]),
        "task": str(payload["task"]),
        "module": str(payload["module"]),
        "manifest_s_digest": str(payload["manifest_s_digest"]),
        "manifest_r_digest": str(payload["manifest_r_digest"]),
        "manifest_digest": str(payload["manifest_digest"]),
        "request_digest": str(payload["request_digest"]),
        "role_snapshot_digest": str(payload["role_snapshot_digest"]),
        "required_roles": ",".join(str(role) for role in required_roles),
        "expires_at": str(payload["expires_at"]),
    }


def _message(
    *,
    authenticated: bool = True,
    payload: dict[str, object] | None = None,
    message_id: str | None = None,
    evidence_references: list[str] | None = None,
    sender_email: str = "release-gate@example.com",
) -> dict[str, object]:
    request_payload = payload or _request_payload()
    encoded = base64.urlsafe_b64encode(
        canonical_json(request_payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    effective_message_id = message_id or str(request_payload["original_message_id"])
    message: dict[str, object] = {
        "uid": "7",
        "uidvalidity": "11",
        "message_id": effective_message_id,
        "subject": "【发布申请】Release task-client-2026-07-16",
        "body_text": f"{BEGIN_MARKER}\n{encoded}\n{END_MARKER}",
        "from": [{"name": "Release Gate", "email": sender_email}],
        "release_workflow_headers": _workflow_headers(request_payload),
    }
    if authenticated:
        references = request_payload["references"]
        assert isinstance(references, list)
        message["evidence"] = {
            "raw_headers_sha256": "a" * 64,
            "message_id": effective_message_id,
            "references": (
                evidence_references
                if evidence_references is not None
                else list(references)
            ),
            "return_path": sender_email,
            "authentication_results": (
                f"mx.example.com; dkim=pass header.d={sender_email.rsplit('@', 1)[1]}; "
                f"dmarc=pass header.from={sender_email.rsplit('@', 1)[1]}"
            ),
            "received_spf": "pass",
        }
    return message

class FakeMailGateway:
    def __init__(self, message: dict[str, object]) -> None:
        self.message = message
        self.search_calls = 0

    def list_accounts(self) -> dict[str, object]:
        return {
            "accounts": [
                {
                    "name": "release-manager",
                    "email": "release-manager@example.com",
                }
            ]
        }

    def search_messages(self, _arguments: dict[str, object]) -> dict[str, object]:
        self.search_calls += 1
        return {"messages": [{"uid": self.message["uid"]}]}

    def read_message(self, _arguments: dict[str, object]) -> dict[str, object]:
        return dict(self.message)

    def require_thread_reply_capability(
        self, _arguments: dict[str, object]
    ) -> None:
        return None


class BatchMailGateway(FakeMailGateway):
    def __init__(self, messages: list[dict[str, object]]) -> None:
        super().__init__(messages[0])
        self.messages = {str(message["uid"]): message for message in messages}

    def search_messages(self, _arguments: dict[str, object]) -> dict[str, object]:
        self.search_calls += 1
        return {"messages": [{"uid": uid} for uid in self.messages]}

    def read_message(self, arguments: dict[str, object]) -> dict[str, object]:
        return dict(self.messages[str(arguments["uid"])])


class FakeScheduler:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def install(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("install", kwargs))
        return {"status": "ready", "mode": kwargs["mode"], "installed": True}

    def status(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(("status", kwargs))
        return {"status": "ready", "mode": kwargs["mode"], "installed": True}


def _close_pages(controller: ReleaseApprovalController) -> None:
    for page in list(controller._live_pages.values()):  # noqa: SLF001
        page.close()


def test_run_once_is_headless_and_explicit_open_page_owns_ui(tmp_path: Path) -> None:
    opened: list[str] = []
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message()),
        browser_opener=opened.append,
        now_fn=lambda: FIXED_NOW,
    )
    try:
        result = controller.run_once()

        assert result["status"] == "ready"
        assert result["matched_events"] == 1
        assert result["created_pages"] == 0
        assert result["opened_pages"] == 0
        assert opened == []
        assert controller._live_pages == {}  # noqa: SLF001

        page = controller.open_page(event_id="release-event-1", round_id=1)
        assert page["status"] == "ready"
        assert page["page_url"].startswith("http://127.0.0.1:")
        assert len(opened) == 1
    finally:
        _close_pages(controller)



def test_each_explicit_open_rotates_the_one_time_page_session(tmp_path: Path) -> None:
    opened: list[str] = []
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message()),
        browser_opener=opened.append,
        now_fn=lambda: FIXED_NOW,
    )
    try:
        controller.run_once()
        first = controller.open_page(event_id="release-event-1", round_id=1)
        key = ("release-event-1", 1, "release-manager")
        first_server = controller._live_pages[key]  # noqa: SLF001
        first_state = json.loads(
            Path(first["page_html_path"]).with_name("page-state.json").read_text(
                encoding="utf-8"
            )
        )

        second = controller.open_page(event_id="release-event-1", round_id=1)
        second_state = json.loads(
            Path(second["page_html_path"]).with_name("page-state.json").read_text(
                encoding="utf-8"
            )
        )

        assert first["page_url"] != second["page_url"]
        assert first_state["nonce_sha256"] != second_state["nonce_sha256"]
        assert first_server.server is None
        assert opened == [first["page_url"], second["page_url"]]
    finally:
        _close_pages(controller)


def test_duplicate_blocked_message_does_not_repeat_audit_side_effect(
    tmp_path: Path,
) -> None:
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message(authenticated=False)),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    first = controller.run_once()
    second = controller.run_once()

    count = controller.store.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type = 'capability_blocked'"
    ).fetchone()[0]
    assert first["status"] == "CAPABILITY_BLOCKED"
    assert second["status"] == "ready"
    assert second["matched_events"] == 0
    assert count == 1



def test_initial_request_with_empty_references_is_authenticated(tmp_path: Path) -> None:
    payload = _request_payload()
    payload["references"] = []
    payload["request_digest"] = build_request_digest(payload)
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message(payload=payload)),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    assert result["status"] == "ready"
    assert result["matched_events"] == 1


def test_request_message_id_mismatch_is_capability_blocked(tmp_path: Path) -> None:
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message(message_id="<transport-other@example.com>")),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"


def test_request_references_mismatch_is_capability_blocked(tmp_path: Path) -> None:
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(
            _message(evidence_references=["<different-root@example.com>"])
        ),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"


def test_request_workflow_header_mismatch_is_capability_blocked(tmp_path: Path) -> None:
    message = _message()
    headers = message["release_workflow_headers"]
    assert isinstance(headers, dict)
    headers["manifest_digest"] = "sha256:" + "f" * 64
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(message),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"


def test_request_authserv_id_must_be_allowlisted(tmp_path: Path) -> None:
    message = _message()
    evidence = dict(message["evidence"])
    evidence["authentication_results"] = (
        "evil.example.net; dkim=pass header.d=example.com; "
        "dmarc=pass action=none header.from=example.com; spf=pass"
    )
    message["evidence"] = evidence
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(message),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert result["events"][0]["reason"] == "request source authentication failed"


def test_untrusted_authserv_cannot_supply_pass_beside_trusted_failure(
    tmp_path: Path,
) -> None:
    message = _message()
    evidence = dict(message["evidence"])
    evidence["authentication_results"] = (
        "mx.example.com; dmarc=fail; dkim=fail; spf=fail\n"
        "evil.example.net; dmarc=pass header.from=example.com; "
        "dkim=pass header.d=example.com; spf=pass"
    )
    message["evidence"] = evidence
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(message),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert result["events"][0]["reason"] == "request source authentication failed"


def test_request_sender_must_be_frozen_and_authenticated(tmp_path: Path) -> None:
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message(sender_email="attacker@example.net")),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert result["events"][0]["reason"] == "request source authentication failed"


def test_repeated_unauthenticated_request_is_transport_checkpoint_deduped(
    tmp_path: Path,
) -> None:
    forged = _message(sender_email="attacker@example.net")
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(forged),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    first = controller.run_once()
    second = controller.run_once()
    blocked_count = controller.store.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type = 'capability_blocked'"
    ).fetchone()[0]

    assert first["status"] == "CAPABILITY_BLOCKED"
    assert first["matched_events"] == 1
    assert second["status"] == "ready"
    assert second["matched_events"] == 0
    assert blocked_count == 1


def test_unauthenticated_request_cannot_poison_the_frozen_request(
    tmp_path: Path,
) -> None:
    forged_payload = _request_payload()
    forged_payload["task"] = "Forged task"
    forged_payload["request_digest"] = build_request_digest(forged_payload)
    forged = _message(payload=forged_payload, sender_email="attacker@example.net")
    forged["uid"] = "6"
    valid = _message()
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=BatchMailGateway([forged, valid]),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.run_once()

    stored = controller.store.connection.execute(
        "SELECT request_digest, task FROM requests WHERE event_id = ? AND round_id = ?",
        ("release-event-1", 1),
    ).fetchone()
    assert result["status"] == "CAPABILITY_BLOCKED"
    assert {event["status"] for event in result["events"]} == {
        "CAPABILITY_BLOCKED",
        "pending",
    }
    assert stored["request_digest"] == _request_payload()["request_digest"]
    assert stored["task"] == "Release task"


def test_malformed_request_is_quarantined_without_stopping_valid_mail(
    tmp_path: Path,
) -> None:
    malformed = _message()
    malformed["uid"] = "6"
    malformed["message_id"] = "<malformed@example.com>"
    malformed["body_text"] = "not a release request machine block"
    valid = _message()
    gateway = BatchMailGateway([malformed, valid])
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=gateway,
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    first = controller.run_once()
    second = controller.run_once()

    statuses = {event["status"] for event in first["events"]}
    quarantined_count = controller.store.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE event_type = 'request_quarantined'"
    ).fetchone()[0]
    assert first["status"] == "CAPABILITY_BLOCKED"
    assert first["matched_events"] == 2
    assert statuses == {"QUARANTINED", "pending"}
    assert any(
        event.get("event_id") == "release-event-1" and event["status"] == "pending"
        for event in first["events"]
    )
    assert second["status"] == "ready"
    assert second["matched_events"] == 1
    assert second["events"][0]["status"] == "reused"
    assert quarantined_count == 1


def test_blocked_request_cannot_open_an_approval_page(tmp_path: Path) -> None:
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message(authenticated=False)),
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )
    controller.run_once()

    with pytest.raises(ReleaseApprovalMcpError) as excinfo:
        controller.open_page(event_id="release-event-1", round_id=1)

    assert excinfo.value.code == "CAPABILITY_BLOCKED"
    assert controller._live_pages == {}  # noqa: SLF001


def test_setup_passes_the_authoritative_repository_root_to_bootstrap(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, Path]] = []

    def bootstrap(profile: str, *, repo_root: Path) -> dict[str, object]:
        calls.append((profile, repo_root))
        return {
            "status": "ready",
            "fresh_task_required": True,
            "dependency_lock": str(tmp_path / "dependency-lock.json"),
        }

    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message()),
        bootstrap_runner=bootstrap,
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    result = controller.start_setup()

    assert result["status"] == "FRESH_TASK_REQUIRED"
    assert calls == [("release-approval", REPO_ROOT)]


def test_setup_status_and_doctor_share_the_os_scheduler_and_controller(
    tmp_path: Path,
) -> None:
    scheduler = FakeScheduler()
    bootstrap_calls: list[tuple[str, Path]] = []

    def bootstrap(profile: str, *, repo_root: Path) -> dict[str, object]:
        bootstrap_calls.append((profile, repo_root))
        return {
            "status": "ready",
            "fresh_task_required": False,
            "dependency_lock": str(tmp_path / "dependency-lock.json"),
        }

    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        config_path=tmp_path / "release-approval.json",
        mail_gateway=FakeMailGateway(_message()),
        bootstrap_runner=bootstrap,
        scheduler=scheduler,
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )

    setup = controller.start_setup()
    status = controller.status()
    doctor = controller.doctor()

    assert setup["status"] == "ready"
    assert setup["scheduler"]["installed"] is True
    assert setup["first_run"]["created_pages"] == 0
    assert bootstrap_calls == [("release-approval", REPO_ROOT)]
    assert scheduler.calls == [
        ("install", {"mode": "auto"}),
        ("status", {"mode": "auto"}),
        ("status", {"mode": "auto"}),
        ("status", {"mode": "auto"}),
    ]
    assert status["status"] == "ready"
    assert status["pending_count"] == 1
    assert doctor["status"] == "ready"
    assert doctor["codex_required"] is False


def test_kernel_run_lock_rejects_overlap_and_recovers_orphan_metadata(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "run-once.lock"
    first = RunOnceLock(lock_path, owner="owner-a", now_fn=lambda: FIXED_NOW)
    second = RunOnceLock(lock_path, owner="owner-b", now_fn=lambda: FIXED_NOW)

    assert first.acquire() == {"status": "acquired", "recovered_owner": None}
    assert second.acquire() == {"status": "active", "owner": "owner-a"}
    first.release()

    first.metadata_path.write_text(
        json.dumps({"status": "active", "owner": "crashed-owner"}),
        encoding="utf-8",
    )
    recovered = RunOnceLock(
        lock_path,
        owner="owner-c",
        now_fn=lambda: FIXED_NOW,
    )
    assert recovered.acquire() == {
        "status": "acquired",
        "recovered_owner": "crashed-owner",
    }
    recovered.release()

def test_controller_overlap_is_a_zero_side_effect_busy_result(tmp_path: Path) -> None:
    gateway = FakeMailGateway(_message())
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=gateway,
        browser_opener=lambda _url: None,
        now_fn=lambda: FIXED_NOW,
    )
    active_lock = RunOnceLock(
        tmp_path / "run-once.lock",
        owner="other-process",
        now_fn=lambda: FIXED_NOW,
    )
    active_lock.acquire()
    before_audit = controller.store.connection.execute(
        "SELECT COUNT(*) FROM audit_events"
    ).fetchone()[0]

    try:
        result = controller.run_once()
    finally:
        active_lock.release()

    after_audit = controller.store.connection.execute(
        "SELECT COUNT(*) FROM audit_events"
    ).fetchone()[0]
    assert result == {"status": "RUN_ALREADY_ACTIVE", "busy": True}
    assert gateway.search_calls == 0
    assert after_audit == before_audit


def test_restart_can_open_page_from_stored_request_without_persisted_bearer(
    tmp_path: Path,
) -> None:
    store = ReleaseApprovalStore(tmp_path / "state.sqlite3")
    store.record_request(_request())
    store.append_audit_event(
        "request_authenticated",
        {
            "event_id": "release-event-1",
            "round_id": 1,
            "role_id": "release-manager",
            "message_id": "<request-1@example.com>",
            "raw_headers_sha256": "a" * 64,
        },
        created_at="2026-07-16T01:02:03Z",
    )
    store.close()
    opened: list[str] = []
    controller = ReleaseApprovalController(
        config=_config(tmp_path),
        mail_gateway=FakeMailGateway(_message()),
        browser_opener=opened.append,
        now_fn=lambda: FIXED_NOW,
    )
    try:
        result = controller.open_page(event_id="release-event-1", round_id=1)

        assert result["status"] == "ready"
        assert len(opened) == 1
        page_state = Path(result["page_html_path"]).with_name("page-state.json")
        state_text = page_state.read_text(encoding="utf-8")
        assert "nonce_sha256" in state_text
        assert "url_key" not in state_text
        assert opened[0] not in state_text
    finally:
        _close_pages(controller)
