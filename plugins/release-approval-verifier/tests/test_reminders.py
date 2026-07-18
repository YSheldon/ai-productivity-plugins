from __future__ import annotations

import sys
from datetime import datetime, time, timedelta, timezone
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from reminder_policy import ReminderPolicy
from role_snapshot import RoleRecord
from verifier_service import VerifierService
from verifier_store import VerifierStore


AUDIT_KEY = b"r" * 32


def _request() -> dict[str, object]:
    return {
        "event_id": "evt-reminder",
        "round_id": 3,
        "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64,
        "manifest_digest": "sha256:" + "3" * 64,
        "request_digest": "sha256:" + "4" * 64,
        "role_snapshot_digest": "sha256:" + "5" * 64,
        "required_roles": ["release-manager", "security-reviewer"],
        "original_message_id": "<request@example.com>",
        "references": ["<root@example.com>", "<request@example.com>"],
        "subject": "[Release request] task-client-20260716",
        "created_at": "2026-07-16T01:00:00Z",
        "expires_at": "2026-07-17T01:00:00Z",
    }


def _roles() -> tuple[RoleRecord, ...]:
    return (
        RoleRecord("release-manager", "manager@example.com", True, True),
        RoleRecord("security-reviewer", "security@example.com", True, True),
    )


def _policy(*, maximum: int = 3) -> ReminderPolicy:
    return ReminderPolicy(
        initial_delay=timedelta(hours=1),
        repeat=timedelta(hours=4),
        maximum=maximum,
        working_days=("Mon", "Tue", "Wed", "Thu", "Fri"),
        working_start=time(9, 0),
        working_end=time(18, 0),
        timezone_name="Asia/Shanghai",
    )


def _record_decision(store: VerifierStore, role: RoleRecord, *, decision: str = "HOLD") -> None:
    store.record_decision(
        decision_id=f"decision-{role.role_id}",
        event_id="evt-reminder",
        round_id=3,
        role_id=role.role_id,
        decision=decision,
        normalized_text=decision.lower(),
        ambiguous=False,
        approver_email=role.email,
        authentication_path="dmarc",
        source_message_id=f"<{role.role_id}@example.com>",
        raw_headers_sha256="a" * 64,
        decided_at="2026-07-16T01:30:00Z",
    )


def test_policy_observes_initial_repeat_working_hours_and_maximum() -> None:
    policy = _policy()
    created = datetime(2026, 7, 16, 1, 0, tzinfo=timezone.utc)

    assert policy.due(created, created + timedelta(minutes=59), ()) is False
    assert policy.due(created, created + timedelta(hours=1), ()) is True
    assert policy.due(created, created + timedelta(hours=10), ()) is False

    accepted = (created + timedelta(hours=1),)
    assert policy.due(created, created + timedelta(hours=4, minutes=59), accepted) is False
    assert policy.due(created, created + timedelta(hours=5), accepted) is True

    maximum = (
        created + timedelta(hours=1),
        created + timedelta(hours=5),
        created + timedelta(hours=9),
    )
    assert policy.due(created, created + timedelta(days=1, hours=1), maximum) is False


def test_service_reminds_only_missing_roles_in_original_thread(tmp_path: Path) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    roles = _roles()
    _record_decision(store, roles[0])
    calls: list[tuple[object, str]] = []

    def smtp_sender(message, *, idempotency_key: str):
        calls.append((message, idempotency_key))
        return {"accepted": True, "message_id": "<reminder@example.com>"}

    service = VerifierService(store=store, audit_key=AUDIT_KEY, smtp_sender=smtp_sender)
    outcomes = service.send_due_reminders(
        _request(),
        roles,
        policy=_policy(),
        now=datetime(2026, 7, 16, 2, 0, tzinfo=timezone.utc),
    )

    assert [outcome.role_id for outcome in outcomes] == ["security-reviewer"]
    assert outcomes[0].accepted is True
    assert len(calls) == 1
    message, _ = calls[0]
    assert message["To"] == "security@example.com"
    assert message["In-Reply-To"] == "<request@example.com>"
    assert message["References"] == "<root@example.com> <request@example.com>"
    body = message.get_content()
    assert "local approval page" in body
    assert "\u540c\u610f" in body and "\u5f85\u8bc4\u4f30" in body and "\u9a73\u56de" in body
    assert "urgent" not in body.lower()
    assert store.get_accepted_reminder_times("evt-reminder", 3, "release-manager") == ()
    assert len(store.get_accepted_reminder_times("evt-reminder", 3, "security-reviewer")) == 1


def test_service_waits_past_one_hour_then_dedupes_accepted_reminder_for_only_missing_role(
    tmp_path: Path,
) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    roles = _roles()
    _record_decision(store, roles[0])
    calls: list[tuple[object, str]] = []

    def smtp_sender(message, *, idempotency_key: str):
        calls.append((message, idempotency_key))
        return {"accepted": True, "message_id": "<accepted@example.com>"}

    service = VerifierService(store=store, audit_key=AUDIT_KEY, smtp_sender=smtp_sender)
    before_due = service.send_due_reminders(
        _request(),
        roles,
        policy=_policy(),
        now=datetime(2026, 7, 16, 1, 59, tzinfo=timezone.utc),
    )
    first_due = service.send_due_reminders(
        _request(),
        roles,
        policy=_policy(),
        now=datetime(2026, 7, 16, 2, 1, tzinfo=timezone.utc),
    )
    duplicate_window = service.send_due_reminders(
        _request(),
        roles,
        policy=_policy(),
        now=datetime(2026, 7, 16, 5, 59, tzinfo=timezone.utc),
    )

    assert before_due == ()
    assert [outcome.role_id for outcome in first_due] == ["security-reviewer"]
    assert first_due[0].accepted is True
    assert duplicate_window == ()
    assert len(calls) == 1
    message, idempotency_key = calls[0]
    assert message["To"] == "security@example.com"
    assert message["In-Reply-To"] == "<request@example.com>"
    assert message["References"] == "<root@example.com> <request@example.com>"
    assert idempotency_key == first_due[0].idempotency_key
    assert store.get_accepted_reminder_times("evt-reminder", 3, "release-manager") == ()
    assert len(store.get_accepted_reminder_times("evt-reminder", 3, "security-reviewer")) == 1


def test_smtp_refusal_and_failure_reuse_idempotency_key_without_incrementing_count(tmp_path: Path) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    role = _roles()[1]
    results: list[object] = [
        {"accepted": False, "refused": {role.email: "550 refused"}},
        RuntimeError("temporary SMTP failure"),
        {"accepted": True, "message_id": "<accepted@example.com>"},
    ]
    keys: list[str] = []

    def smtp_sender(message, *, idempotency_key: str):
        keys.append(idempotency_key)
        result = results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    service = VerifierService(store=store, audit_key=AUDIT_KEY, smtp_sender=smtp_sender)
    now = datetime(2026, 7, 16, 2, 0, tzinfo=timezone.utc)

    first = service.send_due_reminders(_request(), (role,), policy=_policy(), now=now)
    assert first[0].accepted is False
    assert store.get_accepted_reminder_times("evt-reminder", 3, role.role_id) == ()

    second = service.send_due_reminders(_request(), (role,), policy=_policy(), now=now)
    assert second[0].accepted is False
    assert store.get_accepted_reminder_times("evt-reminder", 3, role.role_id) == ()

    third = service.send_due_reminders(_request(), (role,), policy=_policy(), now=now)
    assert third[0].accepted is True
    assert len(store.get_accepted_reminder_times("evt-reminder", 3, role.role_id)) == 1
    assert keys[0] == keys[1] == keys[2]

    assert service.send_due_reminders(
        _request(),
        (role,),
        policy=_policy(),
        now=now + timedelta(hours=3, minutes=59),
    ) == ()
