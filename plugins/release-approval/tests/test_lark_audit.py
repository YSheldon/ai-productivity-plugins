from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from subprocess import CompletedProcess

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PLUGIN_ROOT / "src" / "lark_audit.py"
MODULE_NAME = "release_approval_lark_audit"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
lark_audit = importlib.util.module_from_spec(SPEC)
sys.modules[MODULE_NAME] = lark_audit
SPEC.loader.exec_module(lark_audit)

AuditRecord = lark_audit.AuditRecord
LarkAuditAdapter = lark_audit.LarkAuditAdapter
SUPPORTED_EVENT_TYPES = lark_audit.SUPPORTED_EVENT_TYPES


def test_release_hold_requested_is_a_supported_audit_event() -> None:
    assert "RELEASE_HOLD_REQUESTED" in SUPPORTED_EVENT_TYPES


def _record(*, event_type: str = "REQUEST_CREATED", state: str = "APPROVAL_PENDING") -> object:
    return AuditRecord(
        event_id="release-20260716-001",
        round_id="round-02",
        event_type=event_type,
        manifest_digest="sha256:" + "1" * 64,
        role_snapshot_digest="sha256:" + "2" * 64,
        state=state,
        required_role_emails={
            "release-manager": "release-manager@example.com",
            "security-reviewer": "security-reviewer@example.com",
        },
        audit_payload={
            "created_at": "2026-07-16T08:00:00Z",
            "request_digest": "sha256:" + "3" * 64,
        },
    )


def _readback(markdown: str) -> str:
    return json.dumps(
        {"ok": True, "data": {"document": {"content": markdown}}},
        ensure_ascii=False,
    )


def test_write_uses_argument_arrays_then_fetches_and_verifies_all_bindings() -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_runner(args, **kwargs):
        calls.append((args, kwargs))
        if args[2] == "+update":
            return CompletedProcess(args, 0, stdout='{"ok":true}', stderr="")
        markdown = calls[0][0][calls[0][0].index("--content") + 1]
        return CompletedProcess(args, 0, stdout=_readback(markdown), stderr="")

    result = LarkAuditAdapter(
        "https://example.feishu.cn/docx/audit-ledger",
        required=True,
        runner=fake_runner,
    ).write(_record())

    assert result.status == "AUDIT_WRITTEN"
    assert result.state_advance_allowed is True
    assert result.cloud_readback_verified is True
    assert len(calls) == 2
    update_args, update_kwargs = calls[0]
    fetch_args, fetch_kwargs = calls[1]
    assert isinstance(update_args, list)
    assert update_args[:3] == ["lark-cli", "docs", "+update"]
    assert "append" in update_args
    assert isinstance(fetch_args, list)
    assert fetch_args[:3] == ["lark-cli", "docs", "+fetch"]
    assert result.audit_payload_digest in fetch_args
    assert update_kwargs["shell"] is False
    assert fetch_kwargs["shell"] is False

    markdown = update_args[update_args.index("--content") + 1]
    assert "event_id: `release-20260716-001`" in markdown
    assert "round_id: `round-02`" in markdown
    assert f"manifest_digest: `{'sha256:' + '1' * 64}`" in markdown
    assert f"role_snapshot_digest: `{'sha256:' + '2' * 64}`" in markdown
    assert "state: `APPROVAL_PENDING`" in markdown
    assert f"audit_payload_digest: `{result.audit_payload_digest}`" in markdown


def test_exit_zero_without_cloud_readback_blocks_required_audit() -> None:
    calls: list[list[str]] = []

    def fake_runner(args, **kwargs):
        calls.append(args)
        return CompletedProcess(args, 0, stdout="unrelated cloud text", stderr="")

    result = LarkAuditAdapter(
        "https://example.feishu.cn/docx/audit-ledger",
        required=True,
        runner=fake_runner,
    ).write(_record())

    assert [args[2] for args in calls] == ["+update", "+fetch"]
    assert result.status == "CAPABILITY_BLOCKED"
    assert result.state_advance_allowed is False
    assert result.cloud_readback_verified is False


def test_optional_failure_is_degraded_without_changing_failed_decision() -> None:
    def fake_runner(args, **kwargs):
        return CompletedProcess(args, 9, stdout="", stderr="write denied")

    result = LarkAuditAdapter(
        "https://example.feishu.cn/docx/audit-ledger",
        required=False,
        runner=fake_runner,
    ).write(_record(event_type="MAIL_DECISION", state="APPROVAL_REJECTED"))

    assert result.status == "AUDIT_DEGRADED"
    assert result.state_advance_allowed is True
    assert result.recorded_state == "APPROVAL_REJECTED"
    assert result.recorded_state != "APPROVAL_VERIFIED"


def test_privacy_minimization_excludes_secrets_names_local_keys_and_raw_authentication_results() -> None:
    captured: dict[str, str] = {}

    def fake_runner(args, **kwargs):
        if args[2] == "+update":
            captured["markdown"] = args[args.index("--content") + 1]
            return CompletedProcess(args, 0, stdout='{"ok":true}', stderr="")
        return CompletedProcess(args, 0, stdout=_readback(captured["markdown"]), stderr="")

    record = AuditRecord(
        event_id="release-20260716-privacy",
        round_id="round-01",
        event_type="APPROVAL_MESSAGE_QUARANTINED",
        manifest_digest="sha256:" + "4" * 64,
        role_snapshot_digest="sha256:" + "5" * 64,
        state="APPROVAL_PENDING",
        required_role_emails={"security-reviewer": "security-reviewer@example.com"},
        audit_payload={
            "display_name": "Private Person",
            "credentials": {"password": "secret-password", "token": "secret-token"},
            "localhost_url": "http://localhost:62201/?key=local-secret",
            "Authentication-Results": "dkim=pass raw-private-header",
            "sender_email": "unrelated@example.com",
            "approval_note": "Private Person unrelated@example.com",
            "status": "APPROVAL_PENDING Private Person unrelated@example.com",
            "authentication_evidence_digest": "sha256:" + "6" * 64,
            "reason_code": "THREAD_MISMATCH",
        },
    )

    result = LarkAuditAdapter(
        "https://example.feishu.cn/docx/audit-ledger",
        required=True,
        runner=fake_runner,
    ).write(record)

    assert result.status == "AUDIT_WRITTEN"
    markdown = captured["markdown"]
    assert "security-reviewer@example.com" in markdown
    for private_value in (
        "Private Person",
        "secret-password",
        "secret-token",
        "localhost",
        "local-secret",
        "raw-private-header",
        "unrelated@example.com",
    ):
        assert private_value not in markdown
    assert "authentication_evidence_digest" in markdown
    assert "THREAD_MISMATCH" in markdown


def test_readback_bindings_cannot_be_assembled_from_different_audit_entries() -> None:
    record = _record()
    digest = lark_audit.audit_payload_digest(record)
    cloud_text = f"""### Release approval audit
- contract: `release-approval-audit/v1`
- event_id: `{record.event_id}`
- round_id: `{record.round_id}`
- manifest_digest: `{record.manifest_digest}`

### Release approval audit
- role_snapshot_digest: `{record.role_snapshot_digest}`
- state: `{record.state}`
- audit_payload_digest: `{digest}`
"""

    def fake_runner(args, **kwargs):
        if args[2] == "+update":
            return CompletedProcess(args, 0, stdout='{"ok":true}', stderr="")
        return CompletedProcess(args, 0, stdout=cloud_text, stderr="")

    result = LarkAuditAdapter(
        "https://example.feishu.cn/docx/audit-ledger",
        required=True,
        runner=fake_runner,
    ).write(record)

    assert result.status == "CAPABILITY_BLOCKED"
    assert result.failure_reason == "LARK_READBACK_BINDING_MISMATCH"

@pytest.mark.parametrize("event_type", sorted(SUPPORTED_EVENT_TYPES))
def test_all_required_audit_event_types_render(event_type: str) -> None:
    markdown = lark_audit.render_audit_markdown(_record(event_type=event_type))

    assert f"event_type: `{event_type}`" in markdown
