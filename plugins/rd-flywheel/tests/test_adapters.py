import json
import hashlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import rd_flywheel_adapters as adapters  # noqa: E402
from rd_flywheel_adapters import (  # noqa: E402
    AdapterError,
    LarkDecisionRoleSnapshotFetcher,
    LockedGovernanceDecisionVerifier,
    LockedGovernanceMailPresenter,
    discover_adapter_profiles,
    load_governance_adapters,
    load_runtime_adapters,
)
from rd_flywheel_config import load_config  # noqa: E402
from rd_flywheel_protocol import CapabilityGapEvent, EvidenceReference, PRODUCTION_EVIDENCE_TYPES, compute_idempotency_key  # noqa: E402


def config(tmp_path):
    payload = {
        "schema_version": 2,
        "governance_inbox": str(tmp_path / "inbox"),
        "state_dir": str(tmp_path / "state"),
        "poll_minutes": 60,
        "timezone": "Asia/Shanghai",
        "tool_profiles": ["gitlab"],
        "approved_agent_profiles": ["agent-a"],
        "agent_profile": "agent-a",
        "protected_merge": {"tool_profile": "gitlab", "protected_branch_required": True},
        "notification": None,
        "decision_role_source": None,
        "dependency_lock": str(tmp_path / "lock.json"),
        "dependency_lock_sha256": "0" * 64,
        "decision_verifier_config": str(tmp_path / "verifier-config.json"),
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_config(path)


def event():
    payload = {
        "schema": "CapabilityGapEvent/v1",
        "originating_plugin": "release-approval",
        "originating_event_id": "event-1",
        "originating_round_id": 1,
        "checkpoint_digest": "a" * 64,
        "missing_capability": "mail.headers",
        "required_evidence": list(PRODUCTION_EVIDENCE_TYPES),
        "allowed_tool_profiles": ["gitlab"],
        "created_at": "2026-07-16T08:00:00Z",
    }
    payload["idempotency_key"] = compute_idempotency_key(payload)
    return CapabilityGapEvent.from_mapping(payload)


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, args, *, input_text=None, encoding=None):
        self.calls.append((list(args), input_text, encoding))
        if args[0] == "agent":
            output = {"candidate_id": "c1", "evidence": []}
        else:
            output = {"verified": True}
        return subprocess.CompletedProcess(args, 0, json.dumps(output), "")


def test_default_runner_applies_bounded_timeout(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, "{}", "")

    monkeypatch.delenv("RD_FLYWHEEL_COMMAND_TIMEOUT_SECONDS", raising=False)
    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    completed = adapters._default_runner(("adapter", "run"))

    assert completed.returncode == 0
    assert captured["args"] == ["adapter", "run"]
    assert captured["timeout"] == 1800
    assert captured["shell"] is False


def test_default_runner_rejects_unsafe_timeout_configuration(monkeypatch):
    monkeypatch.setenv("RD_FLYWHEEL_COMMAND_TIMEOUT_SECONDS", "0")

    with pytest.raises(AdapterError, match="30..86400"):
        adapters._default_runner(("adapter", "run"))


def test_environment_registry_discovers_profile_names_not_credentials():
    environ = {
        "RD_FLYWHEEL_AGENT_COMMANDS_JSON": json.dumps({"agent-b": ["b"], "agent-a": ["a"]}),
        "RD_FLYWHEEL_VERIFIER_COMMANDS_JSON": json.dumps({"tests": ["verify"]}),
    }
    discovered = discover_adapter_profiles(environ)
    assert discovered == ("agent-a", "agent-b")


def test_only_approved_agent_profile_is_loaded_and_commands_use_shell_free_argv(tmp_path):
    runner = Runner()
    environ = {
        "RD_FLYWHEEL_AGENT_COMMANDS_JSON": json.dumps(
            {"agent-a": ["agent", "--json"], "unapproved": ["bad"]}
        ),
        "RD_FLYWHEEL_VERIFIER_COMMANDS_JSON": json.dumps({"tests": ["verify-tests"]}),
    }
    agents, verifiers = load_runtime_adapters(config(tmp_path), environ=environ, runner=runner)

    result = agents["agent-a"](dict(event().payload))
    assert result["candidate_id"] == "c1"
    assert "unapproved" not in agents
    assert runner.calls[0][0] == ["agent", "--json"]
    assert json.loads(runner.calls[0][1])["schema"] == "CapabilityGapEvent/v1"

    reference = EvidenceReference(
        kind="tests",
        uri="file:///tests.json",
        sha256="b" * 64,
        verifier="agent-output",
        verified=False,
    )
    assert verifiers["tests"](reference, event()) == {"verified": True}


def test_invalid_or_nonzero_adapter_configuration_fails_closed(tmp_path):
    with pytest.raises(AdapterError):
        load_runtime_adapters(
            config(tmp_path),
            environ={"RD_FLYWHEEL_AGENT_COMMANDS_JSON": '{"agent-a":"shell string"}'},
        )

    def failing(args, **kwargs):
        return subprocess.CompletedProcess(args, 9, "", "provider unavailable")

    agents, _ = load_runtime_adapters(
        config(tmp_path),
        environ={"RD_FLYWHEEL_AGENT_COMMANDS_JSON": '{"agent-a":["agent"]}'},
        runner=failing,
    )
    with pytest.raises(AdapterError, match="provider unavailable"):
        agents["agent-a"](dict(event().payload))


def governance_request():
    return {
        "contract": "ReleaseAuthorizationRequest/v1",
        "authority_scope": "RD_FLYWHEEL_GOVERNANCE",
        "event_id": "event-1",
        "round_id": 3,
        "task": "cloud.scan",
        "module": "submission-gate",
        "source_ref": "capability-17",
        "checkpoint_digest": "a" * 64,
        "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64,
        "manifest_digest": "sha256:" + "3" * 64,
        "request_digest": "sha256:" + "4" * 64,
        "role_snapshot_digest": "sha256:" + "5" * 64,
        "required_roles": ["rd-director", "test-lead"],
        "expires_at": "2026-08-13T08:00:00Z",
        "requested_at": "2026-08-12T08:00:00Z",
        "original_message_id": "<governance-event-1@example.com>",
        "visual_companion": {
            "html_sha256": "sha256:" + "2" * 64,
            "authority": "DESIGN_CONSENT_ONLY",
        },
        "governance_context": {
            "authority_boundary": "DESIGN_CONSENT_ONLY",
            "missing_capability": "cloud.scan",
            "originating_plugin": "submission-gate",
            "originating_event_id": "capability-17",
            "checkpoint_digest": "a" * 64,
            "required_evidence": ["tests", "security_review", "release_readback"],
            "visual_companion_html_sha256": "sha256:" + "2" * 64,
        },
    }


def test_lark_role_fetcher_uses_exact_user_markdown_contract():
    calls = []
    markdown = """## 决策角色
| role_id | email | required | enabled |
| --- | --- | --- | --- |
| rd-director | director@example.com | true | true |
"""

    def runner(args, *, input_text=None, encoding=None):
        calls.append((tuple(args), input_text, encoding))
        return subprocess.CompletedProcess(args, 0, markdown, "")

    source = SimpleNamespace(
        document_url="https://example.feishu.cn/docx/roles",
        heading="## 决策角色",
    )
    snapshot = LarkDecisionRoleSnapshotFetcher(
        runner=runner,
        command_prefix=("lark-cli",),
    )(source)

    assert calls == [
        (
            (
                "lark-cli",
                "docs",
                "+fetch",
                "--api-version",
                "v2",
                "--doc",
                source.document_url,
                "--doc-format",
                "markdown",
                "--as",
                "user",
                "--format",
                "pretty",
            ),
            None,
            "utf-8",
        )
    ]
    assert snapshot.required_role_ids == ("rd-director",)


def test_governance_mail_presenter_sends_exact_scope_headers_and_recipient_order(tmp_path):
    calls = []
    request = governance_request()

    def runner(args, *, input_text=None, encoding=None):
        calls.append((tuple(args), json.loads(input_text), encoding))
        return subprocess.CompletedProcess(
            args,
            0,
            json.dumps(
                {
                    "ok": True,
                    "result": {
                        "sent": True,
                        "message_id": request["original_message_id"],
                        "refused": {},
                        "atomic_recipients": True,
                        "data_submitted": True,
                    },
                }
            )
            + "\n",
            "",
        )

    result = LockedGovernanceMailPresenter(
        tmp_path / "imap_smtp_mail_cli.py",
        runner=runner,
        clock=lambda: datetime(2026, 8, 12, 9, 0, tzinfo=timezone.utc),
    )(
        {
            "request": request,
            "recipients": ["group@example.com", "director@example.com"],
            "mail_profile": "corp-mail",
        }
    )

    assert result == {
        "status": "accepted",
        "message_id": request["original_message_id"],
        "refused": {},
        "atomic_recipients": True,
        "data_submitted": True,
        "recipients": ["group@example.com", "director@example.com"],
        "accepted_at": "2026-08-12T09:00:00Z",
    }
    command, payload, encoding = calls[0]
    assert command[0] == sys.executable
    assert payload["tool"] == "send_email"
    arguments = payload["arguments"]
    assert arguments["to"] == ["group@example.com", "director@example.com"]
    assert arguments["dry_run"] is False
    assert arguments["atomic_recipients"] is True
    assert arguments["message_id"] == request["original_message_id"]
    assert arguments["headers"]["X-RD-Authority-Scope"] == "RD_FLYWHEEL_GOVERNANCE"
    assert arguments["headers"]["X-RD-Request-Digest"] == request["request_digest"]
    assert "生产完成证据：tests、security_review、release_readback" in arguments["text"]
    assert request["governance_context"]["visual_companion_html_sha256"] in arguments["text"]
    assert "attachments" not in arguments
    assert encoding == "utf-8"


def test_governance_mail_presenter_rejects_partial_smtp_acceptance(tmp_path):
    request = governance_request()

    def runner(args, **kwargs):
        return subprocess.CompletedProcess(
            args,
            0,
            json.dumps(
                {
                    "ok": True,
                    "result": {
                        "sent": True,
                        "message_id": request["original_message_id"],
                        "refused": {"director@example.com": [550, "Rejected"]},
                        "atomic_recipients": True,
                        "data_submitted": False,
                    },
                }
            )
            + "\n",
            "",
        )

    result = LockedGovernanceMailPresenter(
        tmp_path / "imap_smtp_mail_cli.py",
        runner=runner,
    )(
        {
            "request": request,
            "recipients": ["group@example.com", "director@example.com"],
            "mail_profile": "corp-mail",
        }
    )

    assert result["status"] == "rejected"
    assert result["refused"] == {"director@example.com": [550, "Rejected"]}


def test_governance_mail_presenter_rejects_non_atomic_success(tmp_path):
    request = governance_request()

    def runner(args, **kwargs):
        return subprocess.CompletedProcess(
            args,
            0,
            json.dumps(
                {
                    "ok": True,
                    "result": {
                        "sent": True,
                        "message_id": request["original_message_id"],
                        "refused": {},
                        "atomic_recipients": False,
                        "data_submitted": True,
                    },
                }
            )
            + "\n",
            "",
        )

    result = LockedGovernanceMailPresenter(
        tmp_path / "imap_smtp_mail_cli.py",
        runner=runner,
    )(
        {
            "request": request,
            "recipients": ["group@example.com", "director@example.com"],
            "mail_profile": "corp-mail",
        }
    )

    assert result["status"] == "rejected"
    assert result["atomic_recipients"] is False


def test_governance_decision_verifier_requires_independent_receipt_verification(tmp_path):
    request = governance_request()
    calls = []
    receipt_path = tmp_path / "receipt.json"
    receipt = {
        "contract": "ApprovalVerificationReceipt/v1",
        "status": "APPROVAL_VERIFIED",
    }

    def runner(args, *, input_text=None, encoding=None):
        calls.append(tuple(args))
        if "run-once" in args:
            payload = {"status": "GOVERNANCE_VERIFIED"}
        elif "get-event" in args:
            payload = {
                "status": "ready",
                "receipt": {
                    "status": "APPROVAL_VERIFIED",
                    "receipt_path": str(receipt_path),
                },
            }
        else:
            payload = {"status": "APPROVAL_VERIFIED", "verified": True, "receipt": receipt}
        return subprocess.CompletedProcess(args, 0, json.dumps(payload) + "\n", "")

    result = LockedGovernanceDecisionVerifier(
        tmp_path / "verifier_cli.py",
        tmp_path / "verifier-config.json",
        runner=runner,
    )(request)

    assert result == {
        "verified": True,
        "status": "APPROVAL_VERIFIED",
        "verifier": "release-approval-verifier",
        "receipt": receipt,
    }
    assert any("run-once" in call for call in calls)
    assert any("get-event" in call for call in calls)
    assert any("verify-receipt" in call for call in calls)
    assert all("--config" in call for call in calls)


def _governance_config_with_lock(tmp_path):
    mail_entry = tmp_path / "plugins" / "imap-smtp-mail" / "src" / "imap_smtp_mail_cli.py"
    verifier_entry = (
        tmp_path
        / "plugins"
        / "release-approval-verifier"
        / "src"
        / "verifier_cli.py"
    )
    mail_entry.parent.mkdir(parents=True)
    verifier_entry.parent.mkdir(parents=True)
    mail_entry.write_text("print('mail')\n", encoding="utf-8")
    verifier_entry.write_text("print('verifier')\n", encoding="utf-8")
    lock = {
        "plugins": [
            {
                "name": "imap-smtp-mail",
                "plugin_root": "plugins/imap-smtp-mail",
                "entrypoints": [
                    {
                        "path": "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py",
                        "sha256": hashlib.sha256(mail_entry.read_bytes()).hexdigest(),
                    }
                ],
            },
            {
                "name": "release-approval-verifier",
                "plugin_root": "plugins/release-approval-verifier",
                "entrypoints": [
                    {
                        "path": "plugins/release-approval-verifier/src/verifier_cli.py",
                        "sha256": hashlib.sha256(verifier_entry.read_bytes()).hexdigest(),
                    }
                ],
            },
        ]
    }
    lock_path = tmp_path / "dependency-lock.rd-flywheel.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    verifier_config = tmp_path / "verifier-config.json"
    verifier_config.write_text("{}\n", encoding="utf-8")
    payload = {
        "schema_version": 2,
        "governance_inbox": str(tmp_path / "inbox"),
        "state_dir": str(tmp_path / "state"),
        "poll_minutes": 60,
        "timezone": "Asia/Shanghai",
        "tool_profiles": [
            "gitlab",
            "imap-smtp-mail",
            "lark-cli",
            "release-approval-verifier",
        ],
        "approved_agent_profiles": [],
        "agent_profile": None,
        "protected_merge": {"tool_profile": "gitlab", "protected_branch_required": True},
        "notification": {
            "mail_profile": "corp-mail",
            "recipients": ["governance@example.com"],
        },
        "decision_role_source": {
            "type": "feishu",
            "document_url": "https://example.feishu.cn/docx/roles",
            "heading": "## 决策角色",
        },
        "dependency_lock": str(lock_path),
        "dependency_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "decision_verifier_config": str(verifier_config),
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    return load_config(config_path), mail_entry


def test_governance_adapter_loader_verifies_locked_entrypoints_and_detects_drift(tmp_path):
    locked_config, mail_entry = _governance_config_with_lock(tmp_path)
    role_fetcher, presenter, verifier = load_governance_adapters(
        locked_config,
        lark_command_prefix=("lark-cli",),
    )

    assert isinstance(role_fetcher, LarkDecisionRoleSnapshotFetcher)
    assert isinstance(presenter, LockedGovernanceMailPresenter)
    assert isinstance(verifier, LockedGovernanceDecisionVerifier)

    mail_entry.write_text("print('tampered')\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="entrypoint drift"):
        load_governance_adapters(locked_config, lark_command_prefix=("lark-cli",))
