from __future__ import annotations

import hashlib
import json
import pytest
import shutil
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
VERIFIER_ROOT = Path(__file__).resolve().parents[1]


def _resolve_plugin_root(plugin_name: str) -> Path | None:
    source_root = REPO_ROOT / "plugins" / plugin_name
    if (source_root / "src").is_dir():
        return source_root
    cache_root = REPO_ROOT / plugin_name
    if not cache_root.is_dir():
        return None
    candidates = sorted(
        (child for child in cache_root.iterdir() if (child / "src").is_dir()),
        key=lambda child: child.name,
    )
    return candidates[-1] if candidates else None


PRODUCT_ROOT = _resolve_plugin_root("product-release-gate")
if PRODUCT_ROOT is None:
    pytest.skip("product-release-gate sibling package is unavailable", allow_module_level=True)
sys.path.insert(0, str(VERIFIER_ROOT / "src"))
sys.path.insert(0, str(PRODUCT_ROOT / "src"))

from lark_audit import AuditWriteResult  # noqa: E402
from product_gate_adapter import ProductGateMcpAdapter  # noqa: E402
from release_gate_production import ProductionReleaseController  # noqa: E402
from release_gate_runtime import ReleaseGateWorkflowRuntime  # noqa: E402
from role_snapshot import RoleRecord, RoleSnapshot  # noqa: E402
from verifier_config import (  # noqa: E402
    AuditDocumentConfig,
    AuthenticationPolicyConfig,
    MailAccountConfig,
    ReminderPolicyConfig,
    StaticRoleSourceConfig,
    VerifierConfig,
    WorkingHoursConfig,
)
from verifier_controller import VerifierController  # noqa: E402


ROLES = (
    RoleRecord("release-director", "director@example.com", True, True),
    RoleRecord("test-lead", "test@example.com", True, True),
)
ROLE_DIGEST = "sha256:" + "5" * 64


class CapturingProductMail:
    def __init__(self) -> None:
        self.payloads: list[dict[str, Any]] = []

    def send_email(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.payloads.append(dict(payload))
        return {
            "sent": True,
            "message_id": payload["message_id"],
            "refused": {},
        }


class FakeVerifierMail:
    def require_thread_reply_capability(self, _payload: dict[str, Any]) -> None:
        return None

    def require_authenticated_readback_capability(
        self, _payload: dict[str, Any]
    ) -> None:
        return None

    def send_email(self, _payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "sent": True,
            "message_id": "<reminder@example.com>",
            "refused": {},
        }


class FakeAudit:
    def write(self, record: Any) -> AuditWriteResult:
        return AuditWriteResult(
            status="AUDIT_WRITTEN",
            state_advance_allowed=True,
            cloud_readback_verified=True,
            audit_payload_digest="sha256:" + "6" * 64,
            recorded_state=record.state,
        )


class FakeScheduler:
    def status(self, *, mode: str = "auto") -> dict[str, Any]:
        return {"status": "ready", "mode": mode, "installed": True}


def _copy_runtime(tmp_path: Path) -> tuple[Path, dict[str, Path]]:
    runtime_root = tmp_path / "runtime-repo"
    copied: dict[str, Path] = {}
    for plugin_name in (
        "product-release-gate",
        "release-approval-verifier",
        "imap-smtp-mail",
    ):
        source_root = _resolve_plugin_root(plugin_name)
        assert source_root is not None
        source = source_root / "src"
        target = runtime_root / "plugins" / plugin_name / "src"
        shutil.copytree(source, target)
    product_root = _resolve_plugin_root("product-release-gate")
    assert product_root is not None
    shutil.copytree(
        product_root / "scripts",
        runtime_root / "plugins/product-release-gate/scripts",
    )
    copied["product_mcp"] = (
        runtime_root
        / "plugins/product-release-gate/src/release_gate_mcp.py"
    )
    copied["verifier_bridge"] = (
        runtime_root
        / "plugins/release-approval-verifier/src/verifier_product_gate_bridge.py"
    )
    copied["mail_cli"] = (
        runtime_root / "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py"
    )
    lock_path = runtime_root / "dependency-lock.product-release-gate.json"
    lock_path.write_text(
        json.dumps(
            {
                "profile": "product-release-gate",
                "plugins": [
                    {
                        "name": "product-release-gate",
                        "plugin_root": "plugins/product-release-gate",
                        "entrypoints": [
                            _entry("product_mcp", copied["product_mcp"])
                        ],
                    },
                    {
                        "name": "release-approval-verifier",
                        "plugin_root": "plugins/release-approval-verifier",
                        "entrypoints": [
                            _entry(
                                "verifier_bridge",
                                copied["verifier_bridge"],
                            )
                        ],
                    },
                    {
                        "name": "imap-smtp-mail",
                        "plugin_root": "plugins/imap-smtp-mail",
                        "entrypoints": [
                            _entry("mail_cli", copied["mail_cli"])
                        ],
                    },
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return lock_path, copied


def _entry(_name: str, path: Path) -> dict[str, str]:
    relative = path.relative_to(path.parents[3]).as_posix()
    return {
        "kind": "runtime_entrypoint",
        "path": relative,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _verifier_payload(
    *, state_dir: Path, lock_path: Path, product_config: Path
) -> dict[str, Any]:
    return {
        "mode": "test",
        "role_source": {
            "type": "static",
            "roles": [
                {
                    "role_id": role.role_id,
                    "email": role.email,
                    "required": role.required,
                    "enabled": role.enabled,
                }
                for role in ROLES
            ],
        },
        "release_group": "release@example.com",
        "mailbox": "INBOX",
        "verifier_mail_account": {
            "profile": "work",
            "email": "verifier@example.com",
        },
        "event_expiry_hours": 24,
        "poll_minutes": 60,
        "timezone": "UTC",
        "working_hours": {
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
            "start": "00:00",
            "end": "23:59",
        },
        "reminder_policy": {
            "initial_delay_minutes": 60,
            "repeat_minutes": 240,
            "maximum": 3,
        },
        "authentication_policy": {
            "accepted_paths": ["dmarc", "dkim", "spf"],
            "allowed_authserv_ids": ["mx.example.com"],
            "trusted_internal_header": "X-Trusted-Relay",
            "trusted_internal_value": "release-gateway",
        },
        "state_dir": str(state_dir),
        "dependency_lock": str(lock_path),
        "dependency_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "audit_document": {
            "url": "https://example.feishu.cn/wiki/release-audit"
        },
        "product_gate": {"config_path": str(product_config)},
    }
def _verifier_config(
    *, state_dir: Path, lock_path: Path, product_config: Path
) -> VerifierConfig:
    return VerifierConfig(
        mode="test",
        role_source=StaticRoleSourceConfig(kind="static", roles=ROLES),
        release_group="release@example.com",
        mailbox="INBOX",
        verifier_mail_account=MailAccountConfig(
            profile="work", email="verifier@example.com"
        ),
        event_expiry_hours=24,
        poll_minutes=60,
        timezone="UTC",
        working_hours=WorkingHoursConfig(
            days=("Mon", "Tue", "Wed", "Thu", "Fri"),
            start="00:00",
            end="23:59",
        ),
        reminder_policy=ReminderPolicyConfig(
            initial_delay_minutes=60,
            repeat_minutes=240,
            maximum=3,
        ),
        authentication_policy=AuthenticationPolicyConfig(
            accepted_paths=("dmarc", "dkim", "spf"),
            allowed_authserv_ids=("mx.example.com",),
            trusted_internal_header="X-Trusted-Relay",
            trusted_internal_value="release-gateway",
        ),
        state_dir=state_dir,
        dependency_lock=lock_path,
        dependency_lock_sha256=hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        audit_document=AuditDocumentConfig(
            url="https://example.feishu.cn/wiki/release-audit"
        ),
        product_gate_config_path=product_config,
    )


def _request_message(payload: dict[str, Any], *, now: datetime) -> EmailMessage:
    message = EmailMessage()
    message["From"] = "Release Bot <bot@example.com>"
    message["To"] = "release@example.com"
    message["Subject"] = payload["subject"]
    message["Date"] = format_datetime(now)
    message["Message-ID"] = payload["message_id"]
    for name, value in payload["headers"].items():
        message[name] = value
    message.set_content(payload["text"])
    return message


def _reply(
    *, role: RoleRecord, request: dict[str, Any], message_id: str, now: datetime
) -> EmailMessage:
    message = EmailMessage()
    message["Return-Path"] = f"<{role.email}>"
    message["From"] = f"Reviewer <{role.email}>"
    message["To"] = "release@example.com"
    message["Subject"] = f"Re: {request['subject']}"
    message["Date"] = format_datetime(now)
    message["Message-ID"] = message_id
    message["In-Reply-To"] = request["message_id"]
    message["References"] = request["message_id"]
    message["Authentication-Results"] = (
        "mx.example.com; dkim=pass header.d=example.com; "
        "dmarc=pass action=none header.from=example.com"
    )
    message["Received-SPF"] = "pass"
    message["X-RD-Event-Id"] = request["headers"]["X-RD-Event-Id"]
    message["X-RD-Round-Id"] = request["headers"]["X-RD-Round-Id"]
    message["X-RD-Manifest-Digest"] = request["headers"][
        "X-RD-Manifest-Digest"
    ]
    message["X-RD-Role-Snapshot-Digest"] = request["headers"][
        "X-RD-Role-Snapshot-Digest"
    ]
    message.set_content("同意")
    return message



def _write_deployment_adapter(tmp_path: Path) -> Path:
    path = tmp_path / "deployment_adapter.py"
    path.write_text(
        """
import json
import os
import sys

action = sys.argv[1]
stage = sys.argv[2]
digest = sys.argv[3]
if action == "deploy":
    target = sys.argv[4]
    print(json.dumps({
        "result": "PASS",
        "deployment_ref": f"deploy:{stage}:1",
        "target_ref": target,
        "rollback_ref": f"rollback:{stage}:1",
        "deployed_manifest_r_digest": digest,
    }))
elif action == "verify":
    target = sys.argv[4]
    result = (
        "FAIL"
        if os.environ.get("E2E_FAIL_STAGE") == stage
        else "PASS"
    )
    print(json.dumps({
        "result": result,
        "verification_ref": f"verify:{stage}:1",
        "observed_manifest_r_digest": digest,
        "target_ref": target,
    }))
elif action == "rollback":
    deployment_ref, rollback_ref, target = sys.argv[4:7]
    print(json.dumps({
        "result": "PASS",
        "deployment_ref": deployment_ref,
        "rollback_ref": rollback_ref,
        "target_ref": target,
        "restored_ref": f"baseline:{stage}",
        "rollback_receipt_ref": f"rollback-receipt:{stage}:1",
    }))
elif action == "rollback_verify":
    deployment_ref, rollback_ref, restored_ref, rollback_receipt_ref, target = (
        sys.argv[4:9]
    )
    print(json.dumps({
        "result": "PASS",
        "deployment_ref": deployment_ref,
        "rollback_ref": rollback_ref,
        "restored_ref": restored_ref,
        "target_ref": target,
        "verification_ref": f"rollback-verify:{stage}:1",
        "rollback_receipt_ref": rollback_receipt_ref,
    }))
elif action == "readback":
    target = sys.argv[4]
    print(json.dumps({
        "result": "PASS",
        "readback_ref": "production:readback:1",
        "observed_manifest_r_digest": digest,
        "target_ref": target,
    }))
else:
    raise SystemExit(2)
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def _deployment_command(adapter: Path, action: str) -> list[str]:
    command = [
        sys.executable,
        str(adapter),
        action,
        "{stage}",
        "{manifest_r_digest}",
    ]
    if action in {"deploy", "verify", "readback"}:
        command.append("{target_ref}")
    elif action == "rollback":
        command.extend(
            ["{deployment_ref}", "{rollback_ref}", "{target_ref}"]
        )
    elif action == "rollback_verify":
        command.extend(
            [
                "{deployment_ref}",
                "{rollback_ref}",
                "{restored_ref}",
                "{rollback_receipt_ref}",
                "{target_ref}",
            ]
        )
    return command


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_deployment_lock(tmp_path: Path, adapter: Path) -> tuple[Path, str]:
    commands = {
        action: _deployment_command(adapter, action)
        for action in (
            "deploy",
            "verify",
            "rollback",
            "rollback_verify",
            "readback",
        )
    }
    lock_path = tmp_path / "deployment-adapter.lock.json"
    lock_payload = {
        "schema_version": 1,
        "root": ".",
        "commands": {
            command_id: {
                "argv_template": argv,
                "entrypoints": [
                    {
                        "argv_index": 0,
                        "path": sys.executable,
                        "sha256": _sha256(Path(sys.executable)),
                    },
                    {
                        "argv_index": 1,
                        "path": adapter.name,
                        "sha256": _sha256(adapter),
                    },
                ],
            }
            for command_id, argv in commands.items()
        },
    }
    lock_path.write_text(json.dumps(lock_payload, sort_keys=True), encoding="utf-8")
    return lock_path, _sha256(lock_path)


def test_real_mcp_handoff_authorizes_once_and_survives_restart(
    tmp_path: Path, monkeypatch
) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    lock_path, copied = _copy_runtime(tmp_path)
    lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    product_config = tmp_path / "product" / "config.json"
    verifier_config = tmp_path / "verifier" / "config.json"
    verifier_state = tmp_path / "verifier" / "state"
    product_events = tmp_path / "product" / "events"
    product_state = tmp_path / "product" / "state"
    deployment_adapter = _write_deployment_adapter(tmp_path)
    deployment_lock_path, deployment_lock_digest = _write_deployment_lock(tmp_path, deployment_adapter)
    source_artifact = tmp_path / "input" / "product.bin"
    source_artifact.parent.mkdir(parents=True)
    source_artifact.write_bytes(b"production-candidate-e2e")
    product_config.parent.mkdir(parents=True)
    verifier_config.parent.mkdir(parents=True)

    monkeypatch.setenv(
        "RELEASE_APPROVAL_VERIFIER_AUDIT_KEY",
        "verifier-audit-key-for-e2e-32-bytes",
    )
    monkeypatch.setenv(
        "PRODUCT_RELEASE_GATE_AUDIT_KEY",
        "product-audit-key-for-e2e-32-bytes",
    )
    monkeypatch.setenv(
        "PRODUCT_RELEASE_GATE_AUTH_KEY",
        "product-auth-key-for-e2e-32-bytes!",
    )
    monkeypatch.setenv(
        "IMAP_SMTP_MAIL_ACCOUNTS_JSON",
        json.dumps(
            [
                {
                    "name": "work",
                    "provider": "custom",
                    "email": "verifier@example.com",
                    "username": "verifier@example.com",
                    "password": "test-only-secret",
                    "imap": {
                        "host": "imap.example.com",
                        "port": 993,
                        "secure": True,
                    },
                    "smtp": {
                        "host": "smtp.example.com",
                        "port": 465,
                        "secure": True,
                    },
                }
            ]
        ),
    )

    product_payload = {
        "storage_dir": str(product_events),
        "runtime": {
            "state_dir": str(product_state),
            "poll_minutes": 60,
            "scheduler_mode": "auto",
            "auto_authorize_verified_pre_release": True,
            "authorization_requester": "rd-flywheel",
        },
        "policy": {
            "allowed_extensions": [".bin"],
            "require_source_ref": False,
            "require_signature": False,
            "require_cloud_scan": False,
            "auto_approve_risk_levels": ["standard"],
        },
        "test": {"command": [sys.executable, "-c", "print('{}')"]},
        "production": {
            "enabled": True,
            "audit": {"key_env": "PRODUCT_RELEASE_GATE_AUDIT_KEY"},
            "authorization": {
                "key_env": "PRODUCT_RELEASE_GATE_AUTH_KEY",
                "ttl_seconds": 3600,
                "verify_command": [],
            },
            "deployment": {
                "stages": [
                    "preproduction",
                    "production_canary",
                    "production_full",
                ],
                "targets": {
                    "preproduction": "env:preproduction",
                    "production_canary": "env:production:canary",
                    "production_full": "env:production:full",
                },
                "dependency_lock": str(deployment_lock_path),
                "dependency_lock_sha256": deployment_lock_digest,
                "deploy_command": _deployment_command(
                    deployment_adapter, "deploy"
                ),
                "verify_command": _deployment_command(
                    deployment_adapter, "verify"
                ),
                "rollback_command": _deployment_command(
                    deployment_adapter, "rollback"
                ),
                "rollback_verify_command": _deployment_command(
                    deployment_adapter, "rollback_verify"
                ),
                "timeout_seconds": 30,
            },
            "readback": {
                "command": _deployment_command(
                    deployment_adapter, "readback"
                ),
                "timeout_seconds": 30,
            },
            "approval_workflow": {
                "mode": "unified_multi_role",
                "dependency_lock": str(lock_path),
                "dependency_lock_sha256": lock_digest,
                "verifier_config_path": str(verifier_config),
                "verify_command": [
                    sys.executable,
                    str(copied["verifier_bridge"]),
                    "--config",
                    str(verifier_config),
                    "--verification-ref",
                    "{verification_ref}",
                ],
                "timeout_seconds": 120,
                "mail": {
                    "profile": "work",
                    "release_group": "release@example.com",
                    "module": "kernel",
                    "dependency_lock": str(lock_path),
                    "dependency_lock_sha256": lock_digest,
                    "command": [sys.executable, str(copied["mail_cli"])],
                    "timeout_seconds": 120,
                },
            },
        },
    }
    product_config.write_text(json.dumps(product_payload), encoding="utf-8")
    verifier_config.write_text(
        json.dumps(
            _verifier_payload(
                state_dir=verifier_state,
                lock_path=lock_path,
                product_config=product_config,
            )
        ),
        encoding="utf-8",
    )

    sent = CapturingProductMail()
    product = ProductionReleaseController(
        str(product_config), approval_mail_gateway=sent
    )
    product.create_submission(
        event_id="event-e2e",
        task_id="TASK-E2E-1",
        artifacts=[
            {
                "logical_name": "product.bin",
                "file_path": str(source_artifact),
                "source_ref": "commit:e2e",
            }
        ],
        source_ref="commit:e2e",
        rollback_ref="rollback:stable",
        risk_level="standard",
    )
    assert product.run_submission_gate("event-e2e")["overall"] == "PASS"
    product.record_test_result(
        "event-e2e",
        "PASS",
        "test-report:e2e",
    )
    product.build_final_release(
        "event-e2e",
        str(tmp_path / "product" / "final"),
    )
    assert product.run_release_gate("event-e2e")["status"] == "RELEASE_READY"
    product.request_unified_release_approval(
        event_id="event-e2e",
        requested_by="bot@example.com",
        target_scope="preproduction,production_canary,production_full",
        round_id=1,
        required_roles=[
            {
                "role_id": role.role_id,
                "email": role.email,
                "required": role.required,
            }
            for role in ROLES
        ],
        role_snapshot_digest=ROLE_DIGEST,
        expires_at=(now + timedelta(hours=4)).isoformat().replace(
            "+00:00", "Z"
        ),
    )
    request_mail = sent.payloads[0]
    verifier = VerifierController(
        config=_verifier_config(
            state_dir=verifier_state,
            lock_path=lock_path,
            product_config=product_config,
        ),
        config_path=verifier_config,
        now_fn=lambda: now,
        audit_key=b"verifier-audit-key-for-e2e-32-bytes",
        role_snapshot_fetcher=lambda: RoleSnapshot(
            document_url="https://example.feishu.cn/docx/release-roles",
            heading="## 审批角色",
            roles=ROLES,
            digest=ROLE_DIGEST,
        ),
        request_scanner=lambda: (
            _request_message(request_mail, now=now),
        ),
        reply_scanner=lambda: tuple(
            _reply(
                role=role,
                request=request_mail,
                message_id=f"<decision-{role.role_id}@example.com>",
                now=now + timedelta(minutes=5),
            )
            for role in ROLES
        ),
        mail_gateway=FakeVerifierMail(),
        audit_adapter=FakeAudit(),
        scheduler=FakeScheduler(),
        product_gate_adapter=ProductGateMcpAdapter(
            lock_path,
            product_config,
            dependency_lock_sha256=lock_digest,
        ),
    )

    verified = verifier.run_once()
    verified_replay = verifier.run_once()
    after_handoff_restart = ProductionReleaseController(str(product_config))
    requested = ReleaseGateWorkflowRuntime(
        after_handoff_restart, product_config
    ).run_once()
    after_request_restart = ProductionReleaseController(str(product_config))
    finalized = ReleaseGateWorkflowRuntime(
        after_request_restart, product_config
    ).run_once()
    restarted = ProductionReleaseController(str(product_config))
    replayed = ReleaseGateWorkflowRuntime(
        restarted, product_config
    ).run_once()
    preproduction = ProductionReleaseController(
        str(product_config)
    ).run_deployment_stage("event-e2e", "preproduction")
    canary = ProductionReleaseController(
        str(product_config)
    ).run_deployment_stage("event-e2e", "production_canary")
    full = ProductionReleaseController(
        str(product_config)
    ).run_deployment_stage("event-e2e", "production_full")
    readback = ProductionReleaseController(
        str(product_config)
    ).run_production_readback("event-e2e")
    event = ProductionReleaseController(str(product_config))._load_event(
        "event-e2e"
    )

    assert verified["status"] == "ready"
    assert verified["receipt"]["status"] == "APPROVAL_VERIFIED"
    assert verified["handoff"]["status"] == "PRE_RELEASE_REQUESTED"
    assert verified_replay["handoff"]["idempotent"] is True
    assert requested["authorization_requested"] == 1
    assert finalized["authorization_finalized"] == 1
    assert replayed["authorization_requested"] == 0
    assert replayed["authorization_finalized"] == 0
    assert preproduction["status"] == "PREPRODUCTION_VERIFIED"
    assert canary["status"] == "CANARY_VERIFIED"
    assert full["status"] == "PRODUCTION_DEPLOYED"
    assert readback["status"] == "PRODUCTION_VERIFIED"
    assert event["status"] == "PRODUCTION_VERIFIED"
    credential_path = Path(event["release_authorization"]["credential_path"])
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    assert credential["schema_version"] == 2
    assert (
        credential["claims"]["authorization_source"]
        == "unified_multi_role_receipt"
    )
    assert credential["claims"]["event_id"] == "event-e2e"
    assert len(list(product_events.glob("event-e2e/release-authorization.json"))) == 1
    deployment_receipts = list(
        product_events.glob("event-e2e/deployments/*.json")
    )
    assert len(deployment_receipts) == 3
    assert (
        product_events / "event-e2e" / "production-readback.json"
    ).is_file()

    rollback_mail = CapturingProductMail()
    rollback_product = ProductionReleaseController(
        str(product_config), approval_mail_gateway=rollback_mail
    )
    rollback_product.create_submission(
        event_id="event-rollback",
        task_id="TASK-E2E-ROLLBACK",
        artifacts=[
            {
                "logical_name": "product.bin",
                "file_path": str(source_artifact),
                "source_ref": "commit:e2e-rollback",
            }
        ],
        source_ref="commit:e2e-rollback",
        rollback_ref="rollback:stable",
        risk_level="standard",
    )
    assert rollback_product.run_submission_gate("event-rollback")[
        "overall"
    ] == "PASS"
    rollback_product.record_test_result(
        "event-rollback",
        "PASS",
        "test-report:e2e-rollback",
    )
    rollback_product.build_final_release(
        "event-rollback",
        str(tmp_path / "product" / "rollback-final"),
    )
    assert rollback_product.run_release_gate("event-rollback")[
        "status"
    ] == "RELEASE_READY"
    rollback_product.request_unified_release_approval(
        event_id="event-rollback",
        requested_by="bot@example.com",
        target_scope="preproduction,production_canary,production_full",
        round_id=1,
        required_roles=[
            {
                "role_id": role.role_id,
                "email": role.email,
                "required": role.required,
            }
            for role in ROLES
        ],
        role_snapshot_digest=ROLE_DIGEST,
        expires_at=(now + timedelta(hours=4)).isoformat().replace(
            "+00:00", "Z"
        ),
    )
    rollback_request = rollback_mail.payloads[0]
    rollback_verifier = VerifierController(
        config=_verifier_config(
            state_dir=verifier_state,
            lock_path=lock_path,
            product_config=product_config,
        ),
        config_path=verifier_config,
        now_fn=lambda: now,
        audit_key=b"verifier-audit-key-for-e2e-32-bytes",
        role_snapshot_fetcher=lambda: RoleSnapshot(
            document_url="https://example.feishu.cn/docx/release-roles",
            heading="## 审批角色",
            roles=ROLES,
            digest=ROLE_DIGEST,
        ),
        request_scanner=lambda: (
            _request_message(rollback_request, now=now),
        ),
        reply_scanner=lambda: tuple(
            _reply(
                role=role,
                request=rollback_request,
                message_id=f"<rollback-{role.role_id}@example.com>",
                now=now + timedelta(minutes=5),
            )
            for role in ROLES
        ),
        mail_gateway=FakeVerifierMail(),
        audit_adapter=FakeAudit(),
        scheduler=FakeScheduler(),
        product_gate_adapter=ProductGateMcpAdapter(
            lock_path,
            product_config,
            dependency_lock_sha256=lock_digest,
        ),
    )

    rollback_verified = rollback_verifier.run_once()
    rollback_requested = ReleaseGateWorkflowRuntime(
        ProductionReleaseController(str(product_config)),
        product_config,
    ).run_once()
    rollback_authorized = ReleaseGateWorkflowRuntime(
        ProductionReleaseController(str(product_config)),
        product_config,
    ).run_once()
    rollback_preproduction = ProductionReleaseController(
        str(product_config)
    ).run_deployment_stage("event-rollback", "preproduction")
    monkeypatch.setenv("E2E_FAIL_STAGE", "production_canary")
    try:
        rollback_canary = ProductionReleaseController(
            str(product_config)
        ).run_deployment_stage("event-rollback", "production_canary")
    finally:
        monkeypatch.delenv("E2E_FAIL_STAGE", raising=False)

    rollback_controller = ProductionReleaseController(str(product_config))
    rollback_event = rollback_controller._load_event("event-rollback")
    rollback_receipt = json.loads(
        (
            product_events
            / "event-rollback"
            / "deployments"
            / "production_canary-rollback.json"
        ).read_text(encoding="utf-8")
    )

    assert rollback_verified["status"] == "ready"
    assert rollback_requested["authorization_requested"] == 1
    assert rollback_authorized["authorization_finalized"] == 1
    assert rollback_preproduction["status"] == "PREPRODUCTION_VERIFIED"
    assert rollback_canary["status"] == "ROLLED_BACK"
    assert rollback_canary["result"] == "BLOCKED"
    assert rollback_canary["failure"]["phase"] == "verify"
    assert rollback_canary["rollback"]["result"] == "PASS"
    assert rollback_event["status"] == "ROLLED_BACK"
    assert rollback_event["deployment"]["stages"][
        "production_canary"
    ]["result"] == "ROLLED_BACK"
    assert rollback_event["deployment"]["stages"]["production_full"][
        "result"
    ] == "PENDING"
    assert not (
        product_events
        / "event-rollback"
        / "deployments"
        / "production_full.json"
    ).exists()
    assert rollback_controller._verify_receipt_seal(rollback_receipt)
    assert rollback_controller.verify_control_event_chain(
        "event-rollback"
    )["valid"]
