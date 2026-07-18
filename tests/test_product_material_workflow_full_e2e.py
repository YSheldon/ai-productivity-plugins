from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "plugins" / "product-release-gate"

if str(PLUGIN_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_core import GateError  # noqa: E402
from release_gate_production import ProductionReleaseController  # noqa: E402


@dataclass(frozen=True)
class LockedWorkflowContext:
    controller: ProductionReleaseController
    workflow_lock_path: Path
    deployment_lock_path: Path
    mail_log_path: Path
    verifier_config_path: Path
    target_paths: dict[str, Path]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


@pytest.fixture()
def production_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "TEST_RELEASE_AUTH_KEY",
        "workflow-test-authorization-key-32-bytes",
    )
    monkeypatch.setenv(
        "TEST_RELEASE_AUDIT_KEY",
        "workflow-test-audit-ledger-key-32-bytes",
    )


def _write_locked_mail_cli(path: Path, mail_log_path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"""
import json
import sys
from pathlib import Path

MAIL_LOG = Path({str(mail_log_path)!r})
request = json.loads(sys.stdin.read())
tool = request.get("tool")
arguments = request.get("arguments") or {{}}
if tool == "list_accounts":
    result = {{"accounts": [{{"name": "release-bot", "email": "release-bot@example.com"}}]}}
elif tool == "send_email":
    MAIL_LOG.parent.mkdir(parents=True, exist_ok=True)
    with MAIL_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(arguments, ensure_ascii=False, sort_keys=True) + "\\n")
    result = {{"sent": True, "message_id": arguments.get("message_id"), "refused": {{}}}}
else:
    print(json.dumps({{"ok": False, "error": f"unsupported tool: {{tool}}"}}))
    raise SystemExit(1)
print(json.dumps({{"ok": True, "result": result}}, ensure_ascii=False))
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_locked_verifier_bridge(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--config", required=True)
parser.add_argument("--verification-ref", required=True)
args = parser.parse_args()
Path(args.config).resolve(strict=True)
receipt = json.loads(Path(args.verification_ref).read_text(encoding="utf-8"))
print(json.dumps({
    "aggregate_status": receipt["status"],
    "verification_ref": str(Path(args.verification_ref).resolve(strict=True)),
    "event_id": receipt["event_id"],
    "round_id": int(receipt["round_id"]),
    "manifest_s_digest": receipt["manifest_s_digest"],
    "manifest_r_digest": receipt["manifest_r_digest"],
    "role_snapshot_digest": receipt["role_snapshot_digest"],
    "target_scope": receipt["target_scope"],
    "expires_at": receipt["expires_at"],
    "evidence_ref": receipt["receipt_id"],
}, ensure_ascii=False, separators=(",", ":")))
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_stateful_deployment_adapter(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """
import json
import sys
from pathlib import Path


def load_target(path_text: str) -> dict | None:
    path = Path(path_text)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_target(path_text: str, payload: dict) -> None:
    path = Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def rollback_meta(path_text: str, stage: str) -> Path:
    path = Path(path_text)
    return path.with_name(path.name + f".rollback-{stage}.json")


def save_meta(path_text: str, stage: str, payload: dict) -> None:
    meta = rollback_meta(path_text, stage)
    meta.parent.mkdir(parents=True, exist_ok=True)
    meta.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def load_meta(path_text: str, stage: str) -> dict:
    return json.loads(rollback_meta(path_text, stage).read_text(encoding="utf-8"))


action = sys.argv[1]
if action == "deploy":
    _, _, stage, manifest_r_digest, target_ref = sys.argv
    previous = load_target(target_ref)
    save_meta(target_ref, stage, {"previous": previous, "expected": manifest_r_digest})
    save_target(target_ref, {"stage": stage, "manifest_r_digest": manifest_r_digest})
    print(json.dumps({
        "result": "PASS",
        "deployment_ref": f"deploy:{stage}:1",
        "target_ref": target_ref,
        "rollback_ref": f"rollback:{stage}:1",
        "deployed_manifest_r_digest": manifest_r_digest,
    }))
elif action == "verify":
    _, _, stage, manifest_r_digest, target_ref = sys.argv
    current = load_target(target_ref)
    observed = "" if current is None else str(current.get("manifest_r_digest") or "")
    print(json.dumps({
        "result": "PASS" if observed == manifest_r_digest else "FAIL",
        "verification_ref": f"verify:{stage}:1",
        "observed_manifest_r_digest": observed,
        "target_ref": target_ref,
    }))
elif action == "rollback":
    _, _, stage, deployment_ref, rollback_ref, target_ref = sys.argv
    metadata = load_meta(target_ref, stage)
    previous = metadata.get("previous")
    target = Path(target_ref)
    if previous is None:
        if target.exists():
            target.unlink()
        restored_ref = f"baseline:{stage}:absent"
    else:
        save_target(target_ref, previous)
        restored_ref = f"baseline:{stage}:present"
    print(json.dumps({
        "result": "PASS",
        "deployment_ref": deployment_ref,
        "rollback_ref": rollback_ref,
        "target_ref": target_ref,
        "restored_ref": restored_ref,
        "rollback_receipt_ref": f"rollback-receipt:{stage}:1",
    }))
elif action == "rollback_verify":
    _, _, stage, deployment_ref, rollback_ref, restored_ref, rollback_receipt_ref, target_ref = sys.argv
    metadata = load_meta(target_ref, stage)
    previous = metadata.get("previous")
    current = load_target(target_ref)
    restored = current == previous
    if previous is None:
        restored = current is None
    print(json.dumps({
        "result": "PASS" if restored else "FAIL",
        "deployment_ref": deployment_ref,
        "rollback_ref": rollback_ref,
        "restored_ref": restored_ref,
        "target_ref": target_ref,
        "verification_ref": f"rollback-verify:{stage}:1" if restored else "",
    }))
elif action == "readback":
    _, _, manifest_r_digest, target_ref = sys.argv
    current = load_target(target_ref)
    observed = "" if current is None else str(current.get("manifest_r_digest") or "")
    print(json.dumps({
        "result": "PASS" if observed == manifest_r_digest else "FAIL",
        "readback_ref": "production:readback:1",
        "observed_manifest_r_digest": observed,
        "target_ref": target_ref,
    }))
else:
    raise SystemExit(2)
""".strip()
        + "\n",
        encoding="utf-8",
    )

def _write_workflow_lock(lock_root: Path, *, mail_cli: Path, verifier_bridge: Path) -> tuple[Path, str]:
    payload = {
        "plugins": [
            {
                "name": "imap-smtp-mail",
                "plugin_root": "plugins/imap-smtp-mail",
                "entrypoints": [
                    {
                        "path": "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py",
                        "sha256": _sha256(mail_cli),
                    }
                ],
            },
            {
                "name": "release-approval-verifier",
                "plugin_root": "plugins/release-approval-verifier",
                "entrypoints": [
                    {
                        "path": "plugins/release-approval-verifier/src/verifier_product_gate_bridge.py",
                        "sha256": _sha256(verifier_bridge),
                    }
                ],
            },
        ]
    }
    path = _write_json(lock_root / "workflow.lock.json", payload)
    return path, _sha256(path)


def _write_deployment_lock(lock_root: Path, adapter: Path) -> tuple[Path, str]:
    def command(action: str) -> list[str]:
        argv = [sys.executable, str(adapter), action]
        if action in {"deploy", "verify"}:
            argv.extend(["{stage}", "{manifest_r_digest}", "{target_ref}"])
        elif action == "rollback":
            argv.extend(["{stage}", "{deployment_ref}", "{rollback_ref}", "{target_ref}"])
        elif action == "rollback_verify":
            argv.extend(
                [
                    "{stage}",
                    "{deployment_ref}",
                    "{rollback_ref}",
                    "{restored_ref}",
                    "{rollback_receipt_ref}",
                    "{target_ref}",
                ]
            )
        elif action == "readback":
            argv.extend(["{manifest_r_digest}", "{target_ref}"])
        return argv

    payload = {
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
            for command_id, argv in {
                "deploy": command("deploy"),
                "verify": command("verify"),
                "rollback": command("rollback"),
                "rollback_verify": command("rollback_verify"),
                "readback": command("readback"),
            }.items()
        },
    }
    path = _write_json(lock_root / "deployment.lock.json", payload)
    return path, _sha256(path)


def _write_config(
    root: Path,
    *,
    workflow_lock_path: Path,
    workflow_lock_digest: str,
    deployment_lock_path: Path,
    deployment_lock_digest: str,
    verifier_config_path: Path,
    deployment_adapter: Path,
    verifier_bridge: Path,
    target_paths: dict[str, Path],
) -> Path:
    config_path = root / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "storage_dir": str(root / "events"),
                "policy": {
                    "allowed_extensions": [".bin"],
                    "require_source_ref": True,
                    "require_signature": False,
                    "require_cloud_scan": False,
                    "allow_unchanged_artifacts": False,
                    "auto_approve_risk_levels": ["standard"],
                },
                "cloud_scan": {"command": []},
                "test": {"command": []},
                "production": {
                    "enabled": True,
                    "authorization": {
                        "key_env": "TEST_RELEASE_AUTH_KEY",
                        "ttl_seconds": 3600,
                        "verify_command": [],
                        "timeout_seconds": 30,
                    },
                    "audit": {"key_env": "TEST_RELEASE_AUDIT_KEY"},
                    "approval_workflow": {
                        "mode": "unified_multi_role",
                        "dependency_lock": str(workflow_lock_path),
                        "dependency_lock_sha256": workflow_lock_digest,
                        "verifier_config_path": str(verifier_config_path),
                        "verify_command": [
                            sys.executable,
                            str(verifier_bridge),
                            "--config",
                            str(verifier_config_path),
                            "--verification-ref",
                            "{verification_ref}",
                        ],
                        "timeout_seconds": 30,
                        "mail": {
                            "profile": "release-bot",
                            "release_group": "release@example.com",
                            "module": "kernel",
                            "dependency_lock": str(workflow_lock_path),
                            "dependency_lock_sha256": workflow_lock_digest,
                            "timeout_seconds": 30,
                        },
                    },
                    "deployment": {
                        "stages": [
                            "preproduction",
                            "production_canary",
                            "production_full",
                        ],
                        "targets": {
                            stage: str(path) for stage, path in target_paths.items()
                        },
                        "dependency_lock": str(deployment_lock_path),
                        "dependency_lock_sha256": deployment_lock_digest,
                        "deploy_command": [
                            sys.executable,
                            str(deployment_adapter),
                            "deploy",
                            "{stage}",
                            "{manifest_r_digest}",
                            "{target_ref}",
                        ],
                        "verify_command": [
                            sys.executable,
                            str(deployment_adapter),
                            "verify",
                            "{stage}",
                            "{manifest_r_digest}",
                            "{target_ref}",
                        ],
                        "rollback_command": [
                            sys.executable,
                            str(deployment_adapter),
                            "rollback",
                            "{stage}",
                            "{deployment_ref}",
                            "{rollback_ref}",
                            "{target_ref}",
                        ],
                        "rollback_verify_command": [
                            sys.executable,
                            str(deployment_adapter),
                            "rollback_verify",
                            "{stage}",
                            "{deployment_ref}",
                            "{rollback_ref}",
                            "{restored_ref}",
                            "{rollback_receipt_ref}",
                            "{target_ref}",
                        ],
                        "timeout_seconds": 30,
                    },
                    "readback": {
                        "command": [
                            sys.executable,
                            str(deployment_adapter),
                            "readback",
                            "{manifest_r_digest}",
                            "{target_ref}",
                        ],
                        "timeout_seconds": 30,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    return config_path


def _controller(tmp_path: Path) -> LockedWorkflowContext:
    lock_root = tmp_path / "locked-fixtures"
    mail_log_path = lock_root / "mail-log.jsonl"
    mail_cli = lock_root / "plugins" / "imap-smtp-mail" / "src" / "imap_smtp_mail_cli.py"
    verifier_bridge = lock_root / "plugins" / "release-approval-verifier" / "src" / "verifier_product_gate_bridge.py"
    deployment_adapter = lock_root / "offline_deployment_adapter.py"
    verifier_config_path = _write_json(lock_root / "verifier-config.json", {"mode": "offline"})
    _write_locked_mail_cli(mail_cli, mail_log_path)
    _write_locked_verifier_bridge(verifier_bridge)
    _write_stateful_deployment_adapter(deployment_adapter)
    workflow_lock_path, workflow_lock_digest = _write_workflow_lock(
        lock_root,
        mail_cli=mail_cli,
        verifier_bridge=verifier_bridge,
    )
    deployment_lock_path, deployment_lock_digest = _write_deployment_lock(
        lock_root,
        deployment_adapter,
    )
    target_paths = {
        "preproduction": tmp_path / "targets" / "preproduction.json",
        "production_canary": tmp_path / "targets" / "production_canary.json",
        "production_full": tmp_path / "targets" / "production_full.json",
    }
    controller = ProductionReleaseController(
        str(
            _write_config(
                tmp_path,
                workflow_lock_path=workflow_lock_path,
                workflow_lock_digest=workflow_lock_digest,
                deployment_lock_path=deployment_lock_path,
                deployment_lock_digest=deployment_lock_digest,
                verifier_config_path=verifier_config_path,
                deployment_adapter=deployment_adapter,
                verifier_bridge=verifier_bridge,
                target_paths=target_paths,
            )
        )
    )
    return LockedWorkflowContext(
        controller=controller,
        workflow_lock_path=workflow_lock_path,
        deployment_lock_path=deployment_lock_path,
        mail_log_path=mail_log_path,
        verifier_config_path=verifier_config_path,
        target_paths=target_paths,
    )


def _make_release_ready(
    controller: ProductionReleaseController,
    artifact_path: Path,
    event_id: str,
) -> dict[str, object]:
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(b"full-offline-release-candidate")
    controller.create_submission(
        event_id=event_id,
        task_id="TASK-FULL-E2E-1",
        artifacts=[
            {
                "logical_name": artifact_path.name,
                "file_path": str(artifact_path),
                "source_ref": "commit:full-offline-release",
            }
        ],
        source_ref="commit:full-offline-release",
        rollback_ref="rollback:stable-v1",
        risk_level="standard",
    )
    assert controller.run_submission_gate(event_id)["overall"] == "PASS"
    controller.record_test_result(event_id, "PASS", "test:full-offline-release")
    controller.build_final_release(event_id, str(artifact_path.parent / "final"))
    release_ready = controller.run_release_gate(event_id)
    assert release_ready["status"] == "RELEASE_READY"
    return controller.get_event(event_id)["event"]


def _request_unified_approval(
    controller: ProductionReleaseController,
    event_id: str,
) -> dict[str, object]:
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=1)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return controller.request_unified_release_approval(
        event_id=event_id,
        requested_by="release-bot@example.com",
        target_scope="preproduction,production_canary,production_full",
        round_id=1,
        required_roles=[
            {
                "role_id": "release-director",
                "email": "director@example.com",
                "required": True,
            },
            {
                "role_id": "test-lead",
                "email": "test@example.com",
                "required": True,
            },
        ],
        role_snapshot_digest="c" * 64,
        expires_at=expires_at,
    )


def _materialize_verified_receipt(
    tmp_path: Path,
    request: dict[str, object],
    *,
    suffix: str,
) -> Path:
    receipt_id = "receipt-" + hashlib.sha256(
        f"{request['event_id']}|{request['round_id']}|{suffix}".encode("utf-8")
    ).hexdigest()
    receipt = {
        "receipt_id": receipt_id,
        "event_id": request["event_id"],
        "round_id": int(request["round_id"]),
        "status": "APPROVAL_VERIFIED",
        "manifest_s_digest": request["manifest_s_digest"],
        "manifest_r_digest": request["manifest_r_digest"],
        "role_snapshot_digest": request["role_snapshot_digest"],
        "target_scope": request["target_scope"],
        "expires_at": request["expires_at"],
    }
    return _write_json(tmp_path / "receipts" / f"{receipt_id}.json", receipt)


def _mail_log_entries(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_locked_offline_chain_requires_verified_approval_and_authorization(
    tmp_path: Path,
    production_keys: None,
) -> None:
    context = _controller(tmp_path)
    artifact_path = tmp_path / "input" / "product.bin"
    event = _make_release_ready(context.controller, artifact_path, "event-full-chain")

    unified_preflight = context.controller.unified_approval_preflight()
    assert unified_preflight["ready"] is True
    assert unified_preflight["checks"]["verification_adapter"]["locked"] is True
    assert unified_preflight["checks"]["approval_mail"]["locked"] is True

    approval_request = _request_unified_approval(context.controller, "event-full-chain")
    assert approval_request["status"] == "APPROVAL_COLLECTING"
    assert context.controller.get_event("event-full-chain")["event"]["status"] == "APPROVAL_COLLECTING"
    mail_entries = _mail_log_entries(context.mail_log_path)
    assert len(mail_entries) == 1
    assert mail_entries[0]["message_id"] == approval_request["request"]["original_message_id"]

    with pytest.raises(
        GateError,
        match="Release authorization cannot be requested from status APPROVAL_COLLECTING",
    ):
        context.controller.request_release_authorization(
            "event-full-chain",
            "rd-flywheel",
            "preproduction,production_canary,production_full",
        )

    verification_ref = _materialize_verified_receipt(
        tmp_path,
        approval_request["request"],
        suffix="full-chain",
    )
    verified_handoff = context.controller.record_unified_release_approval(
        "event-full-chain",
        str(verification_ref),
    )
    assert verified_handoff["status"] == "PRE_RELEASE_REQUESTED"

    with pytest.raises(
        GateError,
        match="Verified release authorization cannot be finalized from status PRE_RELEASE_REQUESTED",
    ):
        context.controller.finalize_verified_release_authorization("event-full-chain")

    authorization_request = context.controller.request_release_authorization(
        "event-full-chain",
        "rd-flywheel",
        "preproduction,production_canary,production_full",
    )
    assert authorization_request["status"] == "RELEASE_AUTHORIZATION_REQUIRED"
    assert (
        authorization_request["request"]["authorization_source"]
        == "unified_multi_role_receipt"
    )

    finalized = context.controller.finalize_verified_release_authorization("event-full-chain")
    assert finalized["status"] == "RELEASE_AUTHORIZED"
    assert finalized["authorization"]["verification_ref"] == str(verification_ref.resolve())
    assert context.controller.get_event("event-full-chain")["event"]["manifest_r_digest"] == event["manifest_r_digest"]

    assert context.controller.run_deployment_stage("event-full-chain", "preproduction")["status"] == "PREPRODUCTION_VERIFIED"
    assert context.controller.run_deployment_stage("event-full-chain", "production_canary")["status"] == "CANARY_VERIFIED"
    assert context.controller.run_deployment_stage("event-full-chain", "production_full")["status"] == "PRODUCTION_DEPLOYED"


def test_locked_offline_chain_requires_readback_for_production_verified(
    tmp_path: Path,
    production_keys: None,
) -> None:
    context = _controller(tmp_path)
    artifact_path = tmp_path / "input" / "product.bin"
    _make_release_ready(context.controller, artifact_path, "event-readback-required")
    approval_request = _request_unified_approval(context.controller, "event-readback-required")
    verification_ref = _materialize_verified_receipt(
        tmp_path,
        approval_request["request"],
        suffix="readback",
    )
    context.controller.record_unified_release_approval(
        "event-readback-required",
        str(verification_ref),
    )
    context.controller.request_release_authorization(
        "event-readback-required",
        "rd-flywheel",
        "preproduction,production_canary,production_full",
    )
    context.controller.finalize_verified_release_authorization("event-readback-required")
    context.controller.run_deployment_stage("event-readback-required", "preproduction")
    context.controller.run_deployment_stage("event-readback-required", "production_canary")
    full_stage = context.controller.run_deployment_stage(
        "event-readback-required",
        "production_full",
    )

    assert full_stage["status"] == "PRODUCTION_DEPLOYED"
    assert (
        context.controller.get_event("event-readback-required")["event"]["status"]
        == "PRODUCTION_DEPLOYED"
    )
    deployed_target = json.loads(
        context.target_paths["production_full"].read_text(encoding="utf-8")
    )
    assert (
        deployed_target["manifest_r_digest"]
        == context.controller.get_event("event-readback-required")["event"]["manifest_r_digest"]
    )

    readback = context.controller.run_production_readback("event-readback-required")
    assert readback["status"] == "PRODUCTION_VERIFIED"
    assert readback["result"] == "PASS"
    assert (
        context.controller.get_event("event-readback-required")["event"]["status"]
        == "PRODUCTION_VERIFIED"
    )


def test_locked_offline_chain_tamper_after_full_deploy_rolls_back_on_readback(
    tmp_path: Path,
    production_keys: None,
) -> None:
    context = _controller(tmp_path)
    artifact_path = tmp_path / "input" / "product.bin"
    _make_release_ready(context.controller, artifact_path, "event-readback-tamper")
    approval_request = _request_unified_approval(context.controller, "event-readback-tamper")
    verification_ref = _materialize_verified_receipt(
        tmp_path,
        approval_request["request"],
        suffix="tamper",
    )
    context.controller.record_unified_release_approval(
        "event-readback-tamper",
        str(verification_ref),
    )
    context.controller.request_release_authorization(
        "event-readback-tamper",
        "rd-flywheel",
        "preproduction,production_canary,production_full",
    )
    context.controller.finalize_verified_release_authorization("event-readback-tamper")
    context.controller.run_deployment_stage("event-readback-tamper", "preproduction")
    context.controller.run_deployment_stage("event-readback-tamper", "production_canary")
    context.controller.run_deployment_stage("event-readback-tamper", "production_full")

    context.target_paths["production_full"].write_text(
        json.dumps(
            {"stage": "production_full", "manifest_r_digest": "0" * 64},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    readback = context.controller.run_production_readback("event-readback-tamper")

    assert readback["status"] == "ROLLED_BACK"
    assert readback["rollback"]["result"] == "PASS"
    assert (
        context.controller.get_event("event-readback-tamper")["event"]["status"]
        != "PRODUCTION_VERIFIED"
    )
    assert not context.target_paths["production_full"].exists()
