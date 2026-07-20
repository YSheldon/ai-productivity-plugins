from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_core import GateError, canonical_json
from release_gate_production import ProductionReleaseController


class FakeReportMailGateway:
    def __init__(self, *, visible: bool = True, connected: bool = True) -> None:
        self.visible = visible
        self.connected = connected
        self.sent_payloads: list[dict] = []

    def list_accounts(self) -> list[dict[str, str]]:
        return [{"name": "release-mail", "email": "release-bot@example.com"}]

    def test_connection(self, _payload: dict) -> dict:
        return {
            "checks": {
                "imap": "ok" if self.connected else "failed",
                "smtp": "ok" if self.connected else "failed",
            }
        }

    def send_email(self, payload: dict) -> dict:
        self.sent_payloads.append(dict(payload))
        return {
            "sent": True,
            "message_id": payload["message_id"],
            "refused": {},
        }

    def search_messages(self, _payload: dict) -> dict:
        if not self.visible or not self.sent_payloads:
            return {"messages": []}
        payload = self.sent_payloads[0]
        return {
            "messages": [
                {"uid": "42", "message_id": payload["message_id"]}
            ]
        }

    def read_message(self, _payload: dict) -> dict:
        payload = self.sent_payloads[0]
        headers = payload["headers"]
        return {
            "uid": "42",
            "uidvalidity": "101",
            "subject": payload["subject"],
            "message_id": payload["message_id"],
            "from": [{"email": "release-bot@example.com"}],
            "to": [{"email": item} for item in payload["to"]],
            "cc": [],
            "evidence": {
                "message_id": payload["message_id"],
                "raw_headers_sha256": "a" * 64,
            },
            "release_workflow_headers": {
                "contract": headers["X-RD-Contract"],
                "event_id": headers["X-RD-Event-Id"],
                "task": headers["X-RD-Task"],
                "module": headers["X-RD-Module"],
                "manifest_s_digest": headers["X-RD-Manifest-S-Digest"],
                "manifest_r_digest": headers["X-RD-Manifest-R-Digest"],
                "manifest_digest": headers["X-RD-Manifest-Digest"],
                "request_digest": headers["X-RD-Request-Digest"],
            },
        }


class ProductionReleaseControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "product.bin"
        self.artifact.write_bytes(b"production-candidate-v1")
        self.adapter = self.root / "adapter.py"
        self.adapter.write_text(
            """
import json
import sys
import time

action, stage, digest, mode = sys.argv[1:5]
if mode == "timeout-deploy" and action == "deploy":
    time.sleep(2)
if mode == "timeout-verify-canary" and action == "verify" and stage == "production_canary":
    time.sleep(2)
if mode == "timeout-rollback" and action == "rollback":
    time.sleep(2)
if mode == "timeout-rollback-verify" and action == "rollback_verify":
    time.sleep(2)
if mode == "timeout-readback" and action == "readback":
    time.sleep(2)
if action == "deploy":
    target = sys.argv[5]
    print(json.dumps({
        "result": "PASS",
        "deployment_ref": f"deploy:{stage}:1",
        "target_ref": "target:wrong" if mode == "bad-target" else target,
        "rollback_ref": f"rollback:{stage}:1",
        "deployed_manifest_r_digest": digest,
    }))
elif action == "verify":
    target = sys.argv[5]
    result = (
        "FAIL"
        if (
            mode in {
                "fail-verify",
                "bad-rollback",
                "timeout-rollback",
                "timeout-rollback-verify",
            }
            and stage == "production_canary"
        )
        or (mode == "fail-full-verify" and stage == "production_full")
        else "PASS"
    )
    print(json.dumps({
        "result": result,
        "verification_ref": f"verify:{stage}:1",
        "observed_manifest_r_digest": digest,
        "target_ref": target,
    }))
elif action == "rollback":
    deployment_ref = sys.argv[5]
    rollback_ref = sys.argv[6]
    target = sys.argv[7]
    refs_match = (
        deployment_ref == f"deploy:{stage}:1"
        and rollback_ref == f"rollback:{stage}:1"
    )
    print(json.dumps({
        "result": "PASS" if refs_match else "FAIL",
        "deployment_ref": deployment_ref,
        "rollback_ref": rollback_ref if mode != "bad-rollback" else "",
        "target_ref": target,
        "restored_ref": f"baseline:{stage}" if mode != "bad-rollback" else "",
        "rollback_receipt_ref": f"rollback-receipt:{stage}:1" if mode != "bad-rollback" else "",
    }))
elif action == "rollback_verify":
    deployment_ref = sys.argv[5]
    rollback_ref = sys.argv[6]
    restored_ref = sys.argv[7]
    rollback_receipt_ref = sys.argv[8]
    target = sys.argv[9]
    valid = all((deployment_ref, rollback_ref, restored_ref, rollback_receipt_ref, target))
    print(json.dumps({
        "result": "PASS" if valid and mode != "bad-rollback" else "FAIL",
        "deployment_ref": deployment_ref,
        "rollback_ref": rollback_ref,
        "restored_ref": restored_ref,
        "target_ref": target,
        "verification_ref": f"rollback-verify:{stage}:1" if valid else "",
    }))
elif action == "readback":
    target = sys.argv[5]
    print(json.dumps({
        "result": "FAIL" if mode == "fail-readback" else "PASS",
        "readback_ref": "production:readback:1",
        "observed_manifest_r_digest": digest,
        "target_ref": target,
    }))
elif action == "authorize":
    manifest_s_digest = sys.argv[5]
    target_scope = sys.argv[6]
    print(json.dumps({
        "result": "APPROVE",
        "approval_ref": stage,
        "approved_by": "release-director",
        "manifest_s_digest": manifest_s_digest,
        "manifest_r_digest": "0" * 64 if mode == "bad-approval" else digest,
        "target_scope": (
            "production_full" if mode == "bad-approval-scope" else target_scope
        ),
        "evidence_ref": f"approval-readback:{stage}",
    }))
else:
    raise SystemExit(2)
""".strip()
            + "\n",
            encoding="utf-8",
        )
        self.previous_key = os.environ.get("TEST_RELEASE_AUTH_KEY")
        self.previous_audit_key = os.environ.get("TEST_RELEASE_AUDIT_KEY")
        os.environ["TEST_RELEASE_AUTH_KEY"] = "unit-test-authorization-key-32-bytes-minimum"
        os.environ["TEST_RELEASE_AUDIT_KEY"] = "unit-test-audit-ledger-key-32-bytes-minimum"

    def tearDown(self) -> None:
        if self.previous_key is None:
            os.environ.pop("TEST_RELEASE_AUTH_KEY", None)
        else:
            os.environ["TEST_RELEASE_AUTH_KEY"] = self.previous_key
        if self.previous_audit_key is None:
            os.environ.pop("TEST_RELEASE_AUDIT_KEY", None)
        else:
            os.environ["TEST_RELEASE_AUDIT_KEY"] = self.previous_audit_key
        self.temporary.cleanup()


    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_dependency_lock(
        self,
        name: str,
        commands: dict[str, list[str]],
    ) -> tuple[Path, str]:
        lock_path = self.root / f"deployment-lock-{name}.json"
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
                            "sha256": self._sha256(Path(sys.executable)),
                        },
                        {
                            "argv_index": 1,
                            "path": self.adapter.name,
                            "sha256": self._sha256(self.adapter),
                        },
                    ],
                }
                for command_id, argv in commands.items()
            },
        }
        lock_path.write_text(
            json.dumps(payload, sort_keys=True),
            encoding="utf-8",
        )
        return lock_path, self._sha256(lock_path)
    def _write_config(self, mode: str = "pass", include_deploy: bool = True) -> Path:
        def command(action: str) -> list[str]:
            values = [
                sys.executable,
                str(self.adapter),
                action,
                "{stage}",
                "{manifest_r_digest}",
                mode,
            ]
            if action in {"deploy", "verify", "readback"}:
                values.append("{target_ref}")
            elif action == "rollback":
                values.extend(["{deployment_ref}", "{rollback_ref}", "{target_ref}"])
            elif action == "rollback_verify":
                values.extend(
                    [
                        "{deployment_ref}",
                        "{rollback_ref}",
                        "{restored_ref}",
                        "{rollback_receipt_ref}",
                        "{target_ref}",
                    ]
                )
            return values

        deploy_command = command("deploy")
        verify_command = command("verify")
        rollback_command = command("rollback")
        rollback_verify_command = command("rollback_verify")
        readback_command = command("readback")
        lock_path, lock_digest = self._write_dependency_lock(
            f"{mode}-{include_deploy}",
            {
                "deploy": deploy_command,
                "verify": verify_command,
                "rollback": rollback_command,
                "rollback_verify": rollback_verify_command,
                "readback": readback_command,
            },
        )
        deployment = {
            "stages": ["preproduction", "production_canary", "production_full"],
            "targets": {
                "preproduction": "env:preproduction",
                "production_canary": "env:production:canary",
                "production_full": "env:production:full",
            },
            "dependency_lock": str(lock_path),
            "dependency_lock_sha256": lock_digest,
            "deploy_command": deploy_command if include_deploy else [],
            "verify_command": verify_command,
            "rollback_command": rollback_command,
            "rollback_verify_command": rollback_verify_command,
            "timeout_seconds": 1 if mode.startswith("timeout-") else 30,
        }
        path = self.root / f"config-{mode}-{include_deploy}.json"
        path.write_text(
            json.dumps(
                {
                    "storage_dir": str(self.root / f"events-{mode}-{include_deploy}"),
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
                            "verify_command": [
                                sys.executable,
                                str(self.adapter),
                                "authorize",
                                "{approval_ref}",
                                "{manifest_r_digest}",
                                mode,
                                "{manifest_s_digest}",
                                "{target_scope}",
                            ],
                            "timeout_seconds": 1 if mode.startswith("timeout-") else 30,
                        },
                        "audit": {"key_env": "TEST_RELEASE_AUDIT_KEY"},
                        "deployment": deployment,
                        "readback": {
                            "command": readback_command,
                            "timeout_seconds": 1 if mode.startswith("timeout-") else 30,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

    def _report_delivery_config(self) -> Path:
        path = self._write_config()
        config = json.loads(path.read_text(encoding="utf-8"))
        config["production"]["report_delivery"] = {
            "enabled": True,
            "profile": "release-mail",
            "sender_email": "release-bot@example.com",
            "recipients": ["release-group@example.com"],
            "module": "client",
            "mailbox": "INBOX",
            "timeout_seconds": 30,
            "readback_timeout_seconds": 3600,
        }
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def _production_verified(
        self,
        controller: ProductionReleaseController,
        event_id: str,
    ) -> None:
        self._release_ready(controller, event_id)
        self._authorize(controller, event_id)
        controller.run_deployment_stage(event_id, "preproduction")
        controller.run_deployment_stage(event_id, "production_canary")
        controller.run_deployment_stage(event_id, "production_full")
        controller.run_production_readback(event_id)

    def _release_ready(self, controller: ProductionReleaseController, event_id: str) -> None:
        controller.create_submission(
            event_id=event_id,
            task_id="TASK-PRODUCTION-1",
            artifacts=[
                {
                    "logical_name": "product.bin",
                    "file_path": str(self.artifact),
                    "source_ref": "commit:production-v1",
                }
            ],
            source_ref="commit:production-v1",
            rollback_ref="rollback:stable-v0",
            risk_level="standard",
        )
        self.assertEqual("PASS", controller.run_submission_gate(event_id)["overall"])
        controller.record_test_result(event_id, "PASS", "test:production-v1")
        controller.build_final_release(event_id, str(self.root / f"final-{event_id}"))
        self.assertEqual("RELEASE_READY", controller.run_release_gate(event_id)["status"])

    def _authorize(self, controller: ProductionReleaseController, event_id: str) -> dict:
        event = controller.get_event(event_id)["event"]
        controller.request_release_authorization(
            event_id,
            requested_by="release-bot",
            target_scope="preproduction,production_canary,production_full",
        )
        return controller.record_release_authorization(
            event_id,
            decision="APPROVE",
            approval_ref="feishu:approval:123",
            approved_by="release-director",
            manifest_s_digest=event["manifest_s_digest"],
            manifest_r_digest=event["manifest_r_digest"],
        )

    def test_bound_approval_generates_scoped_credential(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-authorized")
        authorization = self._authorize(controller, "event-authorized")

        self.assertEqual("RELEASE_AUTHORIZED", authorization["status"])
        credential_path = Path(authorization["credential_path"])
        self.assertTrue(credential_path.is_file())
        credential = json.loads(credential_path.read_text(encoding="utf-8"))
        self.assertEqual("event-authorized", credential["claims"]["event_id"])
        self.assertEqual(
            controller.get_event("event-authorized")["event"]["manifest_r_digest"],
            credential["claims"]["manifest_r_digest"],
        )
        self.assertNotIn("unit-test-key", credential_path.read_text(encoding="utf-8"))

    def test_approval_digest_mismatch_is_rejected(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-mismatch")
        event = controller.get_event("event-mismatch")["event"]
        controller.request_release_authorization(
            "event-mismatch",
            "release-bot",
            "preproduction,production_canary,production_full",
        )

        with self.assertRaises(GateError):
            controller.record_release_authorization(
                "event-mismatch",
                decision="APPROVE",
                approval_ref="feishu:approval:bad",
                approved_by="release-director",
                manifest_s_digest=event["manifest_s_digest"],
                manifest_r_digest="0" * 64,
            )

    def test_external_approval_readback_must_match_current_manifests(self) -> None:
        controller = ProductionReleaseController(str(self._write_config(mode="bad-approval")))
        self._release_ready(controller, "event-bad-approval")
        event = controller.get_event("event-bad-approval")["event"]
        controller.request_release_authorization(
            "event-bad-approval",
            "release-bot",
            "preproduction,production_canary,production_full",
        )

        with self.assertRaises(GateError):
            controller.record_release_authorization(
                "event-bad-approval",
                decision="APPROVE",
                approval_ref="feishu:approval:tampered",
                approved_by="release-director",
                manifest_s_digest=event["manifest_s_digest"],
                manifest_r_digest=event["manifest_r_digest"],
            )
        self.assertEqual(
            "RELEASE_AUTHORIZATION_REQUIRED",
            controller.get_event("event-bad-approval")["event"]["status"],
        )

    def test_pending_event_scope_tampering_cannot_widen_credential(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-scope-tamper")
        event = controller.get_event("event-scope-tamper")["event"]
        controller.request_release_authorization(
            "event-scope-tamper", "release-bot", "preproduction"
        )
        tampered = controller._load_event("event-scope-tamper")
        tampered["release_authorization"]["target_scope"] = (
            "preproduction,production_canary,production_full"
        )
        controller._save_event(tampered)

        authorization = controller.record_release_authorization(
            "event-scope-tamper",
            decision="APPROVE",
            approval_ref="feishu:approval:scope-tamper",
            approved_by="release-director",
            manifest_s_digest=event["manifest_s_digest"],
            manifest_r_digest=event["manifest_r_digest"],
        )
        credential = json.loads(
            Path(authorization["credential_path"]).read_text(encoding="utf-8")
        )

        self.assertEqual("preproduction", credential["claims"]["target_scope"])
        controller.run_deployment_stage("event-scope-tamper", "preproduction")
        with self.assertRaises(GateError):
            controller.run_deployment_stage("event-scope-tamper", "production_canary")

    def test_external_approval_scope_must_match_signed_request(self) -> None:
        controller = ProductionReleaseController(
            str(self._write_config(mode="bad-approval-scope"))
        )
        self._release_ready(controller, "event-approval-scope")
        event = controller.get_event("event-approval-scope")["event"]
        controller.request_release_authorization(
            "event-approval-scope", "release-bot", "preproduction"
        )

        with self.assertRaises(GateError):
            controller.record_release_authorization(
                "event-approval-scope",
                decision="APPROVE",
                approval_ref="feishu:approval:wrong-scope",
                approved_by="release-director",
                manifest_s_digest=event["manifest_s_digest"],
                manifest_r_digest=event["manifest_r_digest"],
            )

    def test_stages_are_ordered_and_production_readback_closes_release(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-stages")
        self._authorize(controller, "event-stages")

        with self.assertRaises(GateError):
            controller.run_deployment_stage("event-stages", "production_canary")

        self.assertEqual(
            "PREPRODUCTION_VERIFIED",
            controller.run_deployment_stage("event-stages", "preproduction")["status"],
        )
        self.assertEqual(
            "CANARY_VERIFIED",
            controller.run_deployment_stage("event-stages", "production_canary")["status"],
        )
        self.assertEqual(
            "PRODUCTION_DEPLOYED",
            controller.run_deployment_stage("event-stages", "production_full")["status"],
        )
        readback = controller.run_production_readback("event-stages")
        self.assertEqual("PRODUCTION_VERIFIED", readback["status"])
        self.assertEqual("PASS", readback["result"])

    def test_report_delivery_preflight_requires_live_imap_and_smtp(self) -> None:
        gateway = FakeReportMailGateway(connected=False)
        controller = ProductionReleaseController(
            str(self._report_delivery_config()), report_mail_gateway=gateway
        )

        preflight = controller.production_preflight()

        self.assertFalse(preflight["ready"])
        self.assertIn("report_delivery", preflight["missing_capabilities"])

    def test_failed_first_send_preflight_does_not_freeze_delivery_intent(self) -> None:
        gateway = FakeReportMailGateway(connected=False)
        controller = ProductionReleaseController(
            str(self._report_delivery_config()), report_mail_gateway=gateway
        )
        event_id = "event-report-preflight-retry"
        self._production_verified(controller, event_id)
        intent_path = controller._event_dir(event_id) / "production-report-delivery-intent.json"

        with self.assertRaisesRegex(GateError, "delivery preflight failed"):
            controller.deliver_production_report(event_id)
        self.assertFalse(intent_path.exists())

        gateway.connected = True
        delivered = controller.deliver_production_report(event_id)

        self.assertEqual("DELIVERED", delivered["status"])
        self.assertTrue(intent_path.is_file())
        self.assertEqual(1, len(gateway.sent_payloads))

    def test_production_report_delivery_is_exactly_once_and_readback_bound(self) -> None:
        gateway = FakeReportMailGateway()
        controller = ProductionReleaseController(
            str(self._report_delivery_config()), report_mail_gateway=gateway
        )
        self._production_verified(controller, "event-report-delivery")

        first = controller.deliver_production_report("event-report-delivery")
        repeated = controller.deliver_production_report("event-report-delivery")

        self.assertEqual("DELIVERED", first["status"])
        self.assertFalse(first["idempotent"])
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(1, len(gateway.sent_payloads))
        self.assertTrue(
            gateway.sent_payloads[0]["subject"].startswith(
                "【发布完成】TASK-PRODUCTION-1-client-"
            )
        )
        self.assertNotIn(str(self.root), gateway.sent_payloads[0]["text"])
        event = controller.get_event("event-report-delivery")["event"]
        self.assertEqual(
            first["message_id"],
            event["production_report_delivery"]["message_id"],
        )

    def test_report_delivery_receipt_repairs_interrupted_event_commit_without_resend(self) -> None:
        gateway = FakeReportMailGateway()
        controller = ProductionReleaseController(
            str(self._report_delivery_config()), report_mail_gateway=gateway
        )
        event_id = "event-report-delivery-repair"
        self._production_verified(controller, event_id)
        delivered = controller.deliver_production_report(event_id)
        chain_before = controller.verify_control_event_chain(event_id)
        event_path = controller._event_path(event_id)
        event = json.loads(event_path.read_text(encoding="utf-8"))
        event.pop("production_report_delivery")
        event_path.write_text(json.dumps(event), encoding="utf-8")

        repaired = controller.deliver_production_report(event_id)
        chain_after = controller.verify_control_event_chain(event_id)

        self.assertTrue(repaired["idempotent"])
        self.assertEqual(delivered["message_id"], repaired["message_id"])
        self.assertEqual(1, len(gateway.sent_payloads))
        self.assertEqual(chain_before["event_count"], chain_after["event_count"])
        repaired_event = controller.get_event(event_id)["event"]
        self.assertEqual(
            delivered["message_id"],
            repaired_event["production_report_delivery"]["message_id"],
        )

    def test_report_readback_pending_never_resends_smtp(self) -> None:
        gateway = FakeReportMailGateway(visible=False)
        controller = ProductionReleaseController(
            str(self._report_delivery_config()), report_mail_gateway=gateway
        )
        self._production_verified(controller, "event-report-pending")

        pending = controller.deliver_production_report("event-report-pending")
        repeated = controller.deliver_production_report("event-report-pending")
        gateway.visible = True
        delivered = controller.deliver_production_report("event-report-pending")

        self.assertEqual("READBACK_PENDING", pending["status"])
        self.assertEqual("READBACK_PENDING", repeated["status"])
        self.assertEqual("DELIVERED", delivered["status"])
        self.assertEqual(1, len(gateway.sent_payloads))

    def test_report_delivery_receipt_tamper_is_rejected(self) -> None:
        gateway = FakeReportMailGateway()
        controller = ProductionReleaseController(
            str(self._report_delivery_config()), report_mail_gateway=gateway
        )
        self._production_verified(controller, "event-report-delivery-tamper")
        delivered = controller.deliver_production_report(
            "event-report-delivery-tamper"
        )
        receipt_path = Path(delivered["receipt_path"])
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["uid"] = "99"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

        with self.assertRaisesRegex(GateError, "delivery receipt signature"):
            controller.deliver_production_report("event-report-delivery-tamper")

    def test_production_report_requires_verified_state_and_is_tamper_evident(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-report")
        self._authorize(controller, "event-report")

        with self.assertRaises(GateError):
            controller.generate_production_report("event-report")

        controller.run_deployment_stage("event-report", "preproduction")
        controller.run_deployment_stage("event-report", "production_canary")
        controller.run_deployment_stage("event-report", "production_full")
        controller.run_production_readback("event-report")

        first = controller.generate_production_report("event-report")
        repeated = controller.generate_production_report("event-report")

        self.assertFalse(first["idempotent"])
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(first["report_sha256"], repeated["report_sha256"])
        self.assertTrue(Path(first["receipt_path"]).is_file())
        Path(first["report_path"]).write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(GateError):
            controller.generate_production_report("event-report")

    def test_authorization_scope_is_enforced_for_each_stage(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-scope")
        event = controller.get_event("event-scope")["event"]
        controller.request_release_authorization(
            "event-scope", "release-bot", "preproduction"
        )
        controller.record_release_authorization(
            "event-scope",
            decision="APPROVE",
            approval_ref="feishu:approval:scope",
            approved_by="release-director",
            manifest_s_digest=event["manifest_s_digest"],
            manifest_r_digest=event["manifest_r_digest"],
        )
        controller.run_deployment_stage("event-scope", "preproduction")

        with self.assertRaises(GateError):
            controller.run_deployment_stage("event-scope", "production_canary")

    def test_deployment_target_mismatch_rolls_back(self) -> None:
        controller = ProductionReleaseController(str(self._write_config(mode="bad-target")))
        self._release_ready(controller, "event-target")
        self._authorize(controller, "event-target")

        result = controller.run_deployment_stage("event-target", "preproduction")
        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertEqual("PASS", result["rollback"]["result"])

    def test_production_readback_failure_rolls_back_full_stage(self) -> None:
        controller = ProductionReleaseController(str(self._write_config(mode="fail-readback")))
        self._release_ready(controller, "event-readback-rollback")
        self._authorize(controller, "event-readback-rollback")
        controller.run_deployment_stage("event-readback-rollback", "preproduction")
        controller.run_deployment_stage("event-readback-rollback", "production_canary")
        controller.run_deployment_stage("event-readback-rollback", "production_full")

        result = controller.run_production_readback("event-readback-rollback")
        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertEqual("PASS", result["rollback"]["result"])

    def test_incomplete_rollback_receipt_is_failure(self) -> None:
        controller = ProductionReleaseController(str(self._write_config(mode="bad-rollback")))
        self._release_ready(controller, "event-bad-rollback")
        self._authorize(controller, "event-bad-rollback")
        controller.run_deployment_stage("event-bad-rollback", "preproduction")
        result = controller.run_deployment_stage("event-bad-rollback", "production_canary")

        self.assertEqual("ROLLBACK_FAILED", result["status"])

    def test_failed_canary_verification_rolls_back_and_blocks_progress(self) -> None:
        controller = ProductionReleaseController(str(self._write_config(mode="fail-verify")))
        self._release_ready(controller, "event-rollback")
        self._authorize(controller, "event-rollback")
        controller.run_deployment_stage("event-rollback", "preproduction")

        canary = controller.run_deployment_stage("event-rollback", "production_canary")
        self.assertEqual("ROLLED_BACK", canary["status"])
        self.assertEqual("PASS", canary["rollback"]["result"])
        with self.assertRaises(GateError):
            controller.run_deployment_stage("event-rollback", "production_full")

    def test_deploy_timeout_fails_closed_and_requires_manual_recovery(self) -> None:
        controller = ProductionReleaseController(
            str(self._write_config(mode="timeout-deploy"))
        )
        self._release_ready(controller, "event-deploy-timeout")
        self._authorize(controller, "event-deploy-timeout")

        result = controller.run_deployment_stage(
            "event-deploy-timeout", "preproduction"
        )

        self.assertEqual("ROLLBACK_FAILED", result["status"])
        self.assertEqual("deploy", result["failure"]["phase"])
        self.assertIn("timed out", result["failure"]["error"].lower())

    def test_verify_timeout_rolls_back_and_blocks_full_deployment(self) -> None:
        controller = ProductionReleaseController(
            str(self._write_config(mode="timeout-verify-canary"))
        )
        self._release_ready(controller, "event-verify-timeout")
        self._authorize(controller, "event-verify-timeout")
        controller.run_deployment_stage("event-verify-timeout", "preproduction")

        result = controller.run_deployment_stage(
            "event-verify-timeout", "production_canary"
        )

        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertEqual("verify", result["failure"]["phase"])
        self.assertIn("timed out", result["failure"]["error"].lower())
        with self.assertRaises(GateError):
            controller.run_deployment_stage(
                "event-verify-timeout", "production_full"
            )

    def test_rollback_timeout_and_rollback_verify_timeout_are_terminal(self) -> None:
        for mode in ("timeout-rollback", "timeout-rollback-verify"):
            with self.subTest(mode=mode):
                controller = ProductionReleaseController(
                    str(self._write_config(mode=mode))
                )
                event_id = f"event-{mode}"
                self._release_ready(controller, event_id)
                self._authorize(controller, event_id)
                controller.run_deployment_stage(event_id, "preproduction")

                result = controller.run_deployment_stage(
                    event_id, "production_canary"
                )

                self.assertEqual("ROLLBACK_FAILED", result["status"])
                self.assertEqual("FAIL", result["rollback"]["result"])

    def test_full_stage_failure_rolls_back_and_prevents_readback(self) -> None:
        controller = ProductionReleaseController(
            str(self._write_config(mode="fail-full-verify"))
        )
        self._release_ready(controller, "event-full-failure")
        self._authorize(controller, "event-full-failure")
        controller.run_deployment_stage("event-full-failure", "preproduction")
        controller.run_deployment_stage(
            "event-full-failure", "production_canary"
        )

        result = controller.run_deployment_stage(
            "event-full-failure", "production_full"
        )

        self.assertEqual("ROLLED_BACK", result["status"])
        with self.assertRaises(GateError):
            controller.run_production_readback("event-full-failure")

    def test_production_readback_timeout_rolls_back_full_stage(self) -> None:
        controller = ProductionReleaseController(
            str(self._write_config(mode="timeout-readback"))
        )
        self._release_ready(controller, "event-readback-timeout")
        self._authorize(controller, "event-readback-timeout")
        controller.run_deployment_stage(
            "event-readback-timeout", "preproduction"
        )
        controller.run_deployment_stage(
            "event-readback-timeout", "production_canary"
        )
        controller.run_deployment_stage(
            "event-readback-timeout", "production_full"
        )

        result = controller.run_production_readback(
            "event-readback-timeout"
        )

        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertIn("timed out", result["receipt"]["error"].lower())


    def test_readback_failure_persists_separate_readback_and_rollback_evidence(
        self,
    ) -> None:
        controller = ProductionReleaseController(str(self._write_config(mode="fail-readback")))
        self._release_ready(controller, "event-readback-evidence")
        self._authorize(controller, "event-readback-evidence")
        controller.run_deployment_stage("event-readback-evidence", "preproduction")
        controller.run_deployment_stage("event-readback-evidence", "production_canary")
        controller.run_deployment_stage("event-readback-evidence", "production_full")

        result = controller.run_production_readback("event-readback-evidence")

        event = controller.get_event("event-readback-evidence")["event"]
        stage = event["deployment"]["stages"]["production_full"]
        readback_path = Path(result["receipt_path"])
        rollback_path = Path(stage["rollback_path"])
        readback_receipt = json.loads(readback_path.read_text(encoding="utf-8"))
        rollback_receipt = json.loads(rollback_path.read_text(encoding="utf-8"))

        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertTrue(readback_path.is_file())
        self.assertTrue(rollback_path.is_file())
        self.assertNotEqual(readback_path, rollback_path)
        self.assertEqual("BLOCKED", readback_receipt["result"])
        self.assertEqual("PASS", rollback_receipt["rollback"]["result"])
        self.assertEqual("production_readback", rollback_receipt["failure"]["phase"])

    def test_signed_production_readback_receipt_repairs_interrupted_state_commit(
        self,
    ) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-readback-replay")
        self._authorize(controller, "event-readback-replay")
        controller.run_deployment_stage("event-readback-replay", "preproduction")
        controller.run_deployment_stage("event-readback-replay", "production_canary")
        controller.run_deployment_stage("event-readback-replay", "production_full")
        initial = controller.run_production_readback("event-readback-replay")
        controller.config["production"]["readback"]["command"] = [
            sys.executable,
            str(self.root / "missing-readback-adapter.py"),
        ]

        event = controller._load_event("event-readback-replay")
        event["status"] = "PRODUCTION_DEPLOYED"
        event.pop("production_readback_path", None)
        controller._save_event(event)

        replay = controller.run_production_readback("event-readback-replay")

        self.assertTrue(replay["idempotent"])
        self.assertEqual("PRODUCTION_VERIFIED", replay["status"])
        self.assertEqual(initial["receipt_path"], replay["receipt_path"])
        self.assertEqual(
            initial["receipt_path"],
            controller.get_event("event-readback-replay")["event"]["production_readback_path"],
        )
        chain_path = Path(
            controller.verify_control_event_chain("event-readback-replay")["path"]
        )
        records = [
            json.loads(line)
            for line in chain_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual("PRODUCTION_READBACK_REPLAYED", records[-1]["event_type"])

    def test_mismatched_production_readback_receipt_fails_closed(
        self,
    ) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-readback-receipt-tamper")
        self._authorize(controller, "event-readback-receipt-tamper")
        controller.run_deployment_stage(
            "event-readback-receipt-tamper", "preproduction"
        )
        controller.run_deployment_stage(
            "event-readback-receipt-tamper", "production_canary"
        )
        controller.run_deployment_stage(
            "event-readback-receipt-tamper", "production_full"
        )
        result = controller.run_production_readback(
            "event-readback-receipt-tamper"
        )
        receipt_path = Path(result["receipt_path"])
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["payload"]["observed_manifest_r_digest"] = "0" * 64
        receipt.pop("receipt_hmac", None)
        receipt_path.write_text(
            json.dumps(controller._seal_receipt(receipt)),
            encoding="utf-8",
        )
        controller.config["production"]["readback"]["command"] = [
            sys.executable,
            str(self.root / "missing-readback-adapter.py"),
        ]

        event = controller._load_event("event-readback-receipt-tamper")
        event["status"] = "PRODUCTION_DEPLOYED"
        event.pop("production_readback_path", None)
        controller._save_event(event)

        with self.assertRaises(GateError):
            controller.run_production_readback("event-readback-receipt-tamper")

        self.assertEqual(
            "PRODUCTION_DEPLOYED",
            controller.get_event("event-readback-receipt-tamper")["event"]["status"],
        )

    def test_expired_authorization_before_readback_rolls_back_full_stage(
        self,
    ) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-readback-expired")
        self._authorize(controller, "event-readback-expired")
        controller.run_deployment_stage(
            "event-readback-expired", "preproduction"
        )
        controller.run_deployment_stage(
            "event-readback-expired", "production_canary"
        )
        controller.run_deployment_stage(
            "event-readback-expired", "production_full"
        )
        event = controller._load_event("event-readback-expired")
        credential_path = Path(
            event["release_authorization"]["credential_path"]
        )
        credential = json.loads(credential_path.read_text(encoding="utf-8"))
        credential["claims"]["expires_at"] = "2000-01-01T00:00:00Z"
        credential["signature"] = hmac.new(
            os.environ["TEST_RELEASE_AUTH_KEY"].encode("utf-8"),
            canonical_json(credential["claims"]).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        credential_path.write_text(
            json.dumps(credential),
            encoding="utf-8",
        )

        result = controller.run_production_readback(
            "event-readback-expired"
        )

        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertEqual(
            "production_readback_precondition",
            result["failure"]["phase"],
        )
        self.assertIn("expired", result["failure"]["error"].lower())
        self.assertEqual(
            "BLOCKED",
            controller._load_event("event-readback-expired")[
                "release_authorization"
            ]["status"],
        )

    def test_missing_capability_preserves_origin_checkpoint(self) -> None:
        controller = ProductionReleaseController(str(self._write_config(include_deploy=False)))
        self._release_ready(controller, "event-capability")
        self._authorize(controller, "event-capability")

        result = controller.ensure_deployment_capabilities("event-capability")
        self.assertEqual("CAPABILITY_BLOCKED", result["status"])
        request = json.loads(Path(result["capability_request_path"]).read_text(encoding="utf-8"))
        self.assertEqual("RELEASE_AUTHORIZED", request["origin_status"])
        self.assertIn("deployment.deploy_command", request["missing_capabilities"])

    def test_capability_recovery_replays_origin_checkpoint(self) -> None:
        controller = ProductionReleaseController(str(self._write_config(include_deploy=False)))
        self._release_ready(controller, "event-capability-recovery")
        self._authorize(controller, "event-capability-recovery")
        blocked = controller.ensure_deployment_capabilities("event-capability-recovery")
        self.assertEqual("CAPABILITY_BLOCKED", blocked["status"])

        ready_controller = ProductionReleaseController(str(self._write_config()))
        controller.config["production"]["deployment"] = ready_controller.config["production"][
            "deployment"
        ]
        restored = controller.ensure_deployment_capabilities("event-capability-recovery")

        self.assertTrue(restored["ready"])
        self.assertEqual("RELEASE_AUTHORIZED", restored["status"])
        chain_path = Path(
            controller.verify_control_event_chain("event-capability-recovery")["path"]
        )
        records = [
            json.loads(line)
            for line in chain_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual("CAPABILITY_RESTORED", records[-1]["event_type"])

    def test_signed_receipt_repairs_interrupted_state_commit(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-receipt-replay")
        self._authorize(controller, "event-receipt-replay")
        controller.run_deployment_stage("event-receipt-replay", "preproduction")

        event = controller._load_event("event-receipt-replay")
        event["status"] = "RELEASE_AUTHORIZED"
        event["deployment"]["stages"]["preproduction"] = {
            "result": "PENDING",
            "manifest_r_digest": event["manifest_r_digest"],
        }
        controller._save_event(event)

        replay = controller.run_deployment_stage("event-receipt-replay", "preproduction")
        self.assertTrue(replay["idempotent"])
        self.assertEqual("PREPRODUCTION_VERIFIED", replay["status"])
        self.assertEqual(
            "PASS",
            controller.get_event("event-receipt-replay")["event"]["deployment"]["stages"][
                "preproduction"
            ]["result"],
        )


    def test_full_stage_signed_receipt_repairs_interrupted_state_commit(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-full-receipt-replay")
        self._authorize(controller, "event-full-receipt-replay")
        controller.run_deployment_stage("event-full-receipt-replay", "preproduction")
        controller.run_deployment_stage("event-full-receipt-replay", "production_canary")
        controller.run_deployment_stage("event-full-receipt-replay", "production_full")

        event = controller._load_event("event-full-receipt-replay")
        event["status"] = "CANARY_VERIFIED"
        event["deployment"]["stages"]["production_full"] = {
            "result": "PENDING",
            "manifest_r_digest": event["manifest_r_digest"],
        }
        controller._save_event(event)

        replay = controller.run_deployment_stage(
            "event-full-receipt-replay",
            "production_full",
        )
        self.assertTrue(replay["idempotent"])
        self.assertEqual("PRODUCTION_DEPLOYED", replay["status"])
        self.assertEqual(
            "PASS",
            controller.get_event("event-full-receipt-replay")["event"]["deployment"][
                "stages"
            ]["production_full"]["result"],
        )
    def test_control_events_form_a_hash_chain(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-ledger")
        self._authorize(controller, "event-ledger")
        controller.run_deployment_stage("event-ledger", "preproduction")

        verification = controller.verify_control_event_chain("event-ledger")
        self.assertTrue(verification["valid"])
        self.assertGreaterEqual(verification["event_count"], 3)

    def test_control_event_chain_rejects_plain_recomputed_tampering(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-ledger-tamper")
        self._authorize(controller, "event-ledger-tamper")
        chain = controller.verify_control_event_chain("event-ledger-tamper")
        path = Path(chain["path"])
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        records[0]["payload"]["target_scope"] = "production_full"
        previous_hash = None
        for record in records:
            record.pop("hash")
            record["previous_hash"] = previous_hash
            record["hash"] = hashlib.sha256(
                canonical_json(record).encode("utf-8")
            ).hexdigest()
            previous_hash = record["hash"]
        path.write_text(
            "\n".join(json.dumps(item, separators=(",", ":")) for item in records) + "\n",
            encoding="utf-8",
        )

        self.assertFalse(controller.verify_control_event_chain("event-ledger-tamper")["valid"])

    def test_control_event_chain_rejects_truncation_against_signed_anchor(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-ledger-truncate")
        self._authorize(controller, "event-ledger-truncate")
        chain = controller.verify_control_event_chain("event-ledger-truncate")
        path = Path(chain["path"])
        records = path.read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(records), 2)
        path.write_text("\n".join(records[:-1]) + "\n", encoding="utf-8")

        self.assertFalse(controller.verify_control_event_chain("event-ledger-truncate")["valid"])


    def test_production_preflight_rejects_invalid_locked_entrypoints(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        lock_path = Path(
            controller.config["production"]["deployment"]["dependency_lock"]
        )

        path_escape = json.loads(lock_path.read_text(encoding="utf-8"))
        path_escape["commands"]["deploy"]["entrypoints"][1]["path"] = "../escape.py"
        lock_path.write_text(json.dumps(path_escape, sort_keys=True), encoding="utf-8")
        controller.config["production"]["deployment"]["dependency_lock_sha256"] = self._sha256(lock_path)
        escaped = controller.production_preflight()
        self.assertFalse(escaped["ready"])
        self.assertIn("deployment.adapter_lock", escaped["missing_capabilities"])

        controller = ProductionReleaseController(str(self._write_config()))
        lock_path = Path(
            controller.config["production"]["deployment"]["dependency_lock"]
        )
        missing = json.loads(lock_path.read_text(encoding="utf-8"))
        missing["commands"]["deploy"]["entrypoints"][1]["path"] = "missing.py"
        lock_path.write_text(json.dumps(missing, sort_keys=True), encoding="utf-8")
        controller.config["production"]["deployment"]["dependency_lock_sha256"] = self._sha256(lock_path)
        missing_preflight = controller.production_preflight()
        self.assertFalse(missing_preflight["ready"])
        self.assertIn("deployment.adapter_lock", missing_preflight["missing_capabilities"])

        controller = ProductionReleaseController(str(self._write_config()))
        lock_path = Path(
            controller.config["production"]["deployment"]["dependency_lock"]
        )
        unknown = json.loads(lock_path.read_text(encoding="utf-8"))
        unknown["commands"]["deploy"]["entrypoints"].append(
            {
                "argv_index": 2,
                "path": self.adapter.name,
                "sha256": self._sha256(self.adapter),
            }
        )
        lock_path.write_text(json.dumps(unknown, sort_keys=True), encoding="utf-8")
        controller.config["production"]["deployment"]["dependency_lock_sha256"] = self._sha256(lock_path)
        unknown_preflight = controller.production_preflight()
        self.assertFalse(unknown_preflight["ready"])
        self.assertIn("deployment.adapter_lock", unknown_preflight["missing_capabilities"])

    def test_production_preflight_rejects_locked_test_only_adapter_path(self) -> None:
        config_path = self._write_config()
        config = json.loads(config_path.read_text(encoding="utf-8"))
        test_dir = self.root / "tests"
        test_dir.mkdir()
        test_adapter = test_dir / "adapter.py"
        test_adapter.write_bytes(self.adapter.read_bytes())

        deployment = config["production"]["deployment"]
        readback = config["production"]["readback"]
        command_bindings = {
            "deploy": deployment["deploy_command"],
            "verify": deployment["verify_command"],
            "rollback": deployment["rollback_command"],
            "rollback_verify": deployment["rollback_verify_command"],
            "readback": readback["command"],
        }
        lock_path = Path(deployment["dependency_lock"])
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        for command_id, command in command_bindings.items():
            command[1] = str(test_adapter)
            locked = lock["commands"][command_id]
            locked["argv_template"][1] = str(test_adapter)
            script_entrypoint = next(
                item for item in locked["entrypoints"] if item["argv_index"] == 1
            )
            script_entrypoint["path"] = "tests/adapter.py"
            script_entrypoint["sha256"] = self._sha256(test_adapter)
        lock_path.write_text(json.dumps(lock, sort_keys=True), encoding="utf-8")
        deployment["dependency_lock_sha256"] = self._sha256(lock_path)
        config_path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")

        controller = ProductionReleaseController(str(config_path))
        with self.assertRaisesRegex(GateError, "test-only"):
            controller._validate_locked_deployment_command(
                "deploy", deployment["deploy_command"]
            )
        preflight = controller.production_preflight()
        self.assertFalse(preflight["ready"])
        self.assertIn("deployment.adapter_lock", preflight["missing_capabilities"])

    def test_lock_drift_after_authorization_blocks_canary_stage(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-lock-drift")
        self._authorize(controller, "event-lock-drift")
        controller.run_deployment_stage("event-lock-drift", "preproduction")
        lock_path = Path(
            controller.config["production"]["deployment"]["dependency_lock"]
        )
        lock_path.write_text(
            lock_path.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )

        result = controller.run_deployment_stage("event-lock-drift", "production_canary")

        self.assertFalse(result["ready"])
        self.assertEqual("CAPABILITY_BLOCKED", result["status"])
        self.assertIn("deployment.adapter_lock", result["missing_capabilities"])
        self.assertTrue(result["capability_request_path"].endswith("capability-request.json"))

    def test_entrypoint_drift_after_authorization_blocks_full_stage(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-entrypoint-full")
        self._authorize(controller, "event-entrypoint-full")
        controller.run_deployment_stage("event-entrypoint-full", "preproduction")
        controller.run_deployment_stage("event-entrypoint-full", "production_canary")
        self.adapter.write_text("print(\"tampered\")\n", encoding="utf-8")

        result = controller.run_deployment_stage("event-entrypoint-full", "production_full")

        self.assertFalse(result["ready"])
        self.assertEqual("CAPABILITY_BLOCKED", result["status"])
        self.assertIn("deployment.adapter_lock", result["missing_capabilities"])
        self.assertTrue(result["capability_request_path"].endswith("capability-request.json"))

    def test_entrypoint_drift_before_readback_fails_closed(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        self._release_ready(controller, "event-entrypoint-readback")
        self._authorize(controller, "event-entrypoint-readback")
        controller.run_deployment_stage("event-entrypoint-readback", "preproduction")
        controller.run_deployment_stage("event-entrypoint-readback", "production_canary")
        controller.run_deployment_stage("event-entrypoint-readback", "production_full")
        self.adapter.write_text("print(\"tampered\")\n", encoding="utf-8")

        result = controller.run_production_readback("event-entrypoint-readback")

        self.assertEqual("ROLLBACK_FAILED", result["status"])
        self.assertEqual("BLOCKED", result["result"])
        self.assertIn("entrypoint drift", result["receipt"]["error"].lower())
        self.assertIn("entrypoint drift", (result["rollback"]["adapter_error"] or "").lower())


if __name__ == "__main__":
    unittest.main()
