from __future__ import annotations

import hashlib
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

action, stage, digest, mode = sys.argv[1:5]
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
        if mode in {"fail-verify", "bad-rollback"} and stage == "production_canary"
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

        deployment = {
            "stages": ["preproduction", "production_canary", "production_full"],
            "targets": {
                "preproduction": "env:preproduction",
                "production_canary": "env:production:canary",
                "production_full": "env:production:full",
            },
            "deploy_command": command("deploy") if include_deploy else [],
            "verify_command": command("verify"),
            "rollback_command": command("rollback"),
            "rollback_verify_command": command("rollback_verify"),
            "timeout_seconds": 30,
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
                            "timeout_seconds": 30,
                        },
                        "audit": {"key_env": "TEST_RELEASE_AUDIT_KEY"},
                        "deployment": deployment,
                        "readback": {
                            "command": command("readback"),
                            "timeout_seconds": 30,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

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
        # Submission tests intentionally use unsigned local fixtures. Once the
        # event is release-ready, switch the in-memory policy to the production
        # contract so deployment tests exercise the hardened preflight.
        controller.config["policy"]["require_signature"] = True
        controller.config["policy"]["require_cloud_scan"] = True
        controller.config["signature"]["expected_thumbprints"] = ["A" * 40]
        controller.config["cloud_scan"]["command"] = [
            sys.executable,
            "-c",
            "print('{\"verdict\":\"CLEAN\"}')",
        ]

    def test_production_preflight_rejects_disabled_integrity_policy(self) -> None:
        controller = ProductionReleaseController(str(self._write_config()))
        preflight = controller.production_preflight()
        self.assertFalse(preflight["ready"])
        self.assertIn("policy.require_signature", preflight["missing_capabilities"])
        self.assertIn("signature.expected_thumbprints", preflight["missing_capabilities"])
        self.assertIn("policy.require_cloud_scan", preflight["missing_capabilities"])
        self.assertIn("cloud_scan.command", preflight["missing_capabilities"])

    def test_production_preflight_rejects_compatibility_adapter_path(self) -> None:
        config_path = self._write_config()
        import json

        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["policy"]["require_signature"] = True
        config["policy"]["require_cloud_scan"] = True
        config.setdefault("signature", {})["expected_thumbprints"] = ["A" * 40]
        config.setdefault("cloud_scan", {})["command"] = [sys.executable, "-c", "print('{}')"]
        config["production"]["deployment"]["deploy_command"] = [
            sys.executable,
            r"C:\\repo\\tests\\first_practice_adapter_compat.py",
        ]
        config_path.write_text(json.dumps(config), encoding="utf-8")
        preflight = ProductionReleaseController(str(config_path)).production_preflight()
        self.assertFalse(preflight["ready"])
        self.assertIn("deployment.deploy_command", preflight["missing_capabilities"])

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


if __name__ == "__main__":
    unittest.main()
