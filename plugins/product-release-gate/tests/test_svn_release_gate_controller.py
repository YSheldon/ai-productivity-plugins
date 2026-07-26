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

from release_gate_core import GateError
from release_gate_credentials import (
    current_runtime_principal,
    runtime_principal_sha256,
)
from release_gate_production import ProductionReleaseController
from release_gate_svn_handoff import (
    VERIFIED_RECEIPT_SCHEMA,
    approval_binding_sha256,
    workflow_digest,
)


class SvnReleaseGateControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "product.bin"
        self.artifact.write_bytes(b"frozen-release-candidate")
        self.verifier = self.root / "verify_receipt.py"
        self.verifier.write_text(
            """
import json
import sys

receipt_path, event_id, request_sha256, manifest_r_digest, project_id = sys.argv[1:6]
payload = json.loads(open(receipt_path, encoding="utf-8").read())
payload["verifier_context_matches"] = (
    payload.get("event_id") == event_id
    and payload.get("request_sha256") == request_sha256
    and payload.get("manifest_r_digest") == manifest_r_digest
    and payload.get("project_id") == int(project_id)
)
payload.pop("verifier_context_matches")
print(json.dumps(payload))
""".strip()
            + "\n",
            encoding="utf-8",
        )
        self.previous_auth = os.environ.get("TEST_SVN_GATE_AUTH_KEY")
        self.previous_audit = os.environ.get("TEST_SVN_GATE_AUDIT_KEY")
        os.environ["TEST_SVN_GATE_AUTH_KEY"] = (
            "test-svn-gate-authorization-key-32-bytes"
        )
        os.environ["TEST_SVN_GATE_AUDIT_KEY"] = (
            "test-svn-gate-audit-key-separate-32-bytes"
        )

    def tearDown(self) -> None:
        if self.previous_auth is None:
            os.environ.pop("TEST_SVN_GATE_AUTH_KEY", None)
        else:
            os.environ["TEST_SVN_GATE_AUTH_KEY"] = self.previous_auth
        if self.previous_audit is None:
            os.environ.pop("TEST_SVN_GATE_AUDIT_KEY", None)
        else:
            os.environ["TEST_SVN_GATE_AUDIT_KEY"] = self.previous_audit
        self.temporary.cleanup()

    def _config(self, *, verifier_enabled: bool = True) -> Path:
        verify_command = (
            [
                sys.executable,
                str(self.verifier),
                "{receipt_path}",
                "{event_id}",
                "{request_sha256}",
                "{manifest_r_digest}",
                "{expected_project_id}",
            ]
            if verifier_enabled
            else []
        )
        config = {
            "storage_dir": str(self.root / "events"),
            "runtime": {
                "identity_binding": {
                    "required": True,
                    "principal_sha256": runtime_principal_sha256(
                        current_runtime_principal()
                    ),
                }
            },
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
                    "key_env": "TEST_SVN_GATE_AUTH_KEY",
                    "ttl_seconds": 3600,
                    "verify_command": [sys.executable, "unused.py"],
                },
                "audit": {"key_env": "TEST_SVN_GATE_AUDIT_KEY"},
                "svn_release_gate": {
                    "required": True,
                    "expected_project_id": 59,
                    "verify_command": verify_command,
                    "timeout_seconds": 30,
                },
            },
        }
        path = self.root / (
            "config.json" if verifier_enabled else "config-no-verifier.json"
        )
        path.write_text(json.dumps(config), encoding="utf-8")
        return path

    def _controller(
        self,
        *,
        verifier_enabled: bool = True,
    ) -> ProductionReleaseController:
        return ProductionReleaseController(
            str(self._config(verifier_enabled=verifier_enabled)),
            allow_unlocked_test_adapters=True,
        )

    def _release_ready(
        self,
        controller: ProductionReleaseController,
        event_id: str,
    ) -> None:
        controller.create_submission(
            event_id=event_id,
            task_id="TASK-SVN-GATE",
            artifacts=[
                {
                    "logical_name": "product.bin",
                    "file_path": str(self.artifact),
                    "source_ref": "svn:r123",
                }
            ],
            source_ref="svn:r123",
            rollback_ref="rollback:stable",
            risk_level="standard",
        )
        self.assertEqual(
            "PASS",
            controller.run_submission_gate(event_id)["overall"],
        )
        controller.record_test_result(event_id, "PASS", "test:pass")
        controller.build_final_release(
            event_id,
            str(self.root / f"final-{event_id}"),
        )
        self.assertEqual(
            "RELEASE_READY",
            controller.run_release_gate(event_id)["status"],
        )

    def _handoff(
        self,
        controller: ProductionReleaseController,
        event_id: str,
    ) -> dict:
        return controller.build_svn_live_handoff(
            event_id=event_id,
            product_name="Falcon Client",
            product_version="6.7.8",
            repository_root="https://svn.example.test/releases",
            fixed_revision=123,
            pipeline_nonce="pipeline-20260722-001",
            materials=[
                {
                    "logical_name": "product.bin",
                    "svn_path": "products/client/product.bin",
                }
            ],
            pre_release_report_sha256="sha256:" + "6" * 64,
            source_message_id="<release@example.test>",
        )

    def _receipt(
        self,
        controller: ProductionReleaseController,
        event_id: str,
        *,
        verdict: str,
    ) -> Path:
        event = controller.get_event(event_id)["event"]
        gate = event["svn_release_gate"]
        receipt = {
            "schema": VERIFIED_RECEIPT_SCHEMA,
            "verification_status": "VERIFIED",
            "verdict": verdict,
            "event_id": event_id,
            "request_sha256": gate["request_sha256"],
            "manifest_r_digest": gate["manifest_r_digest"],
            "project_id": 59,
            "pipeline_id": 1001,
            "job_id": 2001,
            "commit_sha": "7" * 40,
            "gate_result_sha256": "sha256:" + "8" * 64,
            "artifact_manifest_sha256": "sha256:" + "9" * 64,
            "evidence_ref": "gitlab:59/pipelines/1001/jobs/2001",
            "verified_at": "2026-07-22T03:00:00Z",
        }
        path = self.root / f"{event_id}-{verdict.lower()}-receipt.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        return path

    def test_clean_receipt_is_required_and_reverified_before_authorization(self) -> None:
        controller = self._controller()
        event_id = "event-svn-clean"
        self._release_ready(controller, event_id)

        with self.assertRaisesRegex(GateError, "verified CLEAN"):
            controller.request_release_authorization(
                event_id,
                "release-manager",
                "preproduction",
            )

        handoff = self._handoff(controller, event_id)
        material = handoff["handoff"]["request"]["release_materials"][0]
        manifest = controller.get_event(event_id)["manifest_r"]
        self.assertEqual(manifest["artifacts"][0]["sha1"], material["expected_sha1"])
        self.assertEqual(manifest["artifacts"][0]["sha256"], material["expected_sha256"])
        self.assertEqual(manifest["artifacts"][0]["size"], material["expected_size_bytes"])
        with self.assertRaisesRegex(GateError, "verified CLEAN"):
            controller.request_release_authorization(
                event_id,
                "release-manager",
                "preproduction",
            )

        receipt_path = self._receipt(
            controller,
            event_id,
            verdict="CLEAN",
        )
        recorded = controller.record_svn_live_gate_receipt(
            event_id,
            str(receipt_path),
        )
        self.assertEqual("CLEAN", recorded["svn_release_gate_status"])
        self.assertEqual("RELEASE_READY", recorded["status"])

        authorization = controller.request_release_authorization(
            event_id,
            "release-manager",
            "preproduction",
        )
        self.assertEqual("RELEASE_AUTHORIZATION_REQUIRED", authorization["status"])

    def test_blocked_receipt_stops_the_release(self) -> None:
        controller = self._controller()
        event_id = "event-svn-blocked"
        self._release_ready(controller, event_id)
        self._handoff(controller, event_id)
        receipt_path = self._receipt(
            controller,
            event_id,
            verdict="BLOCKED",
        )

        result = controller.record_svn_live_gate_receipt(
            event_id,
            str(receipt_path),
        )

        self.assertEqual("BLOCKED", result["svn_release_gate_status"])
        self.assertEqual("RELEASE_BLOCKED", result["status"])
        with self.assertRaisesRegex(GateError, "verified CLEAN"):
            controller.request_release_authorization(
                event_id,
                "release-manager",
                "preproduction",
            )

    def test_receipt_and_material_drift_are_rejected_after_clean(self) -> None:
        for drift in ("receipt", "material"):
            with self.subTest(drift=drift):
                controller = self._controller()
                event_id = f"event-svn-drift-{drift}"
                self._release_ready(controller, event_id)
                self._handoff(controller, event_id)
                receipt_path = self._receipt(
                    controller,
                    event_id,
                    verdict="CLEAN",
                )
                controller.record_svn_live_gate_receipt(
                    event_id,
                    str(receipt_path),
                )
                if drift == "receipt":
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    receipt["verdict"] = "BLOCKED"
                    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                else:
                    manifest = controller.get_event(event_id)["manifest_r"]
                    Path(manifest["artifacts"][0]["file_path"]).write_bytes(
                        b"tampered"
                    )

                with self.assertRaises(GateError):
                    controller.request_release_authorization(
                        event_id,
                        "release-manager",
                        "preproduction",
                    )

    def test_malformed_approval_digest_is_rejected_even_if_rebound(self) -> None:
        controller = self._controller()
        event_id = "event-svn-malformed-approval-digest"
        self._release_ready(controller, event_id)
        result = self._handoff(controller, event_id)
        handoff_path = Path(result["handoff_path"])
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        source = handoff["source"]
        source["pre_release_report_sha256"] = "not-a-digest"
        source["approval_binding_sha256"] = approval_binding_sha256(
            event_id=handoff["event_id"],
            request_sha256=handoff["request_sha256"],
            pre_release_report_sha256=source["pre_release_report_sha256"],
            manifest_sha256=source["manifest_sha256"],
            source_message_id=source["source_message_id"],
        )
        handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
        event = controller._load_event(event_id)
        event["svn_release_gate"]["handoff_sha256"] = workflow_digest(handoff)
        with self.assertRaisesRegex(GateError, "not bound"):
            controller._load_bound_svn_handoff(event)

    def test_required_verifier_is_a_production_preflight_capability(self) -> None:
        controller = self._controller(verifier_enabled=False)

        preflight = controller.production_preflight()

        self.assertIn(
            "svn_release_gate.receipt_verifier",
            preflight["missing_capabilities"],
        )


    def test_production_verifier_command_is_dependency_locked(self) -> None:
        config_path = self._config()
        config = json.loads(config_path.read_text(encoding="utf-8"))
        command = config["production"]["svn_release_gate"][
            "verify_command"
        ]

        def digest(path: Path) -> str:
            return hashlib.sha256(path.read_bytes()).hexdigest()

        lock_path = self.root / "svn-verifier.lock.json"
        lock = {
            "schema_version": 1,
            "root": ".",
            "commands": {
                "svn_release_gate_receipt": {
                    "argv_template": command,
                    "entrypoints": [
                        {
                            "argv_index": 0,
                            "path": sys.executable,
                            "sha256": digest(Path(sys.executable)),
                        },
                        {
                            "argv_index": 1,
                            "path": self.verifier.name,
                            "sha256": digest(self.verifier),
                        },
                    ],
                }
            },
        }
        lock_path.write_text(
            json.dumps(lock, sort_keys=True),
            encoding="utf-8",
        )
        config["production"]["deployment"] = {
            "dependency_lock": str(lock_path),
            "dependency_lock_sha256": digest(lock_path),
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        controller = ProductionReleaseController(str(config_path))

        self.assertTrue(controller._svn_release_gate_verifier_ready())

        self.verifier.write_text(
            self.verifier.read_text(encoding="utf-8") + "# drift\n",
            encoding="utf-8",
        )
        self.assertFalse(controller._svn_release_gate_verifier_ready())


if __name__ == "__main__":
    unittest.main()
