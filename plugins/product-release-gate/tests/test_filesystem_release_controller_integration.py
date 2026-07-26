from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from bootstrap_filesystem_production import bootstrap_filesystem_production
from filesystem_release_adapter import FilesystemReleaseAdapter
from release_gate_credentials import runtime_principal_sha256
from release_gate_production import ProductionReleaseController


AUTH_ENV = "TEST_FILESYSTEM_CONTROLLER_AUTH_KEY"
AUDIT_ENV = "TEST_FILESYSTEM_CONTROLLER_AUDIT_KEY"
AUTH_KEY = "controller-filesystem-authorization-key-32-bytes"
AUDIT_KEY = "controller-filesystem-audit-key-at-least-32-bytes"
AUTH_TARGET = "ProductReleaseGate/test-authorization/v1"
AUDIT_TARGET = "ProductReleaseGate/test-audit/v1"
RUNTIME_PRINCIPAL = "windows-sid:S-1-5-21-filesystem-controller"


class FilesystemReleaseControllerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "runtime" / "config.json"
        self.adapter_dir = self.root / "runtime" / "immutable-adapter"
        self.targets = {
            "preproduction": self.root / "targets" / "preproduction",
            "production_canary": self.root / "targets" / "canary",
            "production_full": self.root / "targets" / "production",
        }
        self.previous_auth = os.environ.get(AUTH_ENV)
        self.previous_audit = os.environ.get(AUDIT_ENV)
        os.environ[AUTH_ENV] = AUTH_KEY
        os.environ[AUDIT_ENV] = AUDIT_KEY
        self.approval_adapter = self.root / "approval_adapter.py"
        self.approval_adapter.write_text(
            """
import json
import sys

approval_ref, manifest_r_digest, manifest_s_digest, target_scope = sys.argv[1:5]
print(json.dumps({
    "result": "APPROVE",
    "approval_ref": approval_ref,
    "approved_by": "release-director",
    "manifest_s_digest": manifest_s_digest,
    "manifest_r_digest": manifest_r_digest,
    "target_scope": target_scope,
    "evidence_ref": "approval-readback:" + approval_ref,
}))
""".strip()
            + "\n",
            encoding="utf-8",
        )
        bootstrap_filesystem_production(
            output_config=self.config_path,
            adapter_dir=self.adapter_dir,
            preproduction_target=self.targets["preproduction"],
            canary_target=self.targets["production_canary"],
            production_target=self.targets["production_full"],
            authorization_key_env=AUTH_ENV,
            audit_key_env=AUDIT_ENV,
        )
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["storage_dir"] = str(self.root / "events")
        config["policy"] = {
            "allowed_extensions": [".bin"],
            "require_source_ref": True,
            "require_signature": False,
            "require_cloud_scan": False,
            "allow_unchanged_artifacts": False,
            "auto_approve_risk_levels": ["standard"],
        }
        config["cloud_scan"] = {"command": []}
        config["test"] = {"command": []}
        config["production"]["enabled"] = True
        config["production"]["authorization"].update(
            {
                "key_env": AUTH_ENV,
                "credential_target": AUTH_TARGET,
                "ttl_seconds": 3600,
                "verify_command": [
                    sys.executable,
                    str(self.approval_adapter),
                    "{approval_ref}",
                    "{manifest_r_digest}",
                    "{manifest_s_digest}",
                    "{target_scope}",
                ],
                "timeout_seconds": 30,
            }
        )
        config["production"]["audit"] = {
            "key_env": AUDIT_ENV,
            "credential_target": AUDIT_TARGET,
        }
        config["runtime"]["identity_binding"]["principal_sha256"] = (
            runtime_principal_sha256(RUNTIME_PRINCIPAL)
        )
        self.config_path.write_text(
            json.dumps(config, indent=2) + "\n",
            encoding="utf-8",
        )
        os.environ.pop(AUTH_ENV, None)
        os.environ.pop(AUDIT_ENV, None)
        self.credentials = {
            AUTH_TARGET: AUTH_KEY,
            AUDIT_TARGET: AUDIT_KEY,
        }
        self.controller = ProductionReleaseController(
            str(self.config_path),
            credential_reader=self.credentials.get,
            environ={},
            runtime_principal_provider=lambda: RUNTIME_PRINCIPAL,
        )

    def tearDown(self) -> None:
        if self.previous_auth is None:
            os.environ.pop(AUTH_ENV, None)
        else:
            os.environ[AUTH_ENV] = self.previous_auth
        if self.previous_audit is None:
            os.environ.pop(AUDIT_ENV, None)
        else:
            os.environ[AUDIT_ENV] = self.previous_audit
        self.temporary.cleanup()

    def _release_ready(
        self,
        event_id: str,
        *,
        version: str,
        content: bytes,
    ) -> dict[str, object]:
        artifact = self.root / f"product-{version}.bin"
        artifact.write_bytes(content)
        self.controller.create_submission(
            event_id=event_id,
            task_id=f"TASK-{version.upper()}",
            artifacts=[
                {
                    "logical_name": "product.bin",
                    "file_path": str(artifact),
                    "source_ref": f"commit:{version}",
                }
            ],
            source_ref=f"commit:{version}",
            rollback_ref=f"rollback:{version}",
            risk_level="standard",
        )
        self.controller.config["policy"]["require_signature"] = False
        self.controller.config["policy"]["require_cloud_scan"] = False
        submission = self.controller.run_submission_gate(event_id)
        self.assertEqual("PASS", submission["overall"])
        self.controller.record_test_result(
            event_id,
            "PASS",
            f"test-report:{version}",
        )
        self.controller.build_final_release(
            event_id,
            str(self.root / f"final-{event_id}"),
        )
        release = self.controller.run_release_gate(event_id)
        self.assertEqual("RELEASE_READY", release["status"])
        # Submission uses unsigned local fixtures. After the release gate has
        # frozen the event, switch the in-memory policy to the production
        # integrity contract so deployment tests exercise the hardened
        # preflight without invoking a real cloud-scan service.
        self.controller.config["policy"]["require_signature"] = True
        self.controller.config["policy"]["require_cloud_scan"] = True
        self.controller.config["signature"]["expected_thumbprints"] = [
            "A" * 40
        ]
        self.controller.config["cloud_scan"]["command"] = [
            sys.executable,
            "-c",
            "print('{\"verdict\":\"CLEAN\"}')",
        ]
        return self.controller.get_event(event_id)["event"]

    def _authorize(self, event_id: str) -> dict[str, object]:
        event = self.controller.get_event(event_id)["event"]
        self.controller.request_release_authorization(
            event_id,
            requested_by="release-bot",
            target_scope=(
                "preproduction,production_canary,production_full"
            ),
        )
        result = self.controller.record_release_authorization(
            event_id,
            decision="APPROVE",
            approval_ref=f"approval:{event_id}",
            approved_by="release-director",
            manifest_s_digest=event["manifest_s_digest"],
            manifest_r_digest=event["manifest_r_digest"],
        )
        self.assertEqual("RELEASE_AUTHORIZED", result["status"])
        return result

    def _deploy_all_stages(self, event_id: str) -> dict[str, object]:
        self.assertEqual(
            "PREPRODUCTION_VERIFIED",
            self.controller.run_deployment_stage(
                event_id,
                "preproduction",
            )["status"],
        )
        self.assertEqual(
            "CANARY_VERIFIED",
            self.controller.run_deployment_stage(
                event_id,
                "production_canary",
            )["status"],
        )
        full = self.controller.run_deployment_stage(
            event_id,
            "production_full",
        )
        self.assertEqual("PRODUCTION_DEPLOYED", full["status"])
        return full

    def _run_verified_release(
        self,
        event_id: str,
        *,
        version: str,
        content: bytes,
    ) -> dict[str, object]:
        event = self._release_ready(
            event_id,
            version=version,
            content=content,
        )
        self._authorize(event_id)
        self._deploy_all_stages(event_id)
        readback = self.controller.run_production_readback(event_id)
        self.assertEqual("PRODUCTION_VERIFIED", readback["status"])
        self.assertEqual("PASS", readback["result"])
        return event

    def _active_product_path(self, stage: str) -> Path:
        target = self.targets[stage]
        current = json.loads(
            (
                target / ".product-release-gate" / "current.json"
            ).read_text(encoding="utf-8")
        )
        return (
            target
            / ".product-release-gate"
            / current["release_ref"]
            / "files"
            / "product.bin"
        )

    def test_real_adapter_completes_three_stages_readback_and_report(self) -> None:
        event = self._run_verified_release(
            "event-filesystem-v1",
            version="v1",
            content=b"production-v1",
        )

        preflight = self.controller.production_preflight(
            include_report_delivery=False
        )
        self.assertTrue(preflight["ready"], preflight)
        for stage in self.targets:
            self.assertEqual(
                b"production-v1",
                self._active_product_path(stage).read_bytes(),
            )
        report = self.controller.generate_production_report(
            "event-filesystem-v1"
        )
        self.assertTrue(Path(report["report_path"]).is_file())
        self.assertTrue(Path(report["receipt_path"]).is_file())
        self.assertEqual(
            "PRODUCTION_VERIFIED",
            self.controller.get_event("event-filesystem-v1")["event"][
                "status"
            ],
        )
        self.assertEqual(
            event["manifest_r_digest"],
            json.loads(
                (
                    self.targets["production_full"]
                    / ".product-release-gate"
                    / "current.json"
                ).read_text(encoding="utf-8")
            )["manifest_r_digest"],
        )
        self.assertTrue(
            self.controller.verify_control_event_chain(
                "event-filesystem-v1"
            )["valid"]
        )

    def test_production_tamper_rolls_back_to_previous_verified_release(self) -> None:
        baseline = self._run_verified_release(
            "event-filesystem-baseline",
            version="baseline",
            content=b"stable-production",
        )
        candidate = self._release_ready(
            "event-filesystem-v2",
            version="v2",
            content=b"candidate-production",
        )
        self._authorize("event-filesystem-v2")
        self._deploy_all_stages("event-filesystem-v2")
        self._active_product_path("production_full").write_bytes(
            b"tampered-after-deploy"
        )

        result = self.controller.run_production_readback(
            "event-filesystem-v2"
        )

        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertEqual("PASS", result["rollback"]["result"])
        current = json.loads(
            (
                self.targets["production_full"]
                / ".product-release-gate"
                / "current.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(baseline["manifest_r_digest"], current["manifest_r_digest"])
        self.assertNotEqual(candidate["manifest_r_digest"], current["manifest_r_digest"])
        adapter = FilesystemReleaseAdapter(
            str(self.targets["production_full"]),
            environ={AUTH_ENV: AUTH_KEY},
        )
        readback = adapter.readback(
            expected_digest=str(baseline["manifest_r_digest"])
        )
        self.assertEqual("PASS", readback["result"])
        self.assertEqual(
            b"stable-production",
            self._active_product_path("production_full").read_bytes(),
        )
        self.assertTrue(
            self.controller.verify_control_event_chain(
                "event-filesystem-v2"
            )["valid"]
        )


if __name__ == "__main__":
    unittest.main()
