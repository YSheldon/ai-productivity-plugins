from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_hardened import HardenedReleaseGateController
from release_gate_core import (
    GateError,
    durable_copy_file,
    object_digest,
    read_json,
    write_json,
)


class ReleaseGateFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "product.bin"
        self.artifact.write_bytes(b"approved-build-v1")
        self.config_path = self._write_config(require_cloud_scan=False)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_config(self, require_cloud_scan: bool) -> Path:
        suffix = "cloud" if require_cloud_scan else "local"
        path = self.root / f"config-{suffix}.json"
        path.write_text(
            json.dumps(
                {
                    "storage_dir": str(self.root / f"events-{suffix}"),
                    "policy": {
                        "allowed_extensions": [".bin"],
                        "require_source_ref": True,
                        "require_signature": False,
                        "require_cloud_scan": require_cloud_scan,
                        "allow_unchanged_artifacts": False,
                        "auto_approve_risk_levels": ["standard"],
                    },
                    "cloud_scan": {"command": []},
                    "test": {"command": []},
                }
            ),
            encoding="utf-8",
        )
        return path

    def _controller(self, config_path: Path | None = None) -> HardenedReleaseGateController:
        return HardenedReleaseGateController(str(config_path or self.config_path))

    def _create(self, controller: HardenedReleaseGateController, event_id: str, risk: str = "standard") -> None:
        controller.create_submission(
            event_id=event_id,
            task_id="TASK-1",
            artifacts=[
                {
                    "logical_name": "product.bin",
                    "file_path": str(self.artifact),
                    "source_ref": "commit:abc123",
                }
            ],
            source_ref="commit:abc123",
            rollback_ref="rollback:stable-v0",
            risk_level=risk,
        )

    def _reach_release_gate(self, event_id: str) -> tuple[HardenedReleaseGateController, Path]:
        controller = self._controller()
        self._create(controller, event_id)
        submission = controller.run_submission_gate(event_id)
        self.assertEqual("PASS", submission["overall"])
        self.assertEqual("TESTING", submission["status"])
        test = controller.record_test_result(event_id, "PASS", "test-run:1", "all suites passed")
        self.assertEqual("RELEASE_PREPARING", test["status"])
        output_dir = self.root / f"final-{event_id}"
        final = controller.build_final_release(event_id, str(output_dir))
        self.assertEqual("RELEASE_GATING", final["status"])
        return controller, output_dir

    def test_standard_flow_reaches_release_ready_and_writes_report(self) -> None:
        controller, _ = self._reach_release_gate("event-standard")
        gate = controller.run_release_gate("event-standard")
        self.assertEqual("PASS", gate["overall"])
        self.assertEqual("RELEASE_READY", gate["status"])
        self.assertTrue(all(item["result"] == "PASS" for item in gate["execution"]["results"]))

        report = controller.generate_report("event-standard")
        self.assertTrue(Path(report["report_path"]).is_file())
        self.assertIn("RELEASE_READY", report["report"])

    def test_high_risk_requires_explicit_approval(self) -> None:
        controller = self._controller()
        self._create(controller, "event-high", risk="high")
        controller.run_submission_gate("event-high")
        test = controller.record_test_result("event-high", "PASS", "test-run:high")
        self.assertEqual("TEST_APPROVAL_REQUIRED", test["status"])

        approval = controller.record_test_approval("event-high", "APPROVE", "approval:42")
        self.assertEqual("RELEASE_PREPARING", approval["status"])
        self.assertEqual("APPROVED", approval["approval"]["status"])

    def test_untracked_final_file_is_blocked_by_r04(self) -> None:
        controller, output_dir = self._reach_release_gate("event-extra")
        (output_dir / "unsubmitted.txt").write_text("not submitted", encoding="utf-8")
        gate = controller.run_release_gate("event-extra")
        r04 = [item for item in gate["execution"]["results"] if item["rule_id"] == "R-04"]
        self.assertEqual("SUBMISSION_BLOCKED", gate["status"])
        self.assertEqual(["FAIL"], [item["result"] for item in r04])
        self.assertIn("unsubmitted.txt", r04[0]["detail"])

    def test_missing_final_file_is_blocked_by_r03(self) -> None:
        controller, output_dir = self._reach_release_gate("event-missing")
        (output_dir / "product.bin").unlink()
        gate = controller.run_release_gate("event-missing")
        r03 = [item for item in gate["execution"]["results"] if item["rule_id"] == "R-03"]
        self.assertEqual("SUBMISSION_BLOCKED", gate["status"])
        self.assertEqual(["FAIL"], [item["result"] for item in r03])

    def test_sha1_drift_is_blocked_by_r05(self) -> None:
        controller, output_dir = self._reach_release_gate("event-drift")
        (output_dir / "product.bin").write_bytes(b"changed-after-test")
        gate = controller.run_release_gate("event-drift")
        r05 = [item for item in gate["execution"]["results"] if item["rule_id"] == "R-05"]
        self.assertEqual("SUBMISSION_BLOCKED", gate["status"])
        self.assertEqual(["FAIL"], [item["result"] for item in r05])

    def test_submission_manifest_digest_tamper_is_blocked(self) -> None:
        controller = self._controller()
        self._create(controller, "event-submission-manifest-tamper")
        manifest_path = (
            controller._event_dir("event-submission-manifest-tamper")
            / "manifest-s.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["artifacts"][0]["source_ref"] = "commit:forged"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        gate = controller.run_submission_gate(
            "event-submission-manifest-tamper"
        )
        integrity = [
            item
            for item in gate["execution"]["results"]
            if item["rule_id"] == "T-00"
        ]
        self.assertEqual("SUBMISSION_BLOCKED", gate["status"])
        self.assertEqual(["FAIL"], [item["result"] for item in integrity])

    def test_build_final_rejects_manifest_tamper_without_output(self) -> None:
        controller = self._controller()
        event_id = "event-final-manifest-tamper"
        self._create(controller, event_id)
        self.assertEqual(
            "PASS",
            controller.run_submission_gate(event_id)["overall"],
        )
        controller.record_test_result(event_id, "PASS", "test-run:1")
        manifest_path = (
            controller._event_dir(event_id)
            / "manifest-s.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["artifacts"][0]["source_ref"] = "commit:forged"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        output_dir = self.root / "must-not-exist"

        with self.assertRaisesRegex(GateError, "Manifest-S digest drifted"):
            controller.build_final_release(event_id, str(output_dir))
        self.assertFalse(output_dir.exists())

    def test_write_json_preserves_old_state_and_cleans_temporary_on_failure(self) -> None:
        path = self.root / "durable-state.json"
        write_json(path, {"status": "OLD"})

        with patch(
            "release_gate_core.durable_replace_file",
            side_effect=OSError("injected replace failure"),
        ):
            with self.assertRaisesRegex(OSError, "injected replace failure"):
                write_json(path, {"status": "NEW"})

        self.assertEqual({"status": "OLD"}, read_json(path))
        self.assertEqual(
            [],
            list(path.parent.glob(f".{path.name}.tmp-*")),
        )

    def test_build_final_release_rejects_preexisting_empty_output(self) -> None:
        controller = self._controller()
        event_id = "event-final-existing-output"
        self._create(controller, event_id)
        controller.run_submission_gate(event_id)
        controller.record_test_result(event_id, "PASS", "test-run:1")
        output_dir = self.root / "preexisting-empty-output"
        output_dir.mkdir()

        with self.assertRaisesRegex(GateError, "must not already exist"):
            controller.build_final_release(event_id, str(output_dir))

        self.assertEqual([], list(output_dir.iterdir()))
        self.assertEqual(
            "RELEASE_PREPARING",
            controller._load_event(event_id)["status"],
        )

    def test_build_final_release_cleans_staging_after_copy_failure(self) -> None:
        controller = self._controller()
        event_id = "event-final-copy-failure"
        second_artifact = self.root / "second.bin"
        second_artifact.write_bytes(b"approved-build-v2")
        controller.create_submission(
            event_id=event_id,
            task_id="TASK-1",
            artifacts=[
                {
                    "logical_name": "product.bin",
                    "file_path": str(self.artifact),
                    "source_ref": "commit:abc123",
                },
                {
                    "logical_name": "second.bin",
                    "file_path": str(second_artifact),
                    "source_ref": "commit:abc123",
                },
            ],
            source_ref="commit:abc123",
            rollback_ref="rollback:stable-v0",
            risk_level="standard",
        )
        controller.run_submission_gate(event_id)
        controller.record_test_result(event_id, "PASS", "test-run:1")
        output_dir = self.root / "atomic-final-output"
        original_copy = durable_copy_file
        copy_count = 0

        def fail_second_copy(source: Path, destination: Path) -> None:
            nonlocal copy_count
            copy_count += 1
            if copy_count == 2:
                raise OSError("injected copy failure")
            return original_copy(source, destination)

        with patch(
            "release_gate_core.durable_copy_file",
            side_effect=fail_second_copy,
        ):
            with self.assertRaisesRegex(OSError, "injected copy failure"):
                controller.build_final_release(event_id, str(output_dir))

        self.assertFalse(output_dir.exists())
        self.assertEqual(
            [],
            list(output_dir.parent.glob(f".{output_dir.name}.staging-*")),
        )
        self.assertEqual(
            "RELEASE_PREPARING",
            controller._load_event(event_id)["status"],
        )

    def test_build_final_release_removes_output_after_state_write_failure(self) -> None:
        controller = self._controller()
        event_id = "event-final-state-failure"
        self._create(controller, event_id)
        controller.run_submission_gate(event_id)
        controller.record_test_result(event_id, "PASS", "test-run:1")
        output_dir = self.root / "state-failure-output"

        with patch.object(
            controller,
            "_save_manifest",
            side_effect=OSError("injected state write failure"),
        ):
            with self.assertRaisesRegex(OSError, "injected state write failure"):
                controller.build_final_release(event_id, str(output_dir))

        self.assertFalse(output_dir.exists())
        self.assertEqual(
            [],
            list(output_dir.parent.glob(f".{output_dir.name}.staging-*")),
        )
        self.assertEqual(
            "RELEASE_PREPARING",
            controller._load_event(event_id)["status"],
        )

    def test_hardened_release_gate_binds_source_sha256(self) -> None:
        controller, _ = self._reach_release_gate("event-source-sha256")
        manifest_r = controller._load_manifest(
            "event-source-sha256", "manifest-r.json"
        )
        manifest_r["artifacts"][0]["source_sha256"] = "0" * 64
        manifest_r["digest"] = object_digest(
            {
                "source_manifest_s_digest": manifest_r["source_manifest_s_digest"],
                "artifacts": manifest_r["artifacts"],
            }
        )
        controller._save_manifest(
            "event-source-sha256", "manifest-r.json", manifest_r
        )
        event = controller._load_event("event-source-sha256")
        event["manifest_r_digest"] = manifest_r["digest"]
        controller._save_event(event)

        gate = controller.run_release_gate("event-source-sha256")
        r02 = [
            item
            for item in gate["execution"]["results"]
            if item["rule_id"] == "R-02"
        ]
        self.assertEqual(["FAIL"], [item["result"] for item in r02])

    def test_hardened_release_gate_checks_sha256_when_sha1_is_spoofed(self) -> None:
        event_id = "event-final-sha256"
        controller, output_dir = self._reach_release_gate(event_id)
        final_path = output_dir / "product.bin"
        final_path.write_bytes(b"tampered-after-final-build")
        manifest_s = controller._load_manifest(event_id, "manifest-s.json")
        expected_sha1 = manifest_s["artifacts"][0]["sha1"]

        with patch("release_gate_hardened.sha1_file", return_value=expected_sha1):
            gate = controller.run_release_gate(event_id)

        r05 = [
            item
            for item in gate["execution"]["results"]
            if item["rule_id"] == "R-05"
        ]
        self.assertEqual(["FAIL"], [item["result"] for item in r05])
        self.assertIn(
            "SHA1/SHA256 differs",
            r05[0]["detail"],
        )

    def test_release_manifest_digest_tamper_is_blocked(self) -> None:
        controller, _ = self._reach_release_gate(
            "event-release-manifest-tamper"
        )
        manifest_path = (
            controller._event_dir("event-release-manifest-tamper")
            / "manifest-r.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["artifacts"][0]["source_ref"] = "commit:forged"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        gate = controller.run_release_gate(
            "event-release-manifest-tamper"
        )
        integrity = [
            item
            for item in gate["execution"]["results"]
            if item["rule_id"] == "R-01"
        ]
        self.assertEqual("SUBMISSION_BLOCKED", gate["status"])
        self.assertEqual(["FAIL"], [item["result"] for item in integrity])

    def test_required_cloud_scan_without_adapter_fails_closed(self) -> None:
        cloud_config = self._write_config(require_cloud_scan=True)
        controller = self._controller(cloud_config)
        self._create(controller, "event-cloud")
        gate = controller.run_submission_gate("event-cloud")
        t06 = [item for item in gate["execution"]["results"] if item["rule_id"] == "T-06"]
        self.assertEqual("SUBMISSION_BLOCKED", gate["status"])
        self.assertEqual("BLOCKED", gate["overall"])
        self.assertEqual(["ERROR"], [item["result"] for item in t06])

    def test_required_signature_without_thumbprint_allowlist_fails_preflight(self) -> None:
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["policy"]["require_signature"] = True
        config["signature"] = {"expected_thumbprints": []}
        path = self.root / "config-signature-missing.json"
        path.write_text(json.dumps(config), encoding="utf-8")

        preflight = self._controller(path).preflight()

        self.assertFalse(preflight["ready"])
        self.assertIn("signature_trust_policy", preflight["missing_required_integrations"])

    def test_authenticode_requires_exact_allowed_thumbprint(self) -> None:
        allowed = "A" * 40
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["policy"]["require_signature"] = True
        config["signature"] = {
            "expected_thumbprints": [allowed],
            "expected_subject_contains": "Product Signing",
        }
        path = self.root / "config-signature-allowlist.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        controller = self._controller(path)
        artifact = {"logical_name": "product.bin", "file_path": str(self.artifact)}

        def completed(thumbprint: str) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "status": "Valid",
                        "status_message": "Signature verified",
                        "subject": "CN=Product Signing",
                        "thumbprint": thumbprint,
                    }
                ),
                stderr="",
            )

        with patch("release_gate_core.os.name", "nt"), patch(
            "release_gate_core.subprocess.run",
            return_value=completed("B" * 40),
        ):
            rejected = controller._signature_result("T-05", artifact)
        with patch("release_gate_core.os.name", "nt"), patch(
            "release_gate_core.subprocess.run",
            return_value=completed(allowed),
        ):
            accepted = controller._signature_result("T-05", artifact)

        self.assertEqual("FAIL", rejected["result"])
        self.assertIn("thumbprint", rejected["detail"])
        self.assertEqual("PASS", accepted["result"])
        self.assertIn(allowed, accepted["evidence_ref"])


if __name__ == "__main__":
    unittest.main()
