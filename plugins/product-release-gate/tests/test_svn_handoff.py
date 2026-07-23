from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_svn_handoff import (
    MANIFEST_R_SCHEMA,
    VERIFIED_RECEIPT_SCHEMA,
    SvnGateContractError,
    approval_binding_sha256,
    build_svn_handoff,
    manifest_r_digest,
    validate_verified_receipt,
    workflow_digest,
)


def _manifest() -> dict:
    artifacts = [
        {
            "logical_name": "product.bin",
            "file_path": "C:/frozen/product.bin",
            "size": 19,
            "sha1": "1" * 40,
            "sha256": "2" * 64,
            "source_sha1": "1" * 40,
            "source_sha256": "2" * 64,
            "source_ref": "svn:r123",
        },
        {
            "logical_name": "manifest.txt",
            "file_path": "C:/frozen/manifest.txt",
            "size": 11,
            "sha1": "3" * 40,
            "sha256": "4" * 64,
            "source_sha1": "3" * 40,
            "source_sha256": "4" * 64,
            "source_ref": "svn:r123",
        },
    ]
    manifest = {
        "schema": MANIFEST_R_SCHEMA,
        "event_id": "release-20260722-001",
        "phase": "Manifest-R",
        "created_at": "2026-07-22T01:00:00Z",
        "source_manifest_s_digest": "5" * 64,
        "output_dir": "C:/frozen",
        "artifacts": artifacts,
    }
    manifest["digest"] = manifest_r_digest(manifest)
    return manifest


def _handoff(**overrides: object) -> dict:
    values = {
        "event_id": "release-20260722-001",
        "manifest_r": _manifest(),
        "product_name": "Falcon 客户端",
        "product_version": "6.7.8",
        "repository_root": "https://svn.example.test/releases",
        "fixed_revision": 123,
        "pipeline_nonce": "pipeline-20260722-001",
        "materials": [
            {
                "logical_name": "product.bin",
                "svn_path": "products/client/product.bin",
            },
            {
                "logical_name": "manifest.txt",
                "svn_path": "products/client/manifest.txt",
            },
        ],
        "pre_release_report_sha256": "sha256:" + "6" * 64,
        "source_message_id": "<release-20260722-001@example.test>",
        "created_at": "2026-07-22T02:00:00Z",
    }
    values.update(overrides)
    return build_svn_handoff(**values)


class SvnHandoffTests(unittest.TestCase):
    def test_handoff_derives_every_file_binding_from_manifest_r(self) -> None:
        handoff = _handoff()

        self.assertEqual("ProductMaterialWorkflow/v1", handoff["schema"])
        self.assertEqual("RELEASE_GATE_REQUESTED", handoff["stage"])
        request = handoff["request"]
        self.assertEqual(workflow_digest(request), handoff["request_sha256"])
        expected_digest = "sha256:" + hashlib.sha256(
            json.dumps(
                request,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(expected_digest, handoff["request_sha256"])
        self.assertEqual(handoff["event_id"], handoff["source"]["event_id"])
        self.assertEqual(
            approval_binding_sha256(
                event_id=handoff["event_id"],
                request_sha256=handoff["request_sha256"],
                pre_release_report_sha256=handoff["source"]["pre_release_report_sha256"],
                manifest_sha256=handoff["source"]["manifest_sha256"],
                source_message_id=handoff["source"]["source_message_id"],
            ),
            handoff["source"]["approval_binding_sha256"],
        )
        self.assertEqual(
            {
                "manifest_logical_name": "product.bin",
                "expected_sha1": "1" * 40,
                "expected_sha256": "2" * 64,
                "expected_size_bytes": 19,
            },
            {
                key: handoff["request"]["release_materials"][0][key]
                for key in (
                    "manifest_logical_name",
                    "expected_sha1",
                    "expected_sha256",
                    "expected_size_bytes",
                )
            },
        )

    def test_request_cannot_supply_or_override_manifest_hashes(self) -> None:
        handoff = _handoff(
            materials=[
                {
                    "logical_name": "product.bin",
                    "svn_path": "products/client/product.bin",
                    "expected_sha1": "f" * 40,
                    "expected_sha256": "f" * 64,
                    "expected_size_bytes": 999,
                },
                {
                    "logical_name": "manifest.txt",
                    "svn_path": "products/client/manifest.txt",
                },
            ]
        )

        first = handoff["request"]["release_materials"][0]
        self.assertEqual("1" * 40, first["expected_sha1"])
        self.assertEqual("2" * 64, first["expected_sha256"])
        self.assertEqual(19, first["expected_size_bytes"])

    def test_manifest_drift_and_incomplete_mapping_fail_closed(self) -> None:
        drifted = _manifest()
        drifted["artifacts"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(SvnGateContractError, "semantic digest"):
            _handoff(manifest_r=drifted)

        with self.assertRaisesRegex(SvnGateContractError, "exactly cover"):
            _handoff(
                materials=[
                    {
                        "logical_name": "product.bin",
                        "svn_path": "products/client/product.bin",
                    }
                ]
            )

    def test_unsafe_repository_and_duplicate_paths_fail_closed(self) -> None:
        with self.assertRaisesRegex(SvnGateContractError, "HTTPS URL"):
            _handoff(repository_root="https://user:secret@svn.example.test/releases")
        with self.assertRaisesRegex(SvnGateContractError, "must each be unique"):
            _handoff(
                materials=[
                    {
                        "logical_name": "product.bin",
                        "svn_path": "products/client/same.bin",
                    },
                    {
                        "logical_name": "manifest.txt",
                        "svn_path": "products/client/same.bin",
                    },
                ]
            )

    def test_verified_receipt_is_bound_to_event_request_manifest_and_project(self) -> None:
        handoff = _handoff()
        manifest = _manifest()
        receipt = {
            "schema": VERIFIED_RECEIPT_SCHEMA,
            "verification_status": "VERIFIED",
            "verdict": "CLEAN",
            "event_id": handoff["event_id"],
            "request_sha256": handoff["request_sha256"],
            "manifest_r_digest": "sha256:" + manifest["digest"],
            "project_id": 59,
            "pipeline_id": 1001,
            "job_id": 2001,
            "commit_sha": "7" * 40,
            "gate_result_sha256": "sha256:" + "8" * 64,
            "artifact_manifest_sha256": "sha256:" + "9" * 64,
            "evidence_ref": "gitlab:59/pipelines/1001/jobs/2001",
            "verified_at": "2026-07-22T03:00:00Z",
        }

        validated = validate_verified_receipt(
            receipt,
            event_id=handoff["event_id"],
            request_sha256=handoff["request_sha256"],
            manifest_r_digest=manifest["digest"],
            expected_project_id=59,
        )
        self.assertEqual("CLEAN", validated["verdict"])

        for field, value in (
            ("event_id", "other-event"),
            ("request_sha256", "sha256:" + "a" * 64),
            ("manifest_r_digest", "sha256:" + "b" * 64),
            ("project_id", 60),
            ("verification_status", "UNVERIFIED"),
        ):
            with self.subTest(field=field):
                changed = dict(receipt)
                changed[field] = value
                with self.assertRaises(SvnGateContractError):
                    validate_verified_receipt(
                        changed,
                        event_id=handoff["event_id"],
                        request_sha256=handoff["request_sha256"],
                        manifest_r_digest=manifest["digest"],
                        expected_project_id=59,
                    )

    def test_verified_blocked_receipt_is_valid_evidence_but_not_clean(self) -> None:
        handoff = _handoff()
        manifest = _manifest()
        receipt = {
            "schema": VERIFIED_RECEIPT_SCHEMA,
            "verification_status": "VERIFIED",
            "verdict": "BLOCKED",
            "event_id": handoff["event_id"],
            "request_sha256": handoff["request_sha256"],
            "manifest_r_digest": "sha256:" + manifest["digest"],
            "project_id": 59,
            "pipeline_id": 1001,
            "job_id": 2001,
            "commit_sha": "7" * 40,
            "gate_result_sha256": "sha256:" + "8" * 64,
            "artifact_manifest_sha256": "sha256:" + "9" * 64,
            "evidence_ref": "gitlab:59/pipelines/1001/jobs/2001",
            "verified_at": "2026-07-22T03:00:00Z",
        }

        validated = validate_verified_receipt(
            receipt,
            event_id=handoff["event_id"],
            request_sha256=handoff["request_sha256"],
            manifest_r_digest=manifest["digest"],
            expected_project_id=59,
        )
        self.assertEqual("BLOCKED", validated["verdict"])


if __name__ == "__main__":
    unittest.main()
