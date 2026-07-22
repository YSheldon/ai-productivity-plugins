from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
import zipfile
from io import BytesIO
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = (
    PLUGIN_ROOT / "scripts" / "verify_gitlab_svn_gate_receipt.py"
)
SPEC = importlib.util.spec_from_file_location(
    "verify_gitlab_svn_gate_receipt",
    SCRIPT_PATH,
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)


def _canonical(value: object, *, ensure_ascii: bool = True) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=ensure_ascii,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _handoff() -> tuple[dict, str, str]:
    request = {
        "request_id": "release-20260722-001",
        "pipeline_nonce": "pipeline-20260722-001",
        "product": {"name": "Falcon 客户端", "version": "6.7.8"},
        "svn": {
            "repository_root": "https://svn.example.test/releases",
            "fixed_revision": 123,
        },
        "release_materials": [
            {
                "id": "product.bin",
                "path": "materials/product.bin",
                "svn_path": "products/client/product.bin",
                "manifest_logical_name": "product.bin",
                "expected_sha1": "1" * 40,
                "expected_sha256": "2" * 64,
                "expected_size_bytes": 19,
            }
        ],
    }
    request_digest = "sha256:" + hashlib.sha256(
        _canonical(request, ensure_ascii=False)
    ).hexdigest()
    manifest_digest = "sha256:" + "3" * 64
    return (
        {
            "schema": "ProductMaterialWorkflow/v1",
            "stage": "RELEASE_GATE_REQUESTED",
            "event_id": request["request_id"],
            "request": request,
            "request_sha256": request_digest,
            "source": {
                "pre_release_status": "PASS",
                "pre_release_report_sha256": "sha256:" + "4" * 64,
                "manifest_sha256": manifest_digest,
                "source_message_id": "<release@example.test>",
            },
            "created_at": "2026-07-22T02:00:00Z",
        },
        request_digest,
        manifest_digest,
    )


def _artifact_archive(
    *,
    verdict: str = "CLEAN",
    request_digest: str,
    mutate_attestation: dict | None = None,
) -> bytes:
    stages = [
        {
            "name": name,
            "status": (
                "BLOCKED"
                if verdict == "BLOCKED" and name == "pre_release_binding"
                else "CLEAN"
            ),
            "summary": "verified",
        }
        for name in VERIFIER.REQUIRED_GATE_STAGES
    ]
    gate_result = {
        "artifact_profile": "ci_safe_summary_v1",
        "request_id": "release-20260722-001",
        "verdict": verdict,
        "stages": stages,
    }
    publication_payloads = {
        "gate-result.json": _canonical(gate_result),
        **{
            f"evidence/{stage['name']}.json": _canonical(
                {
                    "artifact_profile": "ci_safe_summary_v1",
                    **stage,
                }
            )
            for stage in stages
        },
    }
    publication_manifest = [
        {
            "relative_path": path,
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        for path, raw in sorted(publication_payloads.items())
    ]
    payload_manifest_digest = hashlib.sha256(
        _canonical(publication_manifest)
    ).hexdigest()
    attestation = {
        "schema_version": 1,
        "mode": "live",
        "project_id": "59",
        "pipeline_id": "1001",
        "job_id": "2001",
        "reviewed_commit": "7" * 40,
        "request_id": "release-20260722-001",
        "request_sha256": request_digest,
        "deployment_manifest_sha256": "5" * 64,
        "authoritative_content_manifest_sha256": "6" * 64,
        "authoritative_content_manifest_file_sha256": "7" * 64,
        "ci_snapshot_manifest_sha256": payload_manifest_digest,
        "runner_identity_receipt_sha256": "8" * 64,
        "runner_id": 42,
        "network_service_in_tcb": True,
    }
    if mutate_attestation:
        attestation.update(mutate_attestation)
    final_payloads = {
        **publication_payloads,
        "runtime-attestation.json": _canonical(attestation),
    }
    final_files = [
        {
            "relative_path": path,
            "size_bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        for path, raw in sorted(final_payloads.items())
    ]
    artifact_manifest = {
        "schema_version": 1,
        "payload_manifest_sha256": payload_manifest_digest,
        "files": final_files,
    }
    artifact_manifest["manifest_sha256"] = hashlib.sha256(
        _canonical(artifact_manifest)
    ).hexdigest()
    root = "artifacts/1001-2001-gate-live/"
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, raw in final_payloads.items():
            archive.writestr(root + path, raw)
        archive.writestr(
            root + "artifact-manifest.json",
            _canonical(artifact_manifest),
        )
    return stream.getvalue()


class GitLabSvnGateVerifierTests(unittest.TestCase):
    def _responses(
        self,
        *,
        verdict: str = "CLEAN",
        request_digest: str,
        protected: bool = True,
        mutate_attestation: dict | None = None,
    ) -> tuple[dict[str, dict], bytes]:
        status = "success" if verdict == "CLEAN" else "failed"
        responses = {
            "/projects/59/pipelines/1001": {
                "id": 1001,
                "ref": "main",
                "sha": "7" * 40,
                "status": status,
            },
            "/projects/59/jobs/2001": {
                "id": 2001,
                "name": "live_gate",
                "ref": "main",
                "tag": False,
                "status": status,
                "pipeline": {"id": 1001},
                "commit": {"id": "7" * 40},
            },
            "/projects/59/repository/branches/main": {
                "name": "main",
                "protected": protected,
            },
        }
        return responses, _artifact_archive(
            verdict=verdict,
            request_digest=request_digest,
            mutate_attestation=mutate_attestation,
        )

    def _verify(
        self,
        *,
        verdict: str = "CLEAN",
        protected: bool = True,
        mutate_attestation: dict | None = None,
    ) -> dict:
        handoff, request_digest, manifest_digest = _handoff()
        responses, archive = self._responses(
            verdict=verdict,
            request_digest=request_digest,
            protected=protected,
            mutate_attestation=mutate_attestation,
        )
        return VERIFIER.verify_gitlab_receipt(
            locator={
                "schema": "ProductMaterialGatePipelineLocator/v1",
                "project_id": 59,
                "pipeline_id": 1001,
                "job_id": 2001,
            },
            handoff=handoff,
            event_id="release-20260722-001",
            request_sha256=request_digest,
            manifest_r_digest=manifest_digest,
            expected_project_id=59,
            expected_ref="main",
            fetch_json=lambda path: responses[path],
            fetch_bytes=lambda path: (
                archive
                if path == "/projects/59/jobs/2001/artifacts"
                else b""
            ),
            verified_at="2026-07-22T04:00:00Z",
        )

    def test_clean_and_blocked_protected_jobs_produce_bound_receipts(self) -> None:
        clean = self._verify(verdict="CLEAN")
        blocked = self._verify(verdict="BLOCKED")

        self.assertEqual("CLEAN", clean["verdict"])
        self.assertEqual("BLOCKED", blocked["verdict"])
        self.assertEqual(59, clean["project_id"])
        self.assertEqual(1001, clean["pipeline_id"])
        self.assertEqual(2001, clean["job_id"])
        self.assertRegex(clean["gate_result_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(
            clean["artifact_manifest_sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )

    def test_unprotected_ref_and_attestation_substitution_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            VERIFIER.ReceiptVerificationError,
            "protected ref binding",
        ):
            self._verify(protected=False)
        for mutation in (
            {"request_id": "other-release"},
            {"request_sha256": "sha256:" + "f" * 64},
            {"pipeline_id": "1002"},
            {"job_id": "2002"},
            {"reviewed_commit": "9" * 40},
            {"network_service_in_tcb": False},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(
                    VERIFIER.ReceiptVerificationError,
                    "runtime attestation",
                ):
                    self._verify(mutate_attestation=mutation)

    def test_handoff_and_locator_substitution_fail_closed(self) -> None:
        handoff, request_digest, manifest_digest = _handoff()
        responses, archive = self._responses(
            request_digest=request_digest,
        )
        handoff["request"]["product"]["version"] = "9.9.9"
        with self.assertRaisesRegex(
            VERIFIER.ReceiptVerificationError,
            "handoff request digest",
        ):
            VERIFIER.verify_gitlab_receipt(
                locator={
                    "schema": "ProductMaterialGatePipelineLocator/v1",
                    "project_id": 59,
                    "pipeline_id": 1001,
                    "job_id": 2001,
                },
                handoff=handoff,
                event_id="release-20260722-001",
                request_sha256=request_digest,
                manifest_r_digest=manifest_digest,
                expected_project_id=59,
                expected_ref="main",
                fetch_json=lambda path: responses[path],
                fetch_bytes=lambda _path: archive,
            )

    def test_archive_path_traversal_is_rejected(self) -> None:
        stream = BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../gate-result.json", b"{}")
        with self.assertRaisesRegex(
            VERIFIER.ReceiptVerificationError,
            "unsafe path",
        ):
            VERIFIER._archive_payloads(stream.getvalue())


if __name__ == "__main__":
    unittest.main()
