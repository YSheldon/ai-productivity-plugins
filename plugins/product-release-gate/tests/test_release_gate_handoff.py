from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from release_gate_core import ReleaseGateController, write_json  # noqa: E402
from release_gate_handoff import HandoffError, build_handoff  # noqa: E402


def request() -> dict:
    return {
        "request_id": "release-20260720-001",
        "pipeline_nonce": "ci-20260720-001",
        "product": {"name": "Widget", "version": "1.2.3"},
        "svn": {"repository_root": "https://svn.example.local/svn/releases", "fixed_revision": 12345},
        "release_materials": [
            {"id": "installer", "path": "materials/installer.bin", "svn_path": "products/widget/installer.bin"},
        ],
    }


def event() -> dict:
    return {"event_id": "event-20260720-001", "status": "RELEASE_READY", "manifest_r_digest": "a" * 64, "history": []}


def manifest() -> dict:
    return {"event_id": "event-20260720-001", "phase": "Manifest-R", "digest": "a" * 64, "artifacts": []}


class ReleaseGateHandoffTests(unittest.TestCase):
    def test_builds_digest_bound_handoff_without_inference(self) -> None:
        handoff = build_handoff(
            event=event(),
            manifest_r=manifest(),
            request=request(),
            pre_release_report_sha256="sha256:" + "b" * 64,
            source_message_id="pre-release-mail-1",
            created_at="2026-07-20T12:00:00Z",
        )
        self.assertEqual("ProductMaterialWorkflow/v1", handoff["schema"])
        self.assertEqual("sha256:" + "a" * 64, handoff["source"]["manifest_sha256"])
        self.assertEqual("sha256:" + "b" * 64, handoff["source"]["pre_release_report_sha256"])

    def test_requires_release_ready_and_matching_manifest(self) -> None:
        blocked = event()
        blocked["status"] = "RELEASE_BLOCKED"
        with self.assertRaisesRegex(HandoffError, "RELEASE_READY"):
            build_handoff(event=blocked, manifest_r=manifest(), request=request(), pre_release_report_sha256="sha256:" + "b" * 64, source_message_id="mail")
        mismatched = manifest()
        mismatched["digest"] = "c" * 64
        with self.assertRaisesRegex(HandoffError, "Manifest-R"):
            build_handoff(event=event(), manifest_r=mismatched, request=request(), pre_release_report_sha256="sha256:" + "b" * 64, source_message_id="mail")

    def test_rejects_unsafe_svn_and_paths(self) -> None:
        bad = request()
        bad["svn"]["repository_root"] = "http://svn.example.local/releases"
        with self.assertRaises(HandoffError):
            build_handoff(event=event(), manifest_r=manifest(), request=bad, pre_release_report_sha256="sha256:" + "b" * 64, source_message_id="mail")
        bad = request()
        bad["release_materials"][0]["path"] = "../installer.bin"
        with self.assertRaises(HandoffError):
            build_handoff(event=event(), manifest_r=manifest(), request=bad, pre_release_report_sha256="sha256:" + "b" * 64, source_message_id="mail")

    def test_controller_records_handoff_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            storage = Path(temp) / "events"
            controller = ReleaseGateController()
            controller.storage_dir = storage
            event_dir = storage / event()["event_id"]
            write_json(event_dir / "event.json", event())
            write_json(event_dir / "manifest-r.json", manifest())
            output = Path(temp) / "handoff.json"
            result = controller.build_live_handoff(
                event()["event_id"], request(), "sha256:" + "b" * 64, "pre-release-mail-1", str(output)
            )
            self.assertEqual("RELEASE_READY", result["status"])
            self.assertTrue(output.is_file())
            stored = json.loads((event_dir / "event.json").read_text(encoding="utf-8"))
            self.assertEqual(str(output.resolve()), stored["live_handoff_path"])
            self.assertTrue(stored["live_handoff_digest"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
