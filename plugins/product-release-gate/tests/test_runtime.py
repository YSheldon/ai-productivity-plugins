from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_lock import RunOnceLock
from release_gate_runtime import ReleaseGateWorkflowRuntime


class FakeController:
    def __init__(self, root: Path) -> None:
        self.storage_dir = root / "events"
        self.storage_dir.mkdir(parents=True)
        self.config = {
            "runtime": {"state_dir": str(root / "state"), "poll_minutes": 60},
            "production": {
                "enabled": True,
                "approval_workflow": {
                    "mode": "unified_multi_role",
                    "verify_command": ["verifier"],
                },
            },
        }
        self.calls: list[tuple[str, str]] = []
        self.authorization_requests: list[str] = []
        self.authorization_finalizations: list[str] = []

    def _event_path(self, event_id: str) -> Path:
        return self.storage_dir / event_id / "event.json"

    def get_event(self, event_id: str) -> dict:
        return json.loads(self._event_path(event_id).read_text(encoding="utf-8"))

    def request_release_authorization(
        self,
        event_id: str,
        requested_by: str,
        target_scope: str,
    ) -> dict:
        event = self.get_event(event_id)
        event["status"] = "RELEASE_AUTHORIZATION_REQUIRED"
        event["release_authorization"] = {
            "authorization_source": "unified_multi_role_receipt",
            "requested_by": requested_by,
            "target_scope": target_scope,
        }
        self._event_path(event_id).write_text(
            json.dumps(event),
            encoding="utf-8",
        )
        self.authorization_requests.append(event_id)
        return {"status": event["status"]}

    def finalize_verified_release_authorization(
        self,
        event_id: str,
    ) -> dict:
        event = self.get_event(event_id)
        event["status"] = "RELEASE_AUTHORIZED"
        self._event_path(event_id).write_text(
            json.dumps(event),
            encoding="utf-8",
        )
        self.authorization_finalizations.append(event_id)
        return {"status": event["status"]}

    def record_unified_release_approval(self, event_id: str, verification_ref: str) -> dict:
        self.calls.append((event_id, verification_ref))
        return {
            "status": "PRE_RELEASE_REQUESTED",
            "pre_release_request_path": str(self.storage_dir / event_id / "pre-release-request.json"),
        }

    def unified_approval_preflight(self) -> dict:
        return {"ready": True, "mode": "unified_multi_role", "missing_capabilities": []}


class RuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.controller = FakeController(self.root)
        self.runtime = ReleaseGateWorkflowRuntime(self.controller, self.root / "config.json")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_enqueue_is_idempotent_and_run_once_reconciles_exactly_once(self) -> None:
        first = self.runtime.enqueue_handoff("event-1", "receipt:1")
        second = self.runtime.enqueue_handoff("event-1", "receipt:1")

        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        result = self.runtime.run_once()
        repeated = self.runtime.run_once()

        self.assertEqual("ready", result["status"])
        self.assertEqual(1, result["processed"])
        self.assertEqual(0, repeated["processed"])
        self.assertEqual([("event-1", "receipt:1")], self.controller.calls)
        pointer = json.loads(Path(first["pointer_path"]).read_text(encoding="utf-8"))
        self.assertEqual("processed", pointer["status"])

    def test_verified_pre_release_is_requested_then_finalized_on_separate_runs(self) -> None:
        self.controller.config["runtime"][
            "auto_authorize_verified_pre_release"
        ] = True
        event_dir = self.controller.storage_dir / "event-auto"
        event_dir.mkdir(parents=True)
        handoff_path = event_dir / "pre-release-request.json"
        handoff_path.write_text(
            json.dumps(
                {
                    "event_id": "event-auto",
                    "target_scope": "preproduction,production_canary",
                }
            ),
            encoding="utf-8",
        )
        (event_dir / "event.json").write_text(
            json.dumps(
                {
                    "event_id": "event-auto",
                    "status": "PRE_RELEASE_REQUESTED",
                    "unified_release_approval": {
                        "pre_release_request_path": str(handoff_path)
                    },
                }
            ),
            encoding="utf-8",
        )
        runtime = ReleaseGateWorkflowRuntime(
            self.controller,
            self.root / "config.json",
        )

        requested = runtime.run_once()
        finalized = runtime.run_once()
        replayed = runtime.run_once()

        self.assertEqual(1, requested["authorization_requested"])
        self.assertEqual(0, requested["authorization_finalized"])
        self.assertEqual(0, finalized["authorization_requested"])
        self.assertEqual(1, finalized["authorization_finalized"])
        self.assertEqual(0, replayed["authorization_requested"])
        self.assertEqual(0, replayed["authorization_finalized"])
        self.assertEqual(["event-auto"], self.controller.authorization_requests)
        self.assertEqual(
            ["event-auto"],
            self.controller.authorization_finalizations,
        )
        self.assertEqual(
            "RELEASE_AUTHORIZED",
            self.controller.get_event("event-auto")["status"],
        )

    def test_kernel_lock_rejects_overlap_before_queue_read_or_side_effect(self) -> None:
        self.runtime.enqueue_handoff("event-2", "receipt:2")
        lock = RunOnceLock(
            self.runtime.lock_path,
            owner="other-owner",
        )
        self.assertEqual("acquired", lock.acquire()["status"])
        try:
            result = self.runtime.run_once()
        finally:
            lock.release()

        self.assertEqual({"status": "RUN_ALREADY_ACTIVE", "busy": True}, result)
        self.assertEqual([], self.controller.calls)

    def test_orphan_metadata_is_recovered_only_after_kernel_lock_is_acquired(self) -> None:
        lock_path = self.runtime.lock_path
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.with_name(f"{lock_path.name}.json").write_text(
            json.dumps({"status": "active", "owner": "dead-owner"}),
            encoding="utf-8",
        )

        result = self.runtime.run_once()

        self.assertEqual("ready", result["status"])
        audit = self.runtime.audit_path.read_text(encoding="utf-8")
        self.assertIn("lock_orphan_recovered", audit)
        self.assertIn("dead-owner", audit)

    def test_status_and_doctor_report_single_config_and_pending_counts(self) -> None:
        self.runtime.enqueue_handoff("event-3", "receipt:3")

        status = self.runtime.status()
        doctor = self.runtime.doctor()

        self.assertEqual(1, status["queued_handoffs"])
        self.assertEqual(str((self.root / "config.json").resolve()), status["config_path"])
        self.assertTrue(doctor["ready"])
        self.assertEqual("unified_multi_role", doctor["workflow"]["mode"])


if __name__ == "__main__":
    unittest.main()
