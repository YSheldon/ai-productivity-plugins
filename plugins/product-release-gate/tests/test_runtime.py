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
        self.deployment_stages: list[tuple[str, str]] = []
        self.production_readbacks: list[str] = []
        self.production_reports: list[str] = []
        self.production_deliveries: list[str] = []
        self.block_stage: str | None = None
        self.capabilities_ready = True
        self.production_ready = True

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

    def ensure_deployment_capabilities(self, event_id: str) -> dict:
        event = self.get_event(event_id)
        if not self.capabilities_ready:
            event["status"] = "CAPABILITY_BLOCKED"
            self._event_path(event_id).write_text(json.dumps(event), encoding="utf-8")
        return {
            "ready": self.capabilities_ready,
            "status": event["status"],
            "missing_capabilities": [] if self.capabilities_ready else ["deployment.adapter"],
        }

    def run_deployment_stage(self, event_id: str, stage: str) -> dict:
        event = self.get_event(event_id)
        self.deployment_stages.append((event_id, stage))
        if not self.capabilities_ready:
            event["status"] = "CAPABILITY_BLOCKED"
            self._event_path(event_id).write_text(json.dumps(event), encoding="utf-8")
            return {
                "ready": False,
                "status": "CAPABILITY_BLOCKED",
                "missing_capabilities": ["deployment.adapter"],
            }
        if stage == self.block_stage:
            event["status"] = "ROLLED_BACK"
            result = "BLOCKED"
        else:
            event["status"] = {
                "preproduction": "PREPRODUCTION_VERIFIED",
                "production_canary": "CANARY_VERIFIED",
                "production_full": "PRODUCTION_DEPLOYED",
            }[stage]
            result = "PASS"
        self._event_path(event_id).write_text(json.dumps(event), encoding="utf-8")
        return {"status": event["status"], "result": result}

    def run_production_readback(self, event_id: str) -> dict:
        event = self.get_event(event_id)
        self.production_readbacks.append(event_id)
        event["status"] = "PRODUCTION_VERIFIED"
        self._event_path(event_id).write_text(json.dumps(event), encoding="utf-8")
        return {"status": event["status"], "result": "PASS"}

    def generate_production_report(self, event_id: str) -> dict:
        path = self.storage_dir / event_id / "production-report.md"
        if path.is_file():
            return {
                "event_id": event_id,
                "status": "PRODUCTION_VERIFIED",
                "report_path": str(path),
                "idempotent": True,
            }
        self.production_reports.append(event_id)
        path.write_text("production report\n", encoding="utf-8")
        event = self.get_event(event_id)
        event["production_report"] = {"report_path": str(path)}
        self._event_path(event_id).write_text(json.dumps(event), encoding="utf-8")
        return {
            "event_id": event_id,
            "status": "PRODUCTION_VERIFIED",
            "report_path": str(path),
            "idempotent": False,
        }

    def deliver_production_report(self, event_id: str) -> dict:
        path = self.storage_dir / event_id / "production-report-delivery.json"
        if path.is_file():
            return {"event_id": event_id, "status": "DELIVERED", "idempotent": True}
        self.production_deliveries.append(event_id)
        path.write_text("{}\n", encoding="utf-8")
        event = self.get_event(event_id)
        event["production_report_delivery"] = {"receipt_path": str(path)}
        self._event_path(event_id).write_text(json.dumps(event), encoding="utf-8")
        return {"event_id": event_id, "status": "DELIVERED", "idempotent": False}

    def production_preflight(self) -> dict:
        return {
            "ready": self.production_ready,
            "status": "ready" if self.production_ready else "CAPABILITY_BLOCKED",
            "missing_capabilities": [] if self.production_ready else ["deployment.adapter"],
        }

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

    def test_explicit_auto_deploy_advances_all_stages_readback_and_report_once(self) -> None:
        self.controller.config["runtime"].update(
            {
                "auto_deploy_authorized_releases": True,
                "auto_generate_production_report": True,
                "auto_deliver_production_report": True,
            }
        )
        event_dir = self.controller.storage_dir / "event-deploy"
        event_dir.mkdir(parents=True)
        (event_dir / "event.json").write_text(
            json.dumps({"event_id": "event-deploy", "status": "RELEASE_AUTHORIZED"}),
            encoding="utf-8",
        )
        runtime = ReleaseGateWorkflowRuntime(
            self.controller,
            self.root / "config.json",
        )

        result = runtime.run_once()
        repeated = runtime.run_once()

        self.assertEqual("ready", result["status"])
        self.assertEqual(3, result["deployment_stages_completed"])
        self.assertEqual(1, result["production_readbacks_completed"])
        self.assertEqual(1, result["production_reports_generated"])
        self.assertEqual(1, result["production_reports_delivered"])
        self.assertEqual(
            [
                ("event-deploy", "preproduction"),
                ("event-deploy", "production_canary"),
                ("event-deploy", "production_full"),
            ],
            self.controller.deployment_stages,
        )
        self.assertEqual(["event-deploy"], self.controller.production_readbacks)
        self.assertEqual(["event-deploy"], self.controller.production_reports)
        self.assertEqual(["event-deploy"], self.controller.production_deliveries)
        self.assertEqual(0, repeated["deployment_stages_completed"])
        self.assertEqual(0, repeated["production_readbacks_completed"])
        self.assertEqual(0, repeated["production_reports_generated"])
        self.assertEqual(0, repeated["production_reports_delivered"])

    def test_auto_deploy_stops_after_stage_failure_and_never_runs_later_actions(self) -> None:
        self.controller.config["runtime"].update(
            {
                "auto_deploy_authorized_releases": True,
                "auto_generate_production_report": True,
                "auto_deliver_production_report": True,
            }
        )
        self.controller.block_stage = "production_canary"
        event_dir = self.controller.storage_dir / "event-rollback"
        event_dir.mkdir(parents=True)
        (event_dir / "event.json").write_text(
            json.dumps({"event_id": "event-rollback", "status": "RELEASE_AUTHORIZED"}),
            encoding="utf-8",
        )
        runtime = ReleaseGateWorkflowRuntime(
            self.controller,
            self.root / "config.json",
        )

        result = runtime.run_once()

        self.assertEqual("CAPABILITY_BLOCKED", result["status"])
        self.assertEqual(1, result["deployment_failures"])
        self.assertEqual(
            [
                ("event-rollback", "preproduction"),
                ("event-rollback", "production_canary"),
            ],
            self.controller.deployment_stages,
        )
        self.assertEqual([], self.controller.production_readbacks)
        self.assertEqual([], self.controller.production_reports)
        self.assertEqual([], self.controller.production_deliveries)
        self.assertEqual(
            "ROLLED_BACK",
            self.controller.get_event("event-rollback")["status"],
        )

    def test_report_delivery_exception_is_not_misclassified_as_deployment_failure(self) -> None:
        self.controller.config["runtime"].update(
            {
                "auto_deploy_authorized_releases": True,
                "auto_generate_production_report": True,
                "auto_deliver_production_report": True,
            }
        )
        event_dir = self.controller.storage_dir / "event-delivery-failure"
        event_dir.mkdir(parents=True)
        (event_dir / "event.json").write_text(
            json.dumps(
                {"event_id": "event-delivery-failure", "status": "PRODUCTION_VERIFIED"}
            ),
            encoding="utf-8",
        )
        self.controller.deliver_production_report = lambda _event_id: (_ for _ in ()).throw(
            OSError("mail unavailable")
        )
        runtime = ReleaseGateWorkflowRuntime(self.controller, self.root / "config.json")

        result = runtime.run_once()

        self.assertEqual("CAPABILITY_BLOCKED", result["status"])
        self.assertEqual(1, result["report_delivery_failures"])
        self.assertEqual(0, result["deployment_failures"])

    def test_missing_deployment_capability_is_blocked_not_counted_as_failed_stage(self) -> None:
        self.controller.config["runtime"].update(
            {
                "auto_deploy_authorized_releases": True,
                "auto_generate_production_report": True,
                "auto_deliver_production_report": True,
            }
        )
        self.controller.capabilities_ready = False
        event_dir = self.controller.storage_dir / "event-capability"
        event_dir.mkdir(parents=True)
        (event_dir / "event.json").write_text(
            json.dumps({"event_id": "event-capability", "status": "RELEASE_AUTHORIZED"}),
            encoding="utf-8",
        )
        runtime = ReleaseGateWorkflowRuntime(self.controller, self.root / "config.json")

        result = runtime.run_once()

        self.assertEqual("CAPABILITY_BLOCKED", result["status"])
        self.assertEqual(1, result["deployment_blocked"])
        self.assertEqual(0, result["deployment_failures"])
        self.assertEqual([], self.controller.production_readbacks)

    def test_doctor_requires_production_preflight_when_auto_deploy_is_enabled(self) -> None:
        self.controller.config["runtime"].update(
            {
                "auto_deploy_authorized_releases": True,
                "auto_generate_production_report": True,
                "auto_deliver_production_report": True,
            }
        )
        self.controller.production_ready = False
        runtime = ReleaseGateWorkflowRuntime(self.controller, self.root / "config.json")

        doctor = runtime.doctor()

        self.assertFalse(doctor["ready"])
        self.assertEqual("CAPABILITY_BLOCKED", doctor["production"]["status"])

    def test_doctor_requires_preflight_when_production_is_enabled(self) -> None:
        self.controller.production_ready = False
        runtime = ReleaseGateWorkflowRuntime(
            self.controller,
            self.root / "config.json",
        )

        doctor = runtime.doctor()

        self.assertFalse(doctor["ready"])
        self.assertEqual("CAPABILITY_BLOCKED", doctor["production"]["status"])

    def test_report_automation_flags_fail_closed_when_dependencies_are_missing(self) -> None:
        self.controller.config["runtime"].update(
            {
                "auto_deploy_authorized_releases": False,
                "auto_generate_production_report": True,
            }
        )
        with self.assertRaisesRegex(Exception, "requires auto_deploy"):
            ReleaseGateWorkflowRuntime(self.controller, self.root / "config.json")

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
