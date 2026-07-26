from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_core import GateError
from release_gate_credentials import runtime_principal_sha256
from release_gate_production import ProductionReleaseController

RUNTIME_PRINCIPAL = "windows-sid:S-1-5-21-unified-approval-runtime"

class FakeApprovalMailGateway:
    def __init__(self) -> None:
        self.payloads: list[dict] = []
        self.result = {"sent": True, "message_id": None, "refused": {}}

    def send_email(self, payload: dict) -> dict:
        self.payloads.append(dict(payload))
        result = dict(self.result)
        if result.get("message_id") is None:
            result["message_id"] = payload["message_id"]
        return result


class UnifiedApprovalControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.adapter = self.root / "approval_adapter.py"
        self.adapter.write_text(
            '''
import hashlib
import json
import sys

kind = sys.argv[1]
if kind == "legacy":
    approval_ref, approved_by, manifest_s, manifest_r, target_scope = sys.argv[2:7]
    print(json.dumps({"result": "APPROVE", "approval_ref": approval_ref,
        "approved_by": approved_by, "manifest_s_digest": manifest_s,
        "manifest_r_digest": manifest_r, "target_scope": target_scope,
        "evidence_ref": f"legacy-evidence:{approval_ref}"}))
elif kind == "unified":
    status, verification_ref, event_id, round_id, manifest_s, manifest_r, role_digest, target_scope, expires_at = sys.argv[2:12]
    if status == "BAD_BINDING":
        status, manifest_r = "APPROVAL_VERIFIED", "0" * 64
    print(json.dumps({"aggregate_status": status, "verification_ref": verification_ref,
        "event_id": event_id, "round_id": int(round_id),
        "manifest_s_digest": manifest_s, "manifest_r_digest": manifest_r,
        "role_snapshot_digest": role_digest, "target_scope": target_scope,
        "expires_at": expires_at, "evidence_ref": f"aggregate-evidence:{event_id}:{round_id}"}))
else:
    raise SystemExit(2)
'''.strip() + "\n",
            encoding="utf-8",
        )
        self.mail = FakeApprovalMailGateway()
        self.previous_auth = os.environ.get("UNIFIED_TEST_AUTH_KEY")
        self.previous_audit = os.environ.get("UNIFIED_TEST_AUDIT_KEY")
        os.environ["UNIFIED_TEST_AUTH_KEY"] = "unified-test-authorization-key-32-bytes"
        os.environ["UNIFIED_TEST_AUDIT_KEY"] = "unified-test-audit-key-32-bytes-minimum"

    def tearDown(self) -> None:
        self._restore_env("UNIFIED_TEST_AUTH_KEY", self.previous_auth)
        self._restore_env("UNIFIED_TEST_AUDIT_KEY", self.previous_audit)
        self.temporary.cleanup()

    @staticmethod
    def _restore_env(name: str, value: str | None) -> None:
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value

    def _write_config(self, workflow_mode: str, aggregate_status: str) -> Path:
        path = self.root / f"config-{workflow_mode}-{aggregate_status}.json"
        path.write_text(json.dumps({
            "storage_dir": str(self.root / f"events-{workflow_mode}-{aggregate_status}"),
            "runtime": {
                "identity_binding": {
                    "required": True,
                    "principal_sha256": runtime_principal_sha256(
                        RUNTIME_PRINCIPAL
                    ),
                }
            },
            "policy": {"allowed_extensions": [".bin"], "require_source_ref": False,
                "require_signature": False, "require_cloud_scan": False,
                "auto_approve_risk_levels": ["standard"]},
            "test": {"command": [sys.executable, "-c", "print('{}')"]},
            "production": {"enabled": True,
                "authorization": {"key_env": "UNIFIED_TEST_AUTH_KEY",
                    "verify_command": [sys.executable, str(self.adapter), "legacy",
                        "{approval_ref}", "{approved_by}", "{manifest_s_digest}",
                        "{manifest_r_digest}", "{target_scope}"], "timeout_seconds": 30},
                "audit": {"key_env": "UNIFIED_TEST_AUDIT_KEY"},
                "approval_workflow": {"mode": workflow_mode,
                    "verify_command": [sys.executable, str(self.adapter), "unified",
                        aggregate_status, "{verification_ref}", "{event_id}", "{round_id}",
                        "{manifest_s_digest}", "{manifest_r_digest}",
                        "{role_snapshot_digest}", "{target_scope}", "{expires_at}"],
                    "timeout_seconds": 30,
                    "mail": {"profile": "release-bot",
                        "release_group": "release@example.com",
                        "module": "kernel",
                        "command": [sys.executable, "imap_smtp_mail_cli.py"],
                        "timeout_seconds": 30}}}
        }), encoding="utf-8")
        return path

    def _controller(self, workflow_mode: str = "unified_multi_role", aggregate_status: str = "APPROVAL_VERIFIED") -> ProductionReleaseController:
        controller = ProductionReleaseController(
            str(self._write_config(workflow_mode, aggregate_status)),
            approval_mail_gateway=self.mail,
            runtime_principal_provider=lambda: RUNTIME_PRINCIPAL,
            allow_unlocked_test_adapters=True,
        )
        controller._save_event({"event_id": "event-unified", "task_id": "TASK-UNIFIED-1",
            "round_number": 1, "risk_level": "standard", "source_ref": "commit:release-candidate",
            "rollback_ref": "rollback:stable", "status": "RELEASE_READY",
            "rule_snapshot_id": "rules-v1", "manifest_s_digest": "a" * 64,
            "manifest_r_digest": "b" * 64, "history": []})
        return controller

    @staticmethod
    def _expires_at() -> str:
        return ((datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0)
            .isoformat().replace("+00:00", "Z"))

    def _request(self, controller: ProductionReleaseController, **changes: object) -> dict:
        values = {"event_id": "event-unified", "requested_by": "release-bot@example.com",
            "target_scope": "preproduction,production_canary", "round_id": 1,
            "required_roles": [
                {"role_id": "release-director", "email": "director@example.com", "required": True},
                {"role_id": "test-lead", "email": "test@example.com", "required": True}],
            "role_snapshot_digest": "c" * 64, "expires_at": self._expires_at()}
        values.update(changes)
        return controller.request_unified_release_approval(**values)

    def test_legacy_authorization_methods_still_issue_the_existing_credential(self) -> None:
        controller = self._controller("legacy_external")
        event = controller._load_event("event-unified")
        controller.request_release_authorization("event-unified", "release-bot",
            "preproduction,production_canary,production_full")
        result = controller.record_release_authorization("event-unified", "APPROVE",
            "legacy:approval:1", "release-director", event["manifest_s_digest"], event["manifest_r_digest"])
        self.assertEqual("RELEASE_AUTHORIZED", result["status"])
        credential = json.loads(Path(result["credential_path"]).read_text(encoding="utf-8"))
        self.assertEqual(1, credential["schema_version"])
        self.assertEqual("event-unified", credential["claims"]["event_id"])

    def test_unified_request_freezes_contract_and_is_exactly_idempotent(self) -> None:
        controller = self._controller()
        created = self._request(controller)
        repeated = self._request(controller, expires_at=created["request"]["expires_at"])
        self.assertEqual("APPROVAL_COLLECTING", created["status"])
        self.assertFalse(created["idempotent"])
        self.assertTrue(repeated["idempotent"])
        request_path = Path(created["request_path"])
        persisted = json.loads(request_path.read_text(encoding="utf-8"))
        self.assertEqual("ReleaseAuthorizationRequest/v1", persisted["schema"])
        self.assertEqual("sha256:" + "a" * 64, persisted["manifest_s_digest"])
        self.assertEqual("sha256:" + "b" * 64, persisted["manifest_r_digest"])
        self.assertEqual("sha256:" + "c" * 64, persisted["role_snapshot_digest"])
        self.assertEqual(2, len(persisted["required_roles"]))
        self.assertFalse((controller._event_dir("event-unified") / "release-authorization.json").exists())

    def test_unified_request_rejects_frozen_field_change_in_same_round(self) -> None:
        controller = self._controller()
        created = self._request(controller)
        with self.assertRaisesRegex(GateError, "new round"):
            self._request(controller, target_scope="preproduction",
                expires_at=created["request"]["expires_at"])

    def test_verified_receipt_creates_one_pre_release_handoff_without_credential(self) -> None:
        controller = self._controller()
        self._request(controller)
        recorded = controller.record_unified_release_approval(
            "event-unified", "receipt:aggregate:1"
        )
        repeated = controller.record_unified_release_approval(
            "event-unified", "receipt:aggregate:1"
        )
        self.assertEqual("PRE_RELEASE_REQUESTED", recorded["status"])
        self.assertFalse(recorded["idempotent"])
        self.assertTrue(repeated["idempotent"])
        handoff_path = Path(recorded["pre_release_request_path"])
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        self.assertEqual("PreReleaseRequest/v1", handoff["schema"])
        self.assertEqual("receipt:aggregate:1", handoff["verification_ref"])
        self.assertEqual("sha256:" + "a" * 64, handoff["manifest_s_digest"])
        self.assertEqual("sha256:" + "b" * 64, handoff["manifest_r_digest"])
        event_dir = controller._event_dir("event-unified")
        self.assertFalse((event_dir / "release-authorization.json").exists())
        event = controller._load_event("event-unified")
        self.assertNotIn("deployment", event)
        records = [
            json.loads(line)
            for line in (event_dir / "control-events.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertEqual(
            1,
            sum(record["event_type"] == "PRE_RELEASE_REQUESTED" for record in records),
        )

    def test_non_verified_receipts_fail_closed_without_handoff(self) -> None:
        for aggregate_status, expected_status in (
            ("APPROVAL_PAUSED", "APPROVAL_PAUSED"),
            ("APPROVAL_REJECTED", "APPROVAL_REJECTED"),
        ):
            with self.subTest(aggregate_status=aggregate_status):
                controller = self._controller(aggregate_status=aggregate_status)
                self._request(controller)
                result = controller.record_unified_release_approval(
                    "event-unified", f"receipt:{aggregate_status.lower()}"
                )
                self.assertEqual(expected_status, result["status"])
                self.assertFalse(
                    (
                        controller._event_dir("event-unified")
                        / "pre-release-request.json"
                    ).exists()
                )
                self.assertFalse(
                    (
                        controller._event_dir("event-unified")
                        / "release-authorization.json"
                    ).exists()
                )

    def test_invalid_verifier_binding_preserves_collecting_state(self) -> None:
        controller = self._controller(aggregate_status="BAD_BINDING")
        self._request(controller)
        with self.assertRaisesRegex(GateError, "not bound"):
            controller.record_unified_release_approval(
                "event-unified", "receipt:tampered"
            )
        self.assertEqual(
            "APPROVAL_COLLECTING",
            controller._load_event("event-unified")["status"],
        )
        self.assertFalse(
            (
                controller._event_dir("event-unified")
                / "pre-release-request.json"
            ).exists()
        )



    def test_unified_request_sends_role_plugin_contract_with_stable_message_id(self) -> None:
        controller = self._controller()

        created = self._request(controller)

        request = created["request"]
        self.assertEqual("ReleaseAuthorizationRequest/v1", request["contract"])
        self.assertEqual("TASK-UNIFIED-1", request["task"])
        self.assertEqual("kernel", request["module"])
        self.assertEqual(["release-director", "test-lead"], request["required_roles"])
        for key in ("manifest_s_digest", "manifest_r_digest", "manifest_digest",
                    "request_digest", "role_snapshot_digest"):
            self.assertRegex(request[key], r"^sha256:[0-9a-f]{64}$")
        payload = self.mail.payloads[0]
        self.assertEqual("release-bot", payload["account"])
        self.assertEqual(["release@example.com"], payload["to"])
        self.assertFalse(payload["dry_run"])
        self.assertEqual(request["original_message_id"], payload["message_id"])
        self.assertIn("【发布申请】TASK-UNIFIED-1-kernel-", payload["subject"])
        self.assertIn("-----BEGIN RELEASE APPROVAL REQUEST-----", payload["text"])
        self.assertEqual("APPROVAL_COLLECTING", created["status"])
        self.assertEqual("accepted", created["delivery"]["status"])

    def test_unified_request_smtp_failure_keeps_release_ready_and_retry_reuses_message_id(self) -> None:
        controller = self._controller()
        expires_at = self._expires_at()
        self.mail.result = {
            "sent": False,
            "message_id": None,
            "refused": {"release@example.com": "550 rejected"},
        }

        with self.assertRaisesRegex(GateError, "SMTP delivery was not accepted"):
            self._request(controller, expires_at=expires_at)

        event = controller._load_event("event-unified")
        self.assertEqual("RELEASE_READY", event["status"])
        first_message_id = self.mail.payloads[0]["message_id"]
        self.mail.result = {"sent": True, "message_id": None, "refused": {}}

        retried = self._request(controller, expires_at=expires_at)

        self.assertEqual("APPROVAL_COLLECTING", retried["status"])
        self.assertEqual(first_message_id, self.mail.payloads[1]["message_id"])

    def test_unicode_request_digest_matches_role_plugin_canonical_json(self) -> None:
        controller = self._controller()
        event = controller._load_event("event-unified")
        event["task_id"] = "发布任务"
        controller._save_event(event)

        created = self._request(controller)

        request = created["request"]
        digest_payload = {
            key: value for key, value in request.items() if key != "request_digest"
        }
        expected = "sha256:" + hashlib.sha256(
            json.dumps(
                digest_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        escaped = "sha256:" + hashlib.sha256(
            json.dumps(
                digest_payload,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(expected, request["request_digest"])
        self.assertNotEqual(escaped, request["request_digest"])
        self.assertIn("【发布申请】发布任务-kernel-", self.mail.payloads[0]["subject"])

    def test_unified_approval_preflight_reports_exact_missing_capability(self) -> None:
        controller = self._controller()

        ready = controller.unified_approval_preflight()
        controller.config["production"]["approval_workflow"]["verify_command"] = []
        blocked = controller.unified_approval_preflight()

        self.assertTrue(ready["ready"])
        self.assertEqual("ready", ready["status"])
        self.assertFalse(blocked["ready"])
        self.assertIn(
            "approval_workflow.verifier_bridge",
            blocked["missing_capabilities"],
        )

    def test_verified_pre_release_requires_a_separate_authorization_and_issues_v2_credential(self) -> None:
        controller = self._controller()
        self._request(controller)
        handoff = controller.record_unified_release_approval(
            "event-unified",
            "receipt:verified:1",
        )
        self.assertEqual("PRE_RELEASE_REQUESTED", handoff["status"])

        requested = controller.request_release_authorization(
            "event-unified",
            "rd-flywheel",
            "preproduction,production_canary",
        )
        self.assertEqual("RELEASE_AUTHORIZATION_REQUIRED", requested["status"])
        self.assertEqual(
            "unified_multi_role_receipt",
            requested["request"]["authorization_source"],
        )
        self.assertFalse(requested["idempotent"])

        finalized = controller.finalize_verified_release_authorization(
            "event-unified"
        )
        self.assertEqual("RELEASE_AUTHORIZED", finalized["status"])
        credential = json.loads(
            Path(finalized["credential_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(2, credential["schema_version"])
        self.assertEqual(
            "unified_multi_role_receipt",
            credential["claims"]["authorization_source"],
        )
        self.assertEqual(
            "receipt:verified:1",
            credential["claims"]["verification_ref"],
        )
        self.assertEqual(
            "release-approval-verifier",
            credential["claims"]["approved_by"],
        )

        replayed = controller.finalize_verified_release_authorization(
            "event-unified"
        )
        self.assertTrue(replayed["idempotent"])
        self.assertEqual("RELEASE_AUTHORIZED", replayed["status"])

    def test_revoked_receipt_blocks_credential_issuance_after_authorization_request(self) -> None:
        controller = self._controller()
        self._request(controller)
        controller.record_unified_release_approval(
            "event-unified",
            "receipt:verified:2",
        )
        controller.request_release_authorization(
            "event-unified",
            "rd-flywheel",
            "preproduction,production_canary",
        )
        workflow = controller.config["production"]["approval_workflow"]
        workflow["verify_command"][3] = "APPROVAL_PAUSED"

        blocked = controller.finalize_verified_release_authorization(
            "event-unified"
        )

        self.assertEqual("RELEASE_BLOCKED", blocked["status"])
        self.assertEqual(
            "APPROVAL_PAUSED",
            blocked["authorization"]["latest_aggregate_status"],
        )
        self.assertFalse(
            (
                controller._event_dir("event-unified")
                / "release-authorization.json"
            ).exists()
        )


    def test_post_authorization_revocation_blocks_every_remaining_deployment_stage(
        self,
    ) -> None:
        for stage, current_status in (
            ("preproduction", "RELEASE_AUTHORIZED"),
            ("production_canary", "PREPRODUCTION_VERIFIED"),
            ("production_full", "CANARY_VERIFIED"),
        ):
            with self.subTest(stage=stage):
                shutil.rmtree(
                    self.root
                    / "events-unified_multi_role-APPROVAL_VERIFIED",
                    ignore_errors=True,
                )
                controller = self._controller()
                scope = "preproduction,production_canary,production_full"
                self._request(controller, target_scope=scope)
                controller.record_unified_release_approval(
                    "event-unified",
                    f"receipt:verified:{stage}",
                )
                controller.request_release_authorization(
                    "event-unified",
                    "rd-flywheel",
                    scope,
                )
                controller.finalize_verified_release_authorization(
                    "event-unified"
                )
                event = controller._load_event("event-unified")
                event["status"] = current_status
                controller._save_event(event)
                controller.config["production"]["approval_workflow"][
                    "verify_command"
                ][3] = "APPROVAL_PAUSED"

                with self.assertRaisesRegex(
                    GateError,
                    "approval is no longer verified",
                ):
                    controller.run_deployment_stage("event-unified", stage)

                blocked = controller._load_event("event-unified")
                self.assertEqual("RELEASE_BLOCKED", blocked["status"])
                self.assertEqual(
                    "REVOKED",
                    blocked["release_authorization"]["credential_status"],
                )
                self.assertEqual(
                    "APPROVAL_PAUSED",
                    blocked["release_authorization"][
                        "latest_aggregate_status"
                    ],
                )


    def test_unified_preflight_does_not_require_legacy_authorization_adapter(
        self,
    ) -> None:
        controller = self._controller()

        preflight = controller.production_preflight()
        authorization_check = next(
            check
            for check in preflight["checks"]
            if check["name"] == "authorization.verify_command"
        )

        self.assertFalse(authorization_check["required"])
        self.assertTrue(authorization_check["configured"])
        self.assertNotIn(
            "authorization.verify_command",
            preflight["missing_capabilities"],
        )


if __name__ == "__main__":
    unittest.main()
