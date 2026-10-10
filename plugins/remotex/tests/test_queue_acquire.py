from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import queue_leases
import remotex_core as core
import remotex_mcp
import vm_queue


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class QueueAcquireTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.queue_file = root / "queue.json"
        self.lease_file = root / "leases.json"
        config = root / "config.json"
        self.host = "host:lab"
        self.service = self.host + "::service::test"
        config.write_text(json.dumps({
            "version": 2,
            "credentials": {},
            "defaults": {},
            "profiles": {
                "lab": {"kind": "ssh", "queue_resource": self.host},
                "service": {"kind": "ssh", "queue_resource": self.service},
                "unmanaged": {"kind": "ssh"},
            },
        }), encoding="utf-8")
        environment = mock.patch.dict(os.environ, {
            "REMOTEX_CONFIG": str(config),
            "REMOTEX_VM_QUEUE_FILE": str(self.queue_file),
            "REMOTEX_VM_QUEUE_LEASE_FILE": str(self.lease_file),
        })
        environment.start()
        self.addCleanup(environment.stop)

    def acquire(self, requester: str, profile: str = "lab") -> dict:
        return payload(queue_leases.queue_acquire({
            "profile": profile, "requester": requester, "lease_seconds": 120,
        }))

    def test_idle_resource_is_acquired_with_bounded_lease_without_confirm(self) -> None:
        result = self.acquire("task-a")
        self.assertTrue(result["acquired"])
        self.assertEqual(result["acquireStatus"], "acquired")
        self.assertEqual(result["owner"]["requester"], "task-a")
        self.assertEqual(result["lease"]["leaseSeconds"], 120)
        self.assertEqual(result["nextAction"], "continue-authorized-operation")

    def test_other_owner_is_preserved_and_requests_are_deduplicated(self) -> None:
        first = self.acquire("task-a")
        result = self.acquire("task-b")
        repeated = self.acquire("task-b")
        self.assertFalse(result["acquired"])
        self.assertEqual(result["acquireStatus"], "queued-owner-active")
        self.assertEqual(repeated["requester_position"], 1)
        self.assertEqual(repeated["queue_length"], 1)
        self.assertEqual(repeated["owner"], first["owner"])
        self.assertEqual(repeated["lease"], first["lease"])
        self.assertEqual(result["nextAction"], "wait-and-retry-acquire")

    def test_repeated_acquire_reuses_lease_without_extending_it(self) -> None:
        with mock.patch.object(queue_leases, "_now", return_value=datetime(2026, 10, 10, tzinfo=timezone.utc)):
            first = self.acquire("task-a")
        with mock.patch.object(queue_leases, "_now", return_value=datetime(2026, 10, 10, 0, 1, tzinfo=timezone.utc)):
            result = self.acquire("task-a")
        self.assertEqual(result["acquireStatus"], "already-owned")
        self.assertTrue(result["acquired"])
        self.assertEqual(result["lease"]["expiresAt"], first["lease"]["expiresAt"])

    def test_fifo_waiter_acquires_only_after_owner_releases(self) -> None:
        self.acquire("task-a")
        self.acquire("task-b")
        self.acquire("task-c")
        queue_leases.queue_release({"profile": "lab", "requester": "task-a"})
        third = self.acquire("task-c")
        self.assertFalse(third["acquired"])
        self.assertEqual(third["acquireStatus"], "queued-behind-first")
        second = self.acquire("task-b")
        self.assertTrue(second["acquired"])
        self.assertEqual(second["owner"]["requester"], "task-b")

    def test_maintenance_waiter_blocks_new_service_acquisition(self) -> None:
        self.acquire("task-a", "service")
        maintenance = self.acquire("maintenance")
        self.assertEqual(maintenance["acquireStatus"], "queued-scope-conflict")
        queue_leases.queue_release({"profile": "service", "requester": "task-a"})
        service = self.acquire("task-b", "service")
        self.assertFalse(service["acquired"])
        self.assertEqual(service["blocking_resources"], [self.host])
        self.assertTrue(self.acquire("maintenance")["acquired"])

    def test_expiry_does_not_allow_skipping_first_waiter(self) -> None:
        self.acquire("task-a")
        self.acquire("task-b")
        leases = json.loads(self.lease_file.read_text(encoding="utf-8"))
        leases["leases"][self.host]["expiresAt"] = "2000-01-01T00:00:00Z"
        self.lease_file.write_text(json.dumps(leases), encoding="utf-8")
        result = self.acquire("task-c")
        self.assertFalse(result["acquired"])
        self.assertIsNone(result["owner"])
        self.assertEqual(result["requester_position"], 2)
        self.assertTrue(self.acquire("task-b")["acquired"])

    def test_concurrent_callers_cannot_both_acquire(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(self.acquire, ["task-a", "task-b"]))
        self.assertEqual(sum(result["acquired"] for result in results), 1)
        state = vm_queue.inspect(self.host)
        self.assertEqual(state["queue_length"], 1)

    def test_lease_write_failure_restores_unowned_fifo_position(self) -> None:
        with mock.patch.object(queue_leases, "_write", side_effect=core.ToolError("lease write failed")):
            with self.assertRaisesRegex(core.ToolError, "lease write failed"):
                self.acquire("task-a")
        state = vm_queue.inspect(self.host, "task-a")
        self.assertIsNone(state["owner"])
        self.assertEqual(state["requester_position"], 1)
        self.assertTrue(self.acquire("task-a")["acquired"])

    def test_legacy_owner_receives_a_lease_without_replacing_owner(self) -> None:
        owner = vm_queue.claim(self.host, "task-a", True)["owner"]
        result = self.acquire("task-a")
        self.assertEqual(result["owner"], owner)
        self.assertTrue(result["acquired"])
        self.assertEqual(result["lease"]["requester"], "task-a")

    def test_owner_lease_mismatch_is_not_overwritten(self) -> None:
        self.acquire("task-a")
        state = json.loads(self.queue_file.read_text(encoding="utf-8"))
        state["resources"][self.host]["owner"]["requester"] = "task-b"
        self.queue_file.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaisesRegex(core.ToolError, "disagree"):
            self.acquire("task-c")
        self.assertEqual(vm_queue.inspect(self.host)["owner"]["requester"], "task-b")

    def test_expired_mismatched_lease_is_not_silently_repaired(self) -> None:
        self.acquire("task-a")
        state = json.loads(self.queue_file.read_text(encoding="utf-8"))
        state["resources"][self.host]["owner"]["requester"] = "task-b"
        self.queue_file.write_text(json.dumps(state), encoding="utf-8")
        leases = json.loads(self.lease_file.read_text(encoding="utf-8"))
        leases["leases"][self.host]["expiresAt"] = "2000-01-01T00:00:00Z"
        self.lease_file.write_text(json.dumps(leases), encoding="utf-8")
        queue_before = self.queue_file.read_bytes()
        lease_before = self.lease_file.read_bytes()
        with self.assertRaisesRegex(core.ToolError, "disagree"):
            self.acquire("task-b")
        self.assertEqual(self.queue_file.read_bytes(), queue_before)
        self.assertEqual(self.lease_file.read_bytes(), lease_before)

    def test_orphan_expired_lease_is_not_silently_cleared(self) -> None:
        self.acquire("task-a")
        self.queue_file.write_text(json.dumps({"version": 1, "resources": {}}), encoding="utf-8")
        leases = json.loads(self.lease_file.read_text(encoding="utf-8"))
        leases["leases"][self.host]["expiresAt"] = "2000-01-01T00:00:00Z"
        self.lease_file.write_text(json.dumps(leases), encoding="utf-8")
        lease_before = self.lease_file.read_bytes()
        with self.assertRaisesRegex(core.ToolError, "disagree"):
            self.acquire("task-b")
        self.assertEqual(self.lease_file.read_bytes(), lease_before)

    def test_invalid_requester_and_lease_do_not_create_queue_ownership(self) -> None:
        with self.assertRaises(core.ToolError):
            self.acquire("another task")
        with self.assertRaises(core.ToolError):
            queue_leases.queue_acquire({"profile": "lab", "requester": "task-a", "lease_seconds": 1})
        self.assertFalse(self.queue_file.exists())

    def test_invalid_queue_state_and_unmanaged_profiles_fail_closed(self) -> None:
        self.queue_file.write_text("invalid", encoding="utf-8")
        with self.assertRaises(core.ToolError):
            self.acquire("task-a")
        self.assertEqual(self.queue_file.read_text(encoding="utf-8"), "invalid")
        with self.assertRaisesRegex(core.ToolError, "queue_resource"):
            self.acquire("task-a", "unmanaged")

    def test_tool_schema_exposes_auto_acquire_and_keeps_manual_claim(self) -> None:
        schema = remotex_mcp.TOOLS["remotex_vm_queue_acquire"]["inputSchema"]
        self.assertEqual(schema["required"], ["profile", "requester"])
        self.assertNotIn("confirm", schema["properties"])
        self.assertIn("confirm", remotex_mcp.TOOLS["remotex_vm_queue_claim"]["inputSchema"]["required"])


if __name__ == "__main__":
    unittest.main()
