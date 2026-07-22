from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import remotex_core as core
import vm_queue


class VMQueueTests(unittest.TestCase):
    def _environment(self, directory: str) -> dict[str, str]:
        config = Path(directory) / "config.json"
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "defaults": {},
                    "profiles": {
                        "rdp-vm": {
                            "kind": "rdp",
                            "host": "windows.example",
                            "queue_resource": "lab:windows",
                            "credential": {
                                "source": "windows-credential-manager",
                                "target": "TERMSRV/windows.example",
                            },
                        },
                        "workstation-vm": {
                            "kind": "vmware-workstation",
                            "vmx_path": str(Path(directory) / "windows.vmx"),
                            "queue_resource": "lab:windows",
                        },
                        "esxi": {
                            "kind": "esxi",
                            "url": "https://esxi.example/sdk",
                            "queue_resource": "lab:esxi:{virtual_machine}",
                            "credential": {
                                "source": "environment",
                                "username_env": "TEST_USER",
                                "password_env": "TEST_PASSWORD",
                            },
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        return {
            "REMOTEX_CONFIG": str(config),
            "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "vm-queue.json"),
        }

    def test_fifo_claim_release_and_non_preemption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, self._environment(directory), clear=True):
                offered = vm_queue.request("lab:windows", "alice")
                self.assertEqual(offered["request_status"], "claim-available")
                self.assertTrue(offered["claim_available"])
                self.assertIsNone(offered["owner"])

                with self.assertRaisesRegex(core.ToolError, "confirm=true"):
                    vm_queue.claim("lab:windows", "alice", False)
                claimed = vm_queue.claim("lab:windows", "alice", True)
                self.assertTrue(claimed["claimed"])

                queued = vm_queue.request("lab:windows", "bob")
                self.assertEqual(queued["request_status"], "queued")
                self.assertEqual(queued["requester_position"], 1)
                blocked = vm_queue.claim("lab:windows", "bob", True)
                self.assertFalse(blocked["claimed"])
                self.assertEqual(blocked["owner"]["requester"], "alice")
                with self.assertRaisesRegex(core.ToolError, "cannot release or preempt"):
                    vm_queue.release("lab:windows", "bob")

                released = vm_queue.release("lab:windows", "alice")
                self.assertEqual(released["next_waiter"], "bob")
                bypass = vm_queue.claim("lab:windows", "alice", True)
                self.assertFalse(bypass["claimed"])
                self.assertEqual(bypass["requester_position"], 2)

                promoted = vm_queue.claim("lab:windows", "bob", True)
                self.assertTrue(promoted["claimed"])
                self.assertEqual(promoted["owner"]["requester"], "bob")
                vm_queue.release("lab:windows", "bob")
                vm_queue.cancel("lab:windows", "alice")
                final = vm_queue.inspect("lab:windows")
                self.assertEqual(final["state"], "unowned")
                self.assertEqual(final["queue_length"], 0)
                persisted = json.loads(
                    Path(os.environ["REMOTEX_VM_QUEUE_FILE"]).read_text(encoding="utf-8")
                )
                self.assertEqual(persisted["resources"], {})

    def test_shared_profile_resource_and_vsphere_template(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, self._environment(directory), clear=True):
                rdp = vm_queue.resolve_profile_resource("rdp-vm")
                workstation = vm_queue.resolve_profile_resource("workstation-vm")
                vsphere = vm_queue.resolve_profile_resource(
                    "esxi", "/Datacenter/vm/windows"
                )
        self.assertEqual(rdp["resource"], workstation["resource"])
        self.assertEqual(vsphere["resource"], "lab:esxi:/Datacenter/vm/windows")

    def test_vsphere_resource_rejects_url_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self._environment(directory)
            config_path = Path(environment["REMOTEX_CONFIG"])
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["profiles"]["esxi"].pop("queue_resource")
            config["profiles"]["esxi"]["url"] = "https://admin:secret@esxi.example/sdk"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(core.ToolError, "must not contain credentials"):
                    vm_queue.resolve_profile_resource("esxi", "/Datacenter/vm/windows")

    def test_owner_cannot_release_during_an_active_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, self._environment(directory), clear=True):
                vm_queue.claim("lab:windows", "alice", True)
                with mock.patch.object(vm_queue, "LOCK_TIMEOUT_SECONDS", 0.1):
                    with vm_queue.owner_operation("lab:windows", "alice"):
                        with self.assertRaisesRegex(core.ToolError, "operation.*stayed busy"):
                            vm_queue.release("lab:windows", "alice")
                released = vm_queue.release("lab:windows", "alice")
        self.assertEqual(released["release_status"], "released")

    def test_corrupt_state_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self._environment(directory)
            Path(environment["REMOTEX_VM_QUEUE_FILE"]).write_text("not-json", encoding="utf-8")
            with mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(core.ToolError, "refusing VM operations"):
                    vm_queue.inspect("lab:windows")

    def test_concurrent_requests_keep_one_fifo_entry_per_requester(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = self._environment(directory)

            def enqueue(requester: str) -> None:
                vm_queue.request("lab:windows", requester)

            requesters = [f"requester-{index}" for index in range(8)]
            with mock.patch.dict(os.environ, environment, clear=True):
                with ThreadPoolExecutor(max_workers=8) as executor:
                    list(executor.map(enqueue, requesters))
                status = vm_queue.inspect("lab:windows")
        self.assertEqual(status["queue_length"], len(requesters))
        self.assertEqual(
            {waiter["requester"] for waiter in status["waiters"]}, set(requesters)
        )


if __name__ == "__main__":
    unittest.main()
