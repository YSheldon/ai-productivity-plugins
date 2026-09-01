from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import queue_leases
import rdp_adapter
import remotex_core as core
import vm_identity
import vm_queue
import vmware_adapter
import windows_guest


def payload(result: dict[str, object]) -> dict[str, object]:
    content = result["content"]
    assert isinstance(content, list)
    first = content[0]
    assert isinstance(first, dict)
    return json.loads(first["text"])


class RemoteXVmGuestTests(unittest.TestCase):
    def _environment(self, directory: str) -> tuple[dict[str, str], Path]:
        root = Path(directory)
        vmx = root / "windows.vmx"
        vmx.write_text(
            'config.version = "8"\nuuid.bios = "00112233-4455-6677-8899-aabbccddeeff"\n',
            encoding="utf-8",
        )
        config = {
            "version": 1,
            "defaults": {
                "rdp": "rdp",
                "windows-guest": "guest",
                "vmware-workstation": "vmware",
            },
            "profiles": {
                "rdp": {
                    "kind": "rdp",
                    "host": "windows.example",
                    "port": 3389,
                    "queue_resource": "lab:windows",
                    "vm_identity": "lab-windows",
                    "credential": {
                        "source": "windows-credential-manager",
                        "target": "TERMSRV/windows.example",
                    },
                },
                "guest": {
                    "kind": "windows-guest",
                    "host": "windows.example",
                    "port": 5985,
                    "transport": "winrm",
                    "authentication": "kerberos",
                    "queue_resource": "lab:windows",
                    "vm_identity": "lab-windows",
                    "guest_machine_id": "LAB-WINDOWS",
                    "staging_root": "C:\\RemoteX\\Staging",
                    "credential": {
                        "source": "windows-credential-manager",
                        "target": "RemoteX/guest",
                    },
                },
                "vmware": {
                    "kind": "vmware-workstation",
                    "host_type": "ws",
                    "vmx_path": str(vmx),
                    "vmware_uuid": "00112233-4455-6677-8899-aabbccddeeff",
                    "queue_resource": "lab:windows",
                    "vm_identity": "lab-windows",
                    "vmrun_path": "vmrun",
                },
            },
        }
        config_path = root / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        return (
            {
                "REMOTEX_CONFIG": str(config_path),
                "REMOTEX_VM_QUEUE_FILE": str(root / "queue.json"),
                "REMOTEX_VM_QUEUE_LEASE_FILE": str(root / "leases.json"),
                "REMOTEX_GUEST_RECEIPT_FILE": str(root / "receipts.json"),
                "REMOTEX_VMWARE_SNAPSHOT_STATE_FILE": str(root / "snapshots.json"),
            },
            vmx,
        )

    def _claim(self, resource: str, requester: str) -> None:
        vm_queue.claim(resource, requester, True)
        queue_leases._set_lease(resource, requester, 3600, "test-lease")

    def test_version_two_guest_alias_reaches_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment, _ = self._environment(directory)
            config_path = Path(environment["REMOTEX_CONFIG"])
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["version"] = 2
            config["credentials"] = {
                "rdp-admin": {
                    "source": "windows-credential-manager",
                    "target": "TERMSRV/windows.example",
                },
                "guest-admin": {
                    "source": "windows-credential-manager",
                    "target": "RemoteX/guest",
                },
            }
            config["profiles"]["rdp"].pop("credential")
            config["profiles"]["rdp"]["credential_ref"] = "rdp-admin"
            config["profiles"]["guest"].pop("credential")
            config["profiles"]["guest"]["credential_ref"] = "guest-admin"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch.object(
                    core,
                    "credential_status",
                    return_value={
                        "source": "windows-credential-manager",
                        "ready": True,
                    },
                ):
                    cfg = windows_guest.connection_config("guest")
        self.assertEqual(cfg["credentialAlias"], "guest-admin")
        self.assertEqual(cfg["configurationVersion"], 2)
        self.assertEqual(
            cfg["credential"],
            {
                "source": "windows-credential-manager",
                "target": "RemoteX/guest",
            },
        )

    def test_composite_identity_binds_rdp_guest_vmx_and_one_queue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment, vmx = self._environment(directory)
            with mock.patch.dict(os.environ, environment, clear=True):
                _, raw, _ = core.select_profile("vmware-workstation", "vmware")
                binding = vm_identity.binding_for_profile(
                    "vmware",
                    raw,
                    require_identity=True,
                    require_guest_profile=True,
                )
                assert binding is not None
                self.assertEqual(binding["queueResource"], "lab:windows")
                self.assertEqual(binding["rdpEndpoint"], {"host": "windows.example", "port": 3389})
                self.assertEqual(binding["guestEndpoint"], {"host": "windows.example", "port": 5985})
                self.assertEqual(
                    vm_identity.verify_vmx(binding, vmx),
                    "00112233445566778899aabbccddeeff",
                )
                vmx.write_text(
                    'uuid.bios = "ffeeddcc-bbaa-9988-7766-554433221100"\n',
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(core.ToolError, "vm-identity-mismatch"):
                    vm_identity.verify_vmx(binding, vmx)

    def test_bound_vmx_mismatch_blocks_rdp_and_snapshot_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment, vmx = self._environment(directory)
            with mock.patch.dict(os.environ, environment, clear=True):
                vmx.write_text(
                    'uuid.bios = "ffeeddcc-bbaa-9988-7766-554433221100"\n',
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(core.ToolError, "vm-identity-mismatch"):
                    rdp_adapter.connection_config("rdp")
                with mock.patch.object(core, "run_process") as runner:
                    with self.assertRaisesRegex(core.ToolError, "vm-identity-mismatch"):
                        vmware_adapter.list_snapshots({"profile": "vmware"})
                runner.assert_not_called()

    def test_snapshot_create_is_idempotent_and_requires_inventory_readback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment, _ = self._environment(directory)
            with mock.patch.dict(os.environ, environment, clear=True):
                resource = vm_queue.resolve_profile_resource("vmware")["resource"]
                self._claim(resource, "alice")
                outcomes = iter(
                    [
                        {"returncode": 0, "timed_out": False, "stdout": "Total snapshots: 0\n", "stderr": ""},
                        {"returncode": 0, "timed_out": False, "stdout": "", "stderr": ""},
                        {"returncode": 0, "timed_out": False, "stdout": "Total snapshots: 1\nbaseline\n", "stderr": ""},
                    ]
                )
                with mock.patch.object(vmware_adapter, "_vmrun_path", return_value="vmrun"):
                    with mock.patch.object(core, "run_process", side_effect=lambda *_a, **_k: next(outcomes)) as runner:
                        with mock.patch.object(
                            windows_guest,
                            "require_preflight_receipt",
                            return_value={"sha256": "a" * 64},
                        ):
                            result = payload(
                                vmware_adapter.snapshot_create(
                                    {
                                        "profile": "vmware",
                                        "requester": "alice",
                                        "snapshot_name": "baseline",
                                        "idempotency_key": "run-1",
                                        "preflight_receipt_sha256": "a" * 64,
                                    }
                                )
                            )
                self.assertTrue(result["ok"])
                self.assertTrue(result["exactSnapshotMatch"])
                self.assertTrue(result["targetStateReadback"])
                self.assertFalse(result["receipt"]["rawOutputExported"])
                self.assertEqual(runner.call_count, 3)

                outcomes = iter(
                    [
                        {"returncode": 0, "timed_out": False, "stdout": "Total snapshots: 1\nbaseline\n", "stderr": ""},
                    ]
                )
                with mock.patch.object(vmware_adapter, "_vmrun_path", return_value="vmrun"):
                    with mock.patch.object(core, "run_process", side_effect=lambda *_a, **_k: next(outcomes)) as runner:
                        with mock.patch.object(
                            windows_guest,
                            "require_preflight_receipt",
                            side_effect=AssertionError("idempotent snapshot must not re-run preflight"),
                        ):
                            repeated = payload(
                                vmware_adapter.snapshot_create(
                                    {
                                        "profile": "vmware",
                                        "requester": "alice",
                                        "snapshot_name": "baseline",
                                        "idempotency_key": "run-1",
                                        "preflight_receipt_sha256": "a" * 64,
                                    }
                                )
                            )
                self.assertTrue(repeated["idempotent"])
                self.assertEqual(runner.call_count, 1)

    def test_snapshot_create_fails_when_post_mutation_inventory_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment, _ = self._environment(directory)
            with mock.patch.dict(os.environ, environment, clear=True):
                resource = vm_queue.resolve_profile_resource("vmware")["resource"]
                self._claim(resource, "alice")
                outcomes = iter(
                    [
                        {"returncode": 0, "timed_out": False, "stdout": "Total snapshots: 0\n", "stderr": ""},
                        {"returncode": 0, "timed_out": False, "stdout": "stale client stdout", "stderr": ""},
                        {"returncode": 0, "timed_out": False, "stdout": "Total snapshots: 0\n", "stderr": ""},
                    ]
                )
                with mock.patch.object(vmware_adapter, "_vmrun_path", return_value="vmrun"):
                    with mock.patch.object(core, "run_process", side_effect=lambda *_a, **_k: next(outcomes)):
                        with mock.patch.object(
                            windows_guest,
                            "require_preflight_receipt",
                            return_value={"sha256": "a" * 64},
                        ):
                            result = payload(
                                vmware_adapter.snapshot_create(
                                    {
                                        "profile": "vmware",
                                        "requester": "alice",
                                        "snapshot_name": "baseline",
                                        "idempotency_key": "run-1",
                                        "preflight_receipt_sha256": "a" * 64,
                                    }
                                )
                            )
                self.assertFalse(result["ok"])
                self.assertFalse(result["targetStateReadback"])
                self.assertFalse(result["receipt"]["rawOutputExported"])

    def test_preflight_policy_reports_independent_failure_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment, _ = self._environment(directory)
            with mock.patch.dict(os.environ, environment, clear=True):
                _, raw, _ = core.select_profile("windows-guest", "guest")
                identity = vm_identity.binding_for_profile(
                    "guest",
                    raw,
                    require_identity=True,
                    require_guest_profile=True,
                )
                assert identity is not None
                cfg = {"identity": identity}
                policy = windows_guest._policy(
                    {
                        "minimum_os_version": "6.1",
                        "required_architecture": "x64",
                        "minimum_powershell_version": "2.0",
                        "minimum_dotnet_release": 1,
                        "required_kbs": ["KB1234"],
                        "required_cmdlets": ["Get-Example"],
                        "minimum_free_system_drive_bytes": 1,
                        "inactive_processes": ["example-process"],
                        "inactive_services": ["example-service"],
                        "inactive_drivers": ["example-driver"],
                        "inactive_etw_sessions": ["example-etw"],
                    }
                )

                def marker(name: str, value: object) -> str:
                    encoded = base64.b64encode(str(value).encode("utf-8")).decode("ascii")
                    return f"REMOTEX_PREFLIGHT|{name}|{encoded}"

                output = "\n".join(
                    [
                        marker("run_id", "run-1"),
                        marker("machine_id", "LAB-WINDOWS"),
                        marker("boot_identity", "boot-1"),
                        marker("os_version", "6.0"),
                        marker("architecture", "x86"),
                        marker("powershell_version", "1.0"),
                        marker("dotnet_release", "0"),
                        marker("pending_reboot", "true"),
                        marker("free_system_drive_bytes", "0"),
                        marker("utc", "2026-07-25T00:00:00Z"),
                        marker("kb:KB1234", "false"),
                        marker("cmdlet:Get-Example", "false"),
                        marker("process:example-process", "true"),
                        marker("service:example-service", "true"),
                        marker("driver:example-driver", "true"),
                        marker("etw:example-etw", "true"),
                    ]
                )
                evidence = windows_guest._preflight_evidence(
                    cfg,
                    "run-1",
                    policy,
                    {"returncode": 0, "timed_out": False, "stdout": output, "stderr": ""},
                )
                failures = windows_guest._preflight_failures(evidence, policy)
        self.assertEqual(
            set(failures),
            {
                "os-version-below-minimum",
                "architecture-mismatch",
                "powershell-version-below-minimum",
                "dotnet-release-below-minimum",
                "required-kb-missing",
                "cmdlet-smoke-failed",
                "pending-reboot",
                "system-drive-space-low",
                "runtime-not-inert",
            },
        )

    def test_guest_wrapper_keeps_credential_out_of_command_line(self) -> None:
        cfg = {
            "host": "windows.example",
            "port": 5985,
            "authentication": "kerberos",
            "credential": {"source": "windows-credential-manager", "target": "RemoteX/guest"},
            "powershellPath": None,
        }
        outcome = {"returncode": 0, "timed_out": False, "stdout": "", "stderr": ""}
        with mock.patch.object(
            windows_guest,
            "_credential_values",
            return_value=("DOMAIN\\operator", "super-secret", ["DOMAIN\\operator", "super-secret"]),
        ):
            with mock.patch.object(core, "find_executable", return_value="powershell.exe"):
                with mock.patch.object(windows_guest.execution, "run_process", return_value=outcome) as runner:
                    windows_guest._invoke(cfg, "Write-Output ok", timeout=30)
        argv = runner.call_args.args[0]
        self.assertNotIn("super-secret", " ".join(argv))
        self.assertNotIn("DOMAIN\\operator", " ".join(argv))
        self.assertIn("super-secret", runner.call_args.kwargs["secrets"])
        self.assertNotIn("-gp", " ".join(argv))

    def test_heartbeat_and_explicit_stale_recovery_do_not_transfer_waiter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment, _ = self._environment(directory)
            with mock.patch.dict(os.environ, environment, clear=True):
                resource = vm_queue.resolve_profile_resource("rdp")["resource"]
                self._claim(resource, "alice")
                heartbeat = payload(
                    queue_leases.queue_heartbeat({"profile": "rdp", "requester": "alice"})
                )
                self.assertEqual(heartbeat["heartbeatStatus"], "renewed")
                vm_queue.request(resource, "bob")
                lease_file = queue_leases.lease_path()
                leases = json.loads(lease_file.read_text(encoding="utf-8"))
                leases["leases"][resource]["expiresAt"] = "2000-01-01T00:00:00Z"
                lease_file.write_text(json.dumps(leases), encoding="utf-8")
                recovered = payload(
                    queue_leases.queue_recover_stale(
                        {"profile": "rdp", "requester": "operator", "confirm": True}
                    )
                )
                status = vm_queue.inspect(resource)
        self.assertEqual(recovered["recoveryStatus"], "recovered-unowned")
        self.assertIsNone(status["owner"])
        self.assertEqual(status["next_waiter"], "bob")


if __name__ == "__main__":
    unittest.main()
