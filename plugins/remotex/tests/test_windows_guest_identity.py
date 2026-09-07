from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import remotex_core as core
import vm_identity
import rdp_adapter
import windows_guest


class WindowsGuestIdentityTests(unittest.TestCase):
    def test_guest_connection_refuses_a_vmx_uuid_mismatch_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vmx = root / "windows.vmx"
            vmx.write_text(
                'uuid.bios = "00112233-4455-6677-8899-aabbccddeeff"\n',
                encoding="utf-8",
            )
            config = {
                "version": 1,
                "defaults": {"windows-guest": "guest"},
                "profiles": {
                    "rdp": {
                        "kind": "rdp",
                        "host": "windows.example",
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
                        "vmx_path": str(vmx),
                        "vmware_uuid": "00112233-4455-6677-8899-aabbccddeeff",
                        "queue_resource": "lab:windows",
                        "vm_identity": "lab-windows",
                    },
                },
            }
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(config_path)}, clear=True):
                ready = {
                    "source": "windows-credential-manager",
                    "target": "RemoteX/guest",
                    "ready": True,
                    "reason": None,
                }
                with mock.patch.object(windows_guest, "_credential_status", return_value=ready):
                    result = windows_guest.connection_config("guest")
                    self.assertEqual(result["boundVmxPath"], vmx)
                    vmx.write_text(
                        'uuid.bios = "ffeeddcc-bbaa-9988-7766-554433221100"\n',
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(core.ToolError, "vm-identity-mismatch"):
                        windows_guest.connection_config("guest")

    def test_physical_host_identity_binds_without_vmware_or_vmx(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {
                "version": 1,
                "defaults": {"windows-guest": "guest"},
                "profiles": {
                    "rdp": {
                        "kind": "rdp",
                        "host": "hlk-202.example",
                        "port": 3389,
                        "host_identity": "hlk-202-host",
                        "queue_resource": "hlk:202",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "TERMSRV/hlk-202.example",
                        },
                    },
                    "guest": {
                        "kind": "windows-guest",
                        "host": "hlk-202.example",
                        "port": 5985,
                        "host_identity": "hlk-202-host",
                        "queue_resource": "hlk:202",
                        "guest_machine_id": "HLK-202",
                        "staging_root": r"C:\RemoteX\Staging",
                        "transport": "winrm",
                        "authentication": "kerberos",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "RemoteX/hlk-202",
                        },
                    },
                },
            }
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(config_path)},
                clear=True,
            ):
                _, raw, _ = core.select_profile("windows-guest", "guest")
                binding = vm_identity.binding_for_profile(
                    "guest",
                    raw,
                    require_identity=True,
                    require_guest_profile=True,
                )
                self.assertEqual(binding["identityKind"], "physical-host")
                self.assertEqual(binding["hostIdentity"], "hlk-202-host")
                self.assertEqual(binding["queueResource"], "hlk:202")
                self.assertNotIn("vmwareProfile", binding)
                self.assertNotIn("vmwareUuid", binding)
                ready = {
                    "source": "windows-credential-manager",
                    "ready": True,
                    "reason": None,
                }
                with mock.patch.object(
                    windows_guest,
                    "_credential_status",
                    return_value=ready,
                ):
                    connection = windows_guest.connection_config("guest")
            self.assertEqual(connection["identity"]["identityKind"], "physical-host")
            self.assertNotIn("boundVmxPath", connection)

    def test_physical_host_status_allows_guest_capabilities_but_not_vm_power(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {
                "version": 1,
                "defaults": {"windows-guest": "guest"},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "host": "hlk-202.example",
                        "port": 5985,
                        "host_identity": "hlk-202-host",
                        "queue_resource": "hlk:202",
                        "guest_machine_id": "HLK-202",
                        "staging_root": r"C:\RemoteX\Staging",
                        "transport": "winrm",
                        "authentication": "kerberos",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "RemoteX/hlk-202",
                        },
                    }
                },
            }
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(config_path)},
                clear=True,
            ):
                ready = {
                    "source": "windows-credential-manager",
                    "ready": True,
                    "reason": None,
                }
                with mock.patch.object(
                    windows_guest,
                    "_credential_status",
                    return_value=ready,
                ):
                    with mock.patch.object(
                        core,
                        "executable_available",
                        return_value=True,
                    ):
                        result = windows_guest.profile_status(
                            "guest",
                            config["profiles"]["guest"],
                        )
        self.assertTrue(result["ready"])
        self.assertEqual(result["vmIdentity"]["identityKind"], "physical-host")
        self.assertTrue(result["capabilities"]["guest_exec"]["available"])
        self.assertTrue(result["capabilities"]["guest_copy"]["available"])
        self.assertTrue(result["capabilities"]["reboot_wait"]["available"])
        self.assertFalse(result["capabilities"]["power"]["available"])
        self.assertFalse(result["capabilities"]["snapshot"]["available"])

    def test_physical_host_identity_rejects_mixed_vm_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "version": 1,
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "host": "hlk.example",
                        "host_identity": "hlk-host",
                        "vm_identity": "unexpected-vm",
                        "queue_resource": "hlk:physical",
                        "guest_machine_id": "HLK",
                        "staging_root": r"C:\RemoteX\Staging",
                        "credential": {
                            "source": "windows-integrated",
                        },
                    }
                },
            }
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(config_path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "cannot configure both vm_identity and host_identity",
                ):
                    vm_identity.binding_for_profile(
                        "guest",
                        config["profiles"]["guest"],
                        require_identity=True,
                        require_guest_profile=True,
                    )

    def test_physical_host_identity_requires_one_shared_queue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "version": 1,
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "host": "hlk.example",
                        "host_identity": "hlk-host",
                        "queue_resource": "hlk:guest",
                        "guest_machine_id": "HLK",
                        "staging_root": r"C:\RemoteX\Staging",
                        "credential": {
                            "source": "windows-integrated",
                        },
                    },
                    "rdp": {
                        "kind": "rdp",
                        "host": "hlk.example",
                        "host_identity": "hlk-host",
                        "queue_resource": "hlk:rdp",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "TERMSRV/hlk.example",
                        },
                    },
                },
            }
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(config_path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "host_identity 'hlk-host' profiles must share one exact queue_resource",
                ):
                    vm_identity.binding_for_profile(
                        "guest",
                        config["profiles"]["guest"],
                        require_identity=True,
                        require_guest_profile=True,
                    )

    def test_physical_rdp_status_does_not_require_vmx(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "version": 1,
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "host": "hlk.example",
                        "host_identity": "hlk-host",
                        "queue_resource": "hlk:physical",
                        "guest_machine_id": "HLK",
                        "staging_root": r"C:\RemoteX\Staging",
                        "credential": {"source": "windows-integrated"},
                    },
                    "rdp": {
                        "kind": "rdp",
                        "host": "hlk.example",
                        "host_identity": "hlk-host",
                        "queue_resource": "hlk:physical",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "TERMSRV/hlk.example",
                        },
                    },
                },
            }
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(config_path)},
                clear=True,
            ):
                with mock.patch.object(
                    rdp_adapter,
                    "_credential_present",
                    return_value=True,
                ):
                    with mock.patch.object(
                        core,
                        "executable_available",
                        return_value=True,
                    ):
                        result = rdp_adapter.profile_status(
                            "rdp",
                            config["profiles"]["rdp"],
                        )
                        connection = rdp_adapter.connection_config("rdp")
        self.assertTrue(result["ready"])
        self.assertEqual(result["vmIdentity"]["identityKind"], "physical-host")
        self.assertNotIn("bound_vmx_path", result)
        self.assertEqual(connection["vmIdentity"]["identityKind"], "physical-host")
        self.assertIsNone(connection["boundVmxPath"])

    def test_physical_host_identity_rejects_non_windows_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "version": 1,
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "host": "hlk.example",
                        "host_identity": "hlk-host",
                        "queue_resource": "hlk:physical",
                        "guest_machine_id": "HLK",
                        "staging_root": r"C:\RemoteX\Staging",
                        "credential": {"source": "windows-integrated"},
                    },
                    "esxi": {
                        "kind": "esxi",
                        "url": "https://esxi.example/sdk",
                        "host_identity": "hlk-host",
                        "queue_resource": "hlk:physical",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "RemoteX/esxi",
                        },
                    },
                },
            }
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(config_path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "cannot bind unsupported profile kind",
                ):
                    vm_identity.binding_for_profile(
                        "guest",
                        config["profiles"]["guest"],
                        require_identity=True,
                        require_guest_profile=True,
                    )

    def test_physical_rdp_status_fails_closed_on_invalid_identity_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "version": 1,
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "host": "hlk.example",
                        "host_identity": "hlk-host",
                        "queue_resource": "hlk:guest",
                        "guest_machine_id": "HLK",
                        "staging_root": r"C:\RemoteX\Staging",
                        "credential": {"source": "windows-integrated"},
                    },
                    "rdp": {
                        "kind": "rdp",
                        "host": "hlk.example",
                        "host_identity": "hlk-host",
                        "queue_resource": "hlk:rdp",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "TERMSRV/hlk.example",
                        },
                    },
                },
            }
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(config_path)},
                clear=True,
            ):
                with mock.patch.object(rdp_adapter, "_credential_present", return_value=True):
                    with mock.patch.object(core, "executable_available", return_value=True):
                        result = rdp_adapter.profile_status(
                            "rdp",
                            config["profiles"]["rdp"],
                        )
        self.assertFalse(result["ready"])
        self.assertTrue(
            any("share one exact queue_resource" in item for item in result["errors"])
        )

    def test_vm_identity_group_rejects_host_identity_on_any_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = {
                "version": 1,
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "host": "vm.example",
                        "vm_identity": "lab-vm",
                        "queue_resource": "lab:vm",
                        "guest_machine_id": "LAB-VM",
                        "staging_root": r"C:\RemoteX\Staging",
                        "credential": {"source": "windows-integrated"},
                    },
                    "rdp": {
                        "kind": "rdp",
                        "host": "vm.example",
                        "vm_identity": "lab-vm",
                        "host_identity": "physical-label",
                        "queue_resource": "lab:vm",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "TERMSRV/vm.example",
                        },
                    },
                    "vmware": {
                        "kind": "vmware-workstation",
                        "vm_identity": "lab-vm",
                        "queue_resource": "lab:vm",
                        "vmx_path": r"C:\VMs\lab.vmx",
                        "vmware_uuid": "00112233445566778899aabbccddeeff",
                    },
                },
            }
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(config_path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "vm_identity 'lab-vm' cannot mix host_identity",
                ):
                    vm_identity.binding_for_profile(
                        "guest",
                        config["profiles"]["guest"],
                        require_identity=True,
                        require_guest_profile=True,
                    )


if __name__ == "__main__":
    unittest.main()
