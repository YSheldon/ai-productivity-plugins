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


if __name__ == "__main__":
    unittest.main()
