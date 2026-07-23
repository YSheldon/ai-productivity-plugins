from __future__ import annotations

import json
from contextlib import nullcontext
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import rdp_adapter
import remotex_core as core
import ssh_adapter
import vmware_adapter
import vm_queue
import vsphere_adapter


class AdapterTests(unittest.TestCase):
    def _config(self, directory: str, profiles: dict, defaults: dict) -> Path:
        path = Path(directory) / "config.json"
        path.write_text(
            json.dumps({"version": 1, "defaults": defaults, "profiles": profiles}),
            encoding="utf-8",
        )
        return path

    def test_ssh_arguments_disable_interactive_passwords(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "id_ed25519"
            identity.write_text("test fixture, not a private key", encoding="utf-8")
            path = self._config(
                directory,
                {
                    "linux": {
                        "kind": "ssh",
                        "host": "linux.example",
                        "user": "root",
                        "credential": {
                            "source": "identity-file",
                            "identity_file": str(identity),
                        },
                    }
                },
                {"ssh": "linux"},
            )
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with mock.patch.object(core, "find_executable", return_value="ssh"):
                    cfg = ssh_adapter.connection_config()
                    argv = ssh_adapter.ssh_arguments(cfg, 10, "hostname")
        rendered = " ".join(argv)
        self.assertIn("BatchMode=yes", rendered)
        self.assertIn("PasswordAuthentication=no", rendered)
        self.assertIn("KbdInteractiveAuthentication=no", rendered)
        self.assertNotIn("test fixture", rendered)

    def test_rdp_open_refuses_missing_saved_credential(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._config(
                directory,
                {
                    "windows": {
                        "kind": "rdp",
                        "host": "windows.example",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "TERMSRV/windows.example",
                        },
                    }
                },
                {"rdp": "windows"},
            )
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with mock.patch.object(rdp_adapter, "_credential_present", return_value=False):
                    with self.assertRaisesRegex(core.ToolError, "never accepts a password"):
                        rdp_adapter.open_connection({})

    def test_rdp_arguments_are_fixed_tokens(self) -> None:
        cfg = {
            "host": "windows.example",
            "port": 3389,
            "rdp_file": None,
            "admin": True,
            "fullscreen": False,
            "width": 1600,
            "height": 900,
            "mstsc_path": None,
        }
        with mock.patch.object(core, "find_executable", return_value="mstsc.exe"):
            argv = rdp_adapter.rdp_arguments(cfg)
        self.assertEqual(
            argv,
            ["mstsc.exe", "/v:windows.example:3389", "/admin", "/w:1600", "/h:900"],
        )

    def test_vsphere_credentials_are_only_in_child_environment(self) -> None:
        cfg = {
            "url": "https://esxi.example/sdk",
            "credential": {
                "source": "environment",
                "username_env": "REMOTEX_VSPHERE_USER",
                "password_env": "REMOTEX_VSPHERE_PASSWORD",
            },
            "insecure": False,
            "datacenter": None,
            "ca_file": None,
        }
        with mock.patch.dict(
            os.environ,
            {"REMOTEX_VSPHERE_USER": "operator", "REMOTEX_VSPHERE_PASSWORD": "secret"},
            clear=True,
        ):
            environment = vsphere_adapter._govc_environment(cfg)
        self.assertEqual(environment["GOVC_USERNAME"], "operator")
        self.assertEqual(environment["GOVC_PASSWORD"], "secret")
        self.assertNotIn("secret", json.dumps(cfg))

    def test_vmware_start_defaults_to_nogui(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vmx = Path(directory) / "example.vmx"
            vmx.write_text("config.version = \"8\"", encoding="utf-8")
            path = self._config(
                directory,
                {
                    "vm": {
                        "kind": "vmware-workstation",
                        "vmx_path": str(vmx),
                    }
                },
                {"vmware-workstation": "vm"},
            )
            outcome = {"returncode": 0, "timed_out": False, "stdout": "", "stderr": ""}
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with mock.patch.object(vmware_adapter, "_vmrun_path", return_value="vmrun"):
                    with mock.patch.object(
                        vmware_adapter.vm_queue,
                        "profile_owner_operation",
                        return_value=nullcontext(
                            {
                                "resource": "vmware:test",
                                "owner": {"requester": "test-owner"},
                            }
                        ),
                    ):
                        with mock.patch.object(core, "run_process", return_value=outcome) as runner:
                            vmware_adapter.power(
                                {"action": "start", "requester": "test-owner"}
                            )
        self.assertEqual(runner.call_args.args[0][-3:], ["start", str(vmx), "nogui"])

    def test_vmware_power_refuses_unowned_vm_before_vmrun(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vmx = Path(directory) / "example.vmx"
            vmx.write_text("config.version = \"8\"", encoding="utf-8")
            path = self._config(
                directory,
                {
                    "vm": {
                        "kind": "vmware-workstation",
                        "vmx_path": str(vmx),
                    }
                },
                {"vmware-workstation": "vm"},
            )
            environment = {
                "REMOTEX_CONFIG": str(path),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch.object(vmware_adapter, "_vmrun_path", return_value="vmrun"):
                    with mock.patch.object(core, "run_process") as runner:
                        with self.assertRaisesRegex(core.ToolError, "unowned"):
                            vmware_adapter.power(
                                {"action": "start", "requester": "test-owner"}
                            )
        runner.assert_not_called()

    def test_rdp_open_does_not_preempt_another_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._config(
                directory,
                {
                    "windows": {
                        "kind": "rdp",
                        "host": "windows.example",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "TERMSRV/windows.example",
                        },
                    }
                },
                {"rdp": "windows"},
            )
            environment = {
                "REMOTEX_CONFIG": str(path),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                target = vm_queue.resolve_profile_resource("windows")
                vm_queue.claim(target["resource"], "alice", True)
                with mock.patch.object(rdp_adapter, "_credential_present", return_value=True):
                    with mock.patch.object(rdp_adapter.subprocess, "Popen") as process:
                        with self.assertRaisesRegex(core.ToolError, "cannot preempt"):
                            rdp_adapter.open_connection({"requester": "bob"})
        process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
