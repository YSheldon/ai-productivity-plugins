from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(SRC))

import remotex_core as core
import remotex_mcp
import secure_paths
import authentication_evidence
import credential_store
import vsphere_adapter
import windows_guest


def credential_tools_module():
    if importlib.util.find_spec("credential_tools") is None:
        raise AssertionError("credential_tools module must exist")
    return importlib.import_module("credential_tools")


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class CredentialToolsTests(unittest.TestCase):
    def _write_config(self, directory: str, value: dict) -> Path:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_doctor_deduplicates_missing_alias_consumers(self) -> None:
        tools = credential_tools_module()
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "id_ed25519"
            identity.write_text("fixture", encoding="utf-8")
            path = self._write_config(
                directory,
                {
                    "version": 2,
                    "credentials": {
                        "shared-guest": {
                            "source": "windows-credential-manager",
                            "target": "RemoteX/shared-guest",
                        },
                        "ready-rdp": {
                            "source": "windows-credential-manager",
                            "target": "TERMSRV/ready.example",
                        },
                        "linux-key": {
                            "source": "identity-file",
                            "identity_file": str(identity),
                        },
                    },
                    "defaults": {},
                    "profiles": {
                        "guest-a": {
                            "kind": "windows-guest",
                            "credential_ref": "shared-guest",
                        },
                        "guest-b": {
                            "kind": "windows-guest",
                            "credential_ref": "shared-guest",
                        },
                        "rdp": {
                            "kind": "rdp",
                            "credential_ref": "ready-rdp",
                        },
                        "ssh": {
                            "kind": "ssh",
                            "credential_ref": "linux-key",
                        },
                    },
                },
            )

            def credential_exists(target: str, credential_types=(1,)) -> bool:
                return target == "TERMSRV/ready.example"

            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with mock.patch.object(
                    credential_store.windows_credentials,
                    "credential_exists",
                    side_effect=credential_exists,
                ):
                    with mock.patch.object(
                        secure_paths,
                        "private_path_status",
                        return_value={"ready": True, "reason": None},
                    ):
                        result = payload(tools.doctor({}))
        self.assertFalse(result["ok"])
        self.assertEqual(result["configurationVersion"], 2)
        self.assertFalse(result["migrationRecommended"])
        self.assertEqual(result["summary"]["credentialProfiles"], 4)
        self.assertEqual(result["summary"]["uniqueReferences"], 3)
        self.assertEqual(result["summary"]["present"], 2)
        self.assertEqual(result["summary"]["missing"], 1)
        self.assertEqual(len(result["uniqueMissing"]), 1)
        missing = result["uniqueMissing"][0]
        self.assertEqual(missing["credentialRef"], "shared-guest")
        self.assertEqual(missing["consumerCount"], 2)
        self.assertEqual(missing["nextStep"], "run-remotex-credential-setup")
        self.assertNotIn("RemoteX/shared-guest", json.dumps(result))
        for item in result["references"]:
            self.assertIn("authenticationVerified", item)
            self.assertIsNone(item["authenticationVerified"])
            self.assertTrue(item["localProtectionReady"])

    def test_doctor_version_one_deduplicates_inline_targets(self) -> None:
        tools = credential_tools_module()
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_config(
                directory,
                {
                    "version": 1,
                    "defaults": {},
                    "profiles": {
                        "guest-a": {
                            "kind": "windows-guest",
                            "credential": {
                                "source": "windows-credential-manager",
                                "target": "RemoteX/shared-inline",
                            },
                        },
                        "guest-b": {
                            "kind": "windows-guest",
                            "credential": {
                                "source": "windows-credential-manager",
                                "target": "RemoteX/shared-inline",
                            },
                        },
                    },
                },
            )
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with mock.patch.object(
                    credential_store.windows_credentials,
                    "credential_exists",
                    return_value=False,
                ):
                    with mock.patch.object(
                        secure_paths,
                        "private_path_status",
                        return_value={"ready": True, "reason": None},
                    ):
                        result = payload(tools.doctor({}))
        self.assertTrue(result["migrationRecommended"])
        self.assertEqual(result["summary"]["credentialProfiles"], 2)
        self.assertEqual(result["summary"]["uniqueReferences"], 1)
        self.assertEqual(result["summary"]["missing"], 1)
        self.assertEqual(result["uniqueMissing"][0]["consumerCount"], 2)

    def test_doctor_profile_filter_is_exact(self) -> None:
        tools = credential_tools_module()
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_config(
                directory,
                {
                    "version": 2,
                    "credentials": {
                        "a": {"source": "windows-integrated"},
                        "b": {"source": "windows-integrated"},
                    },
                    "defaults": {},
                    "profiles": {
                        "guest-a": {"kind": "windows-guest", "credential_ref": "a"},
                        "guest-b": {"kind": "windows-guest", "credential_ref": "b"},
                    },
                },
            )
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with mock.patch.object(
                    secure_paths,
                    "private_path_status",
                    return_value={"ready": True, "reason": None},
                ):
                    result = payload(tools.doctor({"profile": "guest-b"}))
        self.assertEqual(result["summary"]["credentialProfiles"], 1)
        self.assertEqual(result["references"][0]["consumerProfiles"], ["guest-b"])

    def test_doctor_tool_schema_accepts_no_secret_fields(self) -> None:
        self.assertIn("remotex_credential_doctor", remotex_mcp.TOOLS)
        schema = remotex_mcp.TOOLS["remotex_credential_doctor"]["inputSchema"]
        self.assertEqual(set(schema["properties"]), {"profile", "credential_ref"})
        rendered = json.dumps(schema).lower()
        for forbidden in ("password", "token", "secret", "username"):
            self.assertNotIn(forbidden, rendered)

    def test_doctor_reports_fresh_sanitized_authentication_evidence(self) -> None:
        if importlib.util.find_spec("authentication_evidence") is None:
            self.fail("authentication_evidence module must exist")
        evidence = importlib.import_module("authentication_evidence")
        tools = credential_tools_module()
        with tempfile.TemporaryDirectory() as directory:
            config_path = self._write_config(
                directory,
                {
                    "version": 2,
                    "credentials": {
                        "guest-admin": {
                            "source": "windows-integrated",
                        }
                    },
                    "defaults": {},
                    "profiles": {
                        "guest": {
                            "kind": "windows-guest",
                            "credential_ref": "guest-admin",
                        }
                    },
                },
            )
            evidence_path = Path(directory) / "evidence.json"
            environment = {
                "REMOTEX_CONFIG": str(config_path),
                "REMOTEX_CREDENTIAL_EVIDENCE_FILE": str(evidence_path),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch.object(
                    secure_paths,
                    "ensure_private_directory",
                    return_value={"ready": True},
                ):
                    with mock.patch.object(
                        secure_paths,
                        "ensure_private_file",
                        return_value={"ready": True},
                    ):
                        evidence.record_verified(
                            "guest",
                            "windows-integrated",
                            "guest.example:5985",
                        )
                with mock.patch.object(
                    secure_paths,
                    "private_path_status",
                    return_value={"ready": True, "reason": None},
                ):
                    result = payload(tools.doctor({}))
            persisted = evidence_path.read_text(encoding="utf-8")
        self.assertTrue(result["references"][0]["authenticationVerified"])
        self.assertIsNotNone(result["references"][0]["lastVerifiedAt"])
        self.assertNotIn("guest.example", persisted)

    def test_windows_guest_success_records_authentication_evidence(self) -> None:
        cfg = {
            "profile": "guest",
            "host": "guest.example",
            "port": 5985,
            "credentialState": {"source": "windows-integrated"},
        }
        identity = {
            "machineId": "GUEST",
            "bootIdentity": "boot",
            "vmIdentity": {"ready": True},
        }
        with mock.patch.object(windows_guest, "connection_config", return_value=cfg):
            with mock.patch.object(windows_guest, "_probe_identity", return_value=identity):
                with mock.patch.object(authentication_evidence, "record_verified") as record:
                    result = payload(windows_guest.test_connection({"profile": "guest"}))
        self.assertTrue(result["ok"])
        record.assert_called_once_with(
            "guest",
            "windows-integrated",
            "guest.example:5985",
        )

    def test_vsphere_success_records_authentication_evidence(self) -> None:
        cfg = {
            "profile": "esxi",
            "url": "https://esxi.example/sdk",
            "credential": {
                "source": "windows-credential-manager",
                "target": "RemoteX/esxi",
            },
        }
        outcome = {
            "returncode": 0,
            "timed_out": False,
            "stdout": "{}",
            "stderr": "",
        }
        with mock.patch.object(vsphere_adapter, "connection_config", return_value=cfg):
            with mock.patch.object(vsphere_adapter, "_run_govc", return_value=outcome):
                with mock.patch.object(authentication_evidence, "record_verified") as record:
                    result = payload(vsphere_adapter.about({"profile": "esxi"}))
        self.assertTrue(result["ok"])
        record.assert_called_once_with(
            "esxi",
            "windows-credential-manager",
            "https://esxi.example/sdk",
        )


if __name__ == "__main__":
    unittest.main()
