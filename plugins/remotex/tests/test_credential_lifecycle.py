from __future__ import annotations

import hashlib
import inspect
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

import credential_store
import credential_tools
import remotex_core as core
import remotex_mcp


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class CredentialLifecycleTests(unittest.TestCase):
    def _config(self, directory: str, *, source: str = "windows-credential-manager") -> Path:
        credential = {"source": source}
        if source == "windows-credential-manager":
            credential["target"] = "RemoteX/lab-admin"
        path = Path(directory) / "config.json"
        path.write_text(
            json.dumps(
                {
                    "version": 2,
                    "credentials": {"lab-admin": credential},
                    "defaults": {},
                    "profiles": {
                        "guest-a": {
                            "kind": "windows-guest",
                            "credential_ref": "lab-admin",
                        },
                        "guest-b": {
                            "kind": "windows-guest",
                            "credential_ref": "lab-admin",
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_lifecycle_tool_schemas_accept_no_credential_values(self) -> None:
        for name in ("remotex_credential_setup", "remotex_credential_delete"):
            self.assertIn(name, remotex_mcp.TOOLS)
            schema = remotex_mcp.TOOLS[name]["inputSchema"]
            self.assertEqual(
                set(schema["properties"]),
                {"profile", "credential_ref", "confirm", "timeout_seconds"}
                if name == "remotex_credential_setup"
                else {"profile", "credential_ref", "confirm"},
            )
            properties = {key.casefold() for key in schema["properties"]}
            self.assertTrue(
                properties.isdisjoint({"username", "password", "token", "secret", "target"})
            )

    def test_setup_requires_confirmation_and_returns_sanitized_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._config(directory)
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with self.assertRaisesRegex(core.ToolError, "confirm=true"):
                    credential_tools.setup(
                        {"credential_ref": "lab-admin", "confirm": False}
                    )
                with mock.patch.object(
                    credential_store,
                    "launch_secure_setup",
                    return_value={
                        "status": "stored",
                        "existingBefore": True,
                        "referencePresent": True,
                        "targetSha256": "a" * 64,
                    },
                ) as launch:
                    result = payload(
                        credential_tools.setup(
                            {
                                "credential_ref": "lab-admin",
                                "confirm": True,
                                "timeout_seconds": 120,
                            }
                        )
                    )
        self.assertTrue(result["ok"])
        self.assertTrue(result["rotated"])
        self.assertEqual(result["credentialRef"], "lab-admin")
        self.assertNotIn("RemoteX/lab-admin", json.dumps(result))
        reference = launch.call_args.args[0]
        self.assertEqual(reference.alias, "lab-admin")
        self.assertEqual(launch.call_args.kwargs["timeout"], 120)

    def test_setup_rejects_non_credential_manager_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._config(directory, source="windows-integrated")
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with self.assertRaisesRegex(core.ToolError, "Windows Credential Manager"):
                    credential_tools.setup(
                        {"credential_ref": "lab-admin", "confirm": True}
                    )

    def test_delete_is_confirmed_bounded_and_reports_consumers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._config(directory)
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with self.assertRaisesRegex(core.ToolError, "confirm=true"):
                    credential_tools.delete(
                        {"credential_ref": "lab-admin", "confirm": False}
                    )
                with mock.patch.object(
                    credential_store,
                    "delete_windows_credential",
                    return_value={
                        "removed": True,
                        "deletedRecordCount": 1,
                        "referencePresent": False,
                        "targetSha256": "a" * 64,
                    },
                ) as remove:
                    result = payload(
                        credential_tools.delete(
                            {"credential_ref": "lab-admin", "confirm": True}
                        )
                    )
        self.assertTrue(result["ok"])
        self.assertEqual(result["consumerCount"], 2)
        self.assertEqual(result["credentialRef"], "lab-admin")
        self.assertNotIn("RemoteX/lab-admin", json.dumps(result))
        self.assertEqual(remove.call_args.args[0].alias, "lab-admin")

    def test_secure_helper_contract_uses_secure_string_native_write_and_zero(self) -> None:
        script = PLUGIN_ROOT / "scripts" / "manage_windows_credential.ps1"
        self.assertTrue(script.is_file())
        source = script.read_text(encoding="utf-8")
        self.assertIn("Get-Credential", source)
        self.assertIn("CredWriteW", source)
        self.assertIn("SecureStringToCoTaskMemUnicode", source)
        self.assertIn("ZeroFreeCoTaskMemUnicode", source)
        self.assertNotIn("GetNetworkCredential().Password", source)
        self.assertNotIn("cmdkey", source.casefold())

    def test_setup_launcher_arguments_contain_reference_but_no_value_fields(self) -> None:
        self.assertTrue(hasattr(credential_store, "_setup_arguments"))
        config = core.ConfigBundle(
            data={
                "version": 2,
                "credentials": {
                    "lab-admin": {
                        "source": "windows-credential-manager",
                        "target": "RemoteX/lab-admin",
                    }
                },
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "credential_ref": "lab-admin",
                    }
                },
            },
            path=Path("config.json"),
            source="test",
            exists=True,
        )
        reference = credential_store.resolve_profile_reference(
            config,
            "guest",
            config.data["profiles"]["guest"],
            "windows-guest",
        )
        argv = credential_store._setup_arguments(
            reference,
            Path(r"C:\state\receipt.json"),
        )
        rendered = " ".join(argv)
        self.assertIn("RemoteX/lab-admin", rendered)
        self.assertIn("manage_windows_credential.ps1", rendered)
        for forbidden_switch in ("-Password", "-Token", "-Secret", "-Username"):
            self.assertNotIn(forbidden_switch, rendered)

    @unittest.skipUnless(os.name == "nt", "Windows secure helper launch test")
    def test_setup_launcher_rejects_receipt_and_exit_code_mismatch(self) -> None:
        config = core.ConfigBundle(
            data={
                "version": 2,
                "credentials": {
                    "lab-admin": {
                        "source": "windows-credential-manager",
                        "target": "RemoteX/lab-admin",
                    }
                },
                "defaults": {},
                "profiles": {},
            },
            path=Path("config.json"),
            source="test",
            exists=True,
        )
        reference = credential_store.resolve_named_reference(config, "lab-admin")
        target_digest = hashlib.sha256(b"RemoteX/lab-admin").hexdigest()

        class FakeProcess:
            pid = 42
            returncode = 1

            def wait(self, timeout=None):
                return self.returncode

            def kill(self):
                return None

        with tempfile.TemporaryDirectory() as directory:
            environment = {"REMOTEX_CREDENTIAL_SETUP_DIR": directory}

            def popen(arguments, **kwargs):
                receipt = Path(arguments[arguments.index("-ReceiptPath") + 1])
                receipt.write_text(
                    json.dumps(
                        {
                            "schema": "RemoteXCredentialSetupReceipt/v1",
                            "status": "stored",
                            "existingBefore": False,
                            "referencePresent": True,
                            "targetSha256": target_digest,
                        }
                    ),
                    encoding="utf-8",
                )
                return FakeProcess()

            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    credential_store.secure_paths,
                    "ensure_private_directory",
                    return_value={"ready": True},
                ):
                    with mock.patch.object(
                        credential_store.secure_paths,
                        "ensure_private_file",
                        return_value={"ready": True},
                    ):
                        with mock.patch.object(
                            credential_store.subprocess,
                            "Popen",
                            side_effect=popen,
                        ):
                            with mock.patch.object(
                                credential_store.windows_credentials,
                                "credential_exists",
                                return_value=True,
                            ):
                                with self.assertRaisesRegex(
                                    core.ToolError,
                                    "exit status",
                                ):
                                    credential_store.launch_secure_setup(
                                        reference,
                                        timeout=60,
                                    )


if __name__ == "__main__":
    unittest.main()
