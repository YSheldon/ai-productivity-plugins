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
import remotex_mcp


class RemoteXCoreTests(unittest.TestCase):
    def _write(self, directory: str, payload: dict) -> Path:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_empty_status_is_configuration_guidance_not_credential_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            environment = {
                "REMOTEX_CONFIG": str(missing),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                result = remotex_mcp.status({})
        text = result["content"][0]["text"]
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["summary"]["configured"], 0)
        self.assertFalse(payload["vm_queue"]["preemption_allowed"])
        self.assertEqual(payload["vm_queue"]["scope"], "local-cooperative")
        self.assertIn("Create", payload["next_step"])
        self.assertNotIn("no credentials", text.lower())

    def test_literal_password_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {
                    "version": 1,
                    "profiles": {
                        "bad": {
                            "kind": "esxi",
                            "url": "https://esxi.example/sdk",
                            "password": "do-not-store-this",
                        }
                    },
                },
            )
            with mock.patch.dict(os.environ, {"REMOTEX_CONFIG": str(path)}, clear=True):
                with self.assertRaisesRegex(core.ToolError, "not allowed"):
                    core.load_config()

    def test_legacy_ssh_config_is_loaded_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                {
                    "default": "lab",
                    "profiles": {
                        "lab": {
                            "host": "lab.example",
                            "user": "root",
                            "identity_file": "~/.ssh/id_ed25519",
                        }
                    },
                },
            )
            missing = Path(directory) / "missing-remotex.json"
            with mock.patch.object(core, "DEFAULT_CONFIG_PATH", missing):
                with mock.patch.dict(os.environ, {"SSH_CONFIG": str(path)}, clear=True):
                    bundle = core.load_config()
        self.assertEqual(bundle.source, "legacy-ssh")
        self.assertEqual(bundle.data["profiles"]["lab"]["kind"], "ssh")
        self.assertEqual(bundle.data["defaults"]["ssh"], "lab")

    def test_environment_credentials_are_references(self) -> None:
        credential = {
            "source": "environment",
            "username_env": "REMOTEX_TEST_USER",
            "password_env": "REMOTEX_TEST_PASSWORD",
        }
        with mock.patch.dict(
            os.environ,
            {"REMOTEX_TEST_USER": "operator", "REMOTEX_TEST_PASSWORD": "local-secret"},
            clear=True,
        ):
            status = core.credential_status(credential)
            resolved = core.resolve_username_password(credential)
        self.assertTrue(status["ready"])
        self.assertNotIn("operator", json.dumps(status))
        self.assertNotIn("local-secret", json.dumps(status))
        self.assertEqual(resolved.username, "operator")
        self.assertEqual(resolved.password, "local-secret")

    def test_redaction_covers_url_userinfo_and_assignments(self) -> None:
        scrubbed = core.redact_text(
            "https://admin:secret@example.test password=hunter2 ghp_abcdefghijklmnop"
        )
        self.assertNotIn("secret", scrubbed)
        self.assertNotIn("hunter2", scrubbed)
        self.assertNotIn("ghp_abcdefghijklmnop", scrubbed)


if __name__ == "__main__":
    unittest.main()
