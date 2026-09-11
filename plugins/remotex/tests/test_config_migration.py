from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(SRC))

import credential_store
import remotex_core as core
import secure_paths


def migration_module():
    path = PLUGIN_ROOT / "scripts" / "migrate_remotex_config.py"
    if not path.is_file():
        raise AssertionError("migrate_remotex_config.py must exist")
    spec = importlib.util.spec_from_file_location("migrate_remotex_config", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ConfigMigrationTests(unittest.TestCase):
    def _v1(self) -> dict:
        return {
            "version": 1,
            "defaults": {"windows-guest": "guest-a", "ssh": "linux"},
            "profiles": {
                "guest-a": {
                    "kind": "windows-guest",
                    "host": "guest-a.example",
                    "credential": {
                        "source": "windows-credential-manager",
                        "target": "RemoteX/shared-admin",
                    },
                },
                "guest-b": {
                    "kind": "windows-guest",
                    "host": "guest-b.example",
                    "credential": {
                        "source": "windows-credential-manager",
                        "target": "RemoteX/shared-admin",
                    },
                },
                "linux": {
                    "kind": "ssh",
                    "host": "linux.example",
                    "user": "root",
                    "identity_file": "~/.ssh/id_ed25519",
                },
                "vm": {
                    "kind": "vmware-workstation",
                    "vmx_path": "D:/VM/example.vmx",
                },
            },
        }

    def test_migration_deduplicates_references_and_preserves_profiles(self) -> None:
        self.assertTrue(hasattr(credential_store, "migrate_v1_config"))
        source = self._v1()
        migrated = credential_store.migrate_v1_config(source)
        self.assertEqual(migrated["version"], 2)
        self.assertEqual(migrated["defaults"], source["defaults"])
        self.assertEqual(len(migrated["credentials"]), 2)
        self.assertEqual(
            migrated["profiles"]["guest-a"]["credential_ref"],
            migrated["profiles"]["guest-b"]["credential_ref"],
        )
        self.assertNotIn("credential", migrated["profiles"]["guest-a"])
        self.assertNotIn("identity_file", migrated["profiles"]["linux"])
        self.assertIn("credential_ref", migrated["profiles"]["linux"])
        self.assertEqual(
            migrated["profiles"]["vm"],
            source["profiles"]["vm"],
        )
        self.assertEqual(
            core._validate_config(migrated),
            migrated,
        )

    def test_migration_is_deterministic_and_does_not_mutate_source(self) -> None:
        self.assertTrue(hasattr(credential_store, "migrate_v1_config"))
        source = self._v1()
        original = json.loads(json.dumps(source))
        first = credential_store.migrate_v1_config(source)
        second = credential_store.migrate_v1_config(source)
        self.assertEqual(first, second)
        self.assertEqual(source, original)

    def test_check_previews_without_writing(self) -> None:
        module = migration_module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(self._v1()), encoding="utf-8")
            before = path.read_bytes()
            output = io.StringIO()
            with redirect_stdout(output):
                result = module.main(["--config", str(path), "--check"])
            after = path.read_bytes()
        self.assertEqual(result, 0)
        self.assertEqual(before, after)
        preview = json.loads(output.getvalue())
        self.assertEqual(preview["status"], "preview")
        self.assertEqual(preview["candidate"]["version"], 2)
        self.assertEqual(preview["credentialAliasCount"], 2)

    def test_write_requires_confirmation(self) -> None:
        module = migration_module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(self._v1()), encoding="utf-8")
            with self.assertRaisesRegex(core.ToolError, "--confirm"):
                module.main(["--config", str(path), "--write"])

    def test_confirmed_write_keeps_backup_and_validates_readback(self) -> None:
        module = migration_module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(self._v1()), encoding="utf-8")
            output = io.StringIO()
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
                    with redirect_stdout(output):
                        result = module.main(
                            [
                                "--config",
                                str(path),
                                "--write",
                                "--confirm",
                            ]
                        )
            migrated = json.loads(path.read_text(encoding="utf-8"))
            backups = list(Path(directory).glob("config.json.v1-backup-*.json"))
        self.assertEqual(result, 0)
        self.assertEqual(migrated["version"], 2)
        self.assertEqual(len(backups), 1)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["status"], "written")
        self.assertRegex(receipt["configSha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("shared-admin", json.dumps(receipt))


if __name__ == "__main__":
    unittest.main()
