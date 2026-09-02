from __future__ import annotations

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

import remotex_mcp
import remotex_core as core
import profile_tools
import secure_paths
import credential_store
import config_store
import vm_queue


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class ProfileSetupTests(unittest.TestCase):
    def test_profile_setup_schema_accepts_only_non_secret_configuration(self) -> None:
        self.assertIn("remotex_profile_setup", remotex_mcp.TOOLS)
        schema = remotex_mcp.TOOLS["remotex_profile_setup"]["inputSchema"]
        properties = set(schema["properties"])
        self.assertTrue(
            properties.isdisjoint(
                {"password", "token", "secret", "target", "username"}
            )
        )
        rendered = json.dumps(schema).casefold()
        self.assertNotIn('"password"', rendered)
        self.assertNotIn('"token"', rendered)
        self.assertNotIn('"secret"', rendered)

    def test_ssh_preview_migrates_in_memory_without_writing_or_leaking_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = json.dumps(
                {"version": 1, "defaults": {}, "profiles": {}},
                separators=(",", ":"),
            )
            path.write_text(original, encoding="utf-8")
            args = {
                "profile": "arm64",
                "kind": "ssh",
                "host": "arm64.example.internal",
                "user": "builder",
                "port": 22,
                "platform": "posix",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": False,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                try:
                    result = payload(profile_tools.setup(args))
                except core.ToolError as exc:
                    self.fail(f"profile setup preview failed: {exc}")

            self.assertEqual(path.read_text(encoding="utf-8"), original)

        self.assertTrue(result["ok"])
        self.assertTrue(result["preview"])
        self.assertEqual(result["profile"], "arm64")
        self.assertEqual(result["kind"], "ssh")
        self.assertEqual(result["credentialRef"], "arm64-key")
        self.assertEqual(result["credentialSource"], "ssh-agent")
        self.assertEqual(result["queueResource"], "lab:arm64")
        self.assertEqual(result["configurationVersionBefore"], 1)
        self.assertEqual(result["configurationVersionAfter"], 2)
        self.assertTrue(result["migrationRequired"])
        self.assertIn("configurationWriteRequired", result)
        self.assertIn("backupRequired", result)
        self.assertTrue(result["configurationWriteRequired"])
        self.assertTrue(result["backupRequired"])
        self.assertFalse(result["credentialPromptRequired"])
        self.assertEqual(result["nextStep"], "rerun-with-confirm-true")
        rendered = json.dumps(result)
        self.assertNotIn("arm64.example.internal", rendered)
        self.assertNotIn("builder", rendered)

    def test_confirmed_ssh_setup_atomically_writes_v2_and_keeps_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "defaults": {"rdp": "existing-rdp"},
                        "profiles": {
                            "existing-rdp": {
                                "kind": "rdp",
                                "host": "existing.example.internal",
                                "credential": {
                                    "source": "windows-credential-manager",
                                    "target": "TERMSRV/existing.example.internal",
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            args = {
                "profile": "arm64",
                "kind": "ssh",
                "host": "arm64.example.internal",
                "user": "builder",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        try:
                            result = payload(profile_tools.setup(args))
                        except core.ToolError as exc:
                            self.fail(f"confirmed profile setup failed: {exc}")
            stored = json.loads(path.read_text(encoding="utf-8"))
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )

        self.assertEqual(stored["version"], 2)
        self.assertEqual(stored["defaults"], {"rdp": "existing-rdp"})
        self.assertIn("existing-rdp", stored["profiles"])
        self.assertEqual(stored["profiles"]["arm64"]["credential_ref"], "arm64-key")
        self.assertEqual(stored["profiles"]["arm64"]["queue_resource"], "lab:arm64")
        self.assertEqual(stored["credentials"]["arm64-key"], {"source": "ssh-agent"})
        self.assertEqual(len(backups), 1)
        self.assertTrue(result["ok"])
        self.assertFalse(result["preview"])
        self.assertTrue(result["configurationStored"])
        self.assertTrue(result["backupCreated"])
        self.assertEqual(result["credentialPromptStatus"], "not-required")
        self.assertEqual(result["nextStep"], "run-remotex-ssh-host-key-status")
        rendered = json.dumps(result)
        self.assertNotIn("arm64.example.internal", rendered)
        self.assertNotIn("builder", rendered)

    def test_confirmed_rdp_setup_derives_target_and_opens_secure_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "credentials": {},
                        "defaults": {},
                        "profiles": {},
                    }
                ),
                encoding="utf-8",
            )
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
                "timeout_seconds": 120,
            }

            def launch(reference, *, timeout):
                self.assertEqual(
                    reference.reference_dict(),
                    {
                        "source": "windows-credential-manager",
                        "target": "TERMSRV/arm64.example.internal",
                    },
                )
                self.assertEqual(timeout, 120)
                return {
                    "status": "stored",
                    "existingBefore": False,
                    "referencePresent": True,
                    "targetSha256": "a" * 64,
                }

            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store,
                            "launch_secure_setup",
                            side_effect=launch,
                        ):
                            try:
                                result = payload(profile_tools.setup(args))
                            except core.ToolError as exc:
                                self.fail(f"confirmed RDP profile setup failed: {exc}")
            stored = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(
            stored["credentials"]["arm64-rdp"],
            {
                "source": "windows-credential-manager",
                "target": "TERMSRV/arm64.example.internal",
            },
        )
        self.assertEqual(stored["profiles"]["arm64-rdp"]["kind"], "rdp")
        self.assertEqual(
            stored["profiles"]["arm64-rdp"]["credential_ref"],
            "arm64-rdp",
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["credentialPromptStatus"], "stored")
        self.assertTrue(result["referencePresent"])
        self.assertFalse(result["rotated"])
        self.assertEqual(result["nextStep"], "run-remotex-rdp-test")
        rendered = json.dumps(result)
        self.assertNotIn("TERMSRV/arm64.example.internal", rendered)
        self.assertNotIn("arm64.example.internal", rendered)

    def test_cancelled_secure_prompt_rolls_back_config_and_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = b'{"version":2,"credentials":{},"defaults":{},"profiles":{}}'
            path.write_bytes(original)
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            lifecycle = {
                "status": "cancelled",
                "existingBefore": False,
                "referencePresent": False,
                "targetSha256": "a" * 64,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store,
                            "launch_secure_setup",
                            return_value=lifecycle,
                        ):
                            try:
                                result = payload(profile_tools.setup(args))
                            except core.ToolError as exc:
                                self.fail(f"cancelled profile setup failed: {exc}")
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )
            restored = path.read_bytes()

        self.assertEqual(restored, original)
        self.assertEqual(backups, [])
        self.assertFalse(result["ok"])
        self.assertTrue(result["cancelled"])
        self.assertFalse(result["configurationStored"])
        self.assertFalse(result["referencePresent"])
        self.assertEqual(result["credentialPromptStatus"], "cancelled")
        self.assertEqual(result["nextStep"], "credential-setup-cancelled")

    def test_secure_prompt_failure_rolls_back_before_reporting_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = b'{"version":2,"credentials":{},"defaults":{},"profiles":{}}'
            path.write_bytes(original)
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store,
                            "launch_secure_setup",
                            side_effect=core.ToolError("secure prompt failed"),
                        ):
                            with self.assertRaisesRegex(
                                core.ToolError,
                                "secure prompt failed",
                            ):
                                profile_tools.setup(args)
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )
            restored = path.read_bytes()

        self.assertEqual(restored, original)
        self.assertEqual(backups, [])

    def test_post_store_failure_removes_new_credential_before_config_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = b'{"version":2,"credentials":{},"defaults":{},"profiles":{}}'
            path.write_bytes(original)
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            credential_state = {"present": False}

            def credential_exists(target, credential_types=(1,)):
                return credential_state["present"]

            def launch(reference, *, timeout):
                credential_state["present"] = True
                raise core.ToolError("post-store receipt validation failed")

            def remove(reference):
                self.assertEqual(
                    reference.reference_dict()["target"],
                    "TERMSRV/arm64.example.internal",
                )
                credential_state["present"] = False
                return {
                    "removed": True,
                    "deletedRecordCount": 1,
                    "referencePresent": False,
                    "targetSha256": "e" * 64,
                }

            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store.windows_credentials,
                            "credential_exists",
                            side_effect=credential_exists,
                        ):
                            with mock.patch.object(
                                credential_store,
                                "launch_secure_setup",
                                side_effect=launch,
                            ):
                                with mock.patch.object(
                                    credential_store,
                                    "delete_windows_credential",
                                    side_effect=remove,
                                ):
                                    with self.assertRaisesRegex(
                                        core.ToolError,
                                        "post-store receipt validation failed",
                                    ):
                                        profile_tools.setup(args)
            restored = path.read_bytes()
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )

        self.assertFalse(credential_state["present"])
        self.assertEqual(restored, original)
        self.assertEqual(backups, [])

    def test_new_profile_reuses_existing_derived_target_without_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                '{"version":2,"credentials":{},"defaults":{},"profiles":{}}',
                encoding="utf-8",
            )
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store.windows_credentials,
                            "credential_exists",
                            return_value=True,
                        ):
                            with mock.patch.object(
                                credential_store,
                                "launch_secure_setup",
                                side_effect=AssertionError("rotation was attempted"),
                            ):
                                result = payload(profile_tools.setup(args))
            stored = json.loads(path.read_text(encoding="utf-8"))

        self.assertIn("arm64-rdp", stored["profiles"])
        self.assertIn("arm64-rdp", stored["credentials"])
        self.assertTrue(result["ok"])
        self.assertTrue(result["referencePresent"])
        self.assertFalse(result["rotated"])
        self.assertEqual(result["credentialPromptStatus"], "not-required")
        self.assertEqual(result["nextStep"], "run-remotex-rdp-test")

    def test_credential_cleanup_failure_still_rolls_back_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = b'{"version":2,"credentials":{},"defaults":{},"profiles":{}}'
            path.write_bytes(original)
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            credential_state = {"present": False}

            def credential_exists(target, credential_types=(1,)):
                return credential_state["present"]

            def launch(reference, *, timeout):
                credential_state["present"] = True
                raise core.ToolError("post-store receipt validation failed")

            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store.windows_credentials,
                            "credential_exists",
                            side_effect=credential_exists,
                        ):
                            with mock.patch.object(
                                credential_store,
                                "launch_secure_setup",
                                side_effect=launch,
                            ):
                                with mock.patch.object(
                                    credential_store,
                                    "delete_windows_credential",
                                    side_effect=core.ToolError("cleanup failed"),
                                ):
                                    with self.assertRaisesRegex(
                                        core.ToolError,
                                        "new credential could not be removed",
                                    ):
                                        profile_tools.setup(args)
            restored = path.read_bytes()

        self.assertEqual(restored, original)
        self.assertTrue(credential_state["present"])

    def test_cancel_cleanup_failure_still_rolls_back_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = b'{"version":2,"credentials":{},"defaults":{},"profiles":{}}'
            path.write_bytes(original)
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            lifecycle = {
                "status": "cancelled",
                "existingBefore": False,
                "referencePresent": True,
                "targetSha256": "f" * 64,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store.windows_credentials,
                            "credential_exists",
                            return_value=False,
                        ):
                            with mock.patch.object(
                                credential_store,
                                "launch_secure_setup",
                                return_value=lifecycle,
                            ):
                                with mock.patch.object(
                                    credential_store,
                                    "delete_windows_credential",
                                    side_effect=core.ToolError("cleanup failed"),
                                ):
                                    with self.assertRaisesRegex(
                                        core.ToolError,
                                        "new credential could not be removed",
                                    ):
                                        profile_tools.setup(args)
            restored = path.read_bytes()

        self.assertEqual(restored, original)

    def test_windows_guest_setup_requires_identity_and_uses_bounded_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "credentials": {},
                        "defaults": {},
                        "profiles": {},
                    }
                ),
                encoding="utf-8",
            )
            args = {
                "profile": "arm64-guest",
                "kind": "windows-guest",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-guest",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "vm_identity": "lab-arm64",
                "guest_machine_id": "ARM64-WIN",
                "staging_root": r"C:\RemoteX\Staging",
                "authentication": "kerberos",
                "confirm": True,
            }
            lifecycle = {
                "status": "stored",
                "existingBefore": False,
                "referencePresent": True,
                "targetSha256": "b" * 64,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store,
                            "launch_secure_setup",
                            return_value=lifecycle,
                        ):
                            try:
                                result = payload(profile_tools.setup(args))
                            except core.ToolError as exc:
                                self.fail(f"Windows guest profile setup failed: {exc}")
            stored = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(
            stored["credentials"]["arm64-guest"],
            {
                "source": "windows-credential-manager",
                "target": "RemoteX/arm64-guest",
            },
        )
        profile = stored["profiles"]["arm64-guest"]
        self.assertEqual(profile["kind"], "windows-guest")
        self.assertEqual(profile["port"], 5985)
        self.assertEqual(profile["transport"], "winrm")
        self.assertEqual(profile["authentication"], "kerberos")
        self.assertEqual(profile["vm_identity"], "lab-arm64")
        self.assertEqual(profile["guest_machine_id"], "arm64-win")
        self.assertEqual(profile["staging_root"], r"C:\RemoteX\Staging")
        self.assertEqual(result["nextStep"], "run-remotex-windows-guest-test")

    def test_vsphere_setup_keeps_tls_verification_and_vm_queue_template(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "credentials": {},
                        "defaults": {},
                        "profiles": {},
                    }
                ),
                encoding="utf-8",
            )
            args = {
                "profile": "arm64-esxi",
                "kind": "esxi",
                "url": "https://esxi.example.internal/sdk/",
                "credential_ref": "arm64-esxi",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64:{virtual_machine}",
                "ca_file": r"C:\RemoteX\esxi-ca.pem",
                "confirm": True,
            }
            lifecycle = {
                "status": "stored",
                "existingBefore": False,
                "referencePresent": True,
                "targetSha256": "c" * 64,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        with mock.patch.object(
                            credential_store,
                            "launch_secure_setup",
                            return_value=lifecycle,
                        ):
                            try:
                                result = payload(profile_tools.setup(args))
                            except core.ToolError as exc:
                                self.fail(f"vSphere profile setup failed: {exc}")
            stored = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(
            stored["credentials"]["arm64-esxi"],
            {
                "source": "windows-credential-manager",
                "target": "RemoteX/arm64-esxi",
            },
        )
        profile = stored["profiles"]["arm64-esxi"]
        self.assertEqual(profile["kind"], "vsphere")
        self.assertEqual(profile["url"], "https://esxi.example.internal/sdk")
        self.assertEqual(profile["queue_resource"], "lab:arm64:{virtual_machine}")
        self.assertEqual(
            profile["tls"],
            {"insecure": False, "ca_file": r"C:\RemoteX\esxi-ca.pem"},
        )
        self.assertEqual(result["nextStep"], "run-remotex-vsphere-about")

    def test_identical_confirmed_setup_is_idempotent_without_new_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "credentials": {},
                        "defaults": {},
                        "profiles": {},
                    }
                ),
                encoding="utf-8",
            )
            args = {
                "profile": "arm64",
                "kind": "ssh",
                "host": "arm64.example.internal",
                "user": "builder",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
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
                        first = payload(profile_tools.setup(args))
                        before = path.read_bytes()
                        try:
                            second = payload(profile_tools.setup(args))
                        except core.ToolError as exc:
                            self.fail(f"idempotent profile setup failed: {exc}")
                        after = path.read_bytes()
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )

        self.assertFalse(first["alreadyConfigured"])
        self.assertTrue(second["alreadyConfigured"])
        self.assertTrue(second["configurationStored"])
        self.assertFalse(second["backupCreated"])
        self.assertEqual(before, after)
        self.assertEqual(len(backups), 1)

    def test_existing_profile_with_different_configuration_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            existing = {
                "version": 2,
                "credentials": {"arm64-key": {"source": "ssh-agent"}},
                "defaults": {},
                "profiles": {
                    "arm64": {
                        "kind": "ssh",
                        "host": "old.example.internal",
                        "user": "builder",
                        "port": 22,
                        "platform": "posix",
                        "queue_resource": "lab:arm64",
                        "queue_lease_seconds": 14400,
                        "credential_ref": "arm64-key",
                        "known_hosts_file": "~/.ssh/known_hosts",
                        "strict_host_key_checking": "yes",
                        "host_key_policy": "managed",
                        "connect_timeout_seconds": 10,
                    }
                },
            }
            original = json.dumps(existing, separators=(",", ":")).encode("utf-8")
            path.write_bytes(original)
            args = {
                "profile": "arm64",
                "kind": "ssh",
                "host": "new.example.internal",
                "user": "builder",
                "platform": "posix",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": False,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "profile already exists with different configuration",
                ):
                    profile_tools.setup(args)
            after = path.read_bytes()

        self.assertEqual(after, original)

    def test_existing_credential_ref_with_different_configuration_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            existing = {
                "version": 2,
                "credentials": {
                    "arm64-key": {
                        "source": "identity-file",
                        "identity_file": "~/.ssh/existing_ed25519",
                    }
                },
                "defaults": {},
                "profiles": {},
            }
            original = json.dumps(existing, separators=(",", ":")).encode("utf-8")
            path.write_bytes(original)
            args = {
                "profile": "arm64-new",
                "kind": "ssh",
                "host": "new.example.internal",
                "user": "builder",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": False,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "credential_ref already exists with different configuration",
                ):
                    profile_tools.setup(args)
            after = path.read_bytes()

        self.assertEqual(after, original)

    def test_existing_ready_windows_credential_is_idempotent_without_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            config = {
                "version": 2,
                "credentials": {
                    "arm64-rdp": {
                        "source": "windows-credential-manager",
                        "target": "TERMSRV/arm64.example.internal",
                    }
                },
                "defaults": {},
                "profiles": {
                    "arm64-rdp": {
                        "kind": "rdp",
                        "host": "arm64.example.internal",
                        "port": 3389,
                        "queue_resource": "lab:arm64",
                        "queue_lease_seconds": 14400,
                        "credential_ref": "arm64-rdp",
                        "admin": False,
                        "fullscreen": False,
                    }
                },
            }
            original = json.dumps(config, separators=(",", ":")).encode("utf-8")
            path.write_bytes(original)
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                with mock.patch.object(
                    credential_store.windows_credentials,
                    "credential_exists",
                    return_value=True,
                ):
                    with mock.patch.object(
                        credential_store,
                        "launch_secure_setup",
                        side_effect=AssertionError("credential rotation was attempted"),
                    ):
                        try:
                            result = payload(profile_tools.setup(args))
                        except core.ToolError as exc:
                            self.fail(f"idempotent Windows profile setup failed: {exc}")
            after = path.read_bytes()

        self.assertEqual(after, original)
        self.assertTrue(result["alreadyConfigured"])
        self.assertTrue(result["referencePresent"])
        self.assertFalse(result["rotated"])
        self.assertEqual(result["credentialPromptStatus"], "not-required")
        self.assertEqual(result["nextStep"], "run-remotex-rdp-test")

    def test_existing_missing_windows_credential_opens_prompt_without_config_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            config = {
                "version": 2,
                "credentials": {
                    "arm64-rdp": {
                        "source": "windows-credential-manager",
                        "target": "TERMSRV/arm64.example.internal",
                    }
                },
                "defaults": {},
                "profiles": {
                    "arm64-rdp": {
                        "kind": "rdp",
                        "host": "arm64.example.internal",
                        "port": 3389,
                        "queue_resource": "lab:arm64",
                        "queue_lease_seconds": 14400,
                        "credential_ref": "arm64-rdp",
                        "admin": False,
                        "fullscreen": False,
                    }
                },
            }
            original = json.dumps(config, separators=(",", ":")).encode("utf-8")
            path.write_bytes(original)
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "arm64.example.internal",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": True,
                "timeout_seconds": 90,
            }
            lifecycle = {
                "status": "stored",
                "existingBefore": False,
                "referencePresent": True,
                "targetSha256": "d" * 64,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                with mock.patch.object(
                    credential_store.windows_credentials,
                    "credential_exists",
                    return_value=False,
                ):
                    with mock.patch.object(
                        credential_store,
                        "launch_secure_setup",
                        return_value=lifecycle,
                    ):
                        try:
                            result = payload(profile_tools.setup(args))
                        except core.ToolError as exc:
                            self.fail(f"existing missing credential setup failed: {exc}")
            after = path.read_bytes()
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )

        self.assertEqual(after, original)
        self.assertEqual(backups, [])
        self.assertTrue(result["alreadyConfigured"])
        self.assertFalse(result["backupCreated"])
        self.assertEqual(result["credentialPromptStatus"], "stored")
        self.assertTrue(result["referencePresent"])
        self.assertEqual(result["nextStep"], "run-remotex-rdp-test")

    def test_handler_rejects_fields_outside_the_public_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            original = b'{"version":2,"credentials":{},"defaults":{},"profiles":{}}'
            path.write_bytes(original)
            base = {
                "profile": "arm64",
                "kind": "ssh",
                "host": "arm64.example.internal",
                "user": "builder",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": False,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                for field, value in (
                    ("target", "RemoteX/arbitrary"),
                    ("password", "not-a-real-password"),
                ):
                    with self.subTest(field=field):
                        with self.assertRaisesRegex(
                            core.ToolError,
                            f"unknown profile setup field: {field}",
                        ):
                            profile_tools.setup({**base, field: value})
            after = path.read_bytes()

        self.assertEqual(after, original)

    def test_config_write_rejects_semantic_change_after_preview(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            expected = {
                "version": 2,
                "credentials": {},
                "defaults": {},
                "profiles": {},
            }
            changed = {
                "version": 2,
                "credentials": {"other": {"source": "ssh-agent"}},
                "defaults": {},
                "profiles": {
                    "other": {
                        "kind": "ssh",
                        "host": "other.example.internal",
                        "user": "builder",
                        "credential_ref": "other",
                    }
                },
            }
            candidate = {
                "version": 2,
                "credentials": {"arm64": {"source": "ssh-agent"}},
                "defaults": {},
                "profiles": {
                    "arm64": {
                        "kind": "ssh",
                        "host": "arm64.example.internal",
                        "user": "builder",
                        "credential_ref": "arm64",
                    }
                },
            }
            path.write_text(json.dumps(changed), encoding="utf-8")
            original = path.read_bytes()
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
                    with self.assertRaisesRegex(
                        core.ToolError,
                        "config changed before setup",
                    ):
                        config_store.write_config(
                            path,
                            candidate,
                            expected=expected,
                            expected_exists=True,
                        )
            after = path.read_bytes()
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )

        self.assertEqual(after, original)
        self.assertEqual(backups, [])

    def test_config_write_failure_restores_original_and_removes_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            expected = {
                "version": 2,
                "credentials": {},
                "defaults": {},
                "profiles": {},
            }
            candidate = {
                "version": 2,
                "credentials": {"arm64": {"source": "ssh-agent"}},
                "defaults": {},
                "profiles": {
                    "arm64": {
                        "kind": "ssh",
                        "host": "arm64.example.internal",
                        "user": "builder",
                        "credential_ref": "arm64",
                    }
                },
            }
            original = json.dumps(expected, separators=(",", ":")).encode("utf-8")
            path.write_bytes(original)
            raised = False

            def protect(candidate_path):
                nonlocal raised
                if Path(candidate_path) == path and not raised:
                    raised = True
                    raise OSError("simulated ACL failure")
                return {"ready": True}

            with mock.patch.object(
                secure_paths,
                "ensure_private_directory",
                return_value={"ready": True},
            ):
                with mock.patch.object(
                    secure_paths,
                    "ensure_private_file",
                    side_effect=protect,
                ):
                    with self.assertRaisesRegex(
                        core.ToolError,
                        "failed and was rolled back",
                    ):
                        config_store.write_config(
                            path,
                            candidate,
                            expected=expected,
                            expected_exists=True,
                        )
            restored = path.read_bytes()
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )

        self.assertEqual(restored, original)
        self.assertEqual(backups, [])

    def test_backup_protection_failure_leaves_no_partial_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            expected = {
                "version": 2,
                "credentials": {},
                "defaults": {},
                "profiles": {},
            }
            candidate = {
                "version": 2,
                "credentials": {"arm64": {"source": "ssh-agent"}},
                "defaults": {},
                "profiles": {
                    "arm64": {
                        "kind": "ssh",
                        "host": "arm64.example.internal",
                        "user": "builder",
                        "credential_ref": "arm64",
                    }
                },
            }
            original = json.dumps(expected, separators=(",", ":")).encode("utf-8")
            path.write_bytes(original)

            def protect(candidate_path):
                if ".profile-setup-backup-" in Path(candidate_path).name:
                    raise OSError("simulated backup ACL failure")
                return {"ready": True}

            with mock.patch.object(
                secure_paths,
                "ensure_private_directory",
                return_value={"ready": True},
            ):
                with mock.patch.object(
                    secure_paths,
                    "ensure_private_file",
                    side_effect=protect,
                ):
                    try:
                        with self.assertRaisesRegex(
                            core.ToolError,
                            "failed before replacement",
                        ):
                            config_store.write_config(
                                path,
                                candidate,
                                expected=expected,
                                expected_exists=True,
                            )
                    except OSError as exc:
                        self.fail(f"backup failure escaped without cleanup: {exc}")
            after = path.read_bytes()
            backups = list(
                Path(directory).glob("config.json.profile-setup-backup-*.json")
            )

        self.assertEqual(after, original)
        self.assertEqual(backups, [])

    def test_config_write_refuses_to_race_an_existing_writer_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            expected = {
                "version": 2,
                "credentials": {},
                "defaults": {},
                "profiles": {},
            }
            candidate = {
                "version": 2,
                "credentials": {"arm64": {"source": "ssh-agent"}},
                "defaults": {},
                "profiles": {
                    "arm64": {
                        "kind": "ssh",
                        "host": "arm64.example.internal",
                        "user": "builder",
                        "credential_ref": "arm64",
                    }
                },
            }
            original = json.dumps(expected, separators=(",", ":")).encode("utf-8")
            path.write_bytes(original)
            lock_path = path.with_name(f".{path.name}.profile-setup.lock")
            with mock.patch.object(vm_queue, "LOCK_TIMEOUT_SECONDS", 0.05):
                with vm_queue._exclusive_lock(lock_path, "RemoteX config"):
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
                            with self.assertRaisesRegex(
                                core.ToolError,
                                "RemoteX config lock.*stayed busy",
                            ):
                                config_store.write_config(
                                    path,
                                    candidate,
                                    expected=expected,
                                    expected_exists=True,
                                )
            after = path.read_bytes()

        self.assertEqual(after, original)

    def test_kind_specific_fields_are_not_silently_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                '{"version":2,"credentials":{},"defaults":{},"profiles":{}}',
                encoding="utf-8",
            )
            args = {
                "profile": "arm64",
                "kind": "ssh",
                "host": "arm64.example.internal",
                "url": "https://ignored.example.internal/sdk",
                "user": "builder",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": False,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "field url is not valid for kind ssh",
                ):
                    profile_tools.setup(args)

    def test_known_fields_reject_embedded_credential_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                '{"version":2,"credentials":{},"defaults":{},"profiles":{}}',
                encoding="utf-8",
            )
            args = {
                "profile": "arm64",
                "kind": "ssh",
                "host": "password=not-a-real-password",
                "user": "builder",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": False,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "host appears to contain credential material",
                ) as raised:
                    profile_tools.setup(args)

        self.assertNotIn("not-a-real-password", str(raised.exception))

    def test_profile_and_alias_names_are_not_silently_trimmed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                '{"version":2,"credentials":{},"defaults":{},"profiles":{}}',
                encoding="utf-8",
            )
            args = {
                "profile": " arm64",
                "kind": "ssh",
                "host": "arm64.example.internal",
                "user": "builder",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": False,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "profile must use",
                ):
                    profile_tools.setup(args)

    def test_host_cannot_embed_user_information_or_path_delimiters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                '{"version":2,"credentials":{},"defaults":{},"profiles":{}}',
                encoding="utf-8",
            )
            args = {
                "profile": "arm64-rdp",
                "kind": "rdp",
                "host": "operator:credential@arm64.example.internal/path",
                "credential_ref": "arm64-rdp",
                "credential_source": "windows-credential-manager",
                "queue_resource": "lab:arm64",
                "confirm": False,
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_CONFIG": str(path)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    core.ToolError,
                    "host must be only a hostname or address",
                ) as raised:
                    profile_tools.setup(args)

        self.assertNotIn("credential", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
