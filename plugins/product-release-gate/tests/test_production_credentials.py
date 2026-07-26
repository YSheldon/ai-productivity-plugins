from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from provision_windows_credentials import (
    ProvisioningError,
    credential_status,
    main,
    provision_credentials,
)
from release_gate_credentials import (
    DEFAULT_AUDIT_CREDENTIAL_TARGET,
    DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET,
    resolve_configured_secret,
)


class FakeCredentialStore:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.writes: list[str] = []

    def read(self, target: str) -> str | None:
        return self.values.get(target)

    def write(self, target: str, value: str) -> None:
        self.values[target] = value
        self.writes.append(target)


class ProductionCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "config.json"
        self.config_path.write_text(
            json.dumps(
                {
                    "production": {
                        "enabled": False,
                        "authorization": {
                            "key_env": "TEST_RELEASE_AUTH_KEY",
                        },
                        "audit": {
                            "key_env": "TEST_RELEASE_AUDIT_KEY",
                        },
                    }
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self.store = FakeCredentialStore()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_environment_value_precedes_credential_manager(self) -> None:
        self.store.values[DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET] = (
            "credential-manager-secret-that-must-not-win"
        )
        value, source = resolve_configured_secret(
            {
                "key_env": "TEST_RELEASE_AUTH_KEY",
                "credential_target": DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET,
            },
            environ={"TEST_RELEASE_AUTH_KEY": "environment-secret-value"},
            credential_reader=self.store.read,
        )

        self.assertEqual("environment-secret-value", value)
        self.assertEqual("environment", source)

    def test_init_creates_distinct_credentials_without_returning_values(self) -> None:
        result = provision_credentials(self.config_path, store=self.store)

        self.assertTrue(result["ready"])
        self.assertEqual(2, result["credentials_created"])
        self.assertFalse(result["credential_values_printed"])
        self.assertTrue(result["runtime_identity_required"])
        self.assertTrue(result["runtime_identity_bound"])
        self.assertTrue(result["runtime_identity_matches"])
        self.assertFalse(result["principal_values_returned"])
        self.assertEqual(
            {
                DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET,
                DEFAULT_AUDIT_CREDENTIAL_TARGET,
            },
            set(self.store.writes),
        )
        authorization = self.store.values[
            DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET
        ]
        audit = self.store.values[DEFAULT_AUDIT_CREDENTIAL_TARGET]
        self.assertGreaterEqual(len(authorization.encode("utf-8")), 32)
        self.assertGreaterEqual(len(audit.encode("utf-8")), 32)
        self.assertNotEqual(authorization, audit)

        serialized = self.config_path.read_text(encoding="utf-8")
        self.assertNotIn(authorization, serialized)
        self.assertNotIn(audit, serialized)
        config = json.loads(serialized)
        self.assertEqual(
            DEFAULT_AUTHORIZATION_CREDENTIAL_TARGET,
            config["production"]["authorization"]["credential_target"],
        )
        self.assertEqual(
            DEFAULT_AUDIT_CREDENTIAL_TARGET,
            config["production"]["audit"]["credential_target"],
        )
        binding = config["runtime"]["identity_binding"]
        self.assertTrue(binding["required"])
        self.assertEqual(64, len(binding["principal_sha256"]))

    def test_repeated_init_reuses_credentials_without_rotation(self) -> None:
        first = provision_credentials(self.config_path, store=self.store)
        before = dict(self.store.values)
        second = provision_credentials(self.config_path, store=self.store)

        self.assertEqual(2, first["credentials_created"])
        self.assertEqual(0, second["credentials_created"])
        self.assertEqual(2, second["credentials_reused"])
        self.assertEqual(before, self.store.values)

    def test_status_rejects_equal_credentials(self) -> None:
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["production"]["authorization"]["credential_target"] = "auth"
        config["production"]["audit"]["credential_target"] = "audit"
        self.config_path.write_text(
            json.dumps(config, indent=2) + "\n",
            encoding="utf-8",
        )
        self.store.values = {
            "auth": "same-secret-value-that-is-long-enough-0001",
            "audit": "same-secret-value-that-is-long-enough-0001",
        }

        result = credential_status(self.config_path, store=self.store)

        self.assertFalse(result["ready"])
        self.assertFalse(result["credentials_distinct"])
        self.assertFalse(result["secret_values_returned"])

    def test_init_rejects_duplicate_credential_targets(self) -> None:
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["production"]["authorization"]["credential_target"] = "same"
        config["production"]["audit"]["credential_target"] = "same"
        self.config_path.write_text(
            json.dumps(config, indent=2) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ProvisioningError):
            provision_credentials(self.config_path, store=self.store)

    def test_init_rejects_invalid_environment_name(self) -> None:
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["production"]["authorization"]["key_env"] = "INVALID-NAME"
        self.config_path.write_text(
            json.dumps(config, indent=2) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ProvisioningError):
            provision_credentials(self.config_path, store=self.store)

    def test_init_rejects_empty_credential_target(self) -> None:
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["production"]["audit"]["credential_target"] = " "
        self.config_path.write_text(
            json.dumps(config, indent=2) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ProvisioningError):
            provision_credentials(self.config_path, store=self.store)

    def test_init_binds_principal_hash_and_rejects_rebind(self) -> None:
        principal_a = "windows-sid:S-1-5-21-test-runtime-a"
        principal_b = "windows-sid:S-1-5-21-test-runtime-b"
        first = provision_credentials(
            self.config_path,
            store=self.store,
            principal_provider=lambda: principal_a,
        )
        before_values = dict(self.store.values)
        before_writes = list(self.store.writes)
        before_config = self.config_path.read_text(encoding="utf-8")
        binding = json.loads(before_config)["runtime"]["identity_binding"]

        self.assertTrue(first["ready"])
        self.assertTrue(binding["required"])
        self.assertEqual(64, len(binding["principal_sha256"]))
        self.assertNotIn(principal_a, before_config)
        with self.assertRaisesRegex(
            ProvisioningError,
            "current runtime identity differs from the configured binding",
        ):
            provision_credentials(
                self.config_path,
                store=self.store,
                principal_provider=lambda: principal_b,
            )

        self.assertEqual(before_values, self.store.values)
        self.assertEqual(before_writes, self.store.writes)
        self.assertEqual(
            before_config,
            self.config_path.read_text(encoding="utf-8"),
        )

    def test_explicit_rebind_updates_only_the_principal_hash(self) -> None:
        principal_a = "windows-sid:S-1-5-21-test-runtime-a"
        principal_b = "windows-sid:S-1-5-21-test-runtime-b"
        provision_credentials(
            self.config_path,
            store=self.store,
            principal_provider=lambda: principal_a,
        )
        before_values = dict(self.store.values)
        before_writes = list(self.store.writes)
        before_config = json.loads(
            self.config_path.read_text(encoding="utf-8")
        )

        result = provision_credentials(
            self.config_path,
            store=self.store,
            principal_provider=lambda: principal_b,
            allow_identity_rebind=True,
        )
        serialized = self.config_path.read_text(encoding="utf-8")
        after_config = json.loads(serialized)

        self.assertTrue(result["ready"])
        self.assertTrue(result["runtime_identity_rebound"])
        self.assertTrue(result["runtime_identity_rebind_authorized"])
        self.assertTrue(result["runtime_identity_matches"])
        self.assertEqual(before_values, self.store.values)
        self.assertEqual(before_writes, self.store.writes)
        self.assertNotEqual(
            before_config["runtime"]["identity_binding"]["principal_sha256"],
            after_config["runtime"]["identity_binding"]["principal_sha256"],
        )
        self.assertNotIn(principal_a, serialized)
        self.assertNotIn(principal_b, serialized)

    def test_status_fails_closed_for_runtime_identity_mismatch(self) -> None:
        principal_a = "windows-sid:S-1-5-21-test-runtime-a"
        principal_b = "windows-sid:S-1-5-21-test-runtime-b"
        provision_credentials(
            self.config_path,
            store=self.store,
            principal_provider=lambda: principal_a,
        )

        result = credential_status(
            self.config_path,
            store=self.store,
            principal_provider=lambda: principal_b,
        )

        self.assertFalse(result["ready"])
        self.assertEqual("CAPABILITY_BLOCKED", result["status"])
        self.assertTrue(result["runtime_identity_required"])
        self.assertTrue(result["runtime_identity_bound"])
        self.assertFalse(result["runtime_identity_matches"])
        self.assertFalse(result["principal_values_returned"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(principal_a, serialized)
        self.assertNotIn(principal_b, serialized)

    def test_rebind_cli_requires_explicit_confirmation(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                ["--config", str(self.config_path), "rebind"]
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(3, exit_code)
        self.assertEqual("CAPABILITY_BLOCKED", payload["status"])
        self.assertIn(
            "--confirm-runtime-identity-rebind",
            payload["error"],
        )
        self.assertFalse(payload["secret_values_returned"])
        self.assertFalse(payload["principal_values_returned"])

    def test_rebind_confirmation_is_rejected_for_other_actions(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "--config",
                    str(self.config_path),
                    "status",
                    "--confirm-runtime-identity-rebind",
                ]
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(3, exit_code)
        self.assertIn("valid only with rebind", payload["error"])


if __name__ == "__main__":
    unittest.main()
