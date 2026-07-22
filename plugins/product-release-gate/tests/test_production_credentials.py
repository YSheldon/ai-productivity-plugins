from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
