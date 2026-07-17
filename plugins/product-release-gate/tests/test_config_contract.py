from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_core import default_config
from release_gate_production import ProductionReleaseController


class ConfigContractTests(unittest.TestCase):
    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_example_deployment_binding(
        self, root: Path
    ) -> tuple[dict[str, object], list[str]]:
        adapter = root / "deployment_adapter.py"
        adapter.write_text("print('{}')\n", encoding="utf-8")

        def command(action: str) -> list[str]:
            values = [
                sys.executable,
                str(adapter),
                action,
                "{stage}",
                "{manifest_r_digest}",
            ]
            if action in {"deploy", "verify", "readback"}:
                values.append("{target_ref}")
            elif action == "rollback":
                values.extend(["{deployment_ref}", "{rollback_ref}", "{target_ref}"])
            elif action == "rollback_verify":
                values.extend(
                    [
                        "{deployment_ref}",
                        "{rollback_ref}",
                        "{restored_ref}",
                        "{rollback_receipt_ref}",
                        "{target_ref}",
                    ]
                )
            return values

        commands = {
            "deploy": command("deploy"),
            "verify": command("verify"),
            "rollback": command("rollback"),
            "rollback_verify": command("rollback_verify"),
            "readback": command("readback"),
        }
        lock_path = root / "deployment-adapter.lock.json"
        lock_payload = {
            "schema_version": 1,
            "root": ".",
            "commands": {
                command_id: {
                    "argv_template": argv,
                    "entrypoints": [
                        {
                            "argv_index": 0,
                            "path": sys.executable,
                            "sha256": self._sha256(Path(sys.executable)),
                        },
                        {
                            "argv_index": 1,
                            "path": adapter.name,
                            "sha256": self._sha256(adapter),
                        },
                    ],
                }
                for command_id, argv in commands.items()
            },
        }
        lock_path.write_text(json.dumps(lock_payload, sort_keys=True), encoding="utf-8")
        return (
            {
                "dependency_lock": str(lock_path),
                "dependency_lock_sha256": self._sha256(lock_path),
                "deploy_command": commands["deploy"],
                "verify_command": commands["verify"],
                "rollback_command": commands["rollback"],
                "rollback_verify_command": commands["rollback_verify"],
            },
            commands["readback"],
        )

    def test_default_configuration_preserves_legacy_authorization_mode(self) -> None:
        config = default_config()

        self.assertEqual(
            "legacy_external",
            config["production"]["approval_workflow"]["mode"],
        )
        self.assertEqual(60, config["runtime"]["poll_minutes"])

    def test_example_config_matches_runtime_preflight_contract(self) -> None:
        previous_auth = os.environ.get("PRODUCT_RELEASE_GATE_AUTH_KEY")
        previous_audit = os.environ.get("PRODUCT_RELEASE_GATE_AUDIT_KEY")
        try:
            os.environ["PRODUCT_RELEASE_GATE_AUTH_KEY"] = (
                "example-authorization-key-32-bytes-minimum"
            )
            os.environ["PRODUCT_RELEASE_GATE_AUDIT_KEY"] = (
                "example-audit-ledger-key-32-bytes-minimum"
            )
            config = json.loads(
                (PLUGIN_ROOT / "config" / "config.example.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                "legacy_external",
                config["production"]["approval_workflow"]["mode"],
            )
            self.assertIn(
                "dependency_lock",
                config["production"]["deployment"],
            )
            self.assertIn(
                "dependency_lock_sha256",
                config["production"]["deployment"],
            )
            with tempfile.TemporaryDirectory() as temporary:
                config["storage_dir"] = str(Path(temporary) / "events")
                config["signature"]["expected_thumbprints"] = ["A" * 40]
                config["production"]["enabled"] = True
                deployment_binding, readback_command = self._write_example_deployment_binding(
                    Path(temporary)
                )
                config["production"]["deployment"].update(deployment_binding)
                config["production"]["readback"]["command"] = readback_command
                path = Path(temporary) / "config.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                controller = ProductionReleaseController(str(path))

                core = controller.preflight()
                production = controller.production_preflight()

            if os.name == "nt":
                self.assertTrue(core["ready"], core)
            else:
                self.assertEqual(
                    ["signature_verifier"],
                    core["missing_required_integrations"],
                )
            self.assertTrue(production["ready"], production)
        finally:
            if previous_auth is None:
                os.environ.pop("PRODUCT_RELEASE_GATE_AUTH_KEY", None)
            else:
                os.environ["PRODUCT_RELEASE_GATE_AUTH_KEY"] = previous_auth
            if previous_audit is None:
                os.environ.pop("PRODUCT_RELEASE_GATE_AUDIT_KEY", None)
            else:
                os.environ["PRODUCT_RELEASE_GATE_AUDIT_KEY"] = previous_audit


if __name__ == "__main__":
    unittest.main()
