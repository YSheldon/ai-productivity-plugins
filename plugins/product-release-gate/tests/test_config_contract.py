from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_production import ProductionReleaseController


class ConfigContractTests(unittest.TestCase):
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
            with tempfile.TemporaryDirectory() as temporary:
                config["storage_dir"] = str(Path(temporary) / "events")
                config["signature"]["expected_thumbprints"] = ["A" * 40]
                config["production"]["enabled"] = True
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
