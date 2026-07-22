from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(SRC))

import remotex_mcp


class PluginContractTests(unittest.TestCase):
    def test_manifest_marketplace_and_server_versions_match(self) -> None:
        manifest = json.loads(
            (PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        marketplace = json.loads(
            (REPO_ROOT / ".agents" / "plugins" / "marketplace.json").read_text(
                encoding="utf-8"
            )
        )
        remotex_entry = next(item for item in marketplace["plugins"] if item["name"] == "remotex")
        legacy_entry = next(item for item in marketplace["plugins"] if item["name"] == "ssh")
        self.assertEqual(manifest["name"], "remotex")
        self.assertEqual(manifest["version"], remotex_mcp.SERVER_VERSION)
        self.assertEqual(remotex_entry["source"]["path"], "./plugins/remotex")
        self.assertEqual(remotex_entry["policy"]["installation"], "AVAILABLE")
        self.assertEqual(remotex_entry["policy"]["authentication"], "ON_USE")
        self.assertEqual(legacy_entry["policy"]["installation"], "NOT_AVAILABLE")

    def test_example_config_contains_references_not_literal_secrets(self) -> None:
        config = json.loads(
            (PLUGIN_ROOT / "config" / "config.example.json").read_text(encoding="utf-8")
        )
        serialized = json.dumps(config).lower()
        for forbidden in ('"password":', '"secret":', '"token":', '"private_key":'):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(config["version"], 1)
        self.assertEqual(
            {profile["kind"] for profile in config["profiles"].values()},
            {"ssh", "rdp", "esxi", "vmware-workstation"},
        )

    def test_declared_plugin_assets_exist(self) -> None:
        manifest = json.loads(
            (PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        self.assertTrue((PLUGIN_ROOT / manifest["mcpServers"]).is_file())
        self.assertTrue((PLUGIN_ROOT / manifest["interface"]["composerIcon"]).is_file())
        self.assertTrue((PLUGIN_ROOT / "skills" / "remotex" / "SKILL.md").is_file())

    def test_mcp_uses_cross_platform_launcher(self) -> None:
        mcp = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
        server = mcp["mcpServers"]["remotex"]
        self.assertEqual(server["command"], "node")
        self.assertEqual(server["args"], ["./scripts/launch_remotex.mjs"])
        self.assertTrue((PLUGIN_ROOT / "scripts" / "launch_remotex.mjs").is_file())


if __name__ == "__main__":
    unittest.main()
