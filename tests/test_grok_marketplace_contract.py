from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CODEX_MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
GROK_MARKETPLACE = ROOT / ".grok-plugin" / "marketplace.json"
GROK_PLUGIN_NAMES = ("gitlab", "remotex", "imap-smtp-mail")


def test_codex_marketplace_index_is_unchanged_for_shared_plugins() -> None:
    marketplace = json.loads(CODEX_MARKETPLACE.read_text(encoding="utf-8"))
    names = [item["name"] for item in marketplace["plugins"]]
    for name in GROK_PLUGIN_NAMES:
        assert name in names
    entries = {item["name"]: item for item in marketplace["plugins"]}
    for name in GROK_PLUGIN_NAMES:
        source = entries[name]["source"]
        assert source == {"source": "local", "path": f"./plugins/{name}"}


def test_grok_marketplace_lists_only_shared_plugin_directories() -> None:
    marketplace = json.loads(GROK_MARKETPLACE.read_text(encoding="utf-8"))
    names = [item["name"] for item in marketplace["plugins"]]
    assert tuple(names) == GROK_PLUGIN_NAMES
    for item in marketplace["plugins"]:
        assert item["source"] == {"type": "local", "path": f"./plugins/{item['name']}"}
        plugin_root = ROOT / "plugins" / item["name"]
        assert plugin_root.is_dir()
        assert (plugin_root / ".mcp.json").is_file()
        assert (plugin_root / "skills").is_dir()
        mcp = json.loads((plugin_root / ".mcp.json").read_text(encoding="utf-8"))
        server = mcp["mcpServers"][item["name"]]
        assert server["command"] == "node"
        assert server["cwd"] == "."
        args = server["args"]
        assert isinstance(args, list) and len(args) == 1
        assert str(args[0]).startswith("./scripts/")
        assert str(args[0]).endswith((".js", ".mjs"))
        assert (plugin_root / args[0]).is_file()
