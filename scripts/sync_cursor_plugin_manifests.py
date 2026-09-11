#!/usr/bin/env python3
"""Derive Cursor plugin manifests from the existing Codex marketplace.

Codex keeps using `.agents/plugins/marketplace.json` and each plugin's
`.codex-plugin/plugin.json`. Cursor reads `.cursor-plugin/marketplace.json`
and each plugin's `.cursor-plugin/plugin.json`. Skills and local credential
files stay shared. Cursor discovers `mcp.json`; Codex keeps `.mcp.json`.
The generator mirrors `.mcp.json` to `mcp.json` so both hosts load the same
stdio launcher.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CODEX_MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
CURSOR_MARKETPLACE = ROOT / ".cursor-plugin" / "marketplace.json"
REPO_URL = "https://github.com/YSheldon/ai-productivity-plugins"


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"expected JSON object: {path}")
    return payload


def dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8", newline="\n")


def plugin_is_available(entry: dict[str, Any]) -> bool:
    policy = entry.get("policy")
    if not isinstance(policy, dict):
        return False
    return policy.get("installation") == "AVAILABLE"


def relative_asset(path: str) -> str:
    return path[2:] if path.startswith("./") else path


def cursor_plugin_manifest(codex: dict[str, Any], plugin_name: str) -> dict[str, Any]:
    interface = codex.get("interface")
    if not isinstance(interface, dict):
        interface = {}
    author = codex.get("author")
    author_name = "Sheldon"
    if isinstance(author, dict) and isinstance(author.get("name"), str) and author["name"]:
        author_name = author["name"]

    manifest: dict[str, Any] = {
        "name": plugin_name,
        "displayName": interface.get("displayName") or plugin_name,
        "version": codex["version"],
        "description": codex["description"],
        "author": {"name": author_name},
        "homepage": f"{REPO_URL}/tree/main/plugins/{plugin_name}",
        "repository": REPO_URL,
        "license": codex.get("license") or "MIT",
        "keywords": list(codex.get("keywords") or []),
        "category": interface.get("category") or "Developer Tools",
    }
    logo = interface.get("logo")
    if isinstance(logo, str) and logo:
        manifest["logo"] = relative_asset(logo)
    skills = codex.get("skills")
    if isinstance(skills, str) and skills:
        manifest["skills"] = skills
    mcp_servers = codex.get("mcpServers")
    if isinstance(mcp_servers, str) and mcp_servers:
        manifest["mcpServers"] = cursor_mcp_path(mcp_servers)
    return manifest


def cursor_mcp_path(codex_mcp_servers: str) -> str:
    if codex_mcp_servers in {"./.mcp.json", ".mcp.json"}:
        return "./mcp.json"
    return relative_asset(codex_mcp_servers)


def mirror_codex_mcp(plugin_root: Path) -> Path | None:
    source = plugin_root / ".mcp.json"
    if not source.is_file():
        return None
    dest = plugin_root / "mcp.json"
    dest.write_bytes(source.read_bytes())
    return dest


def cursor_marketplace_entry(
    plugin_name: str, cursor_manifest: dict[str, Any]
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": plugin_name,
        "source": plugin_name,
        "description": cursor_manifest["description"],
        "version": cursor_manifest["version"],
        "category": cursor_manifest["category"],
        "homepage": cursor_manifest["homepage"],
        "keywords": list(cursor_manifest.get("keywords") or []),
    }
    logo = cursor_manifest.get("logo")
    if isinstance(logo, str) and logo:
        entry["logo"] = logo
    return entry


def available_codex_plugins() -> list[dict[str, Any]]:
    marketplace = load_json(CODEX_MARKETPLACE)
    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list):
        raise TypeError("Codex marketplace plugins must be a list")
    available: list[dict[str, Any]] = []
    for item in plugins:
        if isinstance(item, dict) and plugin_is_available(item):
            available.append(item)
    return available


def build_cursor_marketplace(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": "ai-productivity-plugins",
        "owner": {"name": "Sheldon"},
        "metadata": {
            "description": (
                "Sheldon productivity plugins. Codex keeps using "
                ".agents/plugins/marketplace.json; Cursor reads this index."
            ),
            "pluginRoot": "plugins",
        },
        "plugins": entries,
    }


def sync(root: Path = ROOT) -> dict[str, Path]:
    written: dict[str, Path] = {}
    marketplace_entries: list[dict[str, Any]] = []
    for item in available_codex_plugins():
        name = str(item["name"])
        plugin_root = root / "plugins" / name
        codex_manifest = load_json(plugin_root / ".codex-plugin" / "plugin.json")
        if codex_manifest.get("name") != name:
            raise ValueError(f"{name} Codex manifest name mismatch")
        cursor_manifest = cursor_plugin_manifest(codex_manifest, name)
        cursor_path = plugin_root / ".cursor-plugin" / "plugin.json"
        dump_json(cursor_path, cursor_manifest)
        written[name] = cursor_path
        mcp_path = mirror_codex_mcp(plugin_root)
        if mcp_path is not None:
            written[f"{name}-mcp"] = mcp_path
        marketplace_entries.append(cursor_marketplace_entry(name, cursor_manifest))

    marketplace_path = root / ".cursor-plugin" / "marketplace.json"
    dump_json(marketplace_path, build_cursor_marketplace(marketplace_entries))
    written["marketplace"] = marketplace_path
    return written


def main() -> int:
    written = sync()
    for name, path in written.items():
        print(f"{name}: {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
