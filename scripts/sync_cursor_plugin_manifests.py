#!/usr/bin/env python3
"""Derive Cursor plugin manifests from the existing Codex marketplace.

Codex keeps using `.agents/plugins/marketplace.json` and each plugin's
`.codex-plugin/plugin.json`. Cursor reads `.cursor-plugin/marketplace.json`
and each plugin's `.cursor-plugin/plugin.json`. Skills and local credential
files stay shared. Codex MCP stays in `.mcp.json` with relative `./` paths.
Cursor `mcp.json` launches through `C:\\Windows\\System32\\cmd.exe` and
`scripts/launch_cursor_mcp.cmd` because Cursor plugin MCP spawn often has an
empty PATH (so `node`, `python3`, and even `cmd.exe` fail with ENOENT), and its
cwd is the Cursor install directory rather than the plugin root.
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


CURSOR_MCP_LAUNCHER = "launch_cursor_mcp.cmd"
CURSOR_MCP_COMMAND = r"C:\Windows\System32\cmd.exe"


def cursor_mcp_launcher_name(server_name: str, server_count: int) -> str:
    if server_count == 1:
        return CURSOR_MCP_LAUNCHER
    return f"launch_cursor_mcp_{server_name}.cmd"


def windows_launch_tokens(command: str) -> list[str]:
    if command in {"python3", "python"}:
        return ["py", "-3"]
    return [command]


def cmd_escape_arg(arg: str) -> str:
    if arg.startswith("./") or arg.startswith(".\\"):
        rel = arg[2:].replace("/", "\\")
        return f'"%ROOT%\\{rel}"'
    if not arg or any(ch in arg for ch in ' \t&|^<>()'):
        return '"' + arg.replace('"', '""') + '"'
    return arg


def render_cursor_mcp_launcher(command: str, args: list[Any]) -> str:
    tokens = [*windows_launch_tokens(command), *(cmd_escape_arg(str(arg)) for arg in args)]
    launch = " ".join(tokens)
    return (
        "@echo off\n"
        "setlocal EnableExtensions\n"
        'set "ROOT=%~dp0.."\n'
        'for %%I in ("%ROOT%") do set "ROOT=%%~fI"\n'
        'cd /d "%ROOT%" || (\n'
        "  echo Failed to enter plugin root 1>&2\n"
        "  exit /b 1\n"
        ")\n"
        'set "PATH=%SystemRoot%\\System32;%SystemRoot%;'
        "%SystemRoot%\\System32\\Wbem;"
        "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0;"
        "%ProgramFiles%\\nodejs;"
        "%ProgramFiles(x86)%\\nodejs;"
        "%LocalAppData%\\Programs\\nodejs;"
        '%LocalAppData%\\Programs\\Python\\Launcher;%PATH%"\n'
        f"{launch}\n"
    )


def cursor_mcp_config(codex_mcp: dict[str, Any]) -> dict[str, Any]:
    servers_in = codex_mcp.get("mcpServers")
    if not isinstance(servers_in, dict):
        raise TypeError("Codex MCP config must contain mcpServers")
    server_count = len(servers_in)
    servers: dict[str, Any] = {}
    for name, server in servers_in.items():
        if not isinstance(server, dict):
            raise TypeError(f"MCP server {name} must be an object")
        launcher = cursor_mcp_launcher_name(name, server_count)
        servers[name] = {
            "command": CURSOR_MCP_COMMAND,
            "args": ["/d", "/c", f"${{PLUGIN_ROOT}}/scripts/{launcher}"],
            "cwd": "${PLUGIN_ROOT}",
        }
    return {"mcpServers": servers}


def write_cursor_mcp(plugin_root: Path) -> Path | None:
    source = plugin_root / ".mcp.json"
    if not source.is_file():
        return None
    codex_mcp = load_json(source)
    dest = plugin_root / "mcp.json"
    dump_json(dest, cursor_mcp_config(codex_mcp))
    servers_in = codex_mcp.get("mcpServers")
    if not isinstance(servers_in, dict):
        raise TypeError("Codex MCP config must contain mcpServers")
    scripts = plugin_root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    server_count = len(servers_in)
    for name, server in servers_in.items():
        if not isinstance(server, dict):
            raise TypeError(f"MCP server {name} must be an object")
        command = server.get("command")
        if not isinstance(command, str) or not command:
            raise TypeError(f"MCP server {name} must define a command")
        raw_args = server.get("args") or []
        if not isinstance(raw_args, list):
            raise TypeError(f"MCP server {name} args must be a list")
        launcher = scripts / cursor_mcp_launcher_name(name, server_count)
        launcher.write_text(
            render_cursor_mcp_launcher(command, raw_args),
            encoding="utf-8",
            newline="\n",
        )
    return dest


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
        mcp_path = write_cursor_mcp(plugin_root)
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
