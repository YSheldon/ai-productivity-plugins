from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import sync_cursor_plugin_manifests as cursor_sync  # noqa: E402


CODEX_MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
CURSOR_MARKETPLACE = ROOT / ".cursor-plugin" / "marketplace.json"
GROK_MARKETPLACE = ROOT / ".grok-plugin" / "marketplace.json"


def _load(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), f"expected JSON object: {path}"
    return payload


def test_cursor_marketplace_tracks_available_codex_plugins_without_ssh() -> None:
    marketplace = _load(CURSOR_MARKETPLACE)
    assert marketplace["name"] == "ai-productivity-plugins"
    assert marketplace["owner"] == {"name": "Sheldon"}
    metadata = marketplace["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["pluginRoot"] == "plugins"

    cursor_names = [item["name"] for item in marketplace["plugins"]]
    expected = [item["name"] for item in cursor_sync.available_codex_plugins()]
    assert cursor_names == expected
    assert "ssh" not in cursor_names
    assert "remotex" in cursor_names
    assert "gitlab" in cursor_names

    generated = cursor_sync.build_cursor_marketplace(
        [
            cursor_sync.cursor_marketplace_entry(
                item["name"],
                cursor_sync.cursor_plugin_manifest(
                    cursor_sync.load_json(
                        ROOT / "plugins" / item["name"] / ".codex-plugin" / "plugin.json"
                    ),
                    item["name"],
                ),
            )
            for item in cursor_sync.available_codex_plugins()
        ]
    )
    assert marketplace == generated


def test_cursor_plugin_manifests_reuse_codex_skills_and_mcp() -> None:
    for item in cursor_sync.available_codex_plugins():
        name = item["name"]
        plugin_root = ROOT / "plugins" / name
        codex = cursor_sync.load_json(plugin_root / ".codex-plugin" / "plugin.json")
        cursor = cursor_sync.load_json(plugin_root / ".cursor-plugin" / "plugin.json")
        expected = cursor_sync.cursor_plugin_manifest(codex, name)
        assert cursor == expected
        assert cursor["name"] == name
        assert cursor["version"] == codex["version"]
        assert cursor["skills"] == "./skills/"
        assert (plugin_root / "skills").is_dir()
        logo = cursor.get("logo")
        if isinstance(logo, str):
            assert (plugin_root / logo).is_file()
        mcp = cursor.get("mcpServers")
        if isinstance(mcp, str):
            assert mcp == "./mcp.json"
            assert (plugin_root / ".mcp.json").is_file()
            assert (plugin_root / "mcp.json").is_file()
            cursor_mcp = cursor_sync.load_json(plugin_root / "mcp.json")
            expected_mcp = cursor_sync.cursor_mcp_config(
                cursor_sync.load_json(plugin_root / ".mcp.json")
            )
            assert cursor_mcp == expected_mcp
            serialized = json.dumps(cursor_mcp)
            assert "${PLUGIN_ROOT}" in serialized
            assert "./scripts/" not in serialized
            assert "./src/" not in serialized
            for server_name, server in cursor_mcp["mcpServers"].items():
                assert isinstance(server, dict)
                assert server["command"] == cursor_sync.CURSOR_MCP_COMMAND
                assert "cwd" not in server
                launcher_name = cursor_sync.cursor_mcp_launcher_name(
                    server_name, len(cursor_mcp["mcpServers"])
                )
                assert server["args"] == [
                    "/d",
                    "/c",
                    f"${{PLUGIN_ROOT}}/scripts/{launcher_name}",
                ]
                launcher = plugin_root / "scripts" / launcher_name
                assert launcher.is_file()
                launcher_text = launcher.read_text(encoding="utf-8")
                assert r"%ProgramFiles%\nodejs" in launcher_text
                assert r"%LocalAppData%\Programs\Python\Launcher" in launcher_text
                assert "%ROOT%" in launcher_text
                original = cursor_sync.load_json(plugin_root / ".mcp.json")
                original_server = original["mcpServers"][server_name]
                assert isinstance(original_server, dict)
                original_command = original_server["command"]
                if original_command in {"python3", "python"}:
                    assert "py -3" in launcher_text
                else:
                    assert f"{original_command} " in launcher_text
        else:
            assert not (plugin_root / ".mcp.json").exists()
            assert not (plugin_root / "mcp.json").exists()


def test_codex_and_grok_indexes_are_unchanged_by_cursor_packaging() -> None:
    codex = _load(CODEX_MARKETPLACE)
    grok = _load(GROK_MARKETPLACE)
    names = [item["name"] for item in codex["plugins"]]
    assert "ssh" in names
    ssh = next(item for item in codex["plugins"] if item["name"] == "ssh")
    assert ssh["policy"]["installation"] == "NOT_AVAILABLE"
    assert [item["name"] for item in grok["plugins"]] == [
        "gitlab",
        "remotex",
        "imap-smtp-mail",
    ]
    for name in ("gitlab", "remotex", "imap-smtp-mail"):
        assert (ROOT / "plugins" / name / ".codex-plugin" / "plugin.json").is_file()
        assert (ROOT / "plugins" / name / ".cursor-plugin" / "plugin.json").is_file()
        assert (ROOT / "plugins" / name / ".mcp.json").is_file()
        assert (ROOT / "plugins" / name / "mcp.json").is_file()
        cursor_mcp = cursor_sync.load_json(ROOT / "plugins" / name / "mcp.json")
        assert cursor_mcp == cursor_sync.cursor_mcp_config(
            cursor_sync.load_json(ROOT / "plugins" / name / ".mcp.json")
        )


def test_cursor_mcp_launcher_maps_python3_to_py() -> None:
    text = cursor_sync.render_cursor_mcp_launcher(
        "python3", ["./src/wecom_codex_usage_mcp.py"]
    )
    assert text.startswith("@echo off")
    assert r"%ProgramFiles%\nodejs" in text
    assert "py -3" in text
    assert r'"%ROOT%\src\wecom_codex_usage_mcp.py"' in text
    assert "python3" not in text


def test_readme_documents_cursor_install_without_replacing_codex() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert ".cursor-plugin/marketplace.json" in readme
    assert ".agents/plugins/marketplace.json" in readme
    assert "https://github.com/YSheldon/ai-productivity-plugins" in readme
    assert "codex plugin marketplace add https://github.com/YSheldon/ai-productivity-plugins.git" in readme
    assert "Import from Repo" in readme
    assert "agent plugin marketplace add https://github.com/YSheldon/ai-productivity-plugins" in readme
    assert r".cursor\plugins\local" in readme or "~/.cursor/plugins/local" in readme
    assert "py -3 scripts/sync_cursor_plugin_manifests.py" in readme
