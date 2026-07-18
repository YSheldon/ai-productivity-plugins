from __future__ import annotations

import json
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def test_skill_documents_all_four_surfaces() -> None:
    skill_path = PLUGIN_ROOT / "skills" / "test-submission" / "SKILL.md"
    config_ref = skill_path.parent / "references" / "configuration.md"
    automation_ref = skill_path.parent / "references" / "automation-contract.md"
    text = skill_path.read_text(encoding="utf-8")
    assert config_ref.is_file()
    assert automation_ref.is_file()
    assert "MCP-first" in text
    assert "CLI fallback" in text
    assert "test_submission_cli.py setup" in text
    assert "scheduler install" in text
    assert "Codex is optional" in text
    assert "module" in text


def test_manifest_and_readme_advertise_standalone_operation() -> None:
    manifest = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["version"] == "0.1.3"
    assert manifest["skills"] == "./skills/"
    assert manifest["mcpServers"] == "./.mcp.json"
    readme = (PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")
    assert "four surfaces" in readme
    assert "zero manual JSON" in readme
    assert "Codex is optional" in readme
    config = json.loads((PLUGIN_ROOT / "config" / "config.example.json").read_text(encoding="utf-8"))
    assert "default_module" not in config
