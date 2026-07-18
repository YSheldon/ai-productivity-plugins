from __future__ import annotations

import json
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


def test_skill_documents_all_four_surfaces_without_duplicate_policy() -> None:
    skill_path = PLUGIN_ROOT / "skills" / "release-approval-verifier" / "SKILL.md"
    config_ref = skill_path.parent / "references" / "configuration.md"
    automation_ref = skill_path.parent / "references" / "automation-contract.md"
    assert skill_path.is_file()
    assert config_ref.is_file()
    assert automation_ref.is_file()

    text = skill_path.read_text(encoding="utf-8")
    assert "MCP-first" in text
    assert "CLI fallback" in text
    assert "verifier_cli.py setup" in text
    assert "verifier_cli.py run-once" in text
    assert "scheduler install" in text
    assert "Codex is optional" in text
    assert "APPROVAL_VERIFIED" in text
    assert "PRE_RELEASE_REQUESTED" in text
    assert "RELEASE_AUTHORIZED" in text
    assert "single configuration" in text

    automation = automation_ref.read_text(encoding="utf-8")
    assert "skip all missed" in automation.lower()
    assert "RUN_ALREADY_ACTIVE" in automation
    assert "HMAC" in automation
    assert "SMTP acceptance" in automation


def test_manifest_and_readme_advertise_standalone_operation() -> None:
    manifest = json.loads(
        (PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    assert manifest["version"] == "0.2.2"
    assert manifest["skills"] == "./skills/"
    assert manifest["mcpServers"] == "./.mcp.json"

    readme = (PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")
    assert "four surfaces" in readme
    assert "zero manual JSON" in readme
    assert "Codex is optional" in readme
    assert "verifier_cli.py" in readme
