from __future__ import annotations

import json
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SKILL = PLUGIN_ROOT / "skills" / "release-approval" / "SKILL.md"


def test_task6_skill_and_references_exist() -> None:
    assert SKILL.is_file(), f"missing skill file: {SKILL}"

    references = {
        "configuration.md",
        "automation-contract.md",
    }
    text = SKILL.read_text(encoding="utf-8")
    for name in references:
        assert f"references/{name}" in text
        assert (SKILL.parent / "references" / name).is_file()


def test_task6_skill_encodes_setup_and_run_once_contract() -> None:
    text = SKILL.read_text(encoding="utf-8")
    required_tokens = {
        "release_approval_preflight",
        "release_approval_start_setup",
        "release_approval_run_once",
        "release_approval_status",
        "release_approval_doctor",
        "release_approval_list_pending",
        "release_approval_open_page",
        "release_approval_get_event",
        "release_approval_verify_audit_chain",
        "FRESH_TASK_REQUIRED",
        "CAPABILITY_BLOCKED",
        "loopback",
        "hourly",
        "immediately",
        "dependency lock",
        "fresh one-time",
        "standalone CLI",
        "OS scheduler",
        "headless",
        "Codex is optional",
        "zero manual JSON",
        "four prompts",
        "RUN_ALREADY_ACTIVE",
        "skip all missed",
        "scheduler install|status|remove",
        "Message-ID",
        "UIDVALIDITY",
        "UID",
    }
    missing = sorted(token for token in required_tokens if token not in text)
    assert not missing, f"missing skill contract tokens: {missing}"


def test_task6_plugin_metadata_exposes_skill_and_task6_interface_boundary() -> None:
    manifest = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["version"] == "0.2.0"
    assert manifest["skills"] == "./skills/"
    assert manifest["mcpServers"] == "./.mcp.json"
    long_description = manifest["interface"]["longDescription"].lower()
    assert "standalone cli" in long_description
    assert "headless" in long_description
    assert "os scheduler" in long_description
    assert "setup" in " ".join(manifest["interface"]["defaultPrompt"]).lower()
