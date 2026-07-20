from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "plugins" / "gitlab"


def test_gitlab_marketplace_and_privileged_version_contract() -> None:
    marketplace = json.loads(
        (ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8")
    )
    entry = next(item for item in marketplace["plugins"] if item["name"] == "gitlab")
    assert entry["source"] == {"source": "local", "path": "./plugins/gitlab"}
    assert entry["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }
    assert entry["category"] == "Developer Tools"

    manifest = json.loads(
        (PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    assert manifest["version"] == "0.2.6"
    source = (PLUGIN_ROOT / "src" / "gitlab_mcp.py").read_text(encoding="utf-8")
    assignment = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "SERVER_VERSION" for target in node.targets)
    )
    assert isinstance(assignment.value, ast.Constant)
    assert assignment.value.value == manifest["version"]


def test_gitlab_marketplace_runtime_exposes_only_policy_bound_runner_arguments() -> None:
    module_path = PLUGIN_ROOT / "src" / "gitlab_mcp.py"
    spec = importlib.util.spec_from_file_location("gitlab_marketplace_contract", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema = module.TOOLS["gitlab_provision_windows_project_runner"]["inputSchema"]
    assert set(schema["properties"]) == {"profile", "policy_name"}
    assert schema["additionalProperties"] is False
    assert (PLUGIN_ROOT / "config" / "runner-policy.example.json").is_file()
