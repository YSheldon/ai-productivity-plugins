from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_PATH = ROOT / ".agents" / "plugins" / "marketplace.json"
MARKETPLACE_NAME = "ai-productivity-plugins"
MARKETPLACE_URL = "https://github.com/YSheldon/ai-productivity-plugins.git"


@dataclass(frozen=True)
class MarketplacePlugin:
    name: str
    version: str
    mcp_script: str
    cli_script: str

    @property
    def root(self) -> Path:
        return ROOT / "plugins" / self.name


PLUGINS = (
    MarketplacePlugin("release-approval", "0.2.3", "release_approval_mcp.py", "release_approval_cli.py"),
    MarketplacePlugin(
        "release-approval-verifier",
        "0.2.3",
        "release_approval_verifier_mcp.py",
        "verifier_cli.py",
    ),
    MarketplacePlugin("product-release-gate", "0.3.4", "release_gate_mcp.py", "release_gate_cli.py"),
    MarketplacePlugin("test-submission", "0.1.3", "test_submission_mcp.py", "test_submission_cli.py"),
    MarketplacePlugin("submission-gate", "0.1.3", "submission_gate_mcp.py", "submission_gate_cli.py"),
    MarketplacePlugin("pre-release", "0.1.4", "pre_release_mcp.py", "pre_release_cli.py"),
    MarketplacePlugin("release-gate", "0.1.4", "release_gate_mcp.py", "release_gate_cli.py"),
    MarketplacePlugin("rd-flywheel", "0.2.3", "rd_flywheel_mcp.py", "rd_flywheel_cli.py"),
)


def _load_json(path: Path) -> dict[str, object]:
    assert path.is_file(), f"missing JSON file: {path.relative_to(ROOT)}"
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), f"expected JSON object: {path.relative_to(ROOT)}"
    return value


def _marketplace_entries() -> dict[str, dict[str, object]]:
    marketplace = _load_json(MARKETPLACE_PATH)
    assert marketplace.get("name") == MARKETPLACE_NAME
    raw_entries = marketplace.get("plugins")
    assert isinstance(raw_entries, list)
    names = [entry.get("name") for entry in raw_entries if isinstance(entry, dict)]
    assert len(names) == len(set(names)), f"duplicate marketplace plugin names: {names}"
    return {
        str(entry["name"]): entry
        for entry in raw_entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }


def _literal_assignment(path: Path, name: str) -> str | None:
    source = path.read_text(encoding="utf-8")
    for node in ast.parse(source).body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return node.value.value
    return None


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda item: item.name)
def test_marketplace_entry_has_exact_local_source_and_install_policy(
    plugin: MarketplacePlugin,
) -> None:
    entries = _marketplace_entries()
    assert plugin.name in entries, f"{plugin.name} is not registered in the marketplace"
    entry = entries[plugin.name]
    expected_source = {"source": "local", "path": f"./plugins/{plugin.name}"}
    assert entry.get("source") == expected_source
    assert entry.get("policy") == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }
    assert entry.get("category") == "Developer Tools"

    source_path = str(expected_source["path"])
    assert not Path(source_path).is_absolute()
    resolved = (ROOT / source_path).resolve(strict=False)
    assert resolved == plugin.root.resolve(strict=False)
    assert resolved.is_dir()


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda item: item.name)
def test_manifest_version_and_four_surface_metadata_are_consistent(
    plugin: MarketplacePlugin,
) -> None:
    manifest = _load_json(plugin.root / ".codex-plugin" / "plugin.json")
    assert manifest.get("name") == plugin.name
    assert manifest.get("version") == plugin.version
    assert re.fullmatch(
        r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)",
        plugin.version,
    )
    assert manifest.get("skills") == "./skills/"
    assert manifest.get("mcpServers") == "./.mcp.json"
    interface = manifest.get("interface")
    assert isinstance(interface, dict)
    assert interface.get("category") == "Developer Tools"

    skill = plugin.root / "skills" / plugin.name / "SKILL.md"
    assert skill.is_file(), f"manifest skill path does not resolve: {skill.relative_to(ROOT)}"
    mcp_path = plugin.root / ".mcp.json"
    assert mcp_path.is_file(), f"manifest MCP path does not resolve: {mcp_path.relative_to(ROOT)}"

    mcp_source = plugin.root / "src" / plugin.mcp_script
    assert mcp_source.is_file(), f"missing MCP runtime: {mcp_source.relative_to(ROOT)}"
    assert _literal_assignment(mcp_source, "SERVER_VERSION") == plugin.version


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda item: item.name)
def test_mcp_launcher_is_portable_relative_and_resolves_inside_plugin(
    plugin: MarketplacePlugin,
) -> None:
    mcp = _load_json(plugin.root / ".mcp.json")
    servers = mcp.get("mcpServers")
    assert isinstance(servers, dict)
    assert set(servers) == {plugin.name}
    server = servers[plugin.name]
    assert isinstance(server, dict)
    assert server.get("command") == "py"
    assert server.get("cwd") == "."
    args = server.get("args")
    assert args == ["-3", f"./src/{plugin.mcp_script}"]

    script_argument = str(args[-1])
    assert not Path(script_argument).is_absolute()
    resolved = (plugin.root / script_argument).resolve(strict=False)
    assert resolved.is_relative_to(plugin.root.resolve(strict=False))
    assert resolved.is_file()
    assert not re.match(r"^[A-Za-z]:[\\/]", script_argument)
    assert "%USERPROFILE%" not in script_argument.upper()


def test_repository_documents_feature_branch_and_per_plugin_install_commands() -> None:
    readme_path = ROOT / "README.md"
    assert readme_path.is_file()
    readme = readme_path.read_text(encoding="utf-8")
    assert f"codex plugin marketplace add {MARKETPLACE_URL}" in readme
    assert "build-embedded shared `release_workflow_core`" in readme
    assert "no longer depend on a runtime `product-release-gate` bridge" in readme
    for plugin in PLUGINS:
        assert f"codex plugin add {plugin.name}@{MARKETPLACE_NAME}" in readme
        assert plugin.name in readme


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda item: item.name)
def test_plugin_readme_documents_codex_optional_standalone_activation(
    plugin: MarketplacePlugin,
) -> None:
    readme_path = plugin.root / "README.md"
    assert readme_path.is_file(), f"missing plugin README: {readme_path.relative_to(ROOT)}"
    text = readme_path.read_text(encoding="utf-8").casefold()
    assert plugin.cli_script.casefold() in text
    assert "setup" in text
    assert "run-once" in text
    assert "scheduler" in text
    assert "status" in text or "doctor" in text or "preflight" in text
    assert "codex is optional" in text or "no codex runtime dependency" in text
