from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "project_docs.py"


def module():
    assert SCRIPT.is_file(), "Project documentation generator/checker is missing"
    spec = importlib.util.spec_from_file_location("project_docs", SCRIPT)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixture(tmp_path):
    for path, data in {
        ".agents/plugins/marketplace.json": {"plugins": [
            {"name": "remotex", "policy": {"installation": "AVAILABLE"}},
            {"name": "ssh", "policy": {"installation": "NOT_AVAILABLE"}}]},
        ".cursor-plugin/marketplace.json": {"plugins": [{"name": "remotex"}]},
        ".grok-plugin/marketplace.json": {"plugins": []},
        "plugins/remotex/.codex-plugin/plugin.json": {"name": "remotex", "version": "1.2.3", "description": "Remote | operations"},
        "plugins/ssh/.codex-plugin/plugin.json": {"name": "ssh", "version": "0.1.0", "description": "Legacy SSH"},
    }.items():
        file = tmp_path / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


def test_catalog_uses_manifest_versions_and_actual_index_membership(tmp_path):
    docs = module()
    text = docs.render_catalog(fixture(tmp_path))
    assert "| 1.2.3 | Yes | Yes | No |" in text
    assert "Remote &#124; operations" in text
    assert text.index("## Legacy") < text.index("[ssh]")
    manifest = tmp_path / "plugins/remotex/.codex-plugin/plugin.json"
    data = json.loads(manifest.read_text())
    data["version"] = "1.2.4"
    manifest.write_text(json.dumps(data))
    assert "| 1.2.4 | Yes | Yes | No |" in docs.render_catalog(tmp_path)


def test_local_document_links_are_checked_and_external_links_are_not_fetched(tmp_path):
    docs = module()
    (tmp_path / "README.md").write_text("# Guide\n[Good](child.md)\n![Missing](assets/missing.png)\n[Web](https://example.invalid/)\n")
    (tmp_path / "child.md").write_text("# Child\n")
    errors = docs.check_documents(tmp_path, [Path("README.md")])
    assert len(errors) == 1
    assert "assets/missing.png" in errors[0]


def test_non_english_copy_and_private_endpoints_are_rejected(tmp_path):
    docs = module()
    (tmp_path / "README.md").write_text("# \u4e2d\u6587\nhttps://10.12.13.14:6868/\n", encoding="utf-8")
    errors = docs.check_documents(tmp_path, [Path("README.md")])
    assert any("English" in error for error in errors)
    assert any("private" in error for error in errors)


def test_heading_links_are_validated_with_github_style_anchors(tmp_path):
    docs = module()
    (tmp_path / "README.md").write_text("# Start\n[OK](child.md#remote-0510)\n[Bad](child.md#missing)\n[Self](#absent)\n")
    (tmp_path / "child.md").write_text("# Remote 0.5.10\n")
    errors = docs.check_documents(tmp_path, [Path("README.md")])
    assert len(errors) == 2
    assert any("#missing" in e for e in errors)
    assert any("#absent" in e for e in errors)


def test_published_project_documents_are_current():
    assert SCRIPT.is_file(), "Project documentation generator/checker is missing"
    result = subprocess.run([sys.executable, str(SCRIPT), "--check"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
