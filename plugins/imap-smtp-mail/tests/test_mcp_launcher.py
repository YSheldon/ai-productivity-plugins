from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_uses_cross_platform_node_launcher() -> None:
    manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    mcp = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    server = mcp["mcpServers"]["imap-smtp-mail"]
    assert manifest["version"] == "0.3.3"
    assert server == {"command": "node", "args": ["./scripts/run_mcp.js"], "cwd": "."}
    assert (ROOT / "scripts" / "run_mcp.js").is_file()


def test_node_launcher_initializes_the_mcp_server() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        }
    ) + "\n"
    completed = subprocess.run(
        [node, str(ROOT / "scripts" / "run_mcp.js")],
        cwd=ROOT,
        input=request,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    response = json.loads(completed.stdout.splitlines()[0])
    assert response["result"]["serverInfo"] == {"name": "imap-smtp-mail", "version": "0.3.3"}
