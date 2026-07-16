from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MCP_MODULE_PATH = SRC_ROOT / "release_approval_mcp.py"


def _load_module():
    assert MCP_MODULE_PATH.is_file(), f"missing MCP server module: {MCP_MODULE_PATH}"
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("release_approval_mcp", MCP_MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("release_approval_mcp", module)
    spec.loader.exec_module(module)
    return module


def test_task6_mcp_server_and_inventory_are_registered() -> None:
    module = _load_module()

    assert module.SERVER_NAME == "release-approval"
    assert module.SERVER_VERSION == "0.1.0"
    assert module.DEFAULT_PROTOCOL_VERSION == "2024-11-05"

    expected_tools = [
        "release_approval_preflight",
        "release_approval_start_setup",
        "release_approval_run_once",
        "release_approval_list_pending",
        "release_approval_open_page",
        "release_approval_get_event",
        "release_approval_verify_audit_chain",
    ]
    assert list(module.TOOLS) == expected_tools

    for name in expected_tools:
        schema = module.TOOLS[name]["inputSchema"]
        assert schema["type"] == "object"
        assert "config_path" not in schema.get("properties", {})


def test_task6_mcp_manifest_points_at_stdio_server() -> None:
    payload = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    assert payload == {
        "mcpServers": {
            "release-approval": {
                "command": "py",
                "args": ["-3", "./src/release_approval_mcp.py"],
                "cwd": ".",
            }
        }
    }
