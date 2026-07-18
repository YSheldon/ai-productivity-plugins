from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "pre_release_mcp.py"


def _load_module():
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("pre_release_mcp", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("pre_release_mcp", module)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_mcp_inventory_and_manifest() -> None:
    module = _load_module()
    assert module.SERVER_NAME == "pre-release"
    assert module.SERVER_VERSION == "0.1.2"
    assert list(module.TOOLS) == [
        "pre_release_preflight",
        "pre_release_start_setup",
        "pre_release_run_once",
        "pre_release_status",
        "pre_release_doctor",
        "pre_release_verify_audit",
        "pre_release_list_tasks",
        "pre_release_create_request",
    ]
    payload = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    assert payload["mcpServers"]["pre-release"]["args"] == ["-3", "./src/pre_release_mcp.py"]
