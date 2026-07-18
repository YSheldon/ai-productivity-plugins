from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "release_gate_mcp.py"


def _load_module():
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("release_gate_mcp", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("release_gate_mcp", module)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_mcp_inventory_and_manifest() -> None:
    module = _load_module()
    assert module.SERVER_NAME == "release-gate"
    assert module.SERVER_VERSION == "0.1.4"
    assert list(module.TOOLS) == [
        "release_gate_preflight",
        "release_gate_start_setup",
        "release_gate_run_once",
        "release_gate_status",
        "release_gate_doctor",
        "release_gate_verify_audit",
    ]
    payload = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    assert payload["mcpServers"]["release-gate"]["args"] == ["-3", "./src/release_gate_mcp.py"]
