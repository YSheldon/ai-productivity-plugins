from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class McpProtocolTests(unittest.TestCase):
    def test_initialize_tool_inventory_and_preflight_call(self) -> None:
        requests = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "release_gate_preflight", "arguments": {}},
            },
        ]
        completed = subprocess.run(
            [sys.executable, str(PLUGIN_ROOT / "src" / "release_gate_mcp.py")],
            input="".join(json.dumps(item) + "\n" for item in requests),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        self.assertEqual([1, 2, 3], [item["id"] for item in responses])
        self.assertEqual("product-release-gate", responses[0]["result"]["serverInfo"]["name"])

        tools = responses[1]["result"]["tools"]
        self.assertEqual(10, len(tools))
        self.assertIn("release_gate_run_release_gate", {item["name"] for item in tools})

        preflight_text = responses[2]["result"]["content"][0]["text"]
        preflight = json.loads(preflight_text)
        self.assertIn("ready", preflight)
        self.assertIn("checks", preflight)


if __name__ == "__main__":
    unittest.main()
