from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
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
        tool_names = {item["name"] for item in tools}
        self.assertEqual(18, len(tools))
        self.assertIn("release_gate_run_release_gate", tool_names)
        self.assertIn("release_gate_request_release_authorization", tool_names)
        self.assertIn("release_gate_record_release_authorization", tool_names)
        self.assertIn("release_gate_run_deployment_stage", tool_names)
        self.assertIn("release_gate_run_production_readback", tool_names)
        self.assertIn("release_gate_verify_control_event_chain", tool_names)

        preflight_text = responses[2]["result"]["content"][0]["text"]
        preflight = json.loads(preflight_text)
        self.assertIn("ready", preflight)
        self.assertIn("checks", preflight)

    def test_configuration_is_locked_at_startup_and_production_tools_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [sys.executable, "-c", "print('{}')"]
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "storage_dir": str(root / "events"),
                        "production": {
                            "enabled": True,
                            "authorization": {
                                "key_env": "MCP_TEST_AUTH_KEY",
                                "verify_command": command,
                            },
                            "audit": {"key_env": "MCP_TEST_AUDIT_KEY"},
                            "deployment": {
                                "stages": [
                                    "preproduction",
                                    "production_canary",
                                    "production_full",
                                ],
                                "targets": {
                                    "preproduction": "env:preproduction",
                                    "production_canary": "env:production:canary",
                                    "production_full": "env:production:full",
                                },
                                "deploy_command": command,
                                "verify_command": command,
                                "rollback_command": command,
                                "rollback_verify_command": command,
                            },
                            "readback": {"command": command},
                        },
                    }
                ),
                encoding="utf-8",
            )
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "release_gate_production_preflight",
                        "arguments": {},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "release_gate_preflight",
                        "arguments": {"config_path": str(root / "attacker.json")},
                    },
                },
            ]
            env = os.environ.copy()
            env["PRODUCT_RELEASE_GATE_CONFIG"] = str(config_path)
            env["MCP_TEST_AUTH_KEY"] = "mcp-test-authorization-key-32-bytes-minimum"
            env["MCP_TEST_AUDIT_KEY"] = "mcp-test-audit-ledger-key-32-bytes-minimum"
            completed = subprocess.run(
                [sys.executable, str(PLUGIN_ROOT / "src" / "release_gate_mcp.py")],
                input="".join(json.dumps(item) + "\n" for item in requests),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env=env,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        tools = responses[0]["result"]["tools"]
        self.assertTrue(
            all("config_path" not in tool["inputSchema"].get("properties", {}) for tool in tools)
        )
        production = json.loads(responses[1]["result"]["content"][0]["text"])
        self.assertTrue(production["ready"], production)
        self.assertTrue(responses[2]["result"]["isError"])
        self.assertIn("cannot be supplied per call", responses[2]["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
