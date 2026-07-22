from __future__ import annotations

import sys
import unittest
from pathlib import Path


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import remotex_mcp


class MCPProtocolTests(unittest.TestCase):
    def test_initialize(self) -> None:
        response = remotex_mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            }
        )
        self.assertEqual(response["result"]["serverInfo"]["name"], "remotex")

    def test_tools_list_has_all_adapters(self) -> None:
        response = remotex_mcp.handle_request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertIn("remotex_status", names)
        self.assertIn("remotex_ssh_test", names)
        self.assertIn("remotex_rdp_open", names)
        self.assertIn("remotex_vsphere_list_vms", names)
        self.assertIn("remotex_vmware_power", names)
        self.assertIn("remotex_vm_queue_claim", names)
        self.assertIn("remotex_vm_queue_release", names)
        self.assertEqual(len(names), 22)

    def test_side_effectful_vm_tools_require_requester(self) -> None:
        response = remotex_mcp.handle_request(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}
        )
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}
        for name in (
            "remotex_rdp_open",
            "remotex_vsphere_power",
            "remotex_vmware_power",
        ):
            self.assertIn("requester", tools[name]["inputSchema"]["required"])

    def test_unknown_tool_is_a_tool_error(self) -> None:
        response = remotex_mcp.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "remotex_unknown", "arguments": {}},
            }
        )
        self.assertTrue(response["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
