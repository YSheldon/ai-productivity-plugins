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
        self.assertEqual(response["result"]["serverInfo"]["version"], "0.5.1")

    def test_tools_list_has_all_adapters(self) -> None:
        response = remotex_mcp.handle_request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}
        names = set(tools)
        self.assertIn("remotex_status", names)
        self.assertIn("remotex_ssh_test", names)
        self.assertIn(
            "server-side authentication evidence",
            tools["remotex_ssh_test"]["description"],
        )
        self.assertIn("remotex_rdp_open", names)
        self.assertIn("remotex_vsphere_list_vms", names)
        self.assertIn("remotex_vmware_power", names)
        self.assertIn("remotex_vmware_snapshot_create", names)
        self.assertIn("remotex_vmware_snapshot_revert", names)
        self.assertIn("remotex_vmware_snapshot_delete", names)
        self.assertIn("remotex_windows_guest_preflight", names)
        self.assertIn("remotex_windows_guest_reboot", names)
        self.assertIn("remotex_vm_queue_claim", names)
        self.assertIn("remotex_vm_queue_heartbeat", names)
        self.assertIn("remotex_vm_queue_recover_stale", names)
        self.assertIn("remotex_ssh_task_cleanup_sensitive_artifacts", names)
        self.assertIn("remotex_credential_doctor", names)
        self.assertIn("remotex_credential_setup", names)
        self.assertIn("remotex_credential_delete", names)
        self.assertIn("remotex_profile_setup", names)
        self.assertEqual(names, set(remotex_mcp.TOOLS))

    def test_side_effectful_vm_tools_require_requester(self) -> None:
        response = remotex_mcp.handle_request(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}
        )
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}
        for name in (
            "remotex_rdp_open",
            "remotex_vsphere_power",
            "remotex_vmware_power",
            "remotex_vmware_snapshot_create",
            "remotex_vmware_snapshot_revert",
            "remotex_vmware_snapshot_delete",
            "remotex_windows_guest_preflight",
            "remotex_windows_guest_run_script",
            "remotex_windows_guest_copy_to",
            "remotex_windows_guest_copy_from",
            "remotex_windows_guest_reboot",
        ):
            self.assertIn("requester", tools[name]["inputSchema"]["required"])
        for name in (
            "remotex_vmware_snapshot_revert",
            "remotex_vmware_snapshot_delete",
            "remotex_windows_guest_reboot",
        ):
            self.assertIn("confirm", tools[name]["inputSchema"]["required"])

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
