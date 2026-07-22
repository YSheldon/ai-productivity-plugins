from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_credentials import (
    current_runtime_principal,
    runtime_principal_sha256,
)
PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class McpProtocolTests(unittest.TestCase):
    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_deployment_binding(
        self, root: Path, command: list[str]
    ) -> dict[str, object]:
        adapter = root / "deployment_adapter.py"
        adapter.write_text("print('{}')\n", encoding="utf-8")
        deploy_command = [sys.executable, str(adapter), "deploy", "{stage}", "{manifest_r_digest}", "{target_ref}"]
        verify_command = [sys.executable, str(adapter), "verify", "{stage}", "{manifest_r_digest}", "{target_ref}"]
        rollback_command = [sys.executable, str(adapter), "rollback", "{stage}", "{manifest_r_digest}", "{deployment_ref}", "{rollback_ref}", "{target_ref}"]
        rollback_verify_command = [sys.executable, str(adapter), "rollback_verify", "{stage}", "{manifest_r_digest}", "{deployment_ref}", "{rollback_ref}", "{restored_ref}", "{rollback_receipt_ref}", "{target_ref}"]
        readback_command = [sys.executable, str(adapter), "readback", "{stage}", "{manifest_r_digest}", "{target_ref}"]
        lock_path = root / "deployment-adapter.lock.json"
        lock_payload = {
            "schema_version": 1,
            "root": ".",
            "commands": {
                command_id: {
                    "argv_template": argv,
                    "entrypoints": [
                        {
                            "argv_index": 0,
                            "path": sys.executable,
                            "sha256": self._sha256(Path(sys.executable)),
                        },
                        {
                            "argv_index": 1,
                            "path": adapter.name,
                            "sha256": self._sha256(adapter),
                        },
                    ],
                }
                for command_id, argv in {
                    "deploy": deploy_command,
                    "verify": verify_command,
                    "rollback": rollback_command,
                    "rollback_verify": rollback_verify_command,
                    "readback": readback_command,
                }.items()
            },
        }
        lock_path.write_text(json.dumps(lock_payload, sort_keys=True), encoding="utf-8")
        return {
            "dependency_lock": str(lock_path),
            "dependency_lock_sha256": self._sha256(lock_path),
            "deploy_command": deploy_command,
            "verify_command": verify_command,
            "rollback_command": rollback_command,
            "rollback_verify_command": rollback_verify_command,
            "readback_command": readback_command,
        }

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
        manifest = json.loads(
            (PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["version"], responses[0]["result"]["serverInfo"]["version"])

        tools = responses[1]["result"]["tools"]
        tool_names = {item["name"] for item in tools}
        self.assertGreaterEqual(len(tools), 29)
        self.assertIn("release_gate_run_release_gate", tool_names)
        self.assertIn("release_gate_request_release_authorization", tool_names)
        self.assertIn("release_gate_record_release_authorization", tool_names)
        self.assertIn("release_gate_unified_approval_preflight", tool_names)
        self.assertIn(
            "release_gate_finalize_verified_release_authorization",
            tool_names,
        )
        self.assertIn("release_gate_request_unified_release_approval", tool_names)
        self.assertIn("release_gate_record_unified_release_approval", tool_names)
        self.assertIn("release_gate_setup", tool_names)
        self.assertIn("release_gate_run_once", tool_names)
        self.assertIn("release_gate_status", tool_names)
        self.assertIn("release_gate_doctor", tool_names)
        self.assertIn("release_gate_list_events", tool_names)
        self.assertIn("release_gate_enqueue_handoff", tool_names)
        self.assertIn("release_gate_scheduler_install", tool_names)
        self.assertIn("release_gate_scheduler_status", tool_names)
        self.assertIn("release_gate_scheduler_remove", tool_names)
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
            deployment_binding = self._write_deployment_binding(root, command)
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "storage_dir": str(root / "events"),
                        "runtime": {
                            "identity_binding": {
                                "required": True,
                                "principal_sha256": runtime_principal_sha256(
                                    current_runtime_principal()
                                ),
                            }
                        },
                        "policy": {
                            "require_signature": True,
                            "require_cloud_scan": True,
                        },
                        "signature": {"expected_thumbprints": ["A" * 40]},
                        "cloud_scan": {
                            "command": [sys.executable, "-c", "print('{}')"],
                        },
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
                                "dependency_lock": deployment_binding["dependency_lock"],
                                "dependency_lock_sha256": deployment_binding["dependency_lock_sha256"],
                                "deploy_command": deployment_binding["deploy_command"],
                                "verify_command": deployment_binding["verify_command"],
                                "rollback_command": deployment_binding["rollback_command"],
                                "rollback_verify_command": deployment_binding["rollback_verify_command"],
                            },
                            "readback": {"command": deployment_binding["readback_command"]},
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
        self.assertIn(
            "release_gate_deliver_production_report",
            {tool["name"] for tool in tools},
        )
        self.assertTrue(
            all("config_path" not in tool["inputSchema"].get("properties", {}) for tool in tools)
        )
        production = json.loads(responses[1]["result"]["content"][0]["text"])
        self.assertTrue(production["ready"], production)
        self.assertTrue(responses[2]["result"]["isError"])
        self.assertIn("cannot be supplied per call", responses[2]["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
