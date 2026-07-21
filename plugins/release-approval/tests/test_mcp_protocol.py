from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


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
    assert module.SERVER_VERSION == "0.2.6"
    assert module.DEFAULT_PROTOCOL_VERSION == "2024-11-05"

    expected_tools = [
        "release_approval_preflight",
        "release_approval_start_setup",
        "release_approval_run_once",
        "release_approval_status",
        "release_approval_doctor",
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

    setup_schema = module.TOOLS["release_approval_start_setup"]["inputSchema"]
    assert setup_schema["properties"]["non_interactive"] == {
        "type": "boolean",
        "const": True,
        "default": True,
    }
    assert set(setup_schema["properties"]) == {
        "non_interactive",
        "scheduler_mode",
        "role_id",
        "role_email",
        "mail_profile",
        "release_group",
        "request_sender_email",
        "trusted_authserv_ids",
        "state_dir",
        "audit_document_url",
    }



def test_mcp_startup_uses_the_same_default_config_without_manual_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    expected = (tmp_path / "config.json").resolve()
    sentinel = object()
    seen: list[tuple[object, Path]] = []
    monkeypatch.delenv("RELEASE_APPROVAL_CONFIG", raising=False)
    monkeypatch.setattr(module, "default_config_path", lambda: expected)
    monkeypatch.setattr(module, "load_config", lambda path: {"loaded": str(path)})
    monkeypatch.setattr(
        module,
        "ReleaseApprovalController",
        lambda *, config, config_path: seen.append((config, Path(config_path))) or sentinel,
    )
    monkeypatch.setattr(module, "_STARTUP_CONTROLLER", None)
    monkeypatch.setattr(module, "_STARTUP_ERROR", None)

    assert module.startup_controller({}) is sentinel
    assert seen == [({"loaded": str(expected)}, expected)]


def test_mcp_setup_cold_starts_without_loading_an_existing_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    expected = (tmp_path / "config.json").resolve()
    seen: list[dict[str, object]] = []

    def fake_setup(**kwargs):
        seen.append(kwargs)
        return {"status": "ready", "config_path": str(kwargs["config_path"])}

    monkeypatch.setattr(module, "default_config_path", lambda: expected)
    monkeypatch.setattr(module, "run_setup_operation", fake_setup, raising=False)
    monkeypatch.setattr(
        module,
        "startup_controller",
        lambda _args: (_ for _ in ()).throw(AssertionError("setup must not load config first")),
    )

    payload = module.start_setup(
        {
            "role_id": "release-manager",
            "release_group": "release@example.com",
            "request_sender_email": "release-gate@example.com",
            "trusted_authserv_ids": "mx.example.com",
            "non_interactive": True,
        }
    )

    assert payload == {"status": "ready", "config_path": str(expected)}
    assert seen == [
        {
            "config_path": expected,
            "repo_root": PLUGIN_ROOT.parents[1],
            "non_interactive": True,
            "scheduler_mode": "auto",
            "provided": {
                "role_id": "release-manager",
                "role_email": None,
                "mail_profile": None,
                "release_group": "release@example.com",
                "request_sender_email": "release-gate@example.com",
                "trusted_authserv_ids": "mx.example.com",
                "state_dir": None,
                "audit_document_url": None,
            },
        }
    ]


def test_mcp_setup_rejects_interactive_mode_and_per_call_config_override() -> None:
    module = _load_module()

    with pytest.raises(module.ReleaseApprovalMcpError) as interactive:
        module.start_setup({"non_interactive": False})
    assert interactive.value.code == "INVALID_ARGUMENT"

    with pytest.raises(Exception, match="cannot be supplied per call"):
        module.start_setup({"config_path": "C:\\unapproved.json"})


def test_mcp_setup_preserves_the_shared_setup_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()

    def fail_setup(**_kwargs):
        raise module.SetupError("SETUP_INPUT_REQUIRED", "role_id is required")

    monkeypatch.setattr(module, "run_setup_operation", fail_setup)
    result = module.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "release_approval_start_setup",
                "arguments": {"non_interactive": True},
            },
        }
    )

    payload = result["result"]["structuredContent"]
    assert payload["error_code"] == "SETUP_INPUT_REQUIRED"
    assert result["result"]["isError"] is True


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
