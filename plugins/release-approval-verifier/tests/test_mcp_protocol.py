from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "release_approval_verifier_mcp.py"


def _load_module():
    assert MODULE_PATH.is_file(), f"missing MCP module: {MODULE_PATH}"
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("release_approval_verifier_mcp", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("release_approval_verifier_mcp", module)
    spec.loader.exec_module(module)
    return module


class FakeController:
    def _result(self, operation, **kwargs):
        return {"status": "ready", "operation": operation, "kwargs": kwargs}

    def preflight(self): return self._result("preflight")
    def run_once(self): return self._result("run_once")
    def status(self): return self._result("status")
    def doctor(self): return self._result("doctor")
    def get_event(self, **kwargs): return self._result("get_event", **kwargs)
    def list_missing_roles(self, **kwargs): return self._result("list_missing_roles", **kwargs)
    def verify_receipt(self, **kwargs): return self._result("verify_receipt", **kwargs)
    def verify_audit_chain(self): return self._result("verify_audit_chain")


def test_mcp_inventory_and_setup_schema_are_complete() -> None:
    module = _load_module()
    assert module.SERVER_NAME == "release-approval-verifier"
    assert module.SERVER_VERSION == "0.2.4"
    assert list(module.TOOLS) == [
        "release_approval_verifier_preflight",
        "release_approval_verifier_start_setup",
        "release_approval_verifier_run_once",
        "release_approval_verifier_status",
        "release_approval_verifier_doctor",
        "release_approval_verifier_get_event",
        "release_approval_verifier_list_missing_roles",
        "release_approval_verifier_verify_receipt",
        "release_approval_verifier_verify_audit_chain",
    ]
    for spec in module.TOOLS.values():
        assert "config_path" not in spec["inputSchema"].get("properties", {})
    setup = module.TOOLS["release_approval_verifier_start_setup"]["inputSchema"]
    assert setup["properties"]["non_interactive"]["const"] is True
    assert "trusted_authserv_ids" in setup["properties"]


def test_mcp_startup_uses_the_shared_default_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    expected = (tmp_path / "verifier.json").resolve()
    sentinel = object()
    seen = []
    monkeypatch.setattr(module, "default_config_path", lambda: expected)
    monkeypatch.setattr(module, "load_config", lambda path: {"loaded": str(path)})
    monkeypatch.setattr(
        module,
        "_controller_type",
        lambda: lambda *, config, config_path: seen.append((config, Path(config_path))) or sentinel,
    )
    monkeypatch.setattr(module, "_STARTUP_CONTROLLER", None)
    monkeypatch.setattr(module, "_STARTUP_ERROR", None)

    assert module.startup_controller({}) is sentinel
    assert seen == [({"loaded": str(expected)}, expected)]


def test_mcp_setup_cold_starts_without_loading_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    expected = (tmp_path / "verifier.json").resolve()
    seen = []
    monkeypatch.setattr(module, "default_config_path", lambda: expected)
    monkeypatch.setattr(
        module,
        "run_setup_operation",
        lambda **kwargs: seen.append(kwargs) or {"status": "ready", "config_path": str(expected)},
    )
    monkeypatch.setattr(
        module,
        "startup_controller",
        lambda _args: (_ for _ in ()).throw(AssertionError("setup must not load config first")),
    )

    result = module.start_setup(
        {
            "non_interactive": True,
            "release_group": "release@example.com",
            "role_document_url": "https://open.feishu.cn/docx/roles",
            "audit_document_url": "https://open.feishu.cn/wiki/audit",
            "trusted_authserv_ids": "mx.example.com",
        }
    )
    assert result["status"] == "ready"
    assert seen[0]["config_path"] == expected
    assert seen[0]["repo_root"] == PLUGIN_ROOT.parents[1]


def test_common_mcp_handlers_return_controller_domain_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    controller = FakeController()
    monkeypatch.setattr(module, "startup_controller", lambda _args: controller)

    assert module.preflight({})["operation"] == "preflight"
    assert module.run_once({})["operation"] == "run_once"
    assert module.status({})["operation"] == "status"
    assert module.doctor({})["operation"] == "doctor"
    assert module.get_event({"event_id": "evt", "round_id": 2})["kwargs"] == {
        "event_id": "evt",
        "round_id": 2,
    }
    assert module.verify_receipt({"path": "C:\\receipt.json"})["operation"] == "verify_receipt"


def test_mcp_setup_and_validation_errors_have_stable_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()

    def fail_setup(**_kwargs):
        raise module.SetupError("SETUP_INPUT_REQUIRED", "mail_profile is required")

    monkeypatch.setattr(module, "run_setup_operation", fail_setup)
    response = module.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "release_approval_verifier_start_setup",
                "arguments": {"non_interactive": True},
            },
        }
    )
    assert response["result"]["structuredContent"]["error_code"] == "SETUP_INPUT_REQUIRED"
    assert response["result"]["isError"] is True

    with pytest.raises(module.VerifierMcpError) as excinfo:
        module.get_event({"event_id": "", "round_id": 0})
    assert excinfo.value.code == "INVALID_ARGUMENT"


def test_mcp_manifest_points_at_stdio_server() -> None:
    payload = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    assert payload["mcpServers"]["release-approval-verifier"]["args"] == [
        "-3",
        "./src/release_approval_verifier_mcp.py",
    ]
