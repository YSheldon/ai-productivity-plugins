from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "verifier_cli.py"


def _load_module():
    assert MODULE_PATH.is_file(), f"missing CLI module: {MODULE_PATH}"
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("verifier_cli", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("verifier_cli", module)
    spec.loader.exec_module(module)
    return module


class FakeController:
    def _result(self, operation: str, **kwargs: Any) -> dict[str, Any]:
        return {"status": "ready", "operation": operation, "kwargs": kwargs}

    def preflight(self): return self._result("preflight")
    def run_once(self): return self._result("run_once")
    def status(self): return self._result("status")
    def doctor(self): return self._result("doctor")
    def list_missing_roles(self, **kwargs): return self._result("list_missing_roles", **kwargs)
    def get_event(self, **kwargs): return self._result("get_event", **kwargs)
    def verify_receipt(self, **kwargs): return self._result("verify_receipt", **kwargs)
    def verify_audit_chain(self): return self._result("verify_audit_chain")


class FakeScheduler:
    def _result(self, operation: str, **kwargs: Any) -> dict[str, Any]:
        return {"status": "ready", "operation": f"scheduler.{operation}", "kwargs": kwargs}

    def install(self, **kwargs): return self._result("install", **kwargs)
    def status(self, **kwargs): return self._result("status", **kwargs)
    def remove(self, **kwargs): return self._result("remove", **kwargs)


def test_cli_inventory_is_complete_and_has_no_codex_dependency() -> None:
    module = _load_module()
    assert module.COMMAND_NAMES == (
        "setup", "preflight", "run-once", "status", "doctor", "get-event",
        "list-missing-roles", "verify-receipt", "verify-audit", "scheduler",
    )
    source = MODULE_PATH.read_text(encoding="utf-8").lower()
    assert "import codex" not in source
    assert "from codex" not in source


def test_cli_operations_use_one_controller_and_structured_arguments(tmp_path: Path) -> None:
    module = _load_module()
    controller = FakeController()
    config_path = tmp_path / "verifier.json"
    for command, operation in {
        "preflight": "preflight", "run-once": "run_once", "status": "status",
        "doctor": "doctor", "verify-audit": "verify_audit_chain",
    }.items():
        code, payload = module.run_cli(
            ["--config", str(config_path), command],
            controller_factory=lambda _path: controller,
        )
        assert code == module.EXIT_OK
        assert payload == {"status": "ready", "operation": operation, "kwargs": {}}

    code, payload = module.run_cli(
        ["--config", str(config_path), "get-event", "--event-id", "evt-1", "--round-id", "2"],
        controller_factory=lambda _path: controller,
    )
    assert code == module.EXIT_OK
    assert payload["kwargs"] == {"event_id": "evt-1", "round_id": 2}

    receipt = tmp_path / "receipt.json"
    code, payload = module.run_cli(
        ["--config", str(config_path), "verify-receipt", "--path", str(receipt)],
        controller_factory=lambda _path: controller,
    )
    assert code == module.EXIT_OK
    assert payload["kwargs"] == {"path": receipt.resolve()}


def test_cli_setup_forwards_only_setup_inputs_and_preserves_errors(tmp_path: Path) -> None:
    module = _load_module()
    config_path = tmp_path / "verifier.json"
    seen: list[dict[str, Any]] = []
    code, payload = module.run_cli(
        ["--config", str(config_path), "setup", "--non-interactive",
         "--release-group", "release@example.com",
         "--role-document-url", "https://open.feishu.cn/docx/roles",
         "--audit-document-url", "https://open.feishu.cn/wiki/audit",
         "--trusted-authserv-ids", "mx.example.com"],
        setup_runner=lambda **kwargs: seen.append(kwargs) or {"status": "ready"},
    )
    assert code == module.EXIT_OK
    assert payload == {"status": "ready"}
    assert seen[0]["config_path"] == config_path.resolve()
    assert seen[0]["provided"]["release_group"] == "release@example.com"
    assert seen[0]["provided"]["trusted_authserv_ids"] == "mx.example.com"

    def fail(**_kwargs):
        raise module.SetupError("SETUP_INPUT_REQUIRED", "mail_profile is required")

    code, error = module.run_cli(
        ["--config", str(config_path), "setup", "--non-interactive"],
        setup_runner=fail,
    )
    assert code == module.EXIT_USAGE
    assert error["error_code"] == "SETUP_INPUT_REQUIRED"


def test_scheduler_subcommands_have_no_per_command_policy_override(tmp_path: Path) -> None:
    module = _load_module()
    scheduler = FakeScheduler()
    config_path = tmp_path / "verifier.json"
    code, payload = module.run_cli(
        ["--config", str(config_path), "scheduler", "install", "--mode", "systemd"],
        scheduler_factory=lambda _path: scheduler,
    )
    assert code == module.EXIT_OK
    assert payload["kwargs"] == {"mode": "systemd"}

    code, error = module.run_cli(
        ["--config", str(config_path), "scheduler", "install", "--poll-minutes", "30"],
        scheduler_factory=lambda _path: scheduler,
    )
    assert code == module.EXIT_USAGE
    assert error["error_code"] == "INVALID_ARGUMENT"


def test_cli_maps_blocked_and_unexpected_errors_to_stable_exit_codes(tmp_path: Path) -> None:
    module = _load_module()

    class Blocked(FakeController):
        def preflight(self):
            return {"status": "CAPABILITY_BLOCKED", "reason": "mail capability missing"}

    code, payload = module.run_cli(
        ["--config", str(tmp_path / "config.json"), "preflight"],
        controller_factory=lambda _path: Blocked(),
    )
    assert code == module.EXIT_CAPABILITY
    assert payload["status"] == "CAPABILITY_BLOCKED"
    code, payload = module.run_cli(["not-a-command"])
    assert code == module.EXIT_USAGE
    assert payload["error_code"] == "INVALID_ARGUMENT"
