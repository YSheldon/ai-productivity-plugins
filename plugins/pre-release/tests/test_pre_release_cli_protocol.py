from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "pre_release_cli.py"


def _load_module():
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("pre_release_cli", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("pre_release_cli", module)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeController:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _result(self, name: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((name, kwargs))
        return {"status": "ready", "operation": name, "kwargs": kwargs}

    def preflight(self) -> dict[str, Any]:
        return self._result("preflight")

    def run_once(self) -> dict[str, Any]:
        return self._result("run_once")

    def status(self) -> dict[str, Any]:
        return self._result("status")

    def doctor(self) -> dict[str, Any]:
        return self._result("doctor")

    def verify_audit(self) -> dict[str, Any]:
        return {"status": "ready", "valid": True, "operation": "verify_audit"}

    def list_tasks(self) -> dict[str, Any]:
        return self._result("list_tasks")

    def create_request(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("create_request", **kwargs)


class FakeScheduler:
    def install(self, **kwargs: Any) -> dict[str, Any]:
        return {"status": "ready", "operation": "scheduler.install", "kwargs": kwargs}

    def status(self, **kwargs: Any) -> dict[str, Any]:
        return {"status": "ready", "operation": "scheduler.status", "kwargs": kwargs}

    def remove(self, **kwargs: Any) -> dict[str, Any]:
        return {"status": "ready", "operation": "scheduler.remove", "kwargs": kwargs}


def test_cli_inventory_and_common_operations(tmp_path: Path) -> None:
    module = _load_module()
    assert module.COMMAND_NAMES == (
        "setup",
        "preflight",
        "run-once",
        "status",
        "doctor",
        "verify-audit",
        "list-tasks",
        "create-request",
        "scheduler",
    )
    controller = FakeController()
    for command, operation in {
        "preflight": "preflight",
        "run-once": "run_once",
        "status": "status",
        "doctor": "doctor",
        "list-tasks": "list_tasks",
    }.items():
        code, payload = module.run_cli(
            ["--config", str(tmp_path / "config.json"), command],
            controller_factory=lambda _path: controller,
        )
        assert code == 0
        assert payload["operation"] == operation

    code, payload = module.run_cli(
        ["--config", str(tmp_path / "config.json"), "verify-audit"],
        controller_factory=lambda _path: controller,
    )
    assert code == 0
    assert payload["valid"] is True

    code, payload = module.run_cli(
        [
            "--config",
            str(tmp_path / "config.json"),
            "create-request",
            "--event-id",
            "evt-1",
            "--round-id",
            "2",
            "--test-result",
            "PASS",
            "--summary",
            "ok",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        controller_factory=lambda _path: controller,
    )
    assert code == 0
    assert payload["operation"] == "create_request"
    assert payload["kwargs"]["round_id"] == 2


def test_cli_scheduler_and_setup_payloads(tmp_path: Path) -> None:
    module = _load_module()
    scheduler = FakeScheduler()
    code, payload = module.run_cli(
        ["--config", str(tmp_path / "config.json"), "scheduler", "install", "--mode", "systemd"],
        scheduler_factory=lambda _path: scheduler,
    )
    assert code == 0
    assert payload["operation"] == "scheduler.install"

    seen: list[dict[str, Any]] = []
    code, payload = module.run_cli(
        [
            "--config",
            str(tmp_path / "config.json"),
            "setup",
            "--non-interactive",
            "--mail-profile",
            "qa-owner",
        ],
        setup_runner=lambda **kwargs: seen.append(kwargs) or {"status": "ready"},
    )
    assert code == 0
    assert payload["status"] == "ready"
    assert seen[0]["provided"]["mail_profile"] == "qa-owner"
