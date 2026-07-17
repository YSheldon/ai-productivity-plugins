from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "release_approval_cli.py"


def _load_module():
    assert MODULE_PATH.is_file(), f"missing CLI module: {MODULE_PATH}"
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("release_approval_cli", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("release_approval_cli", module)
    spec.loader.exec_module(module)
    return module


class FakeController:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def _result(self, name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((name, args, kwargs))
        return {"status": "ready", "operation": name, "kwargs": kwargs}

    def preflight(self) -> dict[str, Any]:
        return self._result("preflight")

    def run_once(self) -> dict[str, Any]:
        return self._result("run_once")

    def status(self) -> dict[str, Any]:
        return self._result("status")

    def doctor(self) -> dict[str, Any]:
        return self._result("doctor")

    def list_pending(self) -> dict[str, Any]:
        return self._result("list_pending")

    def verify_audit_chain(self) -> dict[str, Any]:
        return self._result("verify_audit_chain")

    def open_page(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("open_page", **kwargs)

    def get_event(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("get_event", **kwargs)


class FakeScheduler:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _result(self, name: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((name, kwargs))
        return {"status": "ready", "operation": f"scheduler.{name}", "kwargs": kwargs}

    def install(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("install", **kwargs)

    def status(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("status", **kwargs)

    def remove(self, **kwargs: Any) -> dict[str, Any]:
        return self._result("remove", **kwargs)


def test_cli_inventory_is_complete_and_has_no_import_time_codex_dependency() -> None:
    module = _load_module()

    assert module.COMMAND_NAMES == (
        "setup",
        "preflight",
        "run-once",
        "status",
        "doctor",
        "list-pending",
        "open-page",
        "get-event",
        "verify-audit",
        "scheduler",
    )
    source = MODULE_PATH.read_text(encoding="utf-8").lower()
    assert "import codex" not in source
    assert "from codex" not in source



def test_cli_uses_the_shared_default_config_when_override_is_omitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_module()
    expected = (tmp_path / "config.json").resolve()
    seen: list[Path] = []
    monkeypatch.setattr(module, "default_config_path", lambda: expected)

    code, payload = module.run_cli(
        ["preflight"],
        controller_factory=lambda path: seen.append(path) or FakeController(),
    )

    assert code == 0
    assert payload["operation"] == "preflight"
    assert seen == [expected]


def test_common_cli_operations_return_the_same_controller_payload(tmp_path: Path) -> None:
    module = _load_module()
    controller = FakeController()
    config_path = tmp_path / "release-approval.json"
    factory_paths: list[Path] = []

    def factory(path: Path) -> FakeController:
        factory_paths.append(path)
        return controller

    cases = {
        "preflight": "preflight",
        "run-once": "run_once",
        "status": "status",
        "doctor": "doctor",
        "list-pending": "list_pending",
        "verify-audit": "verify_audit_chain",
    }
    for command, operation in cases.items():
        code, payload = module.run_cli(
            ["--config", str(config_path), command],
            controller_factory=factory,
        )
        assert code == 0
        assert payload == {"status": "ready", "operation": operation, "kwargs": {}}

    code, payload = module.run_cli(
        [
            "--config",
            str(config_path),
            "get-event",
            "--event-id",
            "event-1",
            "--round-id",
            "2",
        ],
        controller_factory=factory,
    )
    assert code == 0
    assert payload["operation"] == "get_event"
    assert payload["kwargs"] == {"event_id": "event-1", "round_id": 2, "role_id": None}
    assert all(path == config_path.resolve() for path in factory_paths)


def test_open_page_waits_in_the_standalone_process_without_changing_payload(
    tmp_path: Path,
) -> None:
    module = _load_module()
    controller = FakeController()
    waits: list[dict[str, Any]] = []

    def waiter(**kwargs: Any) -> None:
        waits.append(kwargs)

    code, payload = module.run_cli(
        [
            "--config",
            str(tmp_path / "config.json"),
            "open-page",
            "--event-id",
            "event-1",
            "--round-id",
            "1",
        ],
        controller_factory=lambda _path: controller,
        page_waiter=waiter,
    )

    assert code == 0
    assert payload["operation"] == "open_page"
    assert len(waits) == 1
    assert waits[0]["controller"] is controller
    assert waits[0]["page_result"] is payload


def test_scheduler_subcommands_use_one_config_and_structured_payload(tmp_path: Path) -> None:
    module = _load_module()
    scheduler = FakeScheduler()
    config_path = tmp_path / "release-approval.json"

    code, payload = module.run_cli(
        [
            "--config",
            str(config_path),
            "scheduler",
            "install",
            "--mode",
            "systemd",
        ],
        scheduler_factory=lambda path: scheduler if path == config_path.resolve() else None,
    )
    assert code == 0
    assert payload == {
        "status": "ready",
        "operation": "scheduler.install",
        "kwargs": {"mode": "systemd"},
    }

    code, error = module.run_cli(
        [
            "--config",
            str(config_path),
            "scheduler",
            "install",
            "--poll-minutes",
            "30",
        ],
        scheduler_factory=lambda _path: scheduler,
    )
    assert code == module.EXIT_USAGE
    assert error["error_code"] == "INVALID_ARGUMENT"

    for action in ("status", "remove"):
        code, payload = module.run_cli(
            ["--config", str(config_path), "scheduler", action, "--mode", "auto"],
            scheduler_factory=lambda _path: scheduler,
        )
        assert code == 0
        assert payload["operation"] == f"scheduler.{action}"


def test_cli_emits_stable_json_errors_and_exit_codes(tmp_path: Path) -> None:
    module = _load_module()

    class FailingController(FakeController):
        def preflight(self) -> dict[str, Any]:
            raise module.ReleaseApprovalMcpError("INVALID_ARGUMENT", "bad input")

    code, payload = module.run_cli(
        ["--config", str(tmp_path / "config.json"), "preflight"],
        controller_factory=lambda _path: FailingController(),
    )

    assert code == module.EXIT_USAGE
    assert payload == {
        "ok": False,
        "error_code": "INVALID_ARGUMENT",
        "message": "bad input",
    }
    assert json.loads(json.dumps(payload)) == payload

def test_setup_cli_forwards_optional_cloud_audit_url(tmp_path: Path) -> None:
    module = _load_module()
    seen: list[dict[str, Any]] = []

    code, payload = module.run_cli(
        [
            "--config",
            str(tmp_path / "config.json"),
            "setup",
            "--non-interactive",
            "--role-id",
            "release-manager",
            "--release-group",
            "release@example.com",
            "--request-sender-email",
            "release-gate@example.com",
            "--trusted-authserv-ids",
            "mx.example.com",
            "--audit-document-url",
            "https://example.com/audit/doc",
        ],
        setup_runner=lambda **kwargs: seen.append(kwargs) or {"status": "ready"},
    )

    assert code == 0
    assert payload["status"] == "ready"
    assert seen[0]["provided"]["audit_document_url"] == "https://example.com/audit/doc"
    assert seen[0]["provided"]["request_sender_email"] == "release-gate@example.com"
    assert seen[0]["provided"]["trusted_authserv_ids"] == "mx.example.com"
