from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "test_submission_cli.py"
sys.path.insert(0, str(SRC_ROOT))


def _load_module():
    spec = importlib.util.spec_from_file_location("test_submission_cli", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeController:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def preflight(self) -> dict[str, Any]:
        self.calls.append(("preflight", None))
        return {"ready": True}

    def submit(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("submit", payload))
        return {"status": "SUBMITTED", "module": payload["module"]}

    def run_once(self) -> dict[str, Any]:
        self.calls.append(("run_once", None))
        return {"status": "ready", "retried": 0, "sent": 0}

    def status(self) -> dict[str, Any]:
        self.calls.append(("status", None))
        return {"status": "ready", "events": 1}

    def doctor(self) -> dict[str, Any]:
        self.calls.append(("doctor", None))
        return {"ready": True}

    def get_event(self, *, event_id: str, round_id: int) -> dict[str, Any]:
        self.calls.append(("get_event", {"event_id": event_id, "round_id": round_id}))
        return {"event": {"event_id": event_id, "round_id": round_id}}


class FakeScheduler:
    def install(self, *, mode: str) -> dict[str, Any]:
        return {"status": "ready", "mode": mode}

    def status(self, *, mode: str) -> dict[str, Any]:
        return {"status": "ready", "mode": mode}

    def remove(self, *, mode: str) -> dict[str, Any]:
        return {"status": "ready", "mode": mode}


def test_cli_inventory_is_complete_and_has_no_import_time_codex_dependency() -> None:
    module = _load_module()
    assert module.COMMAND_NAMES == (
        "setup",
        "preflight",
        "submit",
        "run-once",
        "status",
        "doctor",
        "get-event",
        "scheduler",
    )
    source = MODULE_PATH.read_text(encoding="utf-8").lower()
    assert "import codex" not in source
    assert "from codex" not in source


def test_submit_requires_explicit_module_and_uses_single_json_payload(tmp_path: Path) -> None:
    module = _load_module()
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"scheduler_mode": "auto"}), encoding="utf-8")
    controller = FakeController()
    output = io.StringIO()

    code = module.run_cli(
        [
            "--config",
            str(config_path),
            "submit",
            "--input",
            json.dumps({"task_name": "TASK-1", "module": "kernel", "artifacts": []}),
        ],
        stdout=output,
        controller_factory=lambda _path: controller,
        scheduler_factory=lambda _path: FakeScheduler(),
        setup_runner=lambda **_kwargs: {"status": "ready"},
    )

    assert code == module.EXIT_OK
    payload = json.loads(output.getvalue())
    assert payload["result"]["module"] == "kernel"
    assert controller.calls == [("submit", {"task_name": "TASK-1", "module": "kernel", "artifacts": []})]
