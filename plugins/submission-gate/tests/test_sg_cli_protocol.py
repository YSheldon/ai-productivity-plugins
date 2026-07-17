from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "submission_gate_cli.py"
sys.path.insert(0, str(SRC_ROOT))


def _load_module():
    spec = importlib.util.spec_from_file_location("submission_gate_cli", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeController:
    def preflight(self):
        return {"ready": True}

    def run_once(self):
        return {"status": "ready", "processed": 0, "passed": 0, "blocked": 0, "skipped": 0}

    def status(self):
        return {"status": "ready", "processed_mail": 0}

    def doctor(self):
        return {"ready": True}

    def get_event(self, *, event_id: str, round_id: int):
        return {"event": {"event_id": event_id, "round_id": round_id}}


class FakeScheduler:
    def install(self, *, mode: str):
        return {"status": "ready", "mode": mode}

    def status(self, *, mode: str):
        return {"status": "ready", "mode": mode}

    def remove(self, *, mode: str):
        return {"status": "ready", "mode": mode}


def test_cli_inventory_is_complete_and_has_no_import_time_codex_dependency() -> None:
    module = _load_module()
    assert module.COMMAND_NAMES == (
        "setup",
        "preflight",
        "run-once",
        "status",
        "doctor",
        "verify-audit",
        "get-event",
        "scheduler",
    )
    source = MODULE_PATH.read_text(encoding="utf-8").lower()
    assert "import codex" not in source
    assert "from codex" not in source


def test_common_cli_operations_return_structured_payload(tmp_path: Path) -> None:
    module = _load_module()
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"scheduler_mode": "auto"}), encoding="utf-8")
    output = io.StringIO()
    code = module.run_cli(
        ["--config", str(config_path), "run-once"],
        stdout=output,
        controller_factory=lambda _path: FakeController(),
        scheduler_factory=lambda _path: FakeScheduler(),
        setup_runner=lambda **_kwargs: {"status": "ready"},
    )
    assert code == module.EXIT_OK
    payload = json.loads(output.getvalue())
    assert payload["result"]["processed"] == 0
