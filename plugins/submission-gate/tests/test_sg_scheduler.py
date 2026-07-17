from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "submission_gate_scheduler.py"
sys.path.insert(0, str(SRC_ROOT))


def _load_module():
    spec = importlib.util.spec_from_file_location("submission_gate_scheduler", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_default_runner_uses_argument_arrays_without_shell(monkeypatch) -> None:  # noqa: ANN001
    module = _load_module()
    seen: dict[str, object] = {}

    def fake_run(*args, **kwargs):  # noqa: ANN001
        seen["args"] = args
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0, stdout="{}", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module.run_command(["py", "-3", "submission_gate_cli.py", "run-once"], cwd="C:\\state", input_text="payload")

    assert seen["args"][0] == ["py", "-3", "submission_gate_cli.py", "run-once"]
    assert seen["kwargs"]["cwd"] == "C:\\state"
    assert seen["kwargs"]["input"] == "payload"
    assert seen["kwargs"]["shell"] is False
