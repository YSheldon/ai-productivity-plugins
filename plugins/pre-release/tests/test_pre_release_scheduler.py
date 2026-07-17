from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "pre_release_scheduler.py"


def _load_module():
    sys.path.insert(0, str(SRC_ROOT))
    spec = importlib.util.spec_from_file_location("pre_release_scheduler", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("pre_release_scheduler", module)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def completed(command: list[str], returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


WINDOWS_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>false</StartWhenAvailable>
  </Settings>
</Task>
"""


def test_windows_scheduler_install_and_status(tmp_path: Path) -> None:
    module = _load_module()
    calls: list[list[str]] = []

    def runner(command: list[str], cwd: str | None, input_text: str | None):
        del cwd, input_text
        calls.append(list(command))
        if command[:2] == ["schtasks", "/Query"]:
            return completed(command, stdout=WINDOWS_XML)
        return completed(command)

    scheduler = module.PreReleaseScheduler(
        config_path=tmp_path / "config.json",
        state_dir=tmp_path / "state",
        poll_minutes=60,
        platform="win32",
        which=lambda _name: None,
        runner=runner,
        user_config_root=tmp_path / "config-root",
    )
    result = scheduler.install(mode="windows")
    assert result["mode"] == "windows"
    assert any(command[:2] == ["schtasks", "/Create"] for command in calls)
