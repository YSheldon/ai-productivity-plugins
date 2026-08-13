from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
MODULE_PATH = SRC_ROOT / "submission_gate_core.py"
sys.path.insert(0, str(SRC_ROOT))


def _load_module():
    spec = importlib.util.spec_from_file_location("submission_gate_core", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _config() -> dict[str, object]:
    return {
        "command": ["gate-adapter"],
        "preflight_command": ["gate-adapter", "--preflight"],
        "preflight_timeout_seconds": 7,
    }


def test_preflight_timeout_fails_closed_without_raising() -> None:
    module = _load_module()

    def runner(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="gate-adapter", timeout=7)

    result = module.CommandGateAdapter(_config(), runner=runner).preflight()

    assert result["ready"] is False
    assert result["status"] == "CAPABILITY_BLOCKED"
    assert "timed out" in result["reason"].lower()


def test_preflight_requires_explicit_success_envelope() -> None:
    module = _load_module()

    def runner(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["gate-adapter", "--preflight"],
            returncode=0,
            stdout=json.dumps({"result": {"ready": True}}),
            stderr="",
        )

    result = module.CommandGateAdapter(_config(), runner=runner).preflight()

    assert result == {
        "ready": False,
        "status": "CAPABILITY_BLOCKED",
        "reason": "gate adapter preflight did not report explicit success",
    }


def test_preflight_fails_closed_when_imported_adapter_dependency_drifts(
    tmp_path: Path,
) -> None:
    module = _load_module()
    entrypoint = tmp_path / "adapter.py"
    dependency = tmp_path / "release_workflow_core.py"
    entrypoint.write_text("print('adapter')\n", encoding="utf-8")
    dependency.write_text("CONTRACT = 'trusted'\n", encoding="utf-8")

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    config = {
        **_config(),
        "entrypoint_path": str(entrypoint),
        "entrypoint_sha256": digest(entrypoint),
        "integrity_files": [
            {"path": str(entrypoint), "sha256": digest(entrypoint)},
            {"path": str(dependency), "sha256": digest(dependency)},
        ],
    }

    def runner(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["gate-adapter", "--preflight"],
            returncode=0,
            stdout=json.dumps(
                {"ok": True, "result": {"ready": True, "status": "ready"}}
            ),
            stderr="",
        )

    adapter = module.CommandGateAdapter(config, runner=runner)
    assert adapter.preflight()["ready"] is True

    dependency.write_text("CONTRACT = 'tampered'\n", encoding="utf-8")
    blocked = adapter.preflight()

    assert blocked["ready"] is False
    assert blocked["status"] == "CAPABILITY_BLOCKED"
    assert "integrity" in blocked["reason"].lower()
