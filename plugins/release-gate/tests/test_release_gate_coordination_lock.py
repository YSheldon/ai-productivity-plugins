from __future__ import annotations

import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_gate_controller import ReleaseGateController
from release_workflow_gate_lock import RunOnceLock
from test_release_gate_controller import FakeMailGateway, FakeProductGate, _config


def test_duplicate_mailbox_configs_share_host_coordination_lock(tmp_path: Path, monkeypatch) -> None:
    coordination_root = tmp_path / "coordination"
    monkeypatch.setenv("RELEASE_GATE_COORDINATION_DIR", str(coordination_root))
    monkeypatch.delenv("RELEASE_GATE_COORDINATION_SCOPE", raising=False)
    first = ReleaseGateController(
        _config(tmp_path / "first"),
        mail_gateway=FakeMailGateway([]),
        product_gate=FakeProductGate(),
    )
    second = ReleaseGateController(
        _config(tmp_path / "second"),
        mail_gateway=FakeMailGateway([]),
        product_gate=FakeProductGate(),
    )
    assert first.coordination_lock_path() == second.coordination_lock_path()
    lock = RunOnceLock(first.coordination_lock_path())
    assert lock.acquire()["status"] == "acquired"
    try:
        result = second.run_once()
    finally:
        lock.release()
    assert result == {"status": "RUN_ALREADY_ACTIVE", "busy": True, "scope": "host"}


def test_host_coordination_lock_is_default_even_for_distinct_mailboxes(tmp_path: Path, monkeypatch) -> None:
    coordination_root = tmp_path / "coordination"
    monkeypatch.setenv("RELEASE_GATE_COORDINATION_DIR", str(coordination_root))
    monkeypatch.delenv("RELEASE_GATE_COORDINATION_SCOPE", raising=False)
    first = ReleaseGateController(_config(tmp_path / "first"), mail_gateway=FakeMailGateway([]), product_gate=FakeProductGate())
    second_config = _config(tmp_path / "second")
    second_config = second_config.__class__(**{**second_config.__dict__, "mailbox": "ARCHIVE", "release_gate_group": "other@example.com"})
    second = ReleaseGateController(second_config, mail_gateway=FakeMailGateway([]), product_gate=FakeProductGate())
    assert first.coordination_lock_path() == second.coordination_lock_path()


def test_mailbox_coordination_scope_is_explicit_opt_in(tmp_path: Path, monkeypatch) -> None:
    coordination_root = tmp_path / "coordination"
    monkeypatch.setenv("RELEASE_GATE_COORDINATION_DIR", str(coordination_root))
    monkeypatch.delenv("RELEASE_GATE_COORDINATION_SCOPE", raising=False)
    monkeypatch.setenv("RELEASE_GATE_COORDINATION_SCOPE", "mailbox")
    first = ReleaseGateController(_config(tmp_path / "first"), mail_gateway=FakeMailGateway([]), product_gate=FakeProductGate())
    second_config = _config(tmp_path / "second")
    second_config = second_config.__class__(**{**second_config.__dict__, "mailbox": "ARCHIVE", "release_gate_group": "other@example.com"})
    second = ReleaseGateController(second_config, mail_gateway=FakeMailGateway([]), product_gate=FakeProductGate())
    assert first.coordination_lock_path() != second.coordination_lock_path()
