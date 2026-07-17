from __future__ import annotations

import importlib.util
import inspect
import json
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "src" / "imap_smtp_mail_mcp.py"
SPEC = importlib.util.spec_from_file_location("imap_smtp_mail_mcp_persistence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_config_write_uses_unique_sibling_temp_and_leaves_no_residue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "accounts.json"
    payload = {"accounts": [{"name": "mail-primary", "passwordDpapi": "wrapped"}]}
    monkeypatch.setattr(MODULE, "harden_windows_config_acl", lambda _path: None)

    MODULE.write_config_payload(config_path, payload)

    assert json.loads(config_path.read_text(encoding="utf-8")) == payload
    assert list(tmp_path.glob(f".{config_path.name}.*.tmp")) == []
    source = inspect.getsource(MODULE.write_config_payload)
    assert "NamedTemporaryFile" in source
    assert 'with_suffix(path.suffix + \".tmp\")' not in source


def test_failed_replace_removes_unique_temp_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "accounts.json"
    monkeypatch.setattr(MODULE.os, "replace", lambda _source, _target: (_ for _ in ()).throw(OSError("replace failed")))

    try:
        MODULE.write_config_payload(config_path, {"accounts": []})
    except OSError as exc:
        assert str(exc) == "replace failed"
    else:
        raise AssertionError("write_config_payload must surface replace failures")

    assert list(tmp_path.glob(f".{config_path.name}.*.tmp")) == []
    assert not config_path.exists()

def test_failed_fsync_removes_unique_temp_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "accounts.json"

    def fail_fsync(_file_descriptor: int) -> None:
        raise OSError("fsync failed")

    monkeypatch.setattr(MODULE.os, "fsync", fail_fsync)

    try:
        MODULE.write_config_payload(config_path, {"accounts": []})
    except OSError as exc:
        assert str(exc) == "fsync failed"
    else:
        raise AssertionError("write_config_payload must surface fsync failures")

    assert list(tmp_path.glob(f".{config_path.name}.*.tmp")) == []
    assert not config_path.exists()
