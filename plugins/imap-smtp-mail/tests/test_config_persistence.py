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


def test_acl_failure_preserves_existing_config_and_cleans_temp(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "accounts.json"
    original_payload = {"accounts": [{"name": "existing", "passwordDpapi": "wrapped-old"}]}
    config_path.write_text(json.dumps(original_payload), encoding="utf-8")

    def fail_hardening(_path: Path) -> None:
        raise MODULE.ToolError("ACL unavailable")

    monkeypatch.setattr(MODULE, "harden_windows_config_acl", fail_hardening)

    try:
        MODULE.write_config_payload(config_path, {"accounts": [{"name": "replacement"}]})
    except MODULE.ToolError as exc:
        assert str(exc) == "ACL unavailable"
    else:
        raise AssertionError("write_config_payload must surface ACL hardening failures")

    assert json.loads(config_path.read_text(encoding="utf-8")) == original_payload
    assert list(tmp_path.glob(f".{config_path.name}.*.tmp")) == []


def test_windows_acl_uses_system_root_tools_when_path_is_sparse(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "accounts.json"
    config_path.write_text("{}", encoding="utf-8")
    system32 = tmp_path / "Windows" / "System32"
    system32.mkdir(parents=True)
    whoami = system32 / "whoami.exe"
    icacls = system32 / "icacls.exe"
    whoami.write_text("", encoding="utf-8")
    icacls.write_text("", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(arguments: list[str], **_kwargs):
        calls.append(arguments)
        if Path(arguments[0]).name.casefold() == "whoami.exe":
            return type(
                "Result",
                (),
                {"returncode": 0, "stdout": '"USER","S-1-5-21-111-222-333-444"\\n', "stderr": ""},
            )()
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(MODULE.os, "name", "nt")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "Windows"))
    monkeypatch.delenv("WINDIR", raising=False)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)

    MODULE.harden_windows_config_acl(config_path)

    assert calls[0][0] == str(whoami)
    assert calls[1][0] == str(icacls)


def test_missing_windows_acl_tool_reports_safe_no_save_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(MODULE.os, "name", "nt")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "missing-windows"))
    monkeypatch.delenv("WINDIR", raising=False)

    try:
        MODULE.harden_windows_config_acl(tmp_path / "accounts.json")
    except MODULE.ToolError as exc:
        message = str(exc)
    else:
        raise AssertionError("missing Windows ACL tools must fail safely")

    assert "whoami.exe" in message
    assert "No account configuration was saved" in message
    assert "WinError" not in message


def test_config_path_override_is_used_by_local_account_loading_and_upsert(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = tmp_path / "custom-accounts.json"
    config_path.write_text('{"accounts": []}', encoding="utf-8")
    monkeypatch.setenv("IMAP_SMTP_MAIL_CONFIG", str(config_path))
    monkeypatch.setattr(MODULE, "secure_raw_account_password", lambda account: dict(account))
    monkeypatch.setattr(MODULE, "normalize_account", lambda account: dict(account))
    monkeypatch.setattr(MODULE, "harden_windows_config_acl", lambda _path: None)

    MODULE.upsert_raw_account({"name": "custom"})
    accounts, source = MODULE.load_raw_accounts()

    assert MODULE.configured_config_path() == config_path.resolve()
    assert accounts == [{"name": "custom"}]
    assert source == str(config_path.resolve())


def test_setup_wizard_reports_config_path_override(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "wizard-accounts.json"
    monkeypatch.setenv("IMAP_SMTP_MAIL_CONFIG", str(config_path))
    monkeypatch.setattr(
        MODULE,
        "create_setup_wizard",
        lambda **_kwargs: (None, "http://127.0.0.1:12345/?token=test"),
    )

    result = MODULE.start_setup_wizard({"open_browser": False})

    assert result["structuredContent"]["config_path"] == str(config_path.resolve())


def test_persistence_error_message_does_not_expose_raw_windows_path() -> None:
    message = MODULE.safe_persistence_error_message(
        FileNotFoundError(2, "No such file or directory", "whoami.exe")
    )

    assert "whoami.exe" not in message
    assert "账号未保存" in message
    assert "不要重复提交" in message
