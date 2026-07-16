from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_config import ConfigError, load_config, reject_per_call_config_override


def _base_config() -> dict[str, object]:
    return {
        "role_id": "release-manager",
        "role_email": "release-manager@example.com",
        "mail_account": {
            "profile": "release-manager",
            "email": "release-manager@example.com",
        },
        "release_group": "release-approvers",
        "mailbox": "INBOX",
        "page": {
            "host": "127.0.0.1",
            "port": 8765,
        },
        "working_hours": {
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
            "start": "09:00",
            "end": "18:00",
        },
        "state_dir": "%RELEASE_APPROVAL_STATE_ROOT%\\state",
        "dependency_lock": "~/.codex/release-approval/dependency-lock.json",
        "audit": {
            "verify_chain_on_startup": True,
            "retention_days": 3650,
        },
    }


def test_load_config_expands_paths_applies_defaults_and_freezes_required_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_STATE_ROOT", str(tmp_path))
    payload = _base_config()
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    config = load_config(config_path)

    assert config.poll_minutes == 60
    assert config.timezone == "Asia/Shanghai"
    assert config.role_id == "release-manager"
    assert config.role_email == "release-manager@example.com"
    assert config.mail_account.email == "release-manager@example.com"
    assert config.page.host == "127.0.0.1"
    assert config.state_dir == (tmp_path / "state").resolve()
    assert config.dependency_lock == (Path.home() / ".codex" / "release-approval" / "dependency-lock.json").resolve()
    assert config.working_hours.days == ("Mon", "Tue", "Wed", "Thu", "Fri")

    with pytest.raises(Exception):
        config.role_id = "other-role"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda payload: payload["page"].__setitem__("host", "example.com"), "loopback"),
        (lambda payload: payload.__setitem__("poll_minutes", 4), "5..1440"),
        (lambda payload: payload.__setitem__("role_email", "invalid-email"), "valid email"),
        (
            lambda payload: payload["mail_account"].__setitem__("email", "different@example.com"),
            "must match role_email",
        ),
        (
            lambda payload: payload["mail_account"].__setitem__("password", "secret"),
            "must not contain passwords",
        ),
        (
            lambda payload: payload["mail_account"].__setitem__("authorization_code", "secret"),
            "must not contain passwords",
        ),
    ],
)
def test_load_config_rejects_invalid_runtime_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutator,
    message: str,
) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_STATE_ROOT", str(tmp_path))
    payload = _base_config()
    mutator(payload)
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_rejects_per_call_config_override_and_preserves_exact_runtime_copies() -> None:
    with pytest.raises(ConfigError, match="cannot be supplied per call"):
        reject_per_call_config_override({"config_path": "C:\\evil.json"})

    assert (
        (PLUGIN_ROOT / "scripts" / "bootstrap_dependencies.py").read_bytes()
        == (REPO_ROOT / "tools" / "release_workflow_bootstrap.py").read_bytes()
    )

    contract_root = REPO_ROOT / "contracts" / "release-approval"
    plugin_contract_root = PLUGIN_ROOT / "contracts"
    for name in (
        "release-authorization-request-v1.json",
        "approval-decision-v1.json",
        "approval-verification-receipt-v1.json",
    ):
        assert (plugin_contract_root / name).read_bytes() == (contract_root / name).read_bytes()

def test_mcp_scaffold_is_empty_until_task6_server_exists() -> None:
    mcp_payload = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    assert mcp_payload == {"mcpServers": {}}
