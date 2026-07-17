from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_config import (
    ConfigError,
    default_config_path,
    load_config,
    reject_per_call_config_override,
)


def _base_config() -> dict[str, object]:
    return {
        "role_id": "release-manager",
        "role_email": "release-manager@example.com",
        "mail_account": {
            "profile": "release-manager",
            "email": "release-manager@example.com",
        },
        "request_authentication": {
            "allowed_sender_emails": ["release-gate@example.com"],
            "allowed_authserv_ids": ["mx.example.com"],
            "accepted_paths": ["dmarc", "dkim", "spf"],
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
        "dependency_lock": "%RELEASE_APPROVAL_REPO_ROOT%\\dependency-lock.json",
        "audit": {
            "verify_chain_on_startup": True,
            "retention_days": 3650,
        },
    }



def test_default_config_path_is_shared_and_environment_overridable(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit.json"
    assert default_config_path({"RELEASE_APPROVAL_CONFIG": str(explicit)}) == explicit.resolve()

    local_app_data = tmp_path / "local-app-data"
    assert default_config_path({"LOCALAPPDATA": str(local_app_data)}, platform="win32") == (
        local_app_data / "release-approval" / "config.json"
    ).resolve()

    xdg = tmp_path / "xdg"
    assert default_config_path({"XDG_CONFIG_HOME": str(xdg)}, platform="linux") == (
        xdg / "release-approval" / "config.json"
    ).resolve()


def test_load_config_expands_paths_applies_defaults_and_freezes_required_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv("RELEASE_APPROVAL_REPO_ROOT", str(tmp_path))
    payload = _base_config()
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    config = load_config(config_path)

    assert config.poll_minutes == 60
    assert config.timezone == "Asia/Shanghai"
    assert config.role_id == "release-manager"
    assert config.role_email == "release-manager@example.com"
    assert config.mail_account.email == "release-manager@example.com"
    assert config.request_authentication.allowed_sender_emails == (
        "release-gate@example.com",
    )
    assert config.request_authentication.allowed_authserv_ids == ("mx.example.com",)
    assert config.request_authentication.accepted_paths == ("dmarc", "dkim", "spf")
    assert config.page.host == "127.0.0.1"
    assert config.state_dir == (tmp_path / "state").resolve()
    assert config.dependency_lock == (tmp_path / "dependency-lock.json").resolve()
    assert config.working_hours.days == ("Mon", "Tue", "Wed", "Thu", "Fri")

    with pytest.raises(Exception):
        config.role_id = "other-role"  # type: ignore[misc]


def test_load_config_rejects_unexpanded_environment_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_STATE_ROOT", str(tmp_path))
    monkeypatch.delenv("RELEASE_APPROVAL_REPO_ROOT", raising=False)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_base_config()), encoding="utf-8")

    with pytest.raises(ConfigError, match="unexpanded environment variable"):
        load_config(config_path)


def test_shipped_config_resolves_bootstrap_lock_when_repository_root_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root = tmp_path / "inspected-repository"
    local_app_data = tmp_path / "local-app-data"
    monkeypatch.setenv("RELEASE_APPROVAL_REPO_ROOT", str(repo_root))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))

    config = load_config(PLUGIN_ROOT / "config" / "config.example.json")

    assert config.dependency_lock == (repo_root / "dependency-lock.json").resolve()
    assert config.state_dir == (local_app_data / "release-approval" / "state").resolve()


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
            lambda payload: payload["request_authentication"].__setitem__(
                "allowed_sender_emails", []
            ),
            "allowed_sender_emails must be a non-empty list",
        ),
        (
            lambda payload: payload["request_authentication"].__setitem__(
                "allowed_sender_emails", ["invalid"]
            ),
            "valid email",
        ),
        (
            lambda payload: payload["request_authentication"].__setitem__(
                "accepted_paths", ["trusted_internal"]
            ),
            "unsupported paths",
        ),
        (
            lambda payload: payload["mail_account"].__setitem__("password", "secret"),
            "must not contain passwords",
        ),
        (
            lambda payload: payload["mail_account"].__setitem__("authorization_code", "secret"),
            "must not contain passwords",
        ),
        (
            lambda payload: payload["mail_account"].__setitem__("Access_Token", "secret"),
            "must not contain credentials",
        ),
        (
            lambda payload: payload.__setitem__("client_secret", "secret"),
            "must not contain credentials",
        ),
        (
            lambda payload: payload.__setitem__("Authorization", "Bearer secret"),
            "must not contain credentials",
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
    monkeypatch.setenv("RELEASE_APPROVAL_REPO_ROOT", str(tmp_path))
    payload = _base_config()
    mutator(payload)
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_config(path)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda payload: payload["audit"].__setitem__("verify_chain_on_startup", 1),
            "bool",
        ),
        (
            lambda payload: payload["audit"].__setitem__("verify_chain_on_startup", "true"),
            "bool",
        ),
        (
            lambda payload: payload["audit"].__setitem__("retention_days", True),
            "positive integer",
        ),
        (
            lambda payload: payload["audit"].__setitem__("retention_days", "30"),
            "positive integer",
        ),
        (
            lambda payload: payload["audit"].__setitem__("retention_days", 0),
            "positive integer",
        ),
        (
            lambda payload: payload["working_hours"].__setitem__("days", ["Mon", 2]),
            "strings",
        ),
    ],
)
def test_load_config_rejects_non_strict_audit_and_working_hours_types(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutator,
    message: str,
) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv("RELEASE_APPROVAL_REPO_ROOT", str(tmp_path))
    payload = _base_config()
    mutator(payload)
    path = tmp_path / "invalid-types.json"
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


def test_mcp_manifest_points_at_task6_stdio_server() -> None:
    mcp_payload = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    assert mcp_payload == {
        "mcpServers": {
            "release-approval": {
                "command": "py",
                "args": ["-3", "./src/release_approval_mcp.py"],
                "cwd": ".",
            }
        }
    }


def test_readme_prefers_setup_with_no_manual_json_and_documents_one_config_source() -> None:
    example_payload = json.loads((PLUGIN_ROOT / "config" / "config.example.json").read_text(encoding="utf-8"))
    assert example_payload["dependency_lock"] == "%RELEASE_APPROVAL_REPO_ROOT%\\dependency-lock.json"

    readme_text = (PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")
    assert "release_approval_cli.py setup" in readme_text
    assert "zero manual JSON" in readme_text
    assert "four prompts" in readme_text
    assert "default_config_path" in readme_text
    assert "MCP" in readme_text
    assert "standalone CLI" in readme_text
    assert "OS scheduler" in readme_text
    assert "Codex is optional" in readme_text