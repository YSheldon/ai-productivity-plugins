from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PLUGIN_ROOT.parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from verifier_config import ConfigError, default_config_path, load_config, reject_per_call_config_override


def _base_config() -> dict[str, object]:
    return {
        "mode": "production",
        "role_source": {
            "type": "feishu",
            "document_url": "https://open.feishu.cn/docx/release-role-doc",
        },
        "release_group": "release-approvers@example.com",
        "verifier_mail_account": {
            "profile": "release-verifier",
            "email": "verifier@example.com",
        },
        "working_hours": {
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
            "start": "09:00",
            "end": "18:00",
        },
        "reminder_policy": {
            "initial_delay_minutes": 60,
            "repeat_minutes": 240,
            "maximum": 3,
        },
        "authentication_policy": {
            "accepted_paths": ["dmarc", "dkim", "spf"],
            "allowed_authserv_ids": ["mx.example.com"],
            "trusted_internal_header": "X-Trusted-Relay",
            "trusted_internal_value": "release-gateway",
        },
        "state_dir": "%RELEASE_APPROVAL_VERIFIER_STATE_ROOT%\\state",
        "dependency_lock": "%RELEASE_APPROVAL_REPO_ROOT%\\dependency-lock.json",
        "dependency_lock_sha256": "a" * 64,
        "audit_document": {
            "url": "https://open.feishu.cn/wiki/release-audit",
        },
    }


def test_default_config_path_is_shared_and_environment_overridable(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit.json"
    assert default_config_path({"RELEASE_APPROVAL_VERIFIER_CONFIG": str(explicit)}) == explicit.resolve()

    local_app_data = tmp_path / "local-app-data"
    assert default_config_path({"LOCALAPPDATA": str(local_app_data)}, platform="win32") == (
        local_app_data / "release-approval-verifier" / "config.json"
    ).resolve()

    xdg = tmp_path / "xdg"
    assert default_config_path({"XDG_CONFIG_HOME": str(xdg)}, platform="linux") == (
        xdg / "release-approval-verifier" / "config.json"
    ).resolve()


def test_load_config_expands_paths_applies_defaults_and_freezes_production_role_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_VERIFIER_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv("RELEASE_APPROVAL_REPO_ROOT", str(tmp_path))
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_base_config()), encoding="utf-8")

    config = load_config(config_path)

    assert config.mode == "production"
    assert config.event_expiry_hours == 24
    assert config.poll_minutes == 60
    assert config.timezone == "Asia/Shanghai"
    assert config.role_source.kind == "feishu"
    assert config.role_source.heading == "## 审批角色"
    assert config.verifier_mail_account.email == "verifier@example.com"
    assert config.mailbox == "INBOX"
    assert config.authentication_policy.accepted_paths == ("dmarc", "dkim", "spf")
    assert config.authentication_policy.allowed_authserv_ids == ("mx.example.com",)
    assert config.state_dir == (tmp_path / "state").resolve()
    assert config.dependency_lock == (tmp_path / "dependency-lock.json").resolve()
    assert config.dependency_lock_sha256 == "a" * 64

    with pytest.raises(Exception):
        config.poll_minutes = 30  # type: ignore[misc]


def test_static_roles_are_test_only_and_supported_in_test_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_VERIFIER_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv("RELEASE_APPROVAL_REPO_ROOT", str(tmp_path))

    production_payload = _base_config()
    production_payload["role_source"] = {
        "type": "static",
        "roles": [
            {
                "role_id": "security-reviewer",
                "email": "security-reviewer@example.com",
                "required": True,
                "enabled": True,
            }
        ],
    }
    production_path = tmp_path / "production-static.json"
    production_path.write_text(json.dumps(production_payload), encoding="utf-8")

    with pytest.raises(ConfigError, match="test-only"):
        load_config(production_path)

    test_payload = _base_config()
    test_payload["mode"] = "test"
    test_payload["role_source"] = production_payload["role_source"]
    test_path = tmp_path / "test-static.json"
    test_path.write_text(json.dumps(test_payload), encoding="utf-8")

    config = load_config(test_path)
    assert config.mode == "test"
    assert config.role_source.kind == "static"
    assert tuple(role.role_id for role in config.role_source.roles) == ("security-reviewer",)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda payload: payload["verifier_mail_account"].__setitem__("password", "secret"),
            "must not contain passwords",
        ),
        (
            lambda payload: payload["verifier_mail_account"].__setitem__("Access_Token", "secret"),
            "must not contain credentials",
        ),
        (
            lambda payload: payload.__setitem__("client_secret", "secret"),
            "must not contain credentials",
        ),
        (
            lambda payload: payload["authentication_policy"].__setitem__("accepted_paths", []),
            "accepted_paths",
        ),
        (
            lambda payload: payload["authentication_policy"].__setitem__("allowed_authserv_ids", []),
            "allowed_authserv_ids",
        ),
        (
            lambda payload: payload.__setitem__("event_expiry_hours", "24"),
            "positive integer",
        ),
        (
            lambda payload: payload.__setitem__("event_expiry_hours", 0),
            "positive integer",
        ),
        (
            lambda payload: payload.__setitem__("poll_minutes", 4),
            "5..1440",
        ),
        (
            lambda payload: payload["role_source"].__setitem__("document_url", ""),
            "document_url",
        ),
        (
            lambda payload: payload["role_source"].__setitem__("document_url", "not-a-url"),
            "absolute HTTP",
        ),
        (
            lambda payload: payload["audit_document"].__setitem__("url", "file:///tmp/audit"),
            "absolute HTTP",
        ),
        (
            lambda payload: payload["authentication_policy"].__setitem__("accepted_paths", ["unknown"]),
            "unsupported",
        ),
        (
            lambda payload: payload.__setitem__("dependency_lock_sha256", "not-a-digest"),
            "lowercase SHA-256",
        ),
    ],
)
def test_load_config_rejects_invalid_runtime_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutator,
    message: str,
) -> None:
    monkeypatch.setenv("RELEASE_APPROVAL_VERIFIER_STATE_ROOT", str(tmp_path))
    monkeypatch.setenv("RELEASE_APPROVAL_REPO_ROOT", str(tmp_path))
    payload = _base_config()
    mutator(payload)
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_runtime_copies_match_canonical_bytes_and_document_production_role_source() -> None:
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

    plugin_payload = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert plugin_payload["name"] == "release-approval-verifier"

    mcp_payload = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    assert "release-approval-verifier" in mcp_payload["mcpServers"]

    example_payload = json.loads((PLUGIN_ROOT / "config" / "config.example.json").read_text(encoding="utf-8"))
    assert example_payload["role_source"]["type"] == "feishu"
    assert example_payload["role_source"]["heading"] == "## 审批角色"

    readme_text = (PLUGIN_ROOT / "README.md").read_text(encoding="utf-8")
    assert "Feishu role document" in readme_text
    assert "Static roles are test-only" in readme_text
