import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_config import (  # noqa: E402
    ConfigError,
    default_config_path,
    load_config,
    reject_per_call_config_override,
)


def valid_config(tmp_path: Path) -> dict:
    return {
        "schema_version": 1,
        "governance_inbox": str(tmp_path / "inbox"),
        "state_dir": str(tmp_path / "state"),
        "poll_minutes": 60,
        "timezone": "Asia/Shanghai",
        "tool_profiles": [
            "imap-smtp-mail",
            "gitlab",
            "lark-cli",
            "product-release-gate",
        ],
        "approved_agent_profiles": ["approved-agent"],
        "agent_profile": "approved-agent",
        "protected_merge": {
            "tool_profile": "gitlab",
            "protected_branch_required": True,
        },
        "notification": {
            "mail_profile": "corp-mail",
            "recipients": ["governance@example.com"],
        },
        "decision_role_source": None,
        "dependency_lock": str(tmp_path / "dependency-lock.json"),
    }


def write_config(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_loads_one_versioned_config_for_all_surfaces(tmp_path):
    config = load_config(write_config(tmp_path, valid_config(tmp_path)))
    assert config.schema_version == 1
    assert config.poll_minutes == 60
    assert config.agent_profile == "approved-agent"
    assert config.audit_dir == (tmp_path / "state" / "audit").resolve()
    assert config.database_path == (tmp_path / "state" / "rd-flywheel.sqlite3").resolve()
    assert config.protected_merge.protected_branch_required is True


@pytest.mark.parametrize(
    "secret_key",
    ["password", "TOKEN", "api-key", "clientSecret", "authorization_code", "smtp_password"],
)
def test_config_rejects_credentials_recursively(tmp_path, secret_key):
    payload = valid_config(tmp_path)
    payload["nested"] = {secret_key: "must-not-be-persisted"}
    with pytest.raises(ConfigError, match="credentials"):
        load_config(write_config(tmp_path, payload))


def test_agent_profile_must_be_approved(tmp_path):
    payload = valid_config(tmp_path)
    payload["agent_profile"] = "unapproved-agent"
    with pytest.raises(ConfigError, match="approved_agent_profiles"):
        load_config(write_config(tmp_path, payload))


@pytest.mark.parametrize("minutes", [0, 4, 1441, "60"])
def test_poll_interval_is_bounded(tmp_path, minutes):
    payload = valid_config(tmp_path)
    payload["poll_minutes"] = minutes
    with pytest.raises(ConfigError, match="poll_minutes"):
        load_config(write_config(tmp_path, payload))


def test_tool_profiles_are_unique_and_protected_merge_profile_is_present(tmp_path):
    payload = valid_config(tmp_path)
    payload["tool_profiles"].append("gitlab")
    with pytest.raises(ConfigError, match="unique"):
        load_config(write_config(tmp_path, payload))

    payload = valid_config(tmp_path)
    payload["tool_profiles"].remove("gitlab")
    with pytest.raises(ConfigError, match="protected_merge"):
        load_config(write_config(tmp_path, payload))


def test_default_path_is_platform_native_and_environment_overridable(tmp_path):
    win = default_config_path(
        {"LOCALAPPDATA": str(tmp_path)},
        platform="win32",
    )
    assert win == (tmp_path / "rd-flywheel" / "config.json").resolve()

    explicit = default_config_path(
        {"RD_FLYWHEEL_CONFIG": str(tmp_path / "managed.json")},
        platform="win32",
    )
    assert explicit == (tmp_path / "managed.json").resolve()


def test_mcp_cannot_override_config_per_call():
    with pytest.raises(ConfigError, match="cannot be supplied per call"):
        reject_per_call_config_override({"config_path": "other.json"})


def test_unknown_schema_version_fails_closed(tmp_path):
    payload = valid_config(tmp_path)
    payload["schema_version"] = 2
    with pytest.raises(ConfigError, match="schema_version"):
        load_config(write_config(tmp_path, payload))
