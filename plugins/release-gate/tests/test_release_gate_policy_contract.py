from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_config import (  # noqa: E402
    CANONICAL_REQUIRED_CHECKS,
    ConfigError,
    load_config,
    missing_canonical_required_checks,
)


def test_config_example_pins_canonical_required_checks() -> None:
    payload = json.loads((PLUGIN_ROOT / "config" / "config.example.json").read_text(encoding="utf-8"))
    assert tuple(payload["policy"]["required_checks"]) == CANONICAL_REQUIRED_CHECKS


def test_load_config_fails_closed_when_any_canonical_required_check_is_removed(
    tmp_path: Path,
) -> None:
    payload = json.loads((PLUGIN_ROOT / "config" / "config.example.json").read_text(encoding="utf-8"))
    payload["state_dir"] = str(tmp_path / "state")
    payload["dependency_lock"] = str(tmp_path / "lock.json")
    payload["shared_hmac_secret_path"] = str(tmp_path / "secret.key")
    payload["product_gate"]["config_path"] = str(tmp_path / "gate.json")
    payload["required_checks"] = [] if False else payload["policy"]["required_checks"]
    payload["policy"]["required_checks"] = [check for check in payload["policy"]["required_checks"] if check != "manifest"]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfigError, match="canonical required checks"):
        load_config(config_path)
    assert missing_canonical_required_checks(tuple(payload["policy"]["required_checks"])) == ("manifest",)
