from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "runner_manager_credentials.py"


def load_module():
    spec = importlib.util.spec_from_file_location("gitlab_runner_manager_credentials_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_credential_target_is_policy_bound() -> None:
    module = load_module()

    assert module.credential_target("product-material-gate") == (
        "CodexGitLab/runner-manager/v1/product-material-gate"
    )
    with pytest.raises(module.RunnerManagerCredentialError):
        module.credential_target("Product Material Gate")


@pytest.mark.parametrize(
    "target",
    (
        "arbitrary-target",
        "CodexGitLab/runner-manager/v1/product-material-gate/other",
    ),
)
def test_credential_store_rejects_noncanonical_targets(target: str) -> None:
    module = load_module()

    with pytest.raises(module.RunnerManagerCredentialError, match="credential target"):
        module._normalize_target(target)


@pytest.mark.parametrize("token", ("", "contains\nnewline", "\x7fcontrol", "a" * 8193))
def test_token_validation_rejects_unsafe_or_oversize_values(token: str) -> None:
    module = load_module()

    with pytest.raises(module.RunnerManagerCredentialError):
        module.validate_token(token)


def test_token_validation_returns_non_secret_value_only_to_caller() -> None:
    module = load_module()

    assert module.validate_token("token-value") == "token-value"


def test_windows_credential_store_fails_closed_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    monkeypatch.setattr(module.os, "name", "posix")
    store = module.WindowsCredentialStore()
    target = module.credential_target("product-material-gate")

    with pytest.raises(module.RunnerManagerCredentialError, match="unavailable"):
        store.read(target)