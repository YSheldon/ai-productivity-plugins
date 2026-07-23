from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


CLI_PATH = Path(__file__).resolve().parents[1] / "scripts" / "runner_admin_cli.py"


def load_cli():
    spec = importlib.util.spec_from_file_location("gitlab_runner_admin_cli_test", CLI_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tool_result(payload: dict) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(payload)}]}


class FakeCredentialStore:
    def __init__(self, values: dict[str, str] | None = None, *, delete_fails: bool = False) -> None:
        self.values = dict(values or {})
        self.delete_fails = delete_fails

    def read(self, target: str) -> str | None:
        return self.values.get(target)

    def write(self, target: str, value: str) -> None:
        self.values[target] = value

    def delete(self, target: str) -> bool:
        if self.delete_fails:
            raise RuntimeError("delete failed")
        return self.values.pop(target, None) is not None


def fake_credentials(store: FakeCredentialStore):
    def validate_token(value: object) -> str:
        token = str(value or "")
        if not token:
            raise RuntimeError("token is invalid")
        return token

    return SimpleNamespace(
        credential_target=lambda policy_name: f"CodexGitLab/runner-manager/v1/{policy_name}",
        validate_token=validate_token,
        WindowsCredentialStore=lambda: store,
    )


def clear_gitlab_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "GITLAB_TOKEN",
        "GITLAB_URL",
        "GITLAB_CONFIG",
        "GITLAB_PROFILE",
        "GITLAB_TOKEN_ENV",
    ):
        monkeypatch.delenv(name, raising=False)


def test_non_admin_fails_before_server_load(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    module = load_cli()
    monkeypatch.setattr(module, "_is_windows_administrator", lambda: False)
    monkeypatch.setattr(
        module,
        "_load_server",
        lambda: pytest.fail("server must not load before administrator verification"),
    )

    assert module.main(["provision", "--policy-name", "product-material-gate"]) == 2
    assert "elevated Windows process" in capsys.readouterr().err


def test_ready_result_uses_only_policy_bound_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    module = load_cli()
    captured = []

    def provision(arguments):
        captured.append(arguments)
        return tool_result({"ready": True, "stage": "ready"})

    server = SimpleNamespace(
        provision_windows_project_runner=provision,
        resume_windows_project_runner=lambda _arguments: pytest.fail("wrong handler"),
    )
    monkeypatch.setattr(module, "_is_windows_administrator", lambda: True)
    monkeypatch.setattr(module, "_load_server", lambda: server)
    monkeypatch.setenv("GITLAB_TOKEN", "environment-token")

    assert module.main(
        [
            "provision",
            "--policy-name",
            "product-material-gate",
            "--profile",
            "production",
        ]
    ) == 0
    assert captured == [{"policy_name": "product-material-gate", "profile": "production"}]
    assert json.loads(capsys.readouterr().out) == {"ready": True, "stage": "ready"}


def test_token_set_uses_hidden_input_and_never_prints_value(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    module = load_cli()
    store = FakeCredentialStore()
    credentials = fake_credentials(store)
    monkeypatch.setattr(module, "_is_windows_administrator", lambda: True)
    monkeypatch.setattr(module, "_load_credentials", lambda: credentials)
    monkeypatch.setattr(module.getpass, "getpass", lambda _prompt: "manager-token")
    monkeypatch.setattr(
        module,
        "_load_server",
        lambda: pytest.fail("token-set must not load the GitLab server"),
    )

    assert module.main(["token-set", "--policy-name", "product-material-gate"]) == 0
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert payload == {
        "action": "token-set",
        "credential_target": "CodexGitLab/runner-manager/v1/product-material-gate",
        "replaced": False,
        "token_present": True,
        "token_value_returned": False,
    }
    assert "manager-token" not in output.out + output.err
    assert store.values == {
        "CodexGitLab/runner-manager/v1/product-material-gate": "manager-token"
    }


def test_lifecycle_reads_managed_token_only_temporarily_and_clears_on_ready(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    module = load_cli()
    target = "CodexGitLab/runner-manager/v1/product-material-gate"
    store = FakeCredentialStore({target: "manager-token"})
    credentials = fake_credentials(store)
    captured: list[dict[str, object]] = []

    def provision(arguments):
        captured.append(
            {
                "arguments": dict(arguments),
                "token": os.environ.get("GITLAB_TOKEN"),
                "url": os.environ.get("GITLAB_URL"),
            }
        )
        return tool_result({"ready": True, "stage": "ready"})

    server = SimpleNamespace(
        provision_windows_project_runner=provision,
        resume_windows_project_runner=lambda _arguments: pytest.fail("wrong handler"),
        load_windows_runner_policy=lambda _name, **_kwargs: {
            "gitlab_url": "https://gitlab.example.test"
        },
    )
    clear_gitlab_environment(monkeypatch)
    monkeypatch.setattr(module, "_is_windows_administrator", lambda: True)
    monkeypatch.setattr(module, "_load_credentials", lambda: credentials)
    monkeypatch.setattr(module, "_load_server", lambda: server)

    assert module.main(["provision", "--policy-name", "product-material-gate"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert captured == [
        {
            "arguments": {"policy_name": "product-material-gate"},
            "token": "manager-token",
            "url": "https://gitlab.example.test",
        }
    ]
    assert "GITLAB_TOKEN" not in os.environ
    assert "GITLAB_URL" not in os.environ
    assert store.values == {}
    assert payload["runner_manager_credential"] == {
        "source": "windows_credential_manager",
        "credential_target": target,
        "status": "cleared_after_ready",
        "token_value_returned": False,
    }


def test_non_ready_lifecycle_retains_managed_token_for_resume(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    module = load_cli()
    target = "CodexGitLab/runner-manager/v1/product-material-gate"
    store = FakeCredentialStore({target: "manager-token"})
    credentials = fake_credentials(store)
    server = SimpleNamespace(
        provision_windows_project_runner=lambda _arguments: tool_result(
            {"ready": False, "stage": "registered_paused"}
        ),
        resume_windows_project_runner=lambda _arguments: pytest.fail("wrong handler"),
        load_windows_runner_policy=lambda _name, **_kwargs: {
            "gitlab_url": "https://gitlab.example.test"
        },
    )
    clear_gitlab_environment(monkeypatch)
    monkeypatch.setattr(module, "_is_windows_administrator", lambda: True)
    monkeypatch.setattr(module, "_load_credentials", lambda: credentials)
    monkeypatch.setattr(module, "_load_server", lambda: server)

    assert module.main(["provision", "--policy-name", "product-material-gate"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert store.values[target] == "manager-token"
    assert payload["runner_manager_credential"]["status"] == "retained_for_resume"


def test_ready_lifecycle_with_cleanup_failure_is_not_security_ready(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    module = load_cli()
    target = "CodexGitLab/runner-manager/v1/product-material-gate"
    store = FakeCredentialStore({target: "manager-token"}, delete_fails=True)
    credentials = fake_credentials(store)
    server = SimpleNamespace(
        provision_windows_project_runner=lambda _arguments: tool_result(
            {"ready": True, "stage": "ready"}
        ),
        resume_windows_project_runner=lambda _arguments: pytest.fail("wrong handler"),
        load_windows_runner_policy=lambda _name, **_kwargs: {
            "gitlab_url": "https://gitlab.example.test"
        },
    )
    clear_gitlab_environment(monkeypatch)
    monkeypatch.setattr(module, "_is_windows_administrator", lambda: True)
    monkeypatch.setattr(module, "_load_credentials", lambda: credentials)
    monkeypatch.setattr(module, "_load_server", lambda: server)

    assert module.main(["provision", "--policy-name", "product-material-gate"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["security_ready"] is False
    assert payload["runner_manager_credential"]["status"] == "cleanup_failed"


def test_lifecycle_failure_redacts_managed_token(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    module = load_cli()
    target = "CodexGitLab/runner-manager/v1/product-material-gate"
    store = FakeCredentialStore({target: "manager-token"})
    credentials = fake_credentials(store)

    def sanitize(value: str, *, secrets=()) -> str:
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        return value

    server = SimpleNamespace(
        provision_windows_project_runner=lambda _arguments: (_ for _ in ()).throw(
            RuntimeError("backend rejected manager-token")
        ),
        resume_windows_project_runner=lambda _arguments: pytest.fail("wrong handler"),
        load_windows_runner_policy=lambda _name, **_kwargs: {
            "gitlab_url": "https://gitlab.example.test"
        },
        sanitize_error_text=sanitize,
    )
    clear_gitlab_environment(monkeypatch)
    monkeypatch.setattr(module, "_is_windows_administrator", lambda: True)
    monkeypatch.setattr(module, "_load_credentials", lambda: credentials)
    monkeypatch.setattr(module, "_load_server", lambda: server)

    assert module.main(["provision", "--policy-name", "product-material-gate"]) == 2
    output = capsys.readouterr()
    assert "manager-token" not in output.out + output.err
    assert "[REDACTED]" in output.err

def test_non_ready_resume_is_not_reported_as_success(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    module = load_cli()
    server = SimpleNamespace(
        provision_windows_project_runner=lambda _arguments: pytest.fail("wrong handler"),
        resume_windows_project_runner=lambda arguments: tool_result(
            {"ready": False, "stage": "registered_paused", "policy_name": arguments["policy_name"]}
        ),
    )
    monkeypatch.setattr(module, "_is_windows_administrator", lambda: True)
    monkeypatch.setattr(module, "_load_server", lambda: server)
    monkeypatch.setenv("GITLAB_TOKEN", "environment-token")

    assert module.main(["resume", "--policy-name", "product-material-gate"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "policy_name": "product-material-gate",
        "ready": False,
        "stage": "registered_paused",
    }


@pytest.mark.parametrize(
    "result",
    [
        None,
        {},
        {"content": []},
        {"content": [{"text": "[]"}]},
        {"content": [{"text": "{"}]},
    ],
)
def test_invalid_tool_result_fails_closed(result) -> None:
    module = load_cli()
    with pytest.raises((RuntimeError, json.JSONDecodeError)):
        module._parse_result(result)
