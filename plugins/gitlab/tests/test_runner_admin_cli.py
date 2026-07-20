from __future__ import annotations

import importlib.util
import json
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
