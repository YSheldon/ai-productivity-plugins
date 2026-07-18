from __future__ import annotations

import importlib.util
import io
import json
import shutil
import subprocess
from pathlib import Path
from urllib.error import HTTPError

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "gitlab_mcp.py"


def load_module():
    spec = importlib.util.spec_from_file_location("gitlab_mcp_security_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bare_client(module):
    client = object.__new__(module.GitLabClient)
    client.base_url = "https://gitlab.example.com"
    client.token = "configured-token-must-not-leak"
    client.auth_header = "PRIVATE-TOKEN"
    client.timeout = 5
    return client


def test_tool_results_recursively_redact_sensitive_response_fields() -> None:
    module = load_module()
    result = module.tool_result(
        {
            "runners_token": "runner-secret",
            "nested": {
                "token": "api-secret",
                "token_env": "GITLAB_TOKEN",
                "headers": {"Set-Cookie": "session=secret"},
            },
        }
    )
    payload = json.loads(result["content"][0]["text"])

    assert payload["runners_token"] == module.REDACTED
    assert payload["nested"]["token"] == module.REDACTED
    assert payload["nested"]["headers"]["Set-Cookie"] == module.REDACTED
    assert payload["nested"]["token_env"] == "GITLAB_TOKEN"


@pytest.mark.parametrize(
    "path",
    (
        "https://attacker.example/collect",
        "http://attacker.example/collect",
        "//attacker.example/collect",
        "/projects/1?private_token=secret",
        "/projects/1#fragment",
    ),
)
def test_api_url_rejects_absolute_network_and_embedded_query_paths(path: str) -> None:
    module = load_module()
    with pytest.raises(module.ToolError):
        bare_client(module).api_url(path)


def test_api_url_keeps_requests_on_the_configured_gitlab_origin() -> None:
    module = load_module()
    url = bare_client(module).api_url("/projects/1", {"simple": True})
    assert url == "https://gitlab.example.com/api/v4/projects/1?simple=True"


def test_redirect_handler_never_constructs_a_followup_request() -> None:
    module = load_module()
    handler = module.NoRedirectHandler()
    request = module.Request("https://gitlab.example.com/api/v4/projects/1")
    assert handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://attacker.example/collect",
    ) is None


def test_http_error_body_and_configured_token_are_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    client = bare_client(module)
    error_body = json.dumps(
        {
            "message": client.token,
            "runners_token": "runner-secret",
        }
    ).encode("utf-8")

    def fail_request(_request, _timeout):
        raise HTTPError(
            "https://gitlab.example.com/api/v4/projects/1",
            403,
            "Forbidden",
            {},
            io.BytesIO(error_body),
        )

    monkeypatch.setattr(module, "open_url", fail_request)
    with pytest.raises(module.ToolError) as captured:
        client.request("GET", "/projects/1")

    message = str(captured.value)
    assert client.token not in message
    assert "runner-secret" not in message
    assert module.REDACTED in message



def test_unexpected_exception_details_are_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()

    def leak_secret(_arguments):
        raise RuntimeError("unexpected-secret-must-not-leak")

    monkeypatch.setitem(
        module.TOOLS,
        "security_test_failure",
        {
            "description": "test",
            "inputSchema": {"type": "object"},
            "handler": leak_secret,
        },
    )
    response = module.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "security_test_failure", "arguments": {}},
        }
    )
    assert response is not None
    output = json.dumps(response)
    assert "unexpected-secret-must-not-leak" not in output
    assert "details suppressed" in output


def test_manifest_uses_cross_platform_node_launcher() -> None:
    manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
    mcp = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    server = mcp["mcpServers"]["gitlab"]
    assert manifest["version"] == "0.1.1"
    assert server == {"command": "node", "args": ["./scripts/run_mcp.js"], "cwd": "."}


def test_node_launcher_initializes_the_mcp_server() -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
    ) + "\n"
    completed = subprocess.run(
        [node, str(ROOT / "scripts" / "run_mcp.js")],
        cwd=ROOT,
        input=request,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    response = json.loads(completed.stdout.splitlines()[0])
    assert response["result"]["serverInfo"] == {"name": "gitlab", "version": "0.1.1"}
