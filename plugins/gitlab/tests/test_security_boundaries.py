from __future__ import annotations

import importlib.util
import io
import json
import shutil
import subprocess
from types import SimpleNamespace
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


def test_gitlab_ci_variable_values_are_redacted_contextually() -> None:
    module = load_module()
    result = module.tool_result(
        [
            {
                "key": "SCAN_TOKEN",
                "value": "ci-variable-secret",
                "variable_type": "env_var",
                "protected": True,
                "masked": True,
            },
            {"key": "ordinary-label", "value": "ordinary-value"},
        ]
    )
    payload = json.loads(result["content"][0]["text"])

    assert payload[0]["key"] == "SCAN_TOKEN"
    assert payload[0]["value"] == module.REDACTED
    assert payload[1]["value"] == "ordinary-value"
    assert "ci-variable-secret" not in result["content"][0]["text"]


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



def test_trusted_ssl_context_imports_windows_root_certificates(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()

    class FakeContext:
        def __init__(self) -> None:
            self.loaded = []

        def load_verify_locations(self, *, cadata: str) -> None:
            self.loaded.append(cadata)

    context = FakeContext()
    monkeypatch.setattr(module.ssl, "create_default_context", lambda: context)
    stores = {
        "ROOT": [
            (b"trusted", "x509_asn", True),
            (b"other", "x509_asn", {"1.2.3"}),
            (b"bundle", "pkcs_7_asn", True),
        ],
        "CA": [(b"server", "x509_asn", {"1.3.6.1.5.5.7.3.1"})],
    }
    monkeypatch.setattr(module.ssl, "enum_certificates", lambda store: stores[store])
    monkeypatch.setattr(module.ssl, "DER_cert_to_PEM_cert", lambda value: f"PEM:{value.decode()}\n")
    module.trusted_ssl_context.cache_clear()

    assert module.trusted_ssl_context() is context
    assert context.loaded == ["PEM:trusted\nPEM:server\n"]


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



def test_schannel_fallback_keeps_credentials_out_of_process_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["input"] = kwargs["input"]
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body_base64": "e30=",
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(
        module,
        "system_powershell_path",
        lambda: module.Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
    )
    monkeypatch.setattr(module.Path, "is_file", lambda _path: True)
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    status, _headers, content = module.schannel_request(
        "GET",
        "https://gitlab.example.com/api/v4/user",
        {"PRIVATE-TOKEN": "credential-must-stay-on-stdin"},
        None,
        5,
    )

    assert status == 200
    assert content == b"{}"
    assert "credential-must-stay-on-stdin" not in " ".join(captured["command"])
    assert "credential-must-stay-on-stdin" in captured["input"]



def test_schannel_process_failure_does_not_echo_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    monkeypatch.setattr(
        module,
        "system_powershell_path",
        lambda: module.Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
    )
    monkeypatch.setattr(module.Path, "is_file", lambda _path: True)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="credential-must-not-leak",
        ),
    )

    with pytest.raises(module.ToolError) as captured:
        module.schannel_request(
            "GET",
            "https://gitlab.example.com/api/v4/user",
            {"PRIVATE-TOKEN": "credential-must-not-leak"},
            None,
            5,
        )

    assert "credential-must-not-leak" not in str(captured.value)
    assert "failed closed" in str(captured.value)


def test_system_powershell_resolution_does_not_require_systemroot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("windir", raising=False)
    monkeypatch.setattr(
        module,
        "windows_system_directory",
        lambda: module.Path("C:/Windows/System32"),
    )
    monkeypatch.setattr(module.Path, "is_file", lambda _path: True)
    assert module.system_powershell_path().name.casefold() == "powershell.exe"
    assert "GetSystemDirectoryW" in MODULE_PATH.read_text(encoding="utf-8")


def test_schannel_fails_closed_when_system_powershell_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    monkeypatch.setattr(module, "system_powershell_path", lambda: None)

    with pytest.raises(module.ToolError) as captured:
        module.schannel_request(
            "GET",
            "https://gitlab.example.com/api/v4/user",
            {"PRIVATE-TOKEN": "credential-must-not-leak"},
            None,
            5,
        )

    assert "failed closed" in str(captured.value)
    assert "credential-must-not-leak" not in str(captured.value)


def test_schannel_redirect_response_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_module()
    client = bare_client(module)

    def tls_failure(_request, _timeout):
        raise module.URLError(module.ssl.SSLCertVerificationError(1, "certificate verify failed"))

    monkeypatch.setattr(module, "open_url", tls_failure)
    monkeypatch.setattr(module, "is_windows_tls_verification_failure", lambda _error: True)
    monkeypatch.setattr(
        module,
        "schannel_request",
        lambda *_args: (302, {"Location": "https://attacker.example/collect"}, b"redirect blocked"),
    )

    with pytest.raises(module.ToolError) as captured:
        client.request("GET", "/projects/1")

    assert "302" in str(captured.value)


def test_schannel_helper_disables_redirects() -> None:
    module = load_module()
    helper = module.SCHANNEL_HELPER.read_text(encoding="utf-8")
    assert "Add-Type -AssemblyName System.Net.Http" in helper
    assert "$handler.AllowAutoRedirect = $false" in helper


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
    assert manifest["version"] == "0.2.4"
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
    assert response["result"]["serverInfo"] == {"name": "gitlab", "version": "0.2.4"}
