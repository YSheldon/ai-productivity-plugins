from __future__ import annotations

import importlib.util
import json
import os
import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.request import Request

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "gitlab_mr_scope_gate.py"


def load_module():
    spec = importlib.util.spec_from_file_location("gitlab_mr_scope_gate_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GateHTTPServer(ThreadingHTTPServer):
    responses: dict[str, tuple[int, object] | None]
    requests: list[dict[str, object]]


@contextmanager
def gitlab_server(
    responses: dict[str, tuple[int, object] | None],
) -> Iterator[GateHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            self.server.requests.append(  # type: ignore[attr-defined]
                {
                    "path": self.path,
                    "job_token": self.headers.get("JOB-TOKEN"),
                    "authorization": self.headers.get("Authorization"),
                }
            )
            response = self.server.responses.get(self.path)  # type: ignore[attr-defined]
            if response is None:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            status, body = response
            encoded = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = GateHTTPServer(("127.0.0.1", 0), Handler)
    server.responses = responses
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def valid_manifest(sha: str, iid: str = "7") -> dict[str, object]:
    return {
        "format": "gitlab-mr-approval-scope/v1",
        "candidate_sha": sha,
        "target_branch": "main",
        "approval_source": "gitlab_mr",
        "merge_request_iid": iid,
        "prepared_at": "2026-08-10T12:00:00Z",
        "approved_at": "2026-08-10T12:30:00Z",
        "prepared_by": "release-preparer",
        "approved_by": "release-approver",
        "scope": {
            "id": "release-2026-08-10",
            "items": ["artifact:server", "artifact:web", "deployment:production"],
        },
    }


def write_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def gate_environment(base_url: str, manifest_path: Path, sha: str) -> dict[str, str]:
    return {
        "CI_API_V4_URL": base_url,
        "CI_PROJECT_ID": "123",
        "CI_MERGE_REQUEST_PROJECT_ID": "123",
        "CI_MERGE_REQUEST_IID": "7",
        "CI_MERGE_REQUEST_EVENT_TYPE": "detached",
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_JOB_TOKEN": "job-token-must-not-leak",
        "CI_COMMIT_SHA": sha,
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        "CI_JOB_ID": "456",
        "GITLAB_APPROVAL_SCOPE_FILE": str(manifest_path.resolve()),
    }


def successful_responses(sha: str) -> dict[str, tuple[int, object]]:
    prefix = "/api/v4/projects/123/merge_requests/7"
    return {
        prefix: (
            200,
            {"iid": 7, "sha": sha, "target_branch": "main", "state": "opened"},
        ),
        prefix + "/approvals": (
            200,
            {
                "approved": True,
                "approvals_left": 0,
                "approvals_required": 1,
                "approved_by": [{"user": {"username": "release-approver"}}],
            },
        ),
    }


def test_release_gate_binds_live_mr_approval_candidate_and_raw_scope(tmp_path: Path) -> None:
    module = load_module()
    sha = "a" * 40
    path = tmp_path / "approval.json"
    write_manifest(path, valid_manifest(sha))

    with gitlab_server(successful_responses(sha)) as server:
        base_url = f"http://127.0.0.1:{server.server_port}/api/v4"
        result = module.verify_release_gate(gate_environment(base_url, path, sha))

    assert result == {
        "ok": True,
        "project_id": "123",
        "merge_request_iid": "7",
        "candidate_sha": sha,
        "target_branch": "main",
        "approved": True,
        "approvals_left": 0,
        "approvals_required": 1,
        "scope_sha256": module.hashlib.sha256(path.read_bytes()).hexdigest(),
        "scope_format": "gitlab-mr-approval-scope/v1",
        "scope_id": "release-2026-08-10",
        "job_id": "456",
    }
    assert [item["path"] for item in server.requests] == [
        "/api/v4/projects/123/merge_requests/7",
        "/api/v4/projects/123/merge_requests/7/approvals",
    ]
    assert all(item["job_token"] == "job-token-must-not-leak" for item in server.requests)
    assert all(item["authorization"] is None for item in server.requests)
    assert "job-token-must-not-leak" not in json.dumps(result)
    assert "release-approver" not in json.dumps(result)


@pytest.mark.parametrize(
    ("status", "body", "message"),
    [
        (
            200,
            {
                "approved": False,
                "approvals_left": 1,
                "approvals_required": 1,
                "approved_by": [],
            },
            "not complete",
        ),
        (200, b"{", "malformed"),
        (403, {"message": "job-token-must-not-leak"}, "status 403"),
        (200, {"approved": "true", "approvals_left": 0}, "malformed"),
    ],
)
def test_release_gate_fails_closed_for_pending_malformed_and_unauthorized_approval(
    tmp_path: Path,
    status: int,
    body: object,
    message: str,
) -> None:
    module = load_module()
    sha = "a" * 40
    path = tmp_path / "approval.json"
    write_manifest(path, valid_manifest(sha))
    responses = successful_responses(sha)
    responses["/api/v4/projects/123/merge_requests/7/approvals"] = (status, body)

    with gitlab_server(responses) as server:
        env = gate_environment(f"http://127.0.0.1:{server.server_port}/api/v4", path, sha)
        with pytest.raises(module.GateError, match=message) as captured:
            module.verify_release_gate(env)

    assert "job-token-must-not-leak" not in str(captured.value)


def test_release_gate_fails_closed_on_transport_error(tmp_path: Path) -> None:
    module = load_module()
    sha = "a" * 40
    path = tmp_path / "approval.json"
    write_manifest(path, valid_manifest(sha))
    responses: dict[str, tuple[int, object] | None] = successful_responses(sha)
    responses["/api/v4/projects/123/merge_requests/7/approvals"] = None

    with gitlab_server(responses) as server:
        env = gate_environment(f"http://127.0.0.1:{server.server_port}/api/v4", path, sha)
        with pytest.raises(module.GateError, match="transport") as captured:
            module.verify_release_gate(env)

    assert "job-token-must-not-leak" not in str(captured.value)


@pytest.mark.parametrize(
    ("mr_change", "message"),
    [
        ({"sha": "b" * 40}, "candidate"),
        ({"target_branch": "release"}, "target branch"),
        ({"state": "merged"}, "opened"),
        ({"iid": 8}, "IID"),
    ],
)
def test_release_gate_rejects_mr_identity_mismatch(
    tmp_path: Path,
    mr_change: dict[str, object],
    message: str,
) -> None:
    module = load_module()
    sha = "a" * 40
    path = tmp_path / "approval.json"
    write_manifest(path, valid_manifest(sha))
    responses = successful_responses(sha)
    mr_path = "/api/v4/projects/123/merge_requests/7"
    status, mr = responses[mr_path]
    assert isinstance(mr, dict)
    responses[mr_path] = (status, {**mr, **mr_change})

    with gitlab_server(responses) as server:
        env = gate_environment(f"http://127.0.0.1:{server.server_port}/api/v4", path, sha)
        with pytest.raises(module.GateError, match=message):
            module.verify_release_gate(env)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.update({"unknown": True}), "unknown"),
        (lambda data: data.update({"candidate_sha": "b" * 40}), "candidate"),
        (lambda data: data.update({"target_branch": "release"}), "target branch"),
        (lambda data: data.update({"merge_request_iid": "8"}), "IID"),
        (lambda data: data.update({"approval_source": "manual"}), "approval source"),
        (lambda data: data.update({"approved_by": "release-preparer"}), "different"),
        (lambda data: data.update({"approved_by": "not-the-api-approver"}), "approver"),
        (
            lambda data: data.update(
                {"prepared_at": "2026-08-10T13:00:00Z", "approved_at": "2026-08-10T12:30:00Z"}
            ),
            "predates",
        ),
        (lambda data: data.update({"scope": {"id": "release", "items": []}}), "scope item"),
    ],
)
def test_release_gate_rejects_invalid_scope_contract(
    tmp_path: Path,
    mutate,
    message: str,
) -> None:
    module = load_module()
    sha = "a" * 40
    manifest = valid_manifest(sha)
    mutate(manifest)
    path = tmp_path / "approval.json"
    write_manifest(path, manifest)

    with gitlab_server(successful_responses(sha)) as server:
        env = gate_environment(f"http://127.0.0.1:{server.server_port}/api/v4", path, sha)
        with pytest.raises(module.GateError, match=message):
            module.verify_release_gate(env)


def test_release_gate_rejects_duplicate_scope_items(tmp_path: Path) -> None:
    module = load_module()
    sha = "a" * 40
    manifest = valid_manifest(sha)
    scope = manifest["scope"]
    assert isinstance(scope, dict) and isinstance(scope["items"], list)
    scope["items"].append("artifact:server")
    path = tmp_path / "approval.json"
    write_manifest(path, manifest)

    with gitlab_server(successful_responses(sha)) as server:
        env = gate_environment(f"http://127.0.0.1:{server.server_port}/api/v4", path, sha)
        with pytest.raises(module.GateError, match="duplicate scope item"):
            module.verify_release_gate(env)


def test_release_gate_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    module = load_module()
    sha = "a" * 40
    manifest = json.dumps(valid_manifest(sha), separators=(",", ":"))
    manifest = manifest.replace(
        '"candidate_sha":"' + sha + '"',
        '"candidate_sha":"' + sha + '","candidate_sha":"' + sha + '"',
        1,
    )
    path = tmp_path / "approval.json"
    path.write_text(manifest, encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)

    with gitlab_server(successful_responses(sha)) as server:
        env = gate_environment(f"http://127.0.0.1:{server.server_port}/api/v4", path, sha)
        with pytest.raises(module.GateError, match="duplicate JSON key"):
            module.verify_release_gate(env)


def test_release_gate_rejects_credential_like_scope_content(tmp_path: Path) -> None:
    module = load_module()
    sha = "a" * 40
    manifest = valid_manifest(sha)
    scope = manifest["scope"]
    assert isinstance(scope, dict)
    scope["id"] = "password=do-not-store-this"
    path = tmp_path / "approval.json"
    write_manifest(path, manifest)

    with gitlab_server(successful_responses(sha)) as server:
        env = gate_environment(f"http://127.0.0.1:{server.server_port}/api/v4", path, sha)
        with pytest.raises(module.GateError, match="credential") as captured:
            module.verify_release_gate(env)

    assert "do-not-store-this" not in str(captured.value)


def test_release_gate_requires_only_ci_job_token_and_never_pat_aliases(tmp_path: Path) -> None:
    module = load_module()
    sha = "a" * 40
    path = tmp_path / "approval.json"
    write_manifest(path, valid_manifest(sha))
    env = gate_environment("https://gitlab.example.com/api/v4", path, sha)
    env.pop("CI_JOB_TOKEN")
    env["GITLAB_TOKEN"] = "personal-token-must-not-be-used"
    env["PRIVATE_TOKEN"] = "another-personal-token"

    with pytest.raises(module.GateError, match="CI_JOB_TOKEN") as captured:
        module.verify_release_gate(env)

    assert "personal-token-must-not-be-used" not in str(captured.value)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"CI_PIPELINE_SOURCE": "push"}, "merge request pipeline"),
        ({"CI_MERGE_REQUEST_EVENT_TYPE": "merged_result"}, "detached"),
        ({"CI_MERGE_REQUEST_PROJECT_ID": "999"}, "project"),
    ],
)
def test_release_gate_requires_detached_target_project_mr_pipeline(
    tmp_path: Path,
    change: dict[str, str],
    message: str,
) -> None:
    module = load_module()
    sha = "a" * 40
    path = tmp_path / "approval.json"
    write_manifest(path, valid_manifest(sha))
    env = gate_environment("https://gitlab.example.com/api/v4", path, sha)
    env.update(change)

    with pytest.raises(module.GateError, match=message):
        module.verify_release_gate(env)


def test_api_url_supports_gitlab_relative_url_prefix_and_rejects_cleartext_remote() -> None:
    module = load_module()
    assert (
        module.normalize_api_url("https://gitlab.example.com/gitlab/api/v4/")
        == "https://gitlab.example.com/gitlab/api/v4"
    )
    with pytest.raises(module.GateError, match="HTTPS"):
        module.normalize_api_url("http://gitlab.example.com/api/v4")


def test_gate_redirect_handler_never_forwards_job_token() -> None:
    module = load_module()
    handler = module.NoRedirectHandler()
    request = Request(
        "https://gitlab.example.com/api/v4/projects/1",
        headers={"JOB-TOKEN": "must-not-be-forwarded"},
    )
    assert handler.redirect_request(
        request,
        None,
        302,
        "Found",
        {},
        "https://attacker.example/collect",
    ) is None


@pytest.mark.skipif(os.name != "nt", reason="UNC path semantics are Windows-specific")
def test_release_gate_rejects_unc_scope_path_before_network_access(tmp_path: Path) -> None:
    module = load_module()
    env = gate_environment("https://gitlab.example.com/api/v4", tmp_path / "unused.json", "a" * 40)
    env["GITLAB_APPROVAL_SCOPE_FILE"] = r"\\attacker.example\share\approval.json"

    with pytest.raises(module.GateError, match="local"):
        module.verify_release_gate(env)


def test_cli_suppresses_unexpected_exception_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_module()

    def fail_unexpectedly():
        raise RuntimeError("unexpected-secret-must-not-leak")

    monkeypatch.setattr(module, "verify_release_gate", fail_unexpectedly)
    assert module.main() == 1
    captured = capsys.readouterr()
    assert "unexpected-secret-must-not-leak" not in captured.err
    assert "details suppressed" in captured.err


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not authoritative on Windows")
def test_release_gate_rejects_group_or_world_writable_scope(tmp_path: Path) -> None:
    module = load_module()
    sha = "a" * 40
    path = tmp_path / "approval.json"
    write_manifest(path, valid_manifest(sha))
    path.chmod(0o660)

    with pytest.raises(module.GateError, match="writable"):
        module.verify_release_gate(
            gate_environment("https://gitlab.example.com/api/v4", path, sha)
        )


def test_cli_script_does_not_accept_token_arguments() -> None:
    script = (ROOT / "scripts" / "verify_mr_approval_scope.py").read_text(encoding="utf-8")
    assert "argparse" not in script
    assert "CI_JOB_TOKEN" not in script
    assert "verify_release_gate" in script
