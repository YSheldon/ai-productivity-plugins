from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "gitlab_mcp.py"


def load_module():
    spec = importlib.util.spec_from_file_location("gitlab_mcp_runner_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_tool_result(result: dict[str, object]) -> dict[str, object]:
    return json.loads(result["content"][0]["text"])


class FakeGitLab:
    def __init__(self, *, token: str = "glrt-one-time-secret") -> None:
        self.base_url = "https://gitlab.example.com"
        self.token = token
        self.calls: list[tuple[str, str, object]] = []
        self.paused = True
        self.runner_id = 41
        self.project_id = 59
        self.runner_name = "product-material-gate-windows"
        self.tags = ["product-material-gate-protected", "windows-dedicated"]
        self.access_level = "ref_protected"
        self.fail_create = False
        self.bad_attestation = False

    def request(self, method: str, path: str, query=None, body=None, raw: bool = False):
        del query, raw
        self.calls.append((method, path, body))
        if method == "GET" and path.startswith("/projects/"):
            return {"id": self.project_id}
        if method == "POST" and path == "/user/runners":
            if self.fail_create:
                raise RuntimeError("API secret details must not be echoed")
            assert isinstance(body, dict)
            self.runner_name = str(body["description"])
            self.tags = list(body["tag_list"])
            self.access_level = str(body["access_level"])
            return {"id": self.runner_id, "token": self.token}
        if method == "DELETE" and path == f"/runners/{self.runner_id}":
            return {"status": 204}
        if method == "PUT" and path == f"/runners/{self.runner_id}":
            if isinstance(body, dict) and isinstance(body.get("paused"), bool):
                self.paused = body["paused"]
            return {"status": 200}
        if method == "GET" and path == f"/runners/{self.runner_id}":
            return {
                "id": self.runner_id,
                "description": self.runner_name,
                "paused": self.paused,
                "locked": True,
                "run_untagged": False,
                "access_level": self.access_level,
                "status": "online",
                "tag_list": ["wrong-tag"] if self.bad_attestation else list(self.tags),
                "projects": [{"id": self.project_id}],
            }
        raise AssertionError(f"unexpected fake request: {method} {path}")


def make_policy(
    tmp_path: Path,
    module,
    *,
    install_service: bool = False,
    access_level: str = "ref_protected",
    tags: list[str] | None = None,
) -> dict[str, object]:
    binary = tmp_path / "gitlab-runner.exe"
    binary.write_bytes(b"signed-runner-binary")
    working_dir = tmp_path / "work"
    builds_dir = working_dir / "builds"
    cache_dir = working_dir / "cache"
    builds_dir.mkdir(parents=True)
    cache_dir.mkdir()
    return {
        "policy_name": "product-material-gate",
        "gitlab_url": "https://gitlab.example.com",
        "project": "ai/product-material-gate-ci",
        "runner_name": "product-material-gate-windows",
        "tags": list(tags or ["product-material-gate-protected", "windows-dedicated"]),
        "access_level": access_level,
        "binary_path": binary,
        "binary_sha256": module.sha256_file(binary).upper(),
        "binary_signature_thumbprint": "A" * 40,
        "config_path": tmp_path / "config.toml",
        "journal_path": tmp_path / "provisioning-state.json",
        "identity_path": tmp_path / "runner-identity.json",
        "working_dir": working_dir,
        "builds_dir": builds_dir,
        "cache_dir": cache_dir,
        "application_root": str(tmp_path),
        "install_service": install_service,
        "service_name": "gitlab-runner-product-material-gate" if install_service else "",
        "service_account": "NetworkService" if install_service else "",
        "timeout_seconds": 120,
    }


def load_policy_from_layout(
    tmp_path: Path,
    module,
    monkeypatch: pytest.MonkeyPatch,
    *,
    access_level: str | None,
    tags: list[str],
) -> dict[str, object]:
    program_data = tmp_path / "program-data"
    program_files = tmp_path / "program-files"
    policy_root = program_data / "CodexGitLab" / "runner-policies"
    runtime_root = (
        program_data / "CodexGitLab" / "runners" / "product-material-gate-ci-test-windows"
    )
    builds_dir = runtime_root / "work" / "builds"
    cache_dir = runtime_root / "work" / "cache"
    binary = program_files / "GitLab-Runner" / "gitlab-runner.exe"
    policy_root.mkdir(parents=True)
    builds_dir.mkdir(parents=True)
    cache_dir.mkdir()
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"test-only-runner")
    payload: dict[str, object] = {
        "schema_version": module.RUNNER_POLICY_SCHEMA_VERSION,
        "gitlab_url": "https://gitlab.example.com",
        "project": "ai/product-material-gate-ci",
        "runner_name": "product-material-gate-ci-test-windows",
        "tag_list": tags,
        "runner_binary": str(binary),
        "runner_binary_sha256": "a" * 64,
        "install_service": False,
    }
    if access_level is not None:
        payload["access_level"] = access_level
    (policy_root / "product-material-gate-ci-test-windows.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module,
        "windows_platform_roots",
        lambda: {
            "program_data": str(program_data),
            "program_files": str(program_files),
        },
    )
    monkeypatch.setattr(module, "assert_strict_windows_acl", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module,
        "verify_runner_binary",
        lambda _path, digest: {
            "sha256": digest.upper(),
            "signature_thumbprint": "A" * 40,
        },
    )
    return module.load_windows_runner_policy("product-material-gate-ci-test-windows")


def test_policy_loader_defaults_to_protected_and_allows_explicit_test_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    default_policy = load_policy_from_layout(
        tmp_path / "default",
        module,
        monkeypatch,
        access_level=None,
        tags=["product-material-gate-protected", "windows-dedicated"],
    )
    assert default_policy["access_level"] == "ref_protected"

    test_policy = load_policy_from_layout(
        tmp_path / "test",
        module,
        monkeypatch,
        access_level="not_protected",
        tags=["windows", "product-material-gate-ci-test"],
    )
    assert test_policy["access_level"] == "not_protected"


def test_policy_loader_rejects_nonprotected_live_gate_tags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    with pytest.raises(module.ToolError, match="live-gate tags"):
        load_policy_from_layout(
            tmp_path,
            module,
            monkeypatch,
            access_level="not_protected",
            tags=["product-material-gate-protected", "windows"],
        )

def test_administrator_precondition_runs_before_policy_or_remote_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    touched = {"policy": False, "client": False}

    def reject_not_elevated() -> None:
        raise module.ToolError("administrator required")

    def unexpected_policy(*_args, **_kwargs):
        touched["policy"] = True
        pytest.fail("policy must not load before the administrator gate")

    def unexpected_client(*_args, **_kwargs):
        touched["client"] = True
        pytest.fail("GitLab must not be contacted before the administrator gate")

    monkeypatch.setattr(module, "require_windows_runner_administrator", reject_not_elevated)
    monkeypatch.setattr(module, "load_windows_runner_policy", unexpected_policy)
    monkeypatch.setattr(module, "client", unexpected_client)
    for handler in (
        module.provision_windows_project_runner,
        module.resume_windows_project_runner,
    ):
        with pytest.raises(module.ToolError, match="administrator"):
            handler({"policy_name": "product-material-gate"})
    assert touched == {"policy": False, "client": False}


def test_runner_token_is_private_child_env_only_and_parent_env_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    token = "glrt-private-token-never-in-argv"
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = list(command)
        captured["env"] = dict(kwargs["env"])
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    parent_before = dict(os.environ)
    module.run_gitlab_runner_process(
        policy,
        ["register", "--non-interactive", "--url", "https://gitlab.example.com"],
        "register",
        registration_token=token,
    )

    assert token not in " ".join(captured["command"])
    assert captured["env"]["CI_SERVER_TOKEN"] == token
    assert "CI_SERVER_TOKEN" not in os.environ or os.environ.get("CI_SERVER_TOKEN") == parent_before.get("CI_SERVER_TOKEN")
    assert dict(os.environ) == parent_before
    assert "GITLAB_TOKEN" not in captured["env"]


def test_runner_failure_suppresses_sensitive_child_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    token = "glrt-sensitive-child-output"
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout=token.encode(),
            stderr=("fatal " + token).encode(),
        ),
    )

    with pytest.raises(module.ToolError) as captured:
        module.run_gitlab_runner_process(
            policy,
            ["register", "--non-interactive"],
            "register",
            registration_token=token,
        )
    assert token not in str(captured.value)
    assert "child output suppressed" in str(captured.value)


@pytest.mark.parametrize(
    ("method", "path", "raw"),
    (
        ("GET", "/projects/1", True),
        ("POST", "/user/runners", False),
        ("POST", "/user/runners/token-reset", False),
        ("POST", "/runners/41/reset_authentication_token", False),
        ("POST", "/projects/59/runners/reset_registration_token", False),
        ("PUT", "/runners/41", False),
        ("PATCH", "/api/v4/%72unners/41", False),
        ("PATCH", "/api/v4/%2572unners/41", False),
        ("DELETE", r"/api\v4\runners\41", False),
        ("DELETE", "/safe/%2e%2e/runners/41", False),
        ("DELETE", "/runners/41", False),
        ("POST", "/projects/59/runners", False),
        ("PUT", "/projects/group%2Frepo/runners/41", False),
        ("DELETE", "/groups/7/runners/41", False),
    ),
)
def test_generic_api_blocks_opaque_and_all_runner_management_writes(
    method: str, path: str, raw: bool
) -> None:
    module = load_module()
    with pytest.raises(module.ToolError):
        module.assert_safe_generic_api_operation(method, path, raw)


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("GET", "/runners/41"),
        ("GET", "/projects/59/runners"),
        ("POST", "/projects/59/issues"),
        ("PATCH", "/projects/59/merge_requests/3"),
        ("DELETE", "/projects/59/variables/ORDINARY"),
        ("PUT", "/projects/59/repository/files/foo%2Frunners%2Fbar.txt"),
        ("PUT", "/projects/59/repository/files/runners/bar.txt"),
    ),
)
def test_generic_api_still_allows_runner_reads_and_non_runner_writes(
    method: str, path: str
) -> None:
    module = load_module()
    module.assert_safe_generic_api_operation(method, path, False)


def test_path_policy_rejects_relative_unc_and_workspace_binary_paths() -> None:
    module = load_module()
    for value in ("gitlab-runner.exe", r"\\server\share\gitlab-runner.exe", r"C:\repo\..\gitlab-runner.exe"):
        with pytest.raises(module.ToolError):
            module.canonical_windows_path(value, "runner_binary")
    assert not module.windows_path_is_within(
        r"C:\workspace\gitlab-runner.exe", r"C:\Program Files"
    )
    assert module.windows_path_is_within(
        r"C:\Program Files\GitLab-Runner\gitlab-runner.exe", r"C:\Program Files"
    )


def test_runner_binary_requires_exact_hash_and_valid_authenticode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    binary = tmp_path / "gitlab-runner.exe"
    binary.write_bytes(b"runner")
    digest = module.sha256_file(binary)
    monkeypatch.setattr(
        module,
        "authenticode_summary",
        lambda _path: {"status": "NotSigned", "certificate_thumbprint": ""},
    )
    with pytest.raises(module.ToolError, match="Authenticode"):
        module.verify_runner_binary(binary, digest)
    with pytest.raises(module.ToolError, match="SHA256"):
        module.verify_runner_binary(binary, "0" * 64)


def configure_atomic_test(
    module, monkeypatch: pytest.MonkeyPatch, policy: dict[str, object], gl: FakeGitLab
) -> list[tuple[list[str], str, str | None]]:
    commands: list[tuple[list[str], str, str | None]] = []
    service = {"exists": False, "state": "", "start_name": ""}
    monkeypatch.setattr(module, "require_windows_runner_administrator", lambda: None)
    monkeypatch.setattr(module, "load_windows_runner_policy", lambda _name, **_kwargs: policy)
    monkeypatch.setattr(module, "client", lambda _args: gl)
    monkeypatch.setattr(module, "assert_strict_windows_acl", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "harden_generated_runner_config", lambda *_args: None)
    monkeypatch.setattr(module, "harden_runner_journal", lambda *_args: None)
    monkeypatch.setattr(module, "harden_runner_identity_receipt", lambda *_args: None)
    monkeypatch.setattr(module, "assert_runner_identity_receipt_acl", lambda *_args: None)
    monkeypatch.setattr(module, "harden_windows_service_dacl", lambda *_args: None)
    monkeypatch.setattr(
        module, "windows_machine_identity_sha256", lambda: "b" * 64
    )

    def fake_service_record(_service_name):
        path_name = (
            f'"{policy["binary_path"]}" run '
            f'--working-directory "{policy["working_dir"]}" '
            f'--config "{policy["config_path"]}" '
            f'--service "{policy["service_name"]}"'
        )
        return {
            "exists": service["exists"],
            "state": service["state"],
            "start_name": service["start_name"],
            "path_name": path_name,
            "dacl_safe": True,
        }

    monkeypatch.setattr(module, "windows_service_record", fake_service_record)

    def fake_configure_service_account(_policy):
        service["start_name"] = "NT AUTHORITY\\NetworkService"

    monkeypatch.setattr(
        module,
        "configure_windows_service_network_service",
        fake_configure_service_account,
    )

    def fake_runner_process(_policy, arguments, stage, *, registration_token=None):
        commands.append((list(arguments), stage, registration_token))
        if arguments[0] == "register":
            Path(policy["config_path"]).write_text(
                "\n".join(
                    (
                        "concurrent = 1", "[[runners]]",
                        f'name = "{policy["runner_name"]}"',
                        'url = "https://gitlab.example.com"', 'token = "glrt-fixture"',
                        'executor = "shell"', 'shell = "powershell"',
                        f"builds_dir = '{policy['builds_dir']}'",
                        f"cache_dir = '{policy['cache_dir']}'",
                    )
                ) + "\n",
                encoding="utf-8",
            )
        elif arguments[0] == "install":
            service.update(exists=True, state="Stopped", start_name="LocalSystem")
        elif arguments[0] == "start":
            service.update(exists=True, state="Running")
        elif arguments[0] == "stop":
            service["state"] = "Stopped"
        elif arguments[0] == "uninstall":
            service.update(exists=False, state="", start_name="")

    monkeypatch.setattr(module, "run_gitlab_runner_process", fake_runner_process)
    return commands


def test_atomic_creation_uses_protected_project_runner_defaults_and_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    gl = FakeGitLab()
    commands = configure_atomic_test(module, monkeypatch, policy, gl)

    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": "product-material-gate"})
    )
    create_body = next(body for method, path, body in gl.calls if method == "POST" and path == "/user/runners")
    assert create_body == {
        "runner_type": "project_type",
        "project_id": 59,
        "description": "product-material-gate-windows",
        "locked": True,
        "run_untagged": False,
        "access_level": "ref_protected",
        "paused": True,
        "tag_list": ["product-material-gate-protected", "windows-dedicated"],
    }
    assert [command[0][0] for command in commands] == ["register", "verify"]
    assert commands[0][2] == gl.token
    assert commands[1][2] is None
    assert gl.token not in json.dumps(result)
    assert result["runner"]["registered"] is True
    assert result["stage"] == "registered_paused"
    assert result["paused"] is True
    assert result["ready"] is False


def test_nonprotected_test_runner_is_explicitly_policy_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(
        tmp_path,
        module,
        access_level="not_protected",
        tags=["windows", "product-material-gate-ci-test"],
    )
    gl = FakeGitLab()
    configure_atomic_test(module, monkeypatch, policy, gl)

    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": "product-material-gate"})
    )
    create_body = next(
        body
        for method, path, body in gl.calls
        if method == "POST" and path == "/user/runners"
    )
    assert create_body["access_level"] == "not_protected"
    assert create_body["tag_list"] == ["windows", "product-material-gate-ci-test"]
    assert result["runner"]["access_level"] == "not_protected"


def test_runner_access_level_is_explicit_and_rejects_live_tags() -> None:
    module = load_module()
    assert (
        module.resolve_runner_access_level(None, ["product-material-gate-protected"])
        == "ref_protected"
    )
    assert (
        module.resolve_runner_access_level(
            "not_protected", ["windows", "product-material-gate-ci-test"]
        )
        == "not_protected"
    )
    with pytest.raises(module.ToolError, match="access_level"):
        module.resolve_runner_access_level("unprotected", ["windows"])
    with pytest.raises(module.ToolError, match="live-gate tags"):
        module.resolve_runner_access_level(
            "not_protected", ["product-material-gate-protected"]
        )


def test_nonprotected_policy_rejects_protected_api_attestation(
    tmp_path: Path,
) -> None:
    module = load_module()
    policy = make_policy(
        tmp_path,
        module,
        access_level="not_protected",
        tags=["windows", "product-material-gate-ci-test"],
    )
    record = {
        "id": 41,
        "description": policy["runner_name"],
        "paused": True,
        "locked": True,
        "run_untagged": False,
        "access_level": "ref_protected",
        "tag_list": policy["tags"],
        "projects": [{"id": 59}],
    }
    with pytest.raises(module.ToolError, match="attestation"):
        module.attest_runner_record(record, policy, 41, 59, paused=True)

def test_registration_failure_rolls_back_remote_runner_and_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    gl = FakeGitLab()
    configure_atomic_test(module, monkeypatch, policy, gl)

    def fail_registration(_policy, arguments, _stage, *, registration_token=None):
        Path(policy["config_path"]).write_text("partial", encoding="utf-8")
        raise RuntimeError("leak " + str(registration_token))

    monkeypatch.setattr(module, "run_gitlab_runner_process", fail_registration)
    with pytest.raises(module.ToolError) as captured:
        module.provision_windows_project_runner({"policy_name": "product-material-gate"})
    assert gl.token not in str(captured.value)
    assert ("DELETE", "/runners/41", None) in gl.calls
    assert not Path(policy["config_path"]).exists()
    assert "rollback succeeded" in str(captured.value)


def test_create_api_failure_does_not_start_runner_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    gl = FakeGitLab()
    gl.fail_create = True
    monkeypatch.setattr(module, "require_windows_runner_administrator", lambda: None)
    monkeypatch.setattr(module, "load_windows_runner_policy", lambda _name: policy)
    monkeypatch.setattr(module, "client", lambda _args: gl)
    monkeypatch.setattr(
        module,
        "run_gitlab_runner_process",
        lambda *_args, **_kwargs: pytest.fail("runner process must not start after API failure"),
    )
    with pytest.raises(RuntimeError):
        module.provision_windows_project_runner({"policy_name": "product-material-gate"})
    assert not any(method == "DELETE" for method, _path, _body in gl.calls)


def test_api_attestation_failure_rolls_back_before_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    gl = FakeGitLab()
    gl.bad_attestation = True
    configure_atomic_test(module, monkeypatch, policy, gl)
    with pytest.raises(module.ToolError, match="rollback succeeded"):
        module.provision_windows_project_runner({"policy_name": "product-material-gate"})
    assert ("DELETE", "/runners/41", None) in gl.calls


def test_service_install_failure_preserves_registered_runner_paused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    commands = configure_atomic_test(module, monkeypatch, policy, gl)
    original = module.run_gitlab_runner_process

    def fail_install(_policy, arguments, stage, *, registration_token=None):
        if arguments[0] == "install":
            raise module.ToolError("service output secret")
        return original(_policy, arguments, stage, registration_token=registration_token)

    monkeypatch.setattr(module, "run_gitlab_runner_process", fail_install)
    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": "product-material-gate"})
    )
    assert result["stage"] == "service_install_failed"
    assert result["paused"] is True
    assert result["runner"]["registered"] is True
    assert not any(method == "DELETE" for method, _path, _body in gl.calls)
    assert not any(body == {"paused": False} for method, _path, body in gl.calls if method == "PUT")
    assert [command[0][0] for command in commands] == ["register", "verify"]


def test_successful_service_attestation_unpauses_only_at_the_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    commands = configure_atomic_test(module, monkeypatch, policy, gl)
    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": "product-material-gate"})
    )
    assert [command[0][0] for command in commands] == ["register", "verify", "install", "start"]
    unpause_indexes = [
        index
        for index, (method, _path, body) in enumerate(gl.calls)
        if method == "PUT" and body == {"paused": False}
    ]
    assert len(unpause_indexes) == 1
    assert result["stage"] == "ready"
    assert result["paused"] is False
    assert result["ready"] is True
    assert result["service"]["account"] == "NetworkService"
    install_arguments = next(command for command, stage, _token in commands if stage == "service install")
    assert "--user" not in install_arguments
    assert "--password" not in install_arguments


def test_api_attestation_rejects_duplicate_tags_even_with_the_same_set(tmp_path: Path) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    record = {
        "id": 41,
        "description": policy["runner_name"],
        "paused": True,
        "locked": True,
        "run_untagged": False,
        "access_level": "ref_protected",
        "tag_list": [*policy["tags"], policy["tags"][0]],
        "projects": [{"id": 59}],
    }
    with pytest.raises(module.ToolError, match="attestation"):
        module.attest_runner_record(record, policy, 41, 59, paused=True)


def test_mcp_schema_exposes_policy_name_not_arbitrary_execution_paths() -> None:
    module = load_module()
    schema = module.TOOLS["gitlab_provision_windows_project_runner"]["inputSchema"]
    assert set(schema["properties"]) == {"profile", "policy_name"}
    assert schema["required"] == ["policy_name"]
    assert schema["additionalProperties"] is False
    for forbidden in ("runner_binary", "config_path", "working_dir", "command", "executor"):
        assert forbidden not in schema["properties"]
