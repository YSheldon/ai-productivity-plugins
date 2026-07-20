from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest


HELPER_PATH = Path(__file__).with_name("test_windows_runner_provisioning.py")
HELPER_SPEC = importlib.util.spec_from_file_location("gitlab_runner_test_helpers", HELPER_PATH)
assert HELPER_SPEC is not None and HELPER_SPEC.loader is not None
HELPERS = importlib.util.module_from_spec(HELPER_SPEC)
HELPER_SPEC.loader.exec_module(HELPERS)
FakeGitLab = HELPERS.FakeGitLab
configure_atomic_test = HELPERS.configure_atomic_test
load_module = HELPERS.load_module
make_policy = HELPERS.make_policy
parse_tool_result = HELPERS.parse_tool_result


def valid_config(policy: dict[str, object], *, concurrent: int = 1, extra: str = "") -> str:
    return "\n".join(
        (
            f"concurrent = {concurrent}",
            "[[runners]]",
            f'name = "{policy["runner_name"]}"',
            'url = "https://gitlab.example.com"',
            'token = "glrt-config-token"',
            'executor = "shell"',
            'shell = "powershell"',
            f"builds_dir = '{policy['builds_dir']}'",
            f"cache_dir = '{policy['cache_dir']}'",
            extra,
        )
    ) + "\n"


def service_record(policy: dict[str, object], **overrides) -> dict[str, object]:
    record: dict[str, object] = {
        "exists": True,
        "state": "Running",
        "start_name": "NT AUTHORITY\\NetworkService",
        "path_name": (
            f'"{policy["binary_path"]}" run '
            f'--working-directory "{policy["working_dir"]}" '
            f'--config "{policy["config_path"]}" '
            f'--service "{policy["service_name"]}"'
        ),
        "dacl_safe": True,
    }
    record.update(overrides)
    return record


def test_machine_identity_digest_is_domain_separated_trimmed_and_lowercase() -> None:
    module = load_module()
    machine_guid = "  AABBCCDD-0011-2233-4455-66778899AABB  "
    expected = hashlib.sha256(
        (
            "ProductMaterialGateRunnerIdentity/v1\0"
            "aabbccdd-0011-2233-4455-66778899aabb"
        ).encode("utf-8")
    ).hexdigest()

    assert module.machine_identity_sha256(machine_guid) == expected
    with pytest.raises(module.ToolError, match="MachineGuid"):
        module.machine_identity_sha256("   ")


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL enum semantics")
def test_windows_read_execute_acl_rule_includes_synchronize() -> None:
    module = load_module()
    result = module.run_system_powershell_json(
        r"""
$ErrorActionPreference = 'Stop'
$sid = New-Object Security.Principal.SecurityIdentifier('S-1-5-20')
$rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,'ReadAndExecute','Allow')
[pscustomobject]@{
  rights = [int]$rule.FileSystemRights
  read_execute = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
  synchronize = [int][Security.AccessControl.FileSystemRights]::Synchronize
} | ConvertTo-Json -Compress
""",
        {},
    )

    assert result == {
        "rights": 1179817,
        "read_execute": 131241,
        "synchronize": 1048576,
    }


def test_trusted_windows_powershell_drops_parent_psmodulepath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)
        return module.subprocess.CompletedProcess(
            command,
            0,
            stdout='{"ok":true}',
            stderr='',
        )

    monkeypatch.setattr(module, "system_powershell_path", lambda: Path("powershell.exe"))
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setenv("PSModulePath", r"C:\Program Files\PowerShell\7\Modules")

    assert module.run_system_powershell_json("ignored", {}) == {"ok": True}
    child_environment = captured["env"]
    assert isinstance(child_environment, dict)
    assert all(key.casefold() != "psmodulepath" for key in child_environment)


@pytest.mark.skipif(os.name != "nt", reason="Windows trusted path ACL behavior")
def test_strict_acl_walks_from_file_to_parent_directory() -> None:
    module = load_module()
    powershell = module.system_powershell_path()
    assert powershell is not None

    module.assert_strict_windows_acl(
        str(powershell),
        str(powershell.parent),
    )


def test_identity_receipt_acl_is_exact_protected_and_uses_constructed_read_rights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    captured: list[tuple[str, dict[str, object]]] = []

    def fake_powershell(script, payload):
        captured.append((script, payload))
        return {"ok": True}

    monkeypatch.setattr(module, "run_system_powershell_json", fake_powershell)
    path = tmp_path / "runner-identity.json"
    module.harden_runner_identity_receipt(path)

    harden_script, harden_payload = captured[0]
    assert harden_payload == {"path": str(path)}
    assert "SetAccessRuleProtection($true, $false)" in harden_script
    assert "S-1-5-18" in harden_script
    assert "S-1-5-32-544" in harden_script
    assert "S-1-5-20" in harden_script
    assert "'FullControl','Allow'" in harden_script
    assert "'ReadAndExecute','Allow'" in harden_script

    assert_script, assert_payload = captured[1]
    assert assert_payload == {"path": str(path)}
    assert "AreAccessRulesProtected" in assert_script
    assert "$rules.Count -ne 3" in assert_script
    assert "$networkReadRule.FileSystemRights" in assert_script
    assert "GetAccessRules($true, $false" in assert_script


def test_ready_identity_receipt_has_fixed_fields_and_precedes_unpause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    policy["tags"] = ["windows-dedicated", "product-material-gate-protected"]
    gl = FakeGitLab()
    gl.tags = list(policy["tags"])
    configure_atomic_test(module, monkeypatch, policy, gl)
    raw_machine_guid = "  AABBCCDD-0011-2233-4455-66778899AABB  "
    machine_digest = module.machine_identity_sha256(raw_machine_guid)
    monkeypatch.setattr(
        module, "windows_machine_identity_sha256", lambda: machine_digest
    )
    original_write = module.write_runner_identity_receipt
    receipt_write_call_indexes: list[int] = []

    def tracking_write(receipt_policy, runner_id, project_id):
        assert gl.paused is True
        assert not any(
            body == {"paused": False}
            for method, _path, body in gl.calls
            if method == "PUT"
        )
        receipt_write_call_indexes.append(len(gl.calls))
        return original_write(receipt_policy, runner_id, project_id)

    monkeypatch.setattr(module, "write_runner_identity_receipt", tracking_write)
    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    )

    unpause_index = next(
        index
        for index, (method, _path, body) in enumerate(gl.calls)
        if method == "PUT" and body == {"paused": False}
    )
    assert receipt_write_call_indexes == [unpause_index]
    receipt_path = Path(policy["identity_path"])
    receipt_text = receipt_path.read_text(encoding="utf-8")
    receipt = json.loads(receipt_text)
    assert set(receipt) == module.RUNNER_IDENTITY_FIELDS
    assert receipt == {
        "schema": "ProductMaterialGateRunnerIdentity/v1",
        "policy_name": policy["policy_name"],
        "project_id": gl.project_id,
        "runner_id": gl.runner_id,
        "runner_name": policy["runner_name"],
        "tags": sorted(policy["tags"], key=str.casefold),
        "binary_sha256": module.sha256_file(Path(policy["binary_path"])),
        "config_sha256": module.sha256_file(Path(policy["config_path"])),
        "service_name": policy["service_name"],
        "service_account": "NetworkService",
        "machine_identity_sha256": machine_digest,
        "stage": "ready",
    }
    assert type(receipt["project_id"]) is int and receipt["project_id"] > 0
    assert type(receipt["runner_id"]) is int and receipt["runner_id"] > 0
    assert raw_machine_guid.strip() not in receipt_text
    assert gl.token not in receipt_text
    assert str(policy["gitlab_url"]) not in receipt_text
    assert result["stage"] == "ready"


def test_identity_receipt_failure_never_unpauses_and_removes_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    configure_atomic_test(module, monkeypatch, policy, gl)

    def fail_receipt(_policy, _runner_id, _project_id):
        Path(policy["identity_path"]).write_text("partial", encoding="utf-8")
        raise module.ToolError("identity failure")

    monkeypatch.setattr(module, "write_runner_identity_receipt", fail_receipt)
    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    )

    assert result["stage"] == "identity_receipt_failed"
    assert result["paused"] is True
    assert result["ready"] is False
    assert not Path(policy["identity_path"]).exists()
    assert not any(
        body == {"paused": False}
        for method, _path, body in gl.calls
        if method == "PUT"
    )


def test_resume_revokes_and_rebuilds_receipt_for_current_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    configure_atomic_test(module, monkeypatch, policy, gl)
    first = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    )
    first_receipt = json.loads(Path(policy["identity_path"]).read_text(encoding="utf-8"))
    with Path(policy["config_path"]).open("a", encoding="utf-8") as stream:
        stream.write("# benign config revision\n")

    second = parse_tool_result(
        module.resume_windows_project_runner({"policy_name": policy["policy_name"]})
    )
    second_receipt = json.loads(Path(policy["identity_path"]).read_text(encoding="utf-8"))

    assert first["stage"] == "ready"
    assert second["stage"] == "ready"
    assert second["paused"] is False
    assert second_receipt["config_sha256"] == module.sha256_file(Path(policy["config_path"]))
    assert second_receipt["config_sha256"] != first_receipt["config_sha256"]
    assert sum(
        method == "POST" and path == "/user/runners"
        for method, path, _body in gl.calls
    ) == 1


def test_rollback_removes_identity_receipt(
    tmp_path: Path,
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    for key in ("config_path", "journal_path", "identity_path"):
        Path(policy[key]).write_text(key, encoding="utf-8")

    remote_deleted, local_deleted = module.rollback_created_runner(
        gl, gl.runner_id, policy
    )

    assert remote_deleted is True
    assert local_deleted is True
    assert not Path(policy["identity_path"]).exists()


def test_identity_receipt_rejects_extra_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    configure_atomic_test(module, monkeypatch, policy, gl)
    module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    identity_path = Path(policy["identity_path"])
    receipt = json.loads(identity_path.read_text(encoding="utf-8"))
    receipt["created_at_utc"] = "forbidden"
    identity_path.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(module.ToolError, match="invalid schema"):
        module.load_runner_identity_receipt(policy)



def test_service_dacl_hardening_is_fixed_nonsecret_and_protected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    captured: list[tuple[str, dict[str, object]]] = []

    def fake_powershell(script, payload):
        captured.append((script, payload))
        if "sdset" in script:
            return {"ok": True}
        return {
            "exists": True,
            "state": "Stopped",
            "start_name": "LocalSystem",
            "path_name": "",
            "dacl_safe": True,
        }

    monkeypatch.setattr(module, "run_system_powershell_json", fake_powershell)
    module.harden_windows_service_dacl(policy)
    module.windows_service_record(str(policy["service_name"]))

    harden_script, harden_payload = captured[0]
    assert harden_payload == {"service_name": policy["service_name"]}
    assert "sc.exe" in harden_script
    assert "D:P(" in harden_script
    assert ";;;SY)" in harden_script
    assert ";;;BA)" in harden_script
    assert "password" not in harden_script.casefold()
    assert "token" not in harden_script.casefold()
    inspect_script, _payload = captured[1]
    assert "DiscretionaryAclProtected" in inspect_script
    assert "$null -ne $descriptor.DiscretionaryAcl" in inspect_script
    assert "QualifiedAce" in inspect_script


def test_service_dacl_hardening_failure_cleans_and_keeps_runner_paused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    commands = configure_atomic_test(module, monkeypatch, policy, gl)
    monkeypatch.setattr(
        module,
        "harden_windows_service_dacl",
        lambda _policy: (_ for _ in ()).throw(module.ToolError("DACL hardening failed")),
    )

    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    )

    assert result["stage"] == "service_dacl_hardening_failed"
    assert result["paused"] is True
    assert result["ready"] is False
    assert [arguments[0] for arguments, _stage, _token in commands] == [
        "register",
        "verify",
        "install",
        "stop",
        "uninstall",
    ]
    assert not any(body == {"paused": False} for method, _path, body in gl.calls if method == "PUT")

def test_network_service_transition_uses_fixed_cim_without_password_or_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    captured: dict[str, object] = {}

    def fake_powershell(script, payload):
        captured.update(script=script, payload=payload)
        return {"return_value": 0}

    monkeypatch.setattr(module, "run_system_powershell_json", fake_powershell)
    module.configure_windows_service_network_service(policy)

    assert captured["payload"] == {"service_name": policy["service_name"]}
    script = str(captured["script"]).casefold()
    assert "invoke-cimmethod" in script
    assert "networkservice" in script
    assert "startpassword" not in script
    assert "--password" not in script
    assert "token" not in script


def test_service_attestation_requires_exact_command_account_state_and_dacl(
    tmp_path: Path,
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    module.attest_windows_service(policy, service_record(policy), require_running=True)

    bad_records = (
        service_record(policy, dacl_safe=False),
        service_record(policy, start_name="LocalSystem"),
        service_record(policy, state="Stopped"),
        service_record(
            policy,
            path_name=service_record(policy)["path_name"] + ' --config "C:\\evil\\config.toml"',
        ),
    )
    for record in bad_records:
        with pytest.raises(module.ToolError):
            module.attest_windows_service(policy, record, require_running=True)


def test_service_image_attestation_accepts_runner_18_11_windows_layout(
    tmp_path: Path,
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    record = service_record(
        policy,
        path_name=(
            f'"{policy["binary_path"]}" run '
            f'--config "{policy["config_path"]}" '
            f'--service "{policy["service_name"]}" --syslog'
        ),
    )

    module.attest_windows_service_image(policy, record)

    for suffix in (' --debug', ' --config "C:\\evil\\config.toml"', ' --syslog'):
        rejected = dict(record)
        rejected["path_name"] = str(record["path_name"]) + suffix
        with pytest.raises(module.ToolError):
            module.attest_windows_service_image(policy, rejected)

    wrong_config = dict(record)
    wrong_config["path_name"] = str(record["path_name"]).replace(
        str(policy["config_path"]), "C:\\evil\\config.toml"
    )
    with pytest.raises(module.ToolError):
        module.attest_windows_service_image(policy, wrong_config)


def test_service_account_transition_failure_cleans_and_keeps_runner_paused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    commands = configure_atomic_test(module, monkeypatch, policy, gl)
    monkeypatch.setattr(
        module,
        "configure_windows_service_network_service",
        lambda _policy: (_ for _ in ()).throw(module.ToolError("account transition failed")),
    )

    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    )

    assert result["stage"] == "service_account_configuration_failed"
    assert result["paused"] is True
    assert result["ready"] is False
    assert [arguments[0] for arguments, _stage, _token in commands] == [
        "register",
        "verify",
        "install",
        "stop",
        "uninstall",
    ]
    assert not any(body == {"paused": False} for method, _path, body in gl.calls if method == "PUT")


def test_online_attestation_timeout_never_unpauses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    configure_atomic_test(module, monkeypatch, policy, gl)
    monkeypatch.setattr(module, "wait_for_runner_online", lambda *_args: False)

    result = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    )

    assert result["stage"] == "online_attestation_timeout"
    assert result["paused"] is True
    assert result["ready"] is False
    assert not any(body == {"paused": False} for method, _path, body in gl.calls if method == "PUT")



def test_wait_for_runner_online_honors_full_validated_policy_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    observed: list[float] = []
    clock = iter((100.0, 221.0, 699.0, 700.0))

    def monotonic() -> float:
        value = next(clock)
        observed.append(value)
        return value

    monkeypatch.setattr(module.time, "monotonic", monotonic)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        module,
        "windows_service_record",
        lambda _name: (_ for _ in ()).throw(module.ToolError("not online")),
    )

    assert module.wait_for_runner_online(
        object(),
        {"timeout_seconds": 600, "service_name": "gitlab-runner-product-material-gate"},
        41,
        59,
    ) is False
    assert observed == [100.0, 221.0, 699.0, 700.0]


@pytest.mark.parametrize(
    "config_text",
    (
        "concurrent = 2\n",
        "concurrent = 1\n[[runners]]\nname='wrong'\nurl='https://gitlab.example.com'\ntoken='x'\nexecutor='shell'\nshell='powershell'\nbuilds_dir='C:\\wrong'\ncache_dir='C:\\wrong'\n",
        "concurrent = 1\n[[runners]]\nname='product-material-gate-windows'\nurl='https://gitlab.example.com'\ntoken='x'\nexecutor='shell'\nshell='powershell'\nbuilds_dir='C:\\wrong'\ncache_dir='C:\\wrong'\nenvironment=['SECRET=x']\n",
    ),
)
def test_generated_config_drift_or_injection_is_rejected(
    tmp_path: Path, config_text: str
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    Path(policy["config_path"]).write_text(config_text, encoding="utf-8")
    with pytest.raises(module.ToolError):
        module.verify_runner_config(policy, str(policy["gitlab_url"]))


def test_resume_pauses_before_rejecting_drifted_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    gl.paused = False
    commands = configure_atomic_test(module, monkeypatch, policy, gl)
    module.write_runner_journal(
        policy, gl.runner_id, gl.project_id, "service_start_failed", "installed_not_running"
    )
    Path(policy["config_path"]).write_text("concurrent = 2\n", encoding="utf-8")

    result = parse_tool_result(
        module.resume_windows_project_runner({"policy_name": policy["policy_name"]})
    )

    assert result["stage"] == "resume_config_validation_failed"
    assert result["paused"] is True
    assert gl.paused is True
    assert commands == []
    first_pause = next(
        index
        for index, (method, _path, body) in enumerate(gl.calls)
        if method == "PUT" and body == {"paused": True}
    )
    assert first_pause < next(
        index for index, (method, path, _body) in enumerate(gl.calls) if method == "GET" and path.startswith("/projects/")
    )


def test_resume_after_start_failure_is_idempotent_and_does_not_recreate_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    commands = configure_atomic_test(module, monkeypatch, policy, gl)
    original_process = module.run_gitlab_runner_process
    fail_first_start = {"value": True}

    def flaky_start(_policy, arguments, stage, *, registration_token=None):
        if arguments[0] == "start" and fail_first_start["value"]:
            fail_first_start["value"] = False
            raise module.ToolError("simulated service start failure")
        return original_process(
            _policy, arguments, stage, registration_token=registration_token
        )

    monkeypatch.setattr(module, "run_gitlab_runner_process", flaky_start)
    first = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    )
    resume_boundary = len(commands)
    second = parse_tool_result(
        module.resume_windows_project_runner({"policy_name": policy["policy_name"]})
    )

    assert first["stage"] == "service_start_failed"
    assert first["paused"] is True
    assert second["stage"] == "ready"
    assert second["ready"] is True
    assert sum(method == "POST" and path == "/user/runners" for method, path, _body in gl.calls) == 1
    for arguments, _stage, registration_token in commands[resume_boundary:]:
        assert registration_token is None
        assert gl.token not in " ".join(arguments)


def test_resume_rejects_service_identity_drift_from_protected_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module, install_service=True)
    gl = FakeGitLab()
    commands = configure_atomic_test(module, monkeypatch, policy, gl)
    original_process = module.run_gitlab_runner_process

    def fail_start(_policy, arguments, stage, *, registration_token=None):
        if arguments[0] == "start":
            raise module.ToolError("simulated service start failure")
        return original_process(
            _policy, arguments, stage, registration_token=registration_token
        )

    monkeypatch.setattr(module, "run_gitlab_runner_process", fail_start)
    first = parse_tool_result(
        module.provision_windows_project_runner({"policy_name": policy["policy_name"]})
    )
    call_boundary = len(gl.calls)
    command_boundary = len(commands)
    policy["service_name"] = "gitlab-runner-drifted-service"

    with pytest.raises(module.ToolError, match="does not match the current policy"):
        module.resume_windows_project_runner({"policy_name": policy["policy_name"]})

    assert first["stage"] == "service_start_failed"
    assert gl.paused is True
    assert len(gl.calls) == call_boundary
    assert len(commands) == command_boundary


def test_journal_is_nonsecret_and_resume_schema_is_pathless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    policy = make_policy(tmp_path, module)
    gl = FakeGitLab()
    configure_atomic_test(module, monkeypatch, policy, gl)
    module.provision_windows_project_runner({"policy_name": policy["policy_name"]})

    journal_text = Path(policy["journal_path"]).read_text(encoding="utf-8")
    assert gl.token not in journal_text
    assert "token" not in journal_text.casefold()
    schema = module.TOOLS["gitlab_resume_windows_project_runner"]["inputSchema"]
    assert set(schema["properties"]) == {"profile", "policy_name"}
    assert schema["required"] == ["policy_name"]
    assert schema["additionalProperties"] is False


def test_acl_validation_script_rejects_every_untrusted_writer_sid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    captured: dict[str, object] = {}

    def fake_powershell(script, payload):
        captured.update(script=script, payload=payload)
        return {"ok": True}

    monkeypatch.setattr(module, "run_system_powershell_json", fake_powershell)
    module.assert_strict_windows_acl(
        r"C:\ProgramData\CodexGitLab\runner-policies\gate.json",
        r"C:\ProgramData\CodexGitLab",
    )
    script = str(captured["script"])
    assert "$allowedWriters -notcontains $sid" in script
    assert "untrusted writer ACE rejected" in script
    assert "S-1-5-20" in script


def test_acl_validation_uses_primitive_write_rights_without_read_overlap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    captured: dict[str, object] = {}
    monkeypatch.setattr(module, "run_system_powershell_json", lambda script, payload: captured.update(script=script, payload=payload) or {"ok": True})
    module.assert_strict_windows_acl(r"C:\ProgramData\CodexGitLab\runner-policies\gate.json", r"C:\ProgramData\CodexGitLab")
    script = str(captured["script"])
    assert "$writeCapable = [Security.AccessControl.FileSystemRights]::WriteData" in script
    assert "[Security.AccessControl.FileSystemRights]::Write -bor" not in script
    assert "[Security.AccessControl.FileSystemRights]::Modify" not in script
    assert "[Security.AccessControl.FileSystemRights]::FullControl" not in script
