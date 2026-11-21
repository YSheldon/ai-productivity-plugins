import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import host_keys
import ssh_vnext


HOST = "scan.example.invalid"
ENDPOINT = {"host": HOST, "port": 22}
KEY_LINE = f"{HOST} ssh-ed25519 YWJj\n"
# SHA-256 fingerprint of the synthetic key bytes b"abc".
FINGERPRINT = "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
SCAN_OK = {"returncode": 0, "stdout": KEY_LINE, "stderr": "", "timed_out": False}


def _execution_host(monkeypatch, name):
    monkeypatch.setattr(host_keys, "os", SimpleNamespace(name=name, path=host_keys.os.path))


@pytest.fixture
def run_process(monkeypatch):
    monkeypatch.setattr(host_keys.core, "find_executable", lambda name: name)
    runner = Mock(return_value=SCAN_OK)
    monkeypatch.setattr(host_keys.execution, "run_process", runner)
    return runner


@pytest.fixture
def managed_profile(monkeypatch):
    _execution_host(monkeypatch, "nt")
    profile = {
        **ENDPOINT,
        "profile": "fixture",
        "user": "operator",
        "credential_source": "ssh-agent",
        "host_key_policy": "managed",
        "strict_host_key_checking": "yes",
        "known_hosts_file": None,
        "identity_file": None,
        "identities_only": False,
    }
    record = {**ENDPOINT, "fingerprints": [FINGERPRINT]}
    monkeypatch.setattr(ssh_vnext, "connection_config", lambda _profile: profile)
    monkeypatch.setattr(host_keys, "_load", lambda: {"profiles": {"fixture": record}})
    return record


@pytest.mark.parametrize(
    ("host_os", "requested", "scan_seconds", "process_seconds"),
    [
        ("nt", 1, "1", 3),
        ("nt", 60, "60", 62),
        ("nt", 61, "60", 62),
        ("nt", 120, "60", 62),
        ("nt", 600, "60", 62),
        ("posix", 120, "120", 122),
    ],
)
def test_keyscan_uses_a_bounded_budget_on_windows(
    monkeypatch, run_process, host_os, requested, scan_seconds, process_seconds,
):
    _execution_host(monkeypatch, host_os)
    keys, _ = host_keys._scan(ENDPOINT, requested)
    assert [key["fingerprint"] for key in keys] == [FINGERPRINT]
    assert run_process.call_count == 1
    assert run_process.call_args.args[0] == ["ssh-keyscan", "-T", scan_seconds, "-p", "22", HOST]
    assert run_process.call_args.kwargs["timeout"] == process_seconds


@pytest.mark.parametrize(
    ("diagnostic", "second_scanner"),
    [("unsupported KEX method fixture", "git-keyscan"), ("no matching host key type found", "ssh-keyscan")],
)
def test_windows_compatibility_scan_keeps_the_same_budget(monkeypatch, run_process, diagnostic, second_scanner):
    _execution_host(monkeypatch, "nt")
    monkeypatch.setattr(host_keys, "_git_keyscan", lambda: "git-keyscan")
    run_process.side_effect = [{"returncode": 1, "stdout": "", "stderr": diagnostic, "timed_out": False}, SCAN_OK]

    keys, _ = host_keys._scan(ENDPOINT, 120)

    assert [key["fingerprint"] for key in keys] == [FINGERPRINT]
    assert [call.args[0] for call in run_process.call_args_list] == [
        ["ssh-keyscan", "-T", "60", "-p", "22", HOST],
        [second_scanner, "-T", "60", "-p", "22", "-t", "rsa,ecdsa,ed25519", HOST],
    ]
    assert [call.kwargs["timeout"] for call in run_process.call_args_list] == [62, 62]


def test_long_ssh_command_keeps_its_execution_budget(managed_profile, run_process):
    run_process.side_effect = [SCAN_OK, {**SCAN_OK, "stdout": "fixture\n"}]

    result = ssh_vnext.run_command({"profile": "fixture", "command": "hostname", "timeout_seconds": 120})

    assert json.loads(result["content"][0]["text"])["ok"] is True
    scan, command = run_process.call_args_list
    assert scan.args[0] == ["ssh-keyscan", "-T", "60", "-p", "22", HOST]
    assert scan.kwargs["timeout"] == 62
    assert command.args[0][0] == "ssh"
    assert "ConnectTimeout=120" in command.args[0]
    assert "StrictHostKeyChecking=yes" in command.args[0]
    assert command.kwargs["timeout"] == 120


@pytest.mark.parametrize("failure", ["empty", "timeout", "mismatch"])
def test_failed_host_key_check_blocks_ssh_dispatch(managed_profile, run_process, failure):
    expected_error = "Unable to scan SSH host keys"
    if failure == "empty":
        run_process.return_value = {**SCAN_OK, "returncode": 1, "stdout": ""}
    elif failure == "timeout":
        run_process.return_value = {**SCAN_OK, "timed_out": True}
    else:
        managed_profile["fingerprints"] = ["SHA256:pinned-fixture-fingerprint"]
        expected_error = "The approved SSH host key is absent"

    with pytest.raises(host_keys.core.ToolError, match=expected_error):
        ssh_vnext.run_command({"profile": "fixture", "command": "hostname", "timeout_seconds": 120})

    assert run_process.call_count == 1
    assert run_process.call_args.args[0][0] == "ssh-keyscan"
