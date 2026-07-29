from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_windows_project_runner.ps1"


def test_bootstrap_pins_all_remote_inputs() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "$PluginCommit = '9d0a8bf75f810a4f2dee0a86467a7c4487ab9baf'" in text
    assert (
        "$PythonInstallerSha256 = "
        "'c54d9b9bbb8a36e6489363ddd01139707fd781d72f1f9e90c7ec65d0061368e0'"
        in text
    )
    assert "$PythonSignerThumbprint = '9BA3C2E210C7E8296C5056515BFC0B0BBA78AC48'" in text

    expected_plugin_hashes = {
        "3a6a718a28cba0cc481d788b905b139d62c450e56869505b0ae3ddc1050f19a2",
        "45281b9dfaa660f986206f036f52cf40f362b484b9a5ba416b6874bac6b57dd1",
        "cafa86ab5862a19cee0f916de6f414a20f9cb4b66d94774adf5267064a5fd556",
        "55fdbb5fb30f581257034e6fb58f684796aa9b2ab552514110ae22a9e8378215",
    }
    assert expected_plugin_hashes.issubset(set(re.findall(r"[0-9a-f]{64}", text)))
    assert "raw.githubusercontent.com/YSheldon/ai-productivity-plugins/{0}/" in text
    assert "raw.githubusercontent.com/YSheldon/ai-productivity-plugins/main/" not in text


def test_bootstrap_preserves_privilege_and_secret_boundaries() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    required = (
        "#Requires -RunAsAdministrator",
        "Get-AuthenticodeSignature",
        "Set-ProtectedTreeAcl",
        "ProgramFiles",
        "token-set --policy-name",
        "token-status",
        "manager_credential_present_after_ready = $false",
        "ProductMaterialGateRunnerIdentity/v1",
        "NT AUTHORITY\\NetworkService",
        "-I -S -B",
    )
    for fragment in required:
        assert fragment in text

    forbidden = (
        "--insecure",
        "verify=False",
        "PasswordAuthentication",
        "GITLAB_TOKEN=",
        "registration_token",
        "runner_token",
    )
    for fragment in forbidden:
        assert fragment not in text


def test_bootstrap_fails_closed_on_nonready_or_credential_cleanup_failure() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "$lifecycle.ready -ne $true" in text
    assert "$tokenStatusAfter.token_present -ne $false" in text
    assert "$service.State -ne 'Running'" in text
    assert "$service.StartMode -ne 'Auto'" in text
    assert "$identity.stage -ne 'ready'" in text


def test_bootstrap_parses_in_powershell_when_available() -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        return

    escaped_path = str(SCRIPT).replace("'", "''")
    command = (
        "$tokens=$null;$errors=$null;"
        f"[System.Management.Automation.Language.Parser]::ParseFile('{escaped_path}',"
        "[ref]$tokens,[ref]$errors)|Out-Null;"
        "if($errors.Count -gt 0){"
        "$errors|ForEach-Object{Write-Error $_.Message};exit 1}"
    )
    subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
    )


def test_bootstrap_launcher_pins_script_before_elevation() -> None:
    launcher = (
        SCRIPT.parent / "run_windows_project_runner_bootstrap.cmd"
    ).read_text(encoding="utf-8")

    assert (
        "EXPECTED_SHA256=0cb81ec7fdb703459b5e0f86dcdd69917e1ba51bb87df46915ad33ff4e0e1dc4"
        in launcher
    )
    assert "Get-FileHash -LiteralPath $path -Algorithm SHA256" in launcher
    assert "-Verb RunAs" in launcher
    assert "Bootstrap SHA256 mismatch" in launcher
