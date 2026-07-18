from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_PATH = ROOT / "tools" / "release_workflow_bootstrap.py"
EXPECTED_MARKETPLACE_URL = "https://github.com/YSheldon/ai-productivity-plugins.git"


def load_bootstrap_module() -> Any:
    spec = importlib.util.spec_from_file_location("release_workflow_bootstrap", BOOTSTRAP_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_worktree_git_config(root: Path, origin_url: str = EXPECTED_MARKETPLACE_URL) -> None:
    git_dir = root / ".git-data"
    git_dir.mkdir(parents=True, exist_ok=True)
    (root / ".git").write_text(f"gitdir: {git_dir.as_posix()}\n", encoding="utf-8")
    (git_dir / "config").write_text(
        "\n".join(
            [
                "[remote \"origin\"]",
                f"\turl = {origin_url}",
                "\tfetch = +refs/heads/main:refs/remotes/origin/main",
                "",
            ]
        ),
        encoding="utf-8",
    )


def build_fake_marketplace(
    root: Path,
    *,
    origin_url: str = EXPECTED_MARKETPLACE_URL,
    plugin_overrides: dict[str, dict[str, Any]] | None = None,
) -> None:
    write_worktree_git_config(root, origin_url=origin_url)
    write_json(
        root / ".agents" / "plugins" / "marketplace.json",
        {
            "name": "ai-productivity-plugins",
            "plugins": [
                {"name": "imap-smtp-mail", "source": {"source": "local", "path": "./plugins/imap-smtp-mail"}},
                {"name": "rd-flywheel", "source": {"source": "local", "path": "./plugins/rd-flywheel"}},
                {"name": "lark-cli", "source": {"source": "local", "path": "./plugins/lark-cli"}},
                {"name": "gitlab", "source": {"source": "local", "path": "./plugins/gitlab"}},
                {"name": "test-submission", "source": {"source": "local", "path": "./plugins/test-submission"}},
                {"name": "submission-gate", "source": {"source": "local", "path": "./plugins/submission-gate"}},
                {"name": "pre-release", "source": {"source": "local", "path": "./plugins/pre-release"}},
                {"name": "release-gate", "source": {"source": "local", "path": "./plugins/release-gate"}},
                {
                    "name": "product-release-gate",
                    "source": {"source": "local", "path": "./plugins/product-release-gate"},
                },
                {
                    "name": "release-approval-verifier",
                    "source": {"source": "local", "path": "./plugins/release-approval-verifier"},
                },
            ],
        },
    )

    plugins = {
        "imap-smtp-mail": {
            "version": "0.2.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/imap_smtp_mail_mcp.py",
            "runtime_entrypoints": ["./src/imap_smtp_mail_cli.py"],
        },
        "rd-flywheel": {"version": "0.1.0", "skills_path": "./skills/"},
        "lark-cli": {"version": "0.1.0", "skills_path": "./skills/"},
        "product-release-gate": {
            "version": "0.2.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/release_gate_mcp.py",
        },
        "test-submission": {
            "version": "0.1.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/test_submission_mcp.py",
            "runtime_entrypoints": ["./src/test_submission_cli.py"],
        },
        "submission-gate": {
            "version": "0.1.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/submission_gate_mcp.py",
            "runtime_entrypoints": ["./src/submission_gate_cli.py"],
        },
        "pre-release": {
            "version": "0.1.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/pre_release_mcp.py",
            "runtime_entrypoints": ["./src/pre_release_cli.py"],
        },
        "release-gate": {
            "version": "0.1.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/release_gate_mcp.py",
            "runtime_entrypoints": ["./src/release_gate_cli.py"],
        },
        "release-approval-verifier": {
            "version": "0.2.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/release_approval_verifier_mcp.py",
            "runtime_entrypoints": [
                "./src/verifier_product_gate_bridge.py",
            ],
        },
    }

    plugin_overrides = plugin_overrides or {}

    for name, config in plugins.items():
        config.update(plugin_overrides.get(name, {}))
        plugin_root = root / "plugins" / name
        manifest = {
            "name": name,
            "version": config["version"],
            "description": f"{name} test plugin",
        }
        if "skills_path" in config:
            manifest["skills"] = config["skills_path"]
            skills_root = plugin_root / "skills"
            skills_root.mkdir(parents=True, exist_ok=True)
            (skills_root / "SKILL.md").write_text(f"# {name}\n", encoding="utf-8")
        if "runtime_entrypoints" in config:
            manifest["runtimeEntrypoints"] = config["runtime_entrypoints"]
            for relative_path in config["runtime_entrypoints"]:
                runtime_path = plugin_root / relative_path.replace("./", "")
                runtime_path.parent.mkdir(parents=True, exist_ok=True)
                runtime_path.write_text(
                    f"print('{name}:{relative_path}')\n",
                    encoding="utf-8",
                )
        if "mcp_path" in config:
            manifest["mcpServers"] = config["mcp_path"]
            mcp_config = config.get(
                "mcp_config",
                {
                    "mcpServers": {
                        name: {
                            "command": "py",
                            "args": ["-3", config["mcp_script"]],
                            "cwd": ".",
                        }
                    }
                },
            )
            write_json(plugin_root / ".mcp.json", mcp_config)
            for relative_path in config.get("plugin_files", []):
                file_path = plugin_root / relative_path
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(f"print('{name}:{relative_path}')\n", encoding="utf-8")
            if "mcp_script" in config:
                script_path = plugin_root / config["mcp_script"].replace("./", "")
                script_path.parent.mkdir(parents=True, exist_ok=True)
                script_path.write_text(f"print('{name}')\n", encoding="utf-8")

        write_json(plugin_root / ".codex-plugin" / "plugin.json", manifest)


def completed(command: list[str], stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


def test_rejects_unknown_or_injected_profiles_before_running_commands(tmp_path: Path) -> None:
    module = load_bootstrap_module()
    build_fake_marketplace(tmp_path)
    calls: list[list[str]] = []

    def unexpected_runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        raise AssertionError("runner must not be called for rejected profiles")

    with pytest.raises(ValueError):
        module.bootstrap_profile("unknown-profile", repo_root=tmp_path, runner=unexpected_runner)

    with pytest.raises(ValueError):
        module.bootstrap_profile("release-approval && injected", repo_root=tmp_path, runner=unexpected_runner)

    assert calls == []


def test_rejects_same_marketplace_name_with_wrong_source_before_running_commands(tmp_path: Path) -> None:
    module = load_bootstrap_module()
    build_fake_marketplace(tmp_path, origin_url="https://github.com/example/ai-productivity-plugins.git")
    calls: list[list[str]] = []

    def unexpected_runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        raise AssertionError("runner must not be called for rejected marketplace sources")

    with pytest.raises(ValueError, match="Unsupported marketplace source"):
        module.bootstrap_profile("release-approval", repo_root=tmp_path, runner=unexpected_runner)

    assert calls == []


def test_bootstrap_writes_dependency_lock_and_marks_fresh_task_after_install(tmp_path: Path) -> None:
    module = load_bootstrap_module()
    build_fake_marketplace(tmp_path)
    commands: list[list[str]] = []

    def runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return completed(command, "4a74f13412b784ae0cb101f6eed6f34e73874949\n")
        plugin_id = command[3]
        if plugin_id == "imap-smtp-mail@ai-productivity-plugins":
            return completed(command, json.dumps({"pluginId": plugin_id, "action": "installed"}) + "\n")
        if plugin_id == "rd-flywheel@ai-productivity-plugins":
            return completed(command, json.dumps({"pluginId": plugin_id, "changed": False}) + "\n")
        if plugin_id == "lark-cli@ai-productivity-plugins":
            return completed(command, json.dumps({"pluginId": plugin_id, "updated": True}) + "\n")
        if plugin_id == "product-release-gate@ai-productivity-plugins":
            return completed(command, json.dumps({"pluginId": plugin_id, "action": "unchanged"}) + "\n")
        if plugin_id == "release-approval-verifier@ai-productivity-plugins":
            return completed(command, json.dumps({"pluginId": plugin_id, "action": "unchanged"}) + "\n")
        raise AssertionError(f"unexpected command: {command}")

    result = module.bootstrap_profile(
        "release-approval-verifier",
        repo_root=tmp_path,
        runner=runner,
        codex_command="codex.cmd",
    )

    assert result["fresh_task_required"] is True
    assert [command[:3] for command in commands] == [
        ["git", "rev-parse", "HEAD"],
        ["codex.cmd", "plugin", "add"],
        ["codex.cmd", "plugin", "add"],
        ["codex.cmd", "plugin", "add"],
        ["codex.cmd", "plugin", "add"],
        ["codex.cmd", "plugin", "add"],
    ]
    assert [command[3] for command in commands[1:]] == [
        "imap-smtp-mail@ai-productivity-plugins",
        "rd-flywheel@ai-productivity-plugins",
        "lark-cli@ai-productivity-plugins",
        "product-release-gate@ai-productivity-plugins",
        "release-approval-verifier@ai-productivity-plugins",
    ]

    lock_path = tmp_path / "dependency-lock.release-approval-verifier.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock["marketplace"]["url"] == EXPECTED_MARKETPLACE_URL
    assert lock["marketplace"]["commit"] == "4a74f13412b784ae0cb101f6eed6f34e73874949"
    assert lock["profile"] == "release-approval-verifier"
    assert [plugin["name"] for plugin in lock["plugins"]] == [
        "imap-smtp-mail",
        "rd-flywheel",
        "lark-cli",
        "product-release-gate",
        "release-approval-verifier",
    ]
    assert lock["plugins"][0]["version"] == "0.2.0"
    assert lock["plugins"][1]["version"] == "0.1.0"
    assert lock["plugins"][2]["version"] == "0.1.0"
    assert lock["plugins"][3]["version"] == "0.2.0"
    assert lock["plugins"][4]["version"] == "0.2.0"
    for plugin in lock["plugins"]:
        assert plugin["plugin_root"].startswith("plugins/")
        assert plugin["manifest_path"].startswith("plugins/")
        assert len(plugin["manifest_sha256"]) == 64
        assert all(not Path(entry["path"]).is_absolute() for entry in plugin["entrypoints"])
        assert all(len(entry["sha256"]) == 64 for entry in plugin["entrypoints"])
    assert any(entry["path"] == "plugins/lark-cli/skills" for entry in lock["plugins"][2]["entrypoints"])
    assert any(
        entry["path"] == "plugins/product-release-gate/src/release_gate_mcp.py"
        for entry in lock["plugins"][3]["entrypoints"]
    )
    assert any(
        entry["path"] == "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py"
        and entry["kind"] == "runtime_entrypoint"
        for entry in lock["plugins"][0]["entrypoints"]
    )
    assert any(
        entry["path"]
        == "plugins/release-approval-verifier/src/verifier_product_gate_bridge.py"
        and entry["kind"] == "runtime_entrypoint"
        for entry in lock["plugins"][4]["entrypoints"]
    )



def test_bootstrap_falls_back_to_verified_local_sources_when_codex_is_absent(
    tmp_path: Path,
) -> None:
    module = load_bootstrap_module()
    build_fake_marketplace(tmp_path)
    commands: list[list[str]] = []

    def runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return completed(command, "5555555555555555555555555555555555555555\n")
        raise FileNotFoundError("codex executable is absent")

    result = module.bootstrap_profile(
        "release-approval",
        repo_root=tmp_path,
        runner=runner,
    )

    assert result["fresh_task_required"] is False
    assert result["codex_required"] is False
    assert result["dependency_mode"] == "verified-local-source"
    assert [command[:3] for command in commands] == [
        ["git", "rev-parse", "HEAD"],
        ["codex", "plugin", "add"],
    ]
    for plugin in result["plugins"]:
        assert plugin["install_result"] == {
            "status": "LOCAL_SOURCE_VALIDATED",
            "changed": False,
            "codex_required": False,
        }
        assert len(plugin["manifest_sha256"]) == 64
        assert all(len(entry["sha256"]) == 64 for entry in plugin["entrypoints"])

    lock = json.loads(
        (tmp_path / "dependency-lock.release-approval.json").read_text(
            encoding="utf-8"
        )
    )
    assert lock["dependency_mode"] == "verified-local-source"
    assert lock["codex_required"] is False


def test_lock_paths_are_repo_relative_and_equivalent_checkouts_produce_equivalent_lock_payloads(tmp_path: Path) -> None:
    module = load_bootstrap_module()
    checkout_a = tmp_path / "checkout-a"
    checkout_b = tmp_path / "checkout-b"
    build_fake_marketplace(checkout_a)
    build_fake_marketplace(checkout_b)

    def runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return completed(command, "1111111111111111111111111111111111111111\n")
        return completed(command, json.dumps({"pluginId": command[3], "action": "unchanged"}) + "\n")

    result_a = module.bootstrap_profile("release-approval", repo_root=checkout_a, runner=runner)
    result_b = module.bootstrap_profile("release-approval", repo_root=checkout_b, runner=runner)

    lock_text_a = (
        checkout_a / "dependency-lock.release-approval.json"
    ).read_text(encoding="utf-8")
    lock_text_b = (
        checkout_b / "dependency-lock.release-approval.json"
    ).read_text(encoding="utf-8")
    lock_payload_a = json.loads(lock_text_a)
    lock_payload_b = json.loads(lock_text_b)

    assert lock_payload_a == lock_payload_b
    assert checkout_a.as_posix() not in lock_text_a
    assert checkout_b.as_posix() not in lock_text_b
    assert result_a["dependency_lock"] != result_b["dependency_lock"]


def test_bootstrap_captures_local_entrypoints_from_mcp_command_and_args(tmp_path: Path) -> None:
    module = load_bootstrap_module()
    build_fake_marketplace(
        tmp_path,
        plugin_overrides={
            "product-release-gate": {
                "mcp_config": {
                    "mcpServers": {
                        "python-entry": {
                            "command": "py",
                            "args": ["-3", "src/release_gate_mcp.py", "worker.py"],
                        },
                        "local-command": {
                            "command": "bin/run.py",
                            "args": ["helper.py"],
                        },
                    }
                },
                "plugin_files": ["py", "worker.py", "helper.py", "bin/run.py"],
            }
        },
    )

    def runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return completed(command, "2222222222222222222222222222222222222222\n")
        return completed(command, json.dumps({"pluginId": command[3], "action": "unchanged"}) + "\n")

    result = module.bootstrap_profile("release-approval-verifier", repo_root=tmp_path, runner=runner)
    plugin = next(item for item in result["plugins"] if item["name"] == "product-release-gate")
    entrypoint_paths = {entry["path"] for entry in plugin["entrypoints"]}

    assert "plugins/product-release-gate/src/release_gate_mcp.py" in entrypoint_paths
    assert "plugins/product-release-gate/worker.py" in entrypoint_paths
    assert "plugins/product-release-gate/bin/run.py" in entrypoint_paths
    assert "plugins/product-release-gate/helper.py" in entrypoint_paths
    assert "plugins/product-release-gate/py" not in entrypoint_paths


@pytest.mark.parametrize(
    ("profile", "expected_plugins"),
    (
        ("test-submission", ["imap-smtp-mail", "lark-cli"]),
        ("submission-gate", ["imap-smtp-mail", "gitlab", "lark-cli"]),
        (
            "pre-release",
            [
                "imap-smtp-mail",
                "rd-flywheel",
                "lark-cli",
                "release-approval-verifier",
            ],
        ),
        (
            "release-gate",
            [
                "imap-smtp-mail",
                "rd-flywheel",
                "lark-cli",
                "release-approval-verifier",
            ],
        ),
    ),
)
def test_bootstrap_supports_role_plugin_profiles(tmp_path: Path, profile: str, expected_plugins: list[str]) -> None:
    module = load_bootstrap_module()
    build_fake_marketplace(tmp_path)

    def runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return completed(command, "6666666666666666666666666666666666666666\n")
        return completed(command, json.dumps({"pluginId": command[3], "action": "unchanged"}) + "\n")

    result = module.bootstrap_profile(profile, repo_root=tmp_path, runner=runner)

    assert [plugin["name"] for plugin in result["plugins"]] == expected_plugins
    assert "product-release-gate" not in [plugin["name"] for plugin in result["plugins"]]
    assert Path(result["dependency_lock"]).name == f"dependency-lock.{profile}.json"
    lock = json.loads((tmp_path / f"dependency-lock.{profile}.json").read_text(encoding="utf-8"))
    assert lock["profile"] == profile
    assert [plugin["name"] for plugin in lock["plugins"]] == expected_plugins


def test_rejects_entrypoints_that_escape_plugin_root(tmp_path: Path) -> None:
    module = load_bootstrap_module()
    build_fake_marketplace(
        tmp_path,
        plugin_overrides={
            "product-release-gate": {
                "mcp_config": {
                    "mcpServers": {
                        "escape": {
                            "command": "py",
                            "args": ["-3", "../escape.py"],
                        }
                    }
                }
            }
        },
    )

    def runner(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return completed(command, "3333333333333333333333333333333333333333\n")
        return completed(command, json.dumps({"pluginId": command[3], "action": "unchanged"}) + "\n")

    with pytest.raises(ValueError, match="Path escapes base directory"):
        module.bootstrap_profile("release-approval-verifier", repo_root=tmp_path, runner=runner)


def test_default_runner_uses_argument_arrays_without_shell(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_bootstrap_module()
    seen: dict[str, Any] = {}

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args[0], 0, stdout="{}", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    command = ["codex.cmd", "plugin", "add", "imap-smtp-mail@ai-productivity-plugins", "--json"]

    module.run_command(command, cwd=tmp_path)

    assert seen["args"][0] == command
    assert isinstance(seen["args"][0], list)
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["check"] is False
    assert seen["kwargs"]["capture_output"] is True
    assert seen["kwargs"]["text"] is True

def installed_state_payload(
    marketplace_root: Path,
    plugin_names: list[str],
) -> dict[str, Any]:
    installed: list[dict[str, Any]] = []
    for plugin_name in plugin_names:
        plugin_root = marketplace_root / "plugins" / plugin_name
        manifest = json.loads(
            (plugin_root / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        installed.append(
            {
                "pluginId": f"{plugin_name}@ai-productivity-plugins",
                "name": plugin_name,
                "marketplaceName": "ai-productivity-plugins",
                "version": manifest["version"],
                "installed": True,
                "enabled": True,
                "source": {"source": "local", "path": str(plugin_root)},
            }
        )
    return {"installed": installed, "available": []}


def test_installed_cache_discovers_marketplace_and_skips_matching_plugins(
    tmp_path: Path,
) -> None:
    module = load_bootstrap_module()
    marketplace_root = tmp_path / "marketplace"
    build_fake_marketplace(marketplace_root)
    cache_root = tmp_path / "cache" / "pre-release" / "0.1.0"
    cache_root.mkdir(parents=True)
    required = list(module.PROFILES["pre-release"])
    state = installed_state_payload(marketplace_root, required)
    commands: list[list[str]] = []

    def runner(
        command: list[str],
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["codex", "plugin", "list"]:
            return completed(command, json.dumps(state) + "\n")
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return completed(command, "7777777777777777777777777777777777777777\n")
        raise AssertionError(f"unexpected command: {command}")

    result = module.bootstrap_profile(
        "pre-release",
        repo_root=cache_root,
        runner=runner,
    )

    assert commands == [
        module._plugin_list_command("codex"),
        ["git", "rev-parse", "HEAD"],
    ]
    assert Path(result["dependency_lock"]).parent == marketplace_root.resolve()
    assert all(
        plugin["install_result"]["status"] == "ALREADY_INSTALLED"
        for plugin in result["plugins"]
    )
    assert result["fresh_task_required"] is False


def test_installed_cache_adds_only_missing_plugin_and_revalidates_state(
    tmp_path: Path,
) -> None:
    module = load_bootstrap_module()
    marketplace_root = tmp_path / "marketplace"
    build_fake_marketplace(marketplace_root)
    cache_root = tmp_path / "cache" / "pre-release" / "0.1.0"
    cache_root.mkdir(parents=True)
    required = list(module.PROFILES["pre-release"])
    missing = required[-1]
    installed_names = required[:-1]
    commands: list[list[str]] = []

    def runner(
        command: list[str],
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["codex", "plugin", "list"]:
            state = installed_state_payload(marketplace_root, installed_names)
            return completed(command, json.dumps(state) + "\n")
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return completed(command, "8888888888888888888888888888888888888888\n")
        if command[:3] == ["codex", "plugin", "add"]:
            assert command[3] == f"{missing}@ai-productivity-plugins"
            installed_names.append(missing)
            return completed(
                command,
                json.dumps({"pluginId": command[3], "action": "installed"}) + "\n",
            )
        raise AssertionError(f"unexpected command: {command}")

    result = module.bootstrap_profile(
        "pre-release",
        repo_root=cache_root,
        runner=runner,
    )

    add_commands = [command for command in commands if command[:3] == ["codex", "plugin", "add"]]
    assert add_commands == [
        ["codex", "plugin", "add", f"{missing}@ai-productivity-plugins", "--json"]
    ]
    assert commands.count(module._plugin_list_command("codex")) == 2
    assert result["fresh_task_required"] is True

