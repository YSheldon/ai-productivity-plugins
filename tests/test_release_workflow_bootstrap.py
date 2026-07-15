from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_PATH = ROOT / "tools" / "release_workflow_bootstrap.py"


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


def build_fake_marketplace(root: Path) -> None:
    write_json(
        root / ".agents" / "plugins" / "marketplace.json",
        {
            "name": "ai-productivity-plugins",
            "plugins": [
                {"name": "imap-smtp-mail", "source": {"source": "local", "path": "./plugins/imap-smtp-mail"}},
                {"name": "rd-flywheel", "source": {"source": "local", "path": "./plugins/rd-flywheel"}},
                {"name": "lark-cli", "source": {"source": "local", "path": "./plugins/lark-cli"}},
                {
                    "name": "product-release-gate",
                    "source": {"source": "local", "path": "./plugins/product-release-gate"},
                },
            ],
        },
    )

    plugins = {
        "imap-smtp-mail": {
            "version": "0.2.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/imap_smtp_mail_mcp.py",
        },
        "rd-flywheel": {"version": "0.1.0", "skills_path": "./skills/"},
        "lark-cli": {"version": "0.1.0", "skills_path": "./skills/"},
        "product-release-gate": {
            "version": "0.2.0",
            "mcp_path": "./.mcp.json",
            "mcp_script": "./src/release_gate_mcp.py",
        },
    }

    for name, config in plugins.items():
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
        if "mcp_path" in config:
            manifest["mcpServers"] = config["mcp_path"]
            write_json(
                plugin_root / ".mcp.json",
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
    ]
    assert [command[3] for command in commands[1:]] == [
        "imap-smtp-mail@ai-productivity-plugins",
        "rd-flywheel@ai-productivity-plugins",
        "lark-cli@ai-productivity-plugins",
        "product-release-gate@ai-productivity-plugins",
    ]

    lock_path = tmp_path / "dependency-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert lock["marketplace"]["url"] == "https://github.com/YSheldon/ai-productivity-plugins.git"
    assert lock["marketplace"]["commit"] == "4a74f13412b784ae0cb101f6eed6f34e73874949"
    assert lock["profile"] == "release-approval-verifier"
    assert [plugin["name"] for plugin in lock["plugins"]] == [
        "imap-smtp-mail",
        "rd-flywheel",
        "lark-cli",
        "product-release-gate",
    ]
    assert lock["plugins"][0]["version"] == "0.2.0"
    assert lock["plugins"][1]["version"] == "0.1.0"
    assert lock["plugins"][2]["version"] == "0.1.0"
    assert lock["plugins"][3]["version"] == "0.2.0"
    assert any(entry["path"].endswith("plugins/lark-cli/skills") for entry in lock["plugins"][2]["entrypoints"])
    assert any(
        entry["path"].endswith("plugins/product-release-gate/src/release_gate_mcp.py")
        for entry in lock["plugins"][3]["entrypoints"]
    )
    for plugin in lock["plugins"]:
        assert len(plugin["manifest_sha256"]) == 64
        assert all(len(entry["sha256"]) == 64 for entry in plugin["entrypoints"])


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

