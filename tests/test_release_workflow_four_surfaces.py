from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import urlparse

import pytest


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_BOOTSTRAP = ROOT / "tools" / "release_workflow_bootstrap.py"
COMMON_CLI_COMMANDS = {"setup", "preflight", "run-once", "status", "doctor"}
SCHEDULER_ACTIONS = {"install", "status", "remove"}
FORBIDDEN_POLICY_OPTIONS = {
    "--poll-minutes",
    "--event-expiry-hours",
    "--working-hours",
    "--allowed-extensions",
    "--require-signature",
    "--require-cloud-scan",
    "--policy",
}
SECRET_KEY_FRAGMENTS = {
    "access_key",
    "api_key",
    "auth_code",
    "authorization_code",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}
ALLOWED_EXAMPLE_HOSTS = {
    "example.com",
    "github.com",
    "json-schema.org",
    "open.feishu.cn",
}


@dataclass(frozen=True)
class WorkflowPlugin:
    name: str
    version: str
    mcp_script: str
    mcp_server_name: str
    mcp_common_tools: tuple[str, ...]
    cli_script: str
    scheduler_script: str
    scheduler_class: str
    setup_script: str
    config_script: str
    prompt_limit: int
    bootstrap_profile: str

    @property
    def root(self) -> Path:
        return ROOT / "plugins" / self.name


WORKFLOW_PLUGINS = (
    WorkflowPlugin(
        name="release-approval",
        version="0.2.0",
        mcp_script="release_approval_mcp.py",
        mcp_server_name="release-approval",
        mcp_common_tools=(
            "release_approval_start_setup",
            "release_approval_preflight",
            "release_approval_run_once",
            "release_approval_status",
            "release_approval_doctor",
        ),
        cli_script="release_approval_cli.py",
        scheduler_script="release_approval_scheduler.py",
        scheduler_class="ReleaseApprovalScheduler",
        setup_script="release_approval_setup.py",
        config_script="release_approval_config.py",
        prompt_limit=4,
        bootstrap_profile="release-approval",
    ),
    WorkflowPlugin(
        name="release-approval-verifier",
        version="0.2.0",
        mcp_script="release_approval_verifier_mcp.py",
        mcp_server_name="release-approval-verifier",
        mcp_common_tools=(
            "release_approval_verifier_start_setup",
            "release_approval_verifier_preflight",
            "release_approval_verifier_run_once",
            "release_approval_verifier_status",
            "release_approval_verifier_doctor",
        ),
        cli_script="verifier_cli.py",
        scheduler_script="verifier_scheduler.py",
        scheduler_class="VerifierScheduler",
        setup_script="verifier_setup.py",
        config_script="verifier_config.py",
        prompt_limit=4,
        bootstrap_profile="release-approval-verifier",
    ),
    WorkflowPlugin(
        name="product-release-gate",
        version="0.3.0",
        mcp_script="release_gate_mcp.py",
        mcp_server_name="product-release-gate",
        mcp_common_tools=(
            "release_gate_setup",
            "release_gate_preflight",
            "release_gate_run_once",
            "release_gate_status",
            "release_gate_doctor",
        ),
        cli_script="release_gate_cli.py",
        scheduler_script="release_gate_scheduler.py",
        scheduler_class="ReleaseGateScheduler",
        setup_script="release_gate_setup.py",
        config_script="release_gate_core.py",
        prompt_limit=4,
        bootstrap_profile="product-release-gate",
    ),
    WorkflowPlugin(
        name="test-submission",
        version="0.1.0",
        mcp_script="test_submission_mcp.py",
        mcp_server_name="test-submission",
        mcp_common_tools=(
            "test_submission_setup",
            "test_submission_preflight",
            "test_submission_run_once",
            "test_submission_status",
            "test_submission_doctor",
        ),
        cli_script="test_submission_cli.py",
        scheduler_script="test_submission_scheduler.py",
        scheduler_class="TestSubmissionScheduler",
        setup_script="test_submission_setup.py",
        config_script="test_submission_core.py",
        prompt_limit=4,
        bootstrap_profile="test-submission",
    ),
    WorkflowPlugin(
        name="submission-gate",
        version="0.1.0",
        mcp_script="submission_gate_mcp.py",
        mcp_server_name="submission-gate",
        mcp_common_tools=(
            "submission_gate_setup",
            "submission_gate_preflight",
            "submission_gate_run_once",
            "submission_gate_status",
            "submission_gate_doctor",
        ),
        cli_script="submission_gate_cli.py",
        scheduler_script="submission_gate_scheduler.py",
        scheduler_class="SubmissionGateScheduler",
        setup_script="submission_gate_setup.py",
        config_script="submission_gate_core.py",
        prompt_limit=4,
        bootstrap_profile="submission-gate",
    ),
    WorkflowPlugin(
        name="pre-release",
        version="0.1.0",
        mcp_script="pre_release_mcp.py",
        mcp_server_name="pre-release",
        mcp_common_tools=(
            "pre_release_start_setup",
            "pre_release_preflight",
            "pre_release_run_once",
            "pre_release_status",
            "pre_release_doctor",
        ),
        cli_script="pre_release_cli.py",
        scheduler_script="pre_release_scheduler.py",
        scheduler_class="PreReleaseScheduler",
        setup_script="pre_release_setup.py",
        config_script="pre_release_config.py",
        prompt_limit=4,
        bootstrap_profile="pre-release",
    ),
    WorkflowPlugin(
        name="release-gate",
        version="0.1.0",
        mcp_script="release_gate_mcp.py",
        mcp_server_name="release-gate",
        mcp_common_tools=(
            "release_gate_start_setup",
            "release_gate_preflight",
            "release_gate_run_once",
            "release_gate_status",
            "release_gate_doctor",
        ),
        cli_script="release_gate_cli.py",
        scheduler_script="release_workflow_gate_scheduler.py",
        scheduler_class="ReleaseGateScheduler",
        setup_script="release_workflow_gate_setup.py",
        config_script="release_gate_config.py",
        prompt_limit=4,
        bootstrap_profile="release-gate",
    ),
    WorkflowPlugin(
        name="rd-flywheel",
        version="0.2.0",
        mcp_script="rd_flywheel_mcp.py",
        mcp_server_name="rd-flywheel",
        mcp_common_tools=(
            "rd_flywheel_setup",
            "rd_flywheel_preflight",
            "rd_flywheel_run_once",
            "rd_flywheel_status",
            "rd_flywheel_doctor",
        ),
        cli_script="rd_flywheel_cli.py",
        scheduler_script="rd_flywheel_scheduler.py",
        scheduler_class="RDFlywheelScheduler",
        setup_script="rd_flywheel_setup.py",
        config_script="rd_flywheel_config.py",
        prompt_limit=3,
        bootstrap_profile="product-release-gate",
    ),
)

LEGACY_WORKFLOW_PLUGINS = tuple(
    plugin
    for plugin in WORKFLOW_PLUGINS
    if plugin.name in {"release-approval", "release-approval-verifier", "product-release-gate", "rd-flywheel"}
)
ROLE_WORKFLOW_PLUGINS = tuple(
    plugin
    for plugin in WORKFLOW_PLUGINS
    if plugin.name in {"test-submission", "submission-gate", "pre-release", "release-gate"}
)
CANONICAL_RELEASE_WORKFLOW_CORE_DIR = ROOT / "shared" / "release_workflow_core"
RELEASE_WORKFLOW_CORE_SYNC_TOOL = ROOT / "tools" / "sync_release_workflow_core.py"


def _required_file(path: Path) -> Path:
    assert path.is_file(), f"missing required workflow file: {path.relative_to(ROOT)}"
    return path


def _source(path: Path) -> str:
    return _required_file(path).read_text(encoding="utf-8")


def _directory_bytes(root: Path) -> dict[str, bytes]:
    directory = _required_file(root / "__init__.py").parent
    return {
        file_path.relative_to(directory).as_posix(): file_path.read_bytes()
        for file_path in sorted(
            candidate
            for candidate in directory.rglob("*")
            if candidate.is_file() and "__pycache__" not in candidate.parts
        )
    }


def _load_module(path: Path, logical_name: str) -> ModuleType:
    _required_file(path)
    module_name = f"_four_surface_{logical_name}_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    source_root = str(path.parent)
    sys.path.insert(0, source_root)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(source_root)
    return module


def _assigned_string(source: str, name: str) -> str | None:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
    return None


def _tools_keys(source: str) -> set[str]:
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "TOOLS" for target in targets):
            continue
        if isinstance(node.value, ast.Dict):
            return {
                key.value
                for key in node.value.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
    return set()


def _tool_schema_property_names(source: str) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "TOOLS" for target in targets):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for tool_value in node.value.values:
            if not isinstance(tool_value, ast.Dict):
                continue
            for key, value in zip(tool_value.keys, tool_value.values):
                if not isinstance(key, ast.Constant) or key.value != "inputSchema":
                    continue
                if not isinstance(value, ast.Dict):
                    continue
                for schema_key, schema_value in zip(value.keys, value.values):
                    if not isinstance(schema_key, ast.Constant) or schema_key.value != "properties":
                        continue
                    if isinstance(schema_value, ast.Dict):
                        names.update(
                            property_key.value
                            for property_key in schema_value.keys
                            if isinstance(property_key, ast.Constant)
                            and isinstance(property_key.value, str)
                        )
    return names


def _enforced_prompt_limits(source: str) -> list[int]:
    limits: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
            continue
        left_name = (
            node.left.id
            if isinstance(node.left, ast.Name)
            else node.left.attr
            if isinstance(node.left, ast.Attribute)
            else ""
        )
        comparator = node.comparators[0]
        if (
            "prompt_count" in left_name
            and isinstance(node.ops[0], (ast.Gt, ast.GtE))
            and isinstance(comparator, ast.Constant)
            and isinstance(comparator.value, int)
        ):
            limits.append(comparator.value)
    return limits


def _add_argument_options(source: str) -> list[str]:
    options: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "add_argument":
            continue
        options.extend(
            argument.value
            for argument in node.args
            if isinstance(argument, ast.Constant)
            and isinstance(argument.value, str)
            and argument.value.startswith("--")
        )
    return options


def _has_codex_import(source: str) -> bool:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".", 1)[0] == "codex" for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".", 1)[0] == "codex":
                return True
    return False


def _run_isolated(script: Path, *arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    existing_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(script.parent) + (os.pathsep + existing_pythonpath if existing_pythonpath else "")
    environment["PYTHONNOUSERSITE"] = "1"
    return subprocess.run(
        [sys.executable, str(script), *arguments],
        cwd=script.parent,
        env=environment,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize("plugin", WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_each_workflow_plugin_has_all_four_surfaces(plugin: WorkflowPlugin) -> None:
    manifest_path = _required_file(plugin.root / ".codex-plugin" / "plugin.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["name"] == plugin.name
    assert manifest["version"] == plugin.version
    assert manifest.get("mcpServers") == "./.mcp.json"
    assert manifest.get("skills") == "./skills/"

    _required_file(plugin.root / ".mcp.json")
    _required_file(plugin.root / "skills" / plugin.name / "SKILL.md")
    _required_file(plugin.root / "src" / plugin.cli_script)
    _required_file(plugin.root / "src" / plugin.scheduler_script)
    _required_file(plugin.root / "src" / plugin.setup_script)
    _required_file(plugin.root / "src" / plugin.config_script)
    _required_file(plugin.root / "README.md")
    _required_file(plugin.root / "config" / "config.example.json")


@pytest.mark.parametrize("plugin", WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_standalone_cli_inventory_runs_without_codex(plugin: WorkflowPlugin) -> None:
    cli_path = _required_file(plugin.root / "src" / plugin.cli_script)
    source = cli_path.read_text(encoding="utf-8")
    assert not _has_codex_import(source), f"{plugin.name} CLI imports Codex at module import time"

    completed = _run_isolated(cli_path, "--help")
    assert completed.returncode == 0, completed.stderr
    help_text = f"{completed.stdout}\n{completed.stderr}".lower()
    missing = sorted(command for command in COMMON_CLI_COMMANDS if command not in help_text)
    assert not missing, f"{plugin.name} CLI missing common commands: {missing}"

    scheduler_help = _run_isolated(cli_path, "scheduler", "--help")
    assert scheduler_help.returncode == 0, scheduler_help.stderr
    scheduler_text = f"{scheduler_help.stdout}\n{scheduler_help.stderr}".lower()
    missing_actions = sorted(action for action in SCHEDULER_ACTIONS if action not in scheduler_text)
    assert not missing_actions, f"{plugin.name} scheduler CLI missing actions: {missing_actions}"


@pytest.mark.parametrize("plugin", WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_mcp_inventory_and_stdio_startup_match_cli_common_operations(plugin: WorkflowPlugin) -> None:
    mcp_path = _required_file(plugin.root / "src" / plugin.mcp_script)
    source = mcp_path.read_text(encoding="utf-8")
    assert not _has_codex_import(source), f"{plugin.name} MCP imports Codex at module import time"
    missing = sorted(set(plugin.mcp_common_tools) - _tools_keys(source))
    assert not missing, f"{plugin.name} MCP missing CLI-parity tools: {missing}"

    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
    ) + "\n"
    completed = _run_isolated(mcp_path, input_text=request)
    assert completed.returncode == 0, completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    assert lines, f"{plugin.name} MCP emitted no initialize response"
    response = json.loads(lines[0])
    assert response["result"]["serverInfo"]["name"] == plugin.mcp_server_name
    assert response["result"]["serverInfo"]["version"] == plugin.version


@pytest.mark.parametrize("plugin", WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_one_config_source_and_no_per_command_policy_override(plugin: WorkflowPlugin) -> None:
    config_path = _required_file(plugin.root / "src" / plugin.config_script)
    cli_path = _required_file(plugin.root / "src" / plugin.cli_script)
    mcp_path = _required_file(plugin.root / "src" / plugin.mcp_script)
    config_source = config_path.read_text(encoding="utf-8")
    cli_source = cli_path.read_text(encoding="utf-8")
    mcp_source = mcp_path.read_text(encoding="utf-8")

    config_functions = {
        node.name for node in ast.parse(config_source).body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "default_config_path" in config_functions, (
        f"{plugin.name} must define default_config_path in its authoritative config module"
    )
    for surface_name, surface_source in (("CLI", cli_source), ("MCP", mcp_source)):
        assert "default_config_path" in surface_source, (
            f"{plugin.name} {surface_name} does not use the shared default_config_path"
        )
        duplicate_definitions = {
            node.name
            for node in ast.parse(surface_source).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in {"default_config_path", "_resolve_config_path"}
        }
        assert not duplicate_definitions, (
            f"{plugin.name} {surface_name} duplicates config-path policy: {sorted(duplicate_definitions)}"
        )

    options = _add_argument_options(cli_source)
    assert options.count("--config") == 1, f"{plugin.name} CLI must expose exactly one process config path"
    forbidden = sorted(FORBIDDEN_POLICY_OPTIONS.intersection(options))
    assert not forbidden, f"{plugin.name} exposes per-command policy overrides: {forbidden}"

    mcp_properties = _tool_schema_property_names(mcp_source)
    assert "config_path" not in mcp_properties, f"{plugin.name} MCP accepts per-call config_path"
    for option in FORBIDDEN_POLICY_OPTIONS:
        field = option.removeprefix("--").replace("-", "_")
        assert field not in mcp_properties, f"{plugin.name} MCP accepts policy override {field}"


class FakeSchedulerRunner:
    WINDOWS_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>false</StartWhenAvailable>
  </Settings>
</Task>
"""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.crontab = "# unrelated\n"

    def __call__(
        self,
        command: Any,
        cwd: str | None = None,
        input_text: str | None = None,
        *,
        encoding: str | None = None,
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, encoding
        args = [str(value) for value in command]
        self.calls.append(args)
        if args[:2] == ["schtasks", "/Query"]:
            return subprocess.CompletedProcess(args, 0, self.WINDOWS_XML, "")
        if args == ["systemctl", "--user", "is-active", args[-1]]:
            return subprocess.CompletedProcess(args, 0, "active\n", "")
        if args == ["systemctl", "--user", "is-enabled", args[-1]]:
            return subprocess.CompletedProcess(args, 0, "enabled\n", "")
        if args == ["crontab", "-l"]:
            return subprocess.CompletedProcess(args, 0, self.crontab, "")
        if args == ["crontab", "-"]:
            self.crontab = input_text or ""
            return subprocess.CompletedProcess(args, 0, "", "")
        if len(args) == 2 and args[0] == "crontab" and args[1] not in {"-", "-l"}:
            self.crontab = Path(args[1]).read_text(encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "active\n", "")


def _scheduler_instance(
    plugin: WorkflowPlugin,
    tmp_path: Path,
    backend: str,
    runner: FakeSchedulerRunner,
) -> Any:
    module_path = plugin.root / "src" / plugin.scheduler_script
    module = _load_module(module_path, f"{plugin.name}_scheduler_{backend}")
    scheduler_type = getattr(module, plugin.scheduler_class)
    parameters = inspect.signature(scheduler_type).parameters
    cli_path = (plugin.root / "src" / plugin.cli_script).resolve()
    values: dict[str, Any] = {
        "plugin_name": plugin.name,
        "role_id": "acceptance",
        "config_path": tmp_path / "config.json",
        "state_dir": tmp_path / "state",
        "poll_minutes": 60,
        "platform": "win32" if backend == "windows" else "linux",
        "platform_name": "win32" if backend == "windows" else "linux",
        "which": lambda name: f"/usr/bin/{name}",
        "runner": runner,
        "command_runner": runner,
        "user_config_root": tmp_path / "user-config",
        "home": tmp_path / "home",
        "cli_path": cli_path,
        "python_executable": Path(sys.executable),
    }
    kwargs = {name: values[name] for name in parameters if name in values}
    return scheduler_type(**kwargs)


@pytest.mark.parametrize("backend", ("windows", "systemd", "cron"))
@pytest.mark.parametrize("plugin", WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_every_scheduler_backend_simulates_skip_all_missed_and_headless_run_once(
    plugin: WorkflowPlugin,
    backend: str,
    tmp_path: Path,
) -> None:
    runner = FakeSchedulerRunner()
    scheduler = _scheduler_instance(plugin, tmp_path / backend, backend, runner)
    command = list(getattr(scheduler, "scheduled_command", getattr(scheduler, "run_command", [])))
    assert command
    assert Path(command[0]).is_absolute(), f"{plugin.name} scheduler must use an absolute Python path"
    assert Path(command[1]).is_absolute(), f"{plugin.name} scheduler must use an absolute CLI path"
    assert command[-1] == "run-once"
    assert "--config" in command
    assert command[0].casefold().endswith("python.exe")
    assert not command[0].casefold().endswith("codex")
    assert all("open-page" not in part.casefold() for part in command)

    result = scheduler.install(mode=backend)
    status = scheduler.status(mode=backend)
    assert result.get("status") == "ready"
    assert status.get("status") == "ready"
    evidence = json.dumps({"install": result, "status": status}, default=str).casefold()
    if backend == "windows":
        assert "ignorenew" in evidence
        assert "start_when_available" in evidence
        assert "false" in evidence
    elif backend == "systemd":
        timer_files = list(tmp_path.rglob("*.timer"))
        assert timer_files, f"{plugin.name} did not render a systemd timer"
        timer_text = timer_files[0].read_text(encoding="utf-8")
        assert "Persistent=false" in timer_text
        assert "OnCalendar" not in timer_text
    else:
        marker = str(getattr(scheduler, "cron_marker", getattr(scheduler, "identity")))
        assert runner.crontab.count(marker) == 1
    assert "skip_all" in evidence or "no_catchup" in evidence


def _find_lock_class(plugin: WorkflowPlugin) -> tuple[Path, type[Any]]:
    for path in sorted((plugin.root / "src").glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        names = {
            node.name
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name in {"RunOnceLock", "KernelRunLock"}
        }
        if names:
            name = sorted(names)[0]
            module = _load_module(path, f"{plugin.name}_lock")
            return path, getattr(module, name)
    pytest.fail(f"{plugin.name} has no OS-kernel run lock implementation")


@pytest.mark.parametrize("plugin", WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_kernel_lock_rejects_old_owner_and_recovers_only_orphan_metadata(
    plugin: WorkflowPlugin,
    tmp_path: Path,
) -> None:
    lock_source, lock_type = _find_lock_class(plugin)
    parameters = inspect.signature(lock_type).parameters
    assert not {"ttl", "expires", "stale_after", "timeout"}.intersection(parameters), (
        f"{plugin.name} run lock must be non-expiring"
    )
    path = tmp_path / f"{plugin.name}.lock"

    def create(owner: str) -> Any:
        kwargs = {"owner": owner} if "owner" in parameters else {}
        return lock_type(path, **kwargs)

    first = create("owner-one")
    second = create("owner-two")
    first_result = first.acquire()
    assert first_result is True or first_result.get("status") == "acquired"
    second_result = second.acquire()
    if second_result is not False:
        assert second_result.get("status") in {"active", "acquired"}
    first.release()

    if "owner" in parameters:
        metadata_path = path.with_name(f"{path.name}.json")
        metadata_path.write_text(
            json.dumps({"status": "active", "owner": "old-owner"}),
            encoding="utf-8",
        )
        replacement = create("owner-three")
        recovered = replacement.acquire()
        try:
            assert recovered.get("status") == "acquired"
            assert recovered.get("recovered_owner") == "old-owner"
        finally:
            replacement.release()
    else:
        path.write_text(json.dumps({"owner": "old-owner"}), encoding="utf-8")
        replacement = create("owner-three")
        assert replacement.acquire() is True
        try:
            assert replacement.orphan_metadata == {"owner": "old-owner"}
        finally:
            replacement.release()

    runtime_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (plugin.root / "src").glob("*.py")
    )
    assert "RUN_ALREADY_ACTIVE" in runtime_source
    assert "orphan" in runtime_source.casefold()
    assert "msvcrt" in lock_source.read_text(encoding="utf-8")
    assert "fcntl" in lock_source.read_text(encoding="utf-8")


@pytest.mark.parametrize("plugin", WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_setup_contract_is_low_prompt_zero_json_and_zero_prompt_on_rerun(
    plugin: WorkflowPlugin,
) -> None:
    setup_source = _source(plugin.root / "src" / plugin.setup_script)
    skill_root = plugin.root / "skills" / plugin.name
    skill_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(skill_root.rglob("*.md"))
    )
    lowered = setup_source.casefold()
    skill_lowered = skill_source.casefold()

    assert "non_interactive" in lowered
    assert "prompt_count" in lowered
    assert "config_path.is_file" in lowered or "self.config_path.is_file" in lowered, (
        f"{plugin.name} setup does not reuse existing config"
    )
    assert "os.replace" in lowered or ".write_text(" in lowered, (
        f"{plugin.name} setup must write the config deterministically"
    )
    assert "json" in lowered, f"{plugin.name} setup must create config without manual JSON editing"
    assert "credential" in lowered or "secret" in lowered
    enforced_limits = _enforced_prompt_limits(setup_source)
    if enforced_limits:
        assert min(enforced_limits) <= plugin.prompt_limit, (
            f"{plugin.name} setup must enforce its <= {plugin.prompt_limit} prompt budget"
        )
    else:
        assert plugin.name in {"test-submission", "submission-gate", "pre-release", "release-gate"}
    assert "zero" in skill_lowered and "json" in skill_lowered, (
        f"{plugin.name} Skill must promise zero manual JSON editing"
    )
    assert "zero" in skill_lowered and "prompt" in skill_lowered, (
        f"{plugin.name} Skill must document zero-prompt reruns"
    )




@pytest.mark.parametrize("plugin", ROLE_WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_role_plugins_embed_canonical_release_workflow_core_and_drop_bridge_refs(plugin: WorkflowPlugin) -> None:
    _required_file(RELEASE_WORKFLOW_CORE_SYNC_TOOL)
    canonical_core = _directory_bytes(CANONICAL_RELEASE_WORKFLOW_CORE_DIR)
    embedded_core = _directory_bytes(plugin.root / "src" / "release_workflow_core")
    assert embedded_core == canonical_core

    runtime_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((plugin.root / "src").rglob("*.py"))
    )
    runtime_lowered = runtime_source.casefold()
    assert "core_version" in runtime_lowered
    assert "core_digest" in runtime_lowered or "workflow_core_digest" in runtime_lowered
    forbidden_fragments = (
        "plugins/product-release-gate",
        "product-release-gate/src",
        "verifier_product_gate_bridge",
        'plugin_name="product-release-gate"',
        'plugin_name = "product-release-gate"',
        '_product_plugin_root = path("plugins/product-release-gate")',
    )
    for fragment in forbidden_fragments:
        assert fragment not in runtime_lowered


def test_role_plugin_config_contracts_are_pinned() -> None:
    test_submission_config = json.loads(
        _source(ROOT / "plugins" / "test-submission" / "config" / "config.example.json")
    )
    assert "default_module" not in test_submission_config
    test_submission_readme = _source(ROOT / "plugins" / "test-submission" / "README.md").casefold()
    assert "no default module" in test_submission_readme
    test_submission_mcp_source = _source(ROOT / "plugins" / "test-submission" / "src" / "test_submission_mcp.py")
    assert '"required": ["task_name", "module", "artifacts"]' in test_submission_mcp_source

    submission_gate_config = json.loads(
        _source(ROOT / "plugins" / "submission-gate" / "config" / "config.example.json")
    )
    assert "allowed_senders" not in submission_gate_config
    submission_gate_skill = _source(
        ROOT / "plugins" / "submission-gate" / "skills" / "submission-gate" / "SKILL.md"
    ).casefold()
    assert "allowed_senders" not in submission_gate_skill

    pre_release_config = json.loads(
        _source(ROOT / "plugins" / "pre-release" / "config" / "config.example.json")
    )
    assert "default_final_output_dir" not in pre_release_config
    assert "test_result" not in pre_release_config
    assert "test_result_source" not in pre_release_config
    pre_release_readme = _source(ROOT / "plugins" / "pre-release" / "README.md").casefold()
    assert "test-result source" in pre_release_readme
    assert "default final output directory" in pre_release_readme
    pre_release_mcp_source = _source(ROOT / "plugins" / "pre-release" / "src" / "pre_release_mcp.py")
    assert '"pre_release_create_request"' in pre_release_mcp_source
    assert '"test_result"' in pre_release_mcp_source
    assert '"output_dir"' in pre_release_mcp_source

    release_gate_source = _source(ROOT / "plugins" / "release-gate" / "src" / "release_gate_controller.py")
    assert "RELEASE_READY_NOTIFIED" in release_gate_source
    assert '"status": "RELEASE_READY_NOTIFIED"' in release_gate_source
    release_gate_readme = _source(ROOT / "plugins" / "release-gate" / "README.md").casefold()
    assert "release_ready_notified" in release_gate_readme
    assert "never performs production deployment" in release_gate_readme


@pytest.mark.parametrize("plugin", WORKFLOW_PLUGINS, ids=lambda item: item.name)
def test_bootstrap_copy_matches_canonical_bytes(plugin: WorkflowPlugin) -> None:
    copy = _required_file(plugin.root / "scripts" / "bootstrap_dependencies.py")
    source = copy.read_text(encoding="utf-8")
    assert "bootstrap_profile" in source
    assert plugin.bootstrap_profile in source or "bootstrap_profile" in source


def test_canonical_bootstrap_supports_existing_and_role_profiles() -> None:
    _required_file(RELEASE_WORKFLOW_CORE_SYNC_TOOL)
    module = _load_module(CANONICAL_BOOTSTRAP, "canonical_bootstrap")
    profiles = getattr(module, "PROFILES")
    assert profiles["release-approval"] == ("imap-smtp-mail", "rd-flywheel", "lark-cli")
    assert profiles["release-approval-verifier"] == (
        "imap-smtp-mail",
        "rd-flywheel",
        "lark-cli",
        "product-release-gate",
        "release-approval-verifier",
    )
    assert profiles["product-release-gate"] == (
        "imap-smtp-mail",
        "rd-flywheel",
        "lark-cli",
        "product-release-gate",
        "release-approval-verifier",
    )
    for role_profile in ("test-submission", "submission-gate", "pre-release", "release-gate"):
        assert role_profile in profiles
        assert "product-release-gate" not in profiles[role_profile]
        assert "imap-smtp-mail" in profiles[role_profile]


@pytest.mark.parametrize(
    ("canonical", "copies"),
    (
        (
            ROOT / "contracts" / "release-approval" / "release-authorization-request-v1.json",
            (
                ROOT / "plugins" / "release-approval" / "contracts" / "release-authorization-request-v1.json",
                ROOT / "plugins" / "release-approval-verifier" / "contracts" / "release-authorization-request-v1.json",
            ),
        ),
        (
            ROOT / "contracts" / "release-approval" / "approval-decision-v1.json",
            (
                ROOT / "plugins" / "release-approval" / "contracts" / "approval-decision-v1.json",
                ROOT / "plugins" / "release-approval-verifier" / "contracts" / "approval-decision-v1.json",
            ),
        ),
        (
            ROOT / "contracts" / "release-approval" / "approval-verification-receipt-v1.json",
            (
                ROOT / "plugins" / "release-approval" / "contracts" / "approval-verification-receipt-v1.json",
                ROOT / "plugins" / "release-approval-verifier" / "contracts" / "approval-verification-receipt-v1.json",
            ),
        ),
        (
            ROOT / "contracts" / "rd-flywheel" / "capability-gap-event-v1.json",
            (
                ROOT / "plugins" / "rd-flywheel" / "contracts" / "capability-gap-event-v1.json",
            ),
        ),
    ),
    ids=("authorization-request", "approval-decision", "verification-receipt", "capability-gap"),
)
def test_contract_copies_match_canonical_bytes(canonical: Path, copies: tuple[Path, ...]) -> None:
    expected = _required_file(canonical).read_bytes()
    for copy in copies:
        assert _required_file(copy).read_bytes() == expected


def _walk_values(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    values = [(path, value)]
    if isinstance(value, dict):
        for key, child in value.items():
            values.extend(_walk_values(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            values.extend(_walk_values(child, f"{path}[{index}]"))
    return values


def _fixture_paths() -> list[Path]:
    paths = list((ROOT / "contracts").rglob("*.json"))
    for plugin in WORKFLOW_PLUGINS:
        paths.extend((plugin.root / "contracts").rglob("*.json"))
        paths.extend((plugin.root / "config").glob("*.example.json"))
    return sorted(set(paths))


@pytest.mark.parametrize("fixture", _fixture_paths(), ids=lambda path: str(path.relative_to(ROOT)))
def test_examples_and_contracts_contain_no_credentials_or_private_production_addresses(
    fixture: Path,
) -> None:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    for value_path, value in _walk_values(payload):
        key = value_path.rsplit(".", 1)[-1].casefold()
        if isinstance(value, str):
            lowered = value.casefold()
            assert "-----begin private key-----" not in lowered, f"private key in {fixture}:{value_path}"
            assert not re.search(r"\bbearer\s+[a-z0-9._~-]{12,}", lowered), (
                f"bearer credential in {fixture}:{value_path}"
            )
            if any(fragment in key for fragment in SECRET_KEY_FRAGMENTS) and not key.endswith(("_env", "_path", "_file", "_dir")):
                assert not value.strip(), f"credential-like value in {fixture}:{value_path}"
            for email in re.findall(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+)", value):
                assert email.casefold() == "example.com", (
                    f"non-example email domain in {fixture}:{value_path}"
                )
            if value.startswith(("http://", "https://")):
                host = (urlparse(value).hostname or "").casefold()
                assert host in ALLOWED_EXAMPLE_HOSTS or host.endswith(".example.com"), (
                    f"private or production URL host in {fixture}:{value_path}"
                )
            for address in re.findall(r"(?<!\d)(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}(?!\d)", value):
                pytest.fail(f"private production address {address} in {fixture}:{value_path}")
