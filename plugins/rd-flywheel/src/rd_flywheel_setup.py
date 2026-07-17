from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from rd_flywheel_adapters import discover_adapter_profiles, load_runtime_adapters
from rd_flywheel_config import RDFlywheelConfig, load_config
from rd_flywheel_controller import RDFlywheelController
from rd_flywheel_scheduler import RDFlywheelScheduler


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_ALLOWED_TOOL_PROFILES = (
    "imap-smtp-mail",
    "lark-cli",
    "gitlab",
    "ssh",
    "wecom-codex-usage",
    "product-release-gate",
)


class SetupError(RuntimeError):
    """Raised when setup cannot create a safe deterministic runtime."""

    def __init__(self, message: str, *, code: str = "SETUP_FAILED") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DiscoveryResult:
    tool_profiles: tuple[str, ...]
    agent_profiles: tuple[str, ...]
    scheduler_mode: str
    timezone: str


def discover_runtime(
    *,
    environ: Mapping[str, str] | None = None,
    plugin_root: Path = _PLUGIN_ROOT,
) -> DiscoveryResult:
    environment = os.environ if environ is None else environ
    explicit_tools = {
        item.strip()
        for item in str(environment.get("RD_FLYWHEEL_TOOL_PROFILES") or "").split(",")
        if item.strip()
    }
    tools: set[str] = set()
    sibling_root = plugin_root.parent
    for profile in _ALLOWED_TOOL_PROFILES:
        if profile in explicit_tools or (sibling_root / profile).exists():
            tools.add(profile)
    if shutil.which("lark-cli"):
        tools.add("lark-cli")
    if shutil.which("ssh"):
        tools.add("ssh")
    if shutil.which("git"):
        tools.add("gitlab")
    timezone_name = str(environment.get("TZ") or "Asia/Shanghai").strip()
    return DiscoveryResult(
        tool_profiles=tuple(sorted(tools)),
        agent_profiles=discover_adapter_profiles(environment),
        scheduler_mode="auto",
        timezone=timezone_name,
    )


def _default_prompt(label: str, default: str) -> str:
    answer = input(f"{label} [{default}]: ").strip()
    return answer or default


def _default_controller_factory(config: RDFlywheelConfig) -> RDFlywheelController:
    agents, verifiers = load_runtime_adapters(config)
    return RDFlywheelController(
        config,
        agent_adapters=agents,
        evidence_verifiers=verifiers,
    )


def _default_scheduler_factory(
    config: RDFlywheelConfig,
    config_path: Path,
) -> RDFlywheelScheduler:
    return RDFlywheelScheduler(
        config_path=config_path,
        cli_path=_PLUGIN_ROOT / "src" / "rd_flywheel_cli.py",
        state_dir=config.state_dir,
        poll_minutes=config.poll_minutes,
    )


class RDFlywheelSetup:
    def __init__(
        self,
        *,
        config_path: str | Path,
        discoverer: Callable[[], DiscoveryResult] = discover_runtime,
        prompt: Callable[[str, str], str] = _default_prompt,
        controller_factory: Callable[[RDFlywheelConfig], Any] = _default_controller_factory,
        scheduler_factory: Callable[[RDFlywheelConfig, Path], Any] = _default_scheduler_factory,
    ) -> None:
        self.config_path = Path(config_path).expanduser().resolve(strict=False)
        self.discoverer = discoverer
        self.prompt = prompt
        self.controller_factory = controller_factory
        self.scheduler_factory = scheduler_factory

    def run(
        self,
        *,
        non_interactive: bool = False,
        governance_inbox: str | Path | None = None,
        state_dir: str | Path | None = None,
        agent_profile: str | None = None,
        scheduler_mode: str = "auto",
    ) -> dict[str, Any]:
        reused = self.config_path.is_file()
        prompt_count = 0
        if reused:
            config = load_config(self.config_path)
        else:
            discovered = self.discoverer()
            default_inbox = self.config_path.parent / "inbox"
            default_state = self.config_path.parent / "state"
            if governance_inbox is None:
                if non_interactive:
                    governance_inbox = default_inbox
                else:
                    governance_inbox = self.prompt(
                        "Capability-gap governance inbox",
                        str(default_inbox),
                    )
                    prompt_count += 1
            if state_dir is None:
                if non_interactive:
                    state_dir = default_state
                else:
                    state_dir = self.prompt(
                        "R&D flywheel state root",
                        str(default_state),
                    )
                    prompt_count += 1

            candidates = tuple(sorted(set(discovered.agent_profiles)))
            selected_agent = agent_profile
            if selected_agent is None and len(candidates) == 1:
                selected_agent = candidates[0]
            elif selected_agent is None and len(candidates) > 1 and not non_interactive:
                selected_agent = self.prompt(
                    "Approved capability-construction agent profile",
                    candidates[0],
                )
                prompt_count += 1
            elif selected_agent is None and len(candidates) > 1:
                selected_agent = None
            if selected_agent is not None and selected_agent not in candidates:
                raise SetupError(
                    "selected agent profile was not discovered in the approved adapter registry.",
                    code="AGENT_PROFILE_UNAVAILABLE",
                )
            if prompt_count > 3:
                raise SetupError(
                    "setup exceeded the three-prompt contract.",
                    code="PROMPT_LIMIT_EXCEEDED",
                )
            if "gitlab" not in discovered.tool_profiles:
                raise SetupError(
                    "protected merge tool profile gitlab was not discovered.",
                    code="CAPABILITY_BLOCKED",
                )

            state_path = Path(state_dir).expanduser().resolve(strict=False)
            lock_path = state_path / "dependency-lock.json"
            self._write_dependency_lock(
                lock_path,
                discovered=discovered,
                selected_agent=selected_agent,
            )
            payload = {
                "schema_version": 1,
                "governance_inbox": str(
                    Path(governance_inbox).expanduser().resolve(strict=False)
                ),
                "state_dir": str(state_path),
                "poll_minutes": 60,
                "timezone": discovered.timezone,
                "tool_profiles": list(discovered.tool_profiles),
                "approved_agent_profiles": list(candidates),
                "agent_profile": selected_agent,
                "protected_merge": {
                    "tool_profile": "gitlab",
                    "protected_branch_required": True,
                },
                "notification": None,
                "decision_role_source": None,
                "dependency_lock": str(lock_path),
            }
            self._atomic_json(self.config_path, payload)
            config = load_config(self.config_path)

        mode = scheduler_mode
        if mode == "auto" and not reused:
            discovered_mode = locals().get("discovered")
            if isinstance(discovered_mode, DiscoveryResult):
                mode = discovered_mode.scheduler_mode
        controller = self.controller_factory(config)
        scheduler = self.scheduler_factory(config, self.config_path)
        preflight = controller.preflight()
        scheduler_install = scheduler.install(mode=mode)
        first_run = controller.run_once()
        status = controller.status()
        scheduler_status = scheduler.status(mode=mode)
        overall = self._overall_status(
            preflight,
            scheduler_install,
            first_run,
            status,
            scheduler_status,
        )
        commands = self._commands()
        return {
            "status": overall,
            "config_path": str(self.config_path),
            "config_reused": reused,
            "prompt_count": prompt_count,
            "preflight": preflight,
            "scheduler": scheduler_install,
            "first_run": first_run,
            "runtime_status": status,
            "scheduler_status": scheduler_status,
            "commands": commands,
        }

    @staticmethod
    def _overall_status(*payloads: Mapping[str, Any]) -> str:
        statuses = {str(payload.get("status") or "") for payload in payloads}
        if "CAPABILITY_BLOCKED" in statuses:
            return "CAPABILITY_BLOCKED"
        if "RUN_ALREADY_ACTIVE" in statuses:
            return "RUN_ALREADY_ACTIVE"
        if "EVIDENCE_PENDING" in statuses:
            return "EVIDENCE_PENDING"
        return "ready"

    def _commands(self) -> dict[str, str]:
        python = __import__("sys").executable
        cli = _PLUGIN_ROOT / "src" / "rd_flywheel_cli.py"
        prefix = f'"{python}" "{cli}" --config "{self.config_path}"'
        return {
            "status": f"{prefix} status",
            "doctor": f"{prefix} doctor",
            "scheduler_remove": f"{prefix} scheduler remove --mode auto",
            "rollback": f"{prefix} scheduler remove --mode auto",
        }

    @staticmethod
    def _write_dependency_lock(
        path: Path,
        *,
        discovered: DiscoveryResult,
        selected_agent: str | None,
    ) -> None:
        payload = {
            "schema_version": 1,
            "source": "setup-discovery",
            "tool_profiles": [
                {
                    "profile": profile,
                    "reference_sha256": hashlib.sha256(profile.encode("utf-8")).hexdigest(),
                }
                for profile in discovered.tool_profiles
            ],
            "agent_profile": selected_agent,
            "contains_credentials": False,
        }
        RDFlywheelSetup._atomic_json(path, payload)

    @staticmethod
    def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        temporary.write_text(text, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def run_setup_operation(
    *,
    config_path: str | Path,
    non_interactive: bool = False,
    governance_inbox: str | Path | None = None,
    state_dir: str | Path | None = None,
    agent_profile: str | None = None,
    scheduler_mode: str = "auto",
    setup_factory: Callable[..., RDFlywheelSetup] = RDFlywheelSetup,
) -> Mapping[str, Any]:
    setup = setup_factory(config_path=config_path)
    return setup.run(
        non_interactive=non_interactive,
        governance_inbox=governance_inbox,
        state_dir=state_dir,
        agent_profile=agent_profile,
        scheduler_mode=scheduler_mode,
    )
