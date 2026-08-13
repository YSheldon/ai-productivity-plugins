from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from rd_flywheel_adapters import (
    discover_adapter_profiles,
    load_governance_adapters,
    load_runtime_adapters,
)
from rd_flywheel_config import RDFlywheelConfig, load_config
from rd_flywheel_controller import RDFlywheelController
from rd_flywheel_scheduler import RDFlywheelScheduler


_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _PLUGIN_ROOT.parents[1]
_ALLOWED_TOOL_PROFILES = (
    "imap-smtp-mail",
    "lark-cli",
    "gitlab",
    "ssh",
    "wecom-codex-usage",
    "product-release-gate",
    "release-approval-verifier",
)
_V1_CONFIG_KEYS = {
    "schema_version",
    "governance_inbox",
    "state_dir",
    "poll_minutes",
    "timezone",
    "tool_profiles",
    "approved_agent_profiles",
    "agent_profile",
    "protected_merge",
    "notification",
    "decision_role_source",
    "dependency_lock",
}
_REQUIRED_GOVERNANCE_PROFILES = {
    "imap-smtp-mail",
    "lark-cli",
    "release-approval-verifier",
}


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


def _default_dependency_bootstrapper() -> Mapping[str, Any]:
    script = _PLUGIN_ROOT / "scripts" / "bootstrap_dependencies.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "rd-flywheel",
            "--repo-root",
            str(_REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise SetupError(
            "dependency bootstrap failed: "
            + (completed.stderr or completed.stdout or "unknown error").strip(),
            code="CAPABILITY_BLOCKED",
        )
    try:
        payload = json.loads(completed.stdout or "")
    except json.JSONDecodeError as exc:
        raise SetupError(
            "dependency bootstrap returned invalid JSON.",
            code="CAPABILITY_BLOCKED",
        ) from exc
    if not isinstance(payload, Mapping):
        raise SetupError(
            "dependency bootstrap returned a non-object result.",
            code="CAPABILITY_BLOCKED",
        )
    return dict(payload)


def _default_verifier_config_path(environment: Mapping[str, str]) -> Path:
    explicit = str(environment.get("RELEASE_APPROVAL_VERIFIER_CONFIG") or "").strip()
    if explicit:
        return Path(os.path.expandvars(explicit)).expanduser().resolve(strict=False)
    if sys.platform.startswith("win"):
        root = Path(
            str(environment.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        )
    else:
        root = Path(
            str(environment.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        )
    return (root / "release-approval-verifier" / "config.json").resolve(strict=False)


def _default_controller_factory(config: RDFlywheelConfig) -> RDFlywheelController:
    agents, verifiers = load_runtime_adapters(config)
    role_fetcher, presenter, decision_verifier = load_governance_adapters(config)
    return RDFlywheelController(
        config,
        agent_adapters=agents,
        evidence_verifiers=verifiers,
        role_snapshot_fetcher=role_fetcher,
        decision_presenter=presenter,
        decision_verifier=decision_verifier,
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
    # Setup persists provider profile names only; credentials and secrets stay in
    # the owning mail, Feishu, GitLab, and verifier provider configurations.
    def __init__(
        self,
        *,
        config_path: str | Path,
        discoverer: Callable[[], DiscoveryResult] = discover_runtime,
        prompt: Callable[[str, str], str] = _default_prompt,
        dependency_bootstrapper: Callable[[], Mapping[str, Any]] = _default_dependency_bootstrapper,
        controller_factory: Callable[[RDFlywheelConfig], Any] = _default_controller_factory,
        scheduler_factory: Callable[[RDFlywheelConfig, Path], Any] = _default_scheduler_factory,
    ) -> None:
        self.config_path = Path(config_path).expanduser().resolve(strict=False)
        self.discoverer = discoverer
        self.prompt = prompt
        self.dependency_bootstrapper = dependency_bootstrapper
        self.controller_factory = controller_factory
        self.scheduler_factory = scheduler_factory

    def run(
        self,
        *,
        non_interactive: bool = False,
        governance_inbox: str | Path | None = None,
        state_dir: str | Path | None = None,
        agent_profile: str | None = None,
        mail_profile: str | None = None,
        governance_group: str | None = None,
        role_document_url: str | None = None,
        role_heading: str = "## 决策角色",
        decision_verifier_config: str | Path | None = None,
        scheduler_mode: str = "auto",
    ) -> dict[str, Any]:
        reused = self.config_path.is_file()
        migrated = False
        prompt_count = 0
        if reused:
            raw_config = self._read_config_object()
            if raw_config.get("schema_version") == 1:
                discovered = self.discoverer()
                config, bootstrap, prompt_count = self._migrate_v1_config(
                    raw_config,
                    discovered=discovered,
                    non_interactive=non_interactive,
                    mail_profile=mail_profile,
                    governance_group=governance_group,
                    role_document_url=role_document_url,
                    role_heading=role_heading,
                    decision_verifier_config=decision_verifier_config,
                )
                migrated = True
            else:
                config = load_config(self.config_path)
                bootstrap = None
        else:
            discovered = self.discoverer()
            environment = os.environ
            default_inbox = self.config_path.parent / "inbox"
            default_state = self.config_path.parent / "state"
            governance_inbox = governance_inbox or default_inbox
            state_dir = state_dir or default_state

            setup_values = {
                "mail_profile": str(
                    mail_profile
                    or environment.get("RD_FLYWHEEL_MAIL_PROFILE")
                    or ""
                ).strip(),
                "governance_group": str(
                    governance_group
                    or environment.get("RD_FLYWHEEL_GOVERNANCE_GROUP")
                    or ""
                ).strip(),
                "role_document_url": str(
                    role_document_url
                    or environment.get("RD_FLYWHEEL_ROLE_DOCUMENT_URL")
                    or ""
                ).strip(),
            }
            prompt_labels = {
                "mail_profile": "Configured enterprise mail profile",
                "governance_group": "R&D governance decision mail group",
                "role_document_url": "Feishu decision role document URL",
            }
            for key in ("mail_profile", "governance_group", "role_document_url"):
                if setup_values[key]:
                    continue
                if non_interactive:
                    raise SetupError(
                        f"{key} is required for non-interactive production setup.",
                        code="SETUP_INPUT_REQUIRED",
                    )
                setup_values[key] = self.prompt(prompt_labels[key], "").strip()
                prompt_count += 1
                if not setup_values[key]:
                    raise SetupError(
                        f"{key} is required for production setup.",
                        code="SETUP_INPUT_REQUIRED",
                    )
            if not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+", setup_values["governance_group"]
            ):
                raise SetupError(
                    "governance_group must be a valid email address.",
                    code="INVALID_SETUP_INPUT",
                )

            candidates = tuple(sorted(set(discovered.agent_profiles)))
            selected_agent = agent_profile
            if selected_agent is None and len(candidates) == 1:
                selected_agent = candidates[0]
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

            bootstrap = self.dependency_bootstrapper()
            lock_path, lock_digest = self._freeze_dependency_lock(bootstrap)
            state_path = Path(state_dir).expanduser().resolve(strict=False)
            verifier_config_path = (
                Path(decision_verifier_config).expanduser().resolve(strict=False)
                if decision_verifier_config is not None
                else _default_verifier_config_path(environment)
            )
            payload = {
                "schema_version": 2,
                "governance_inbox": str(
                    Path(governance_inbox).expanduser().resolve(strict=False)
                ),
                "state_dir": str(state_path),
                "poll_minutes": 60,
                "timezone": discovered.timezone,
                "tool_profiles": sorted(
                    set(discovered.tool_profiles)
                    | _REQUIRED_GOVERNANCE_PROFILES
                ),
                "approved_agent_profiles": list(candidates),
                "agent_profile": selected_agent,
                "protected_merge": {
                    "tool_profile": "gitlab",
                    "protected_branch_required": True,
                },
                "notification": {
                    "mail_profile": setup_values["mail_profile"],
                    "recipients": [setup_values["governance_group"]],
                },
                "decision_role_source": {
                    "type": "feishu",
                    "document_url": setup_values["role_document_url"],
                    "heading": role_heading,
                },
                "dependency_lock": str(lock_path),
                "dependency_lock_sha256": lock_digest,
                "decision_verifier_config": str(verifier_config_path),
            }
            config = self._validated_atomic_config(self.config_path, payload)

        if bootstrap is not None and bootstrap.get("fresh_task_required") is True:
            return {
                "status": "FRESH_TASK_REQUIRED",
                "config_path": str(self.config_path),
                "config_reused": reused,
                "config_migrated": migrated,
                "prompt_count": prompt_count,
                "dependency_bootstrap": dict(bootstrap),
                "commands": self._commands(),
            }

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
            "config_migrated": migrated,
            "prompt_count": prompt_count,
            "dependency_bootstrap": dict(bootstrap) if bootstrap is not None else None,
            "preflight": preflight,
            "scheduler": scheduler_install,
            "first_run": first_run,
            "runtime_status": status,
            "scheduler_status": scheduler_status,
            "commands": commands,
        }

    def _read_config_object(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SetupError(
                f"cannot read existing config for migration: {exc}",
                code="CONFIG_ERROR",
            ) from exc
        if not isinstance(payload, dict):
            raise SetupError(
                "existing config root must be an object.",
                code="CONFIG_ERROR",
            )
        return payload

    def _migrate_v1_config(
        self,
        payload: Mapping[str, Any],
        *,
        discovered: DiscoveryResult,
        non_interactive: bool,
        mail_profile: str | None,
        governance_group: str | None,
        role_document_url: str | None,
        role_heading: str,
        decision_verifier_config: str | Path | None,
    ) -> tuple[RDFlywheelConfig, Mapping[str, Any], int]:
        unexpected = set(payload).difference(_V1_CONFIG_KEYS)
        if unexpected:
            raise SetupError(
                "v1 config contains fields that cannot be migrated safely: "
                + ", ".join(sorted(unexpected)),
                code="CONFIG_ERROR",
            )

        notification = payload.get("notification")
        old_mail_profile = ""
        old_governance_group = ""
        if isinstance(notification, Mapping):
            old_mail_profile = str(notification.get("mail_profile") or "").strip()
            old_recipients = notification.get("recipients")
            if isinstance(old_recipients, list) and old_recipients:
                old_governance_group = str(old_recipients[0] or "").strip()

        role_source = payload.get("decision_role_source")
        old_role_document_url = ""
        old_role_heading = ""
        if isinstance(role_source, Mapping):
            old_role_document_url = str(role_source.get("document_url") or "").strip()
            old_role_heading = str(role_source.get("heading") or "").strip()

        environment = os.environ
        values = {
            "mail_profile": str(
                mail_profile
                or old_mail_profile
                or environment.get("RD_FLYWHEEL_MAIL_PROFILE")
                or ""
            ).strip(),
            "governance_group": str(
                governance_group
                or old_governance_group
                or environment.get("RD_FLYWHEEL_GOVERNANCE_GROUP")
                or ""
            ).strip(),
            "role_document_url": str(
                role_document_url
                or old_role_document_url
                or environment.get("RD_FLYWHEEL_ROLE_DOCUMENT_URL")
                or ""
            ).strip(),
        }
        labels = {
            "mail_profile": "Configured enterprise mail profile",
            "governance_group": "R&D governance decision mail group",
            "role_document_url": "Feishu decision role document URL",
        }
        prompt_count = 0
        for key in ("mail_profile", "governance_group", "role_document_url"):
            if values[key]:
                continue
            if non_interactive:
                raise SetupError(
                    f"{key} is required to migrate v1 config for production.",
                    code="SETUP_INPUT_REQUIRED",
                )
            values[key] = self.prompt(labels[key], "").strip()
            prompt_count += 1
            if not values[key]:
                raise SetupError(
                    f"{key} is required to migrate v1 config for production.",
                    code="SETUP_INPUT_REQUIRED",
                )
        if prompt_count > 3:
            raise SetupError(
                "v1 migration exceeded the three-prompt contract.",
                code="PROMPT_LIMIT_EXCEEDED",
            )
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", values["governance_group"]):
            raise SetupError(
                "governance_group must be a valid email address.",
                code="INVALID_SETUP_INPUT",
            )

        bootstrap = self.dependency_bootstrapper()
        lock_path, lock_digest = self._freeze_dependency_lock(bootstrap)
        verifier_path = (
            Path(decision_verifier_config).expanduser().resolve(strict=False)
            if decision_verifier_config is not None
            else _default_verifier_config_path(environment)
        )
        old_tools = payload.get("tool_profiles")
        tool_profiles = (
            {str(item).strip() for item in old_tools if str(item).strip()}
            if isinstance(old_tools, list)
            else set()
        )
        migrated_payload = {
            "schema_version": 2,
            "governance_inbox": payload.get("governance_inbox"),
            "state_dir": payload.get("state_dir"),
            "poll_minutes": payload.get("poll_minutes", 60),
            "timezone": payload.get("timezone") or discovered.timezone,
            "tool_profiles": sorted(
                tool_profiles | set(discovered.tool_profiles) | _REQUIRED_GOVERNANCE_PROFILES
            ),
            "approved_agent_profiles": payload.get("approved_agent_profiles", []),
            "agent_profile": payload.get("agent_profile"),
            "protected_merge": payload.get("protected_merge"),
            "notification": {
                "mail_profile": values["mail_profile"],
                "recipients": [values["governance_group"]],
            },
            "decision_role_source": {
                "type": "feishu",
                "document_url": values["role_document_url"],
                "heading": old_role_heading or role_heading,
            },
            "dependency_lock": str(lock_path),
            "dependency_lock_sha256": lock_digest,
            "decision_verifier_config": str(verifier_path),
        }
        try:
            config = self._validated_atomic_config(
                self.config_path,
                migrated_payload,
            )
        except Exception as exc:
            if isinstance(exc, SetupError):
                raise
            raise SetupError(
                f"migrated v1 config is invalid: {exc}",
                code="CONFIG_ERROR",
            ) from exc
        return config, bootstrap, prompt_count

    @staticmethod
    def _freeze_dependency_lock(
        bootstrap: Mapping[str, Any],
    ) -> tuple[Path, str]:
        raw_path = bootstrap.get("dependency_lock")
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise SetupError(
                "dependency bootstrap did not return a dependency lock path.",
                code="CAPABILITY_BLOCKED",
            )
        try:
            lock_path = Path(raw_path).expanduser().resolve(strict=True)
            if not lock_path.is_file():
                raise OSError("dependency lock is not a file")
            lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise SetupError(
                f"dependency lock cannot be frozen: {exc}",
                code="CAPABILITY_BLOCKED",
            ) from exc
        return lock_path, lock_digest

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
    def _validated_atomic_config(
        path: Path,
        payload: Mapping[str, Any],
    ) -> RDFlywheelConfig:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".candidate",
                delete=False,
            ) as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
                temporary = Path(handle.name)
            config = load_config(temporary)
            os.replace(temporary, path)
            temporary = None
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return config
        except Exception as exc:
            raise SetupError(
                f"candidate config is invalid or cannot be committed: {exc}",
                code="CONFIG_ERROR",
            ) from exc
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass


def run_setup_operation(
    *,
    config_path: str | Path,
    non_interactive: bool = False,
    governance_inbox: str | Path | None = None,
    state_dir: str | Path | None = None,
    agent_profile: str | None = None,
    mail_profile: str | None = None,
    governance_group: str | None = None,
    role_document_url: str | None = None,
    role_heading: str = "## 决策角色",
    decision_verifier_config: str | Path | None = None,
    scheduler_mode: str = "auto",
    setup_factory: Callable[..., RDFlywheelSetup] = RDFlywheelSetup,
) -> Mapping[str, Any]:
    setup = setup_factory(config_path=config_path)
    return setup.run(
        non_interactive=non_interactive,
        governance_inbox=governance_inbox,
        state_dir=state_dir,
        agent_profile=agent_profile,
        mail_profile=mail_profile,
        governance_group=governance_group,
        role_document_url=role_document_url,
        role_heading=role_heading,
        decision_verifier_config=decision_verifier_config,
        scheduler_mode=scheduler_mode,
    )
