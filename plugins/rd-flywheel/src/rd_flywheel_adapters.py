from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Callable, Mapping, Sequence

from rd_flywheel_config import RDFlywheelConfig
from rd_flywheel_protocol import CapabilityGapEvent, EvidenceReference, canonical_json


_AGENT_ENV = "RD_FLYWHEEL_AGENT_COMMANDS_JSON"
_VERIFIER_ENV = "RD_FLYWHEEL_VERIFIER_COMMANDS_JSON"


class AdapterError(RuntimeError):
    """Raised when an external evidence-only adapter is unavailable or malformed."""


def _default_runner(
    args: Sequence[str],
    *,
    input_text: str | None = None,
    encoding: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        input=input_text,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        encoding=encoding or "utf-8",
    )


def _command_registry(
    value: str | None,
    *,
    field_name: str,
) -> dict[str, tuple[str, ...]]:
    if not value:
        return {}
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AdapterError(f"{field_name} must be valid JSON.") from exc
    if not isinstance(payload, Mapping):
        raise AdapterError(f"{field_name} must be a JSON object.")
    registry: dict[str, tuple[str, ...]] = {}
    for profile, command in payload.items():
        if (
            not isinstance(profile, str)
            or not profile.strip()
            or not isinstance(command, list)
            or not command
            or not all(isinstance(item, str) and item for item in command)
        ):
            raise AdapterError(
                f"{field_name} entries must map non-empty profile names to argv arrays."
            )
        registry[profile.strip()] = tuple(command)
    return registry


def discover_adapter_profiles(
    environ: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    environment = os.environ if environ is None else environ
    registry = _command_registry(
        environment.get(_AGENT_ENV),
        field_name=_AGENT_ENV,
    )
    return tuple(sorted(registry))


class CommandAgentAdapter:
    def __init__(
        self,
        command: Sequence[str],
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = _default_runner,
    ) -> None:
        self.command = tuple(command)
        self.runner = runner

    def __call__(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        completed = self.runner(
            self.command,
            input_text=canonical_json(payload),
            encoding="utf-8",
        )
        if completed.returncode != 0:
            raise AdapterError(
                "agent adapter failed: "
                + (completed.stderr or completed.stdout or "unknown error").strip()
            )
        try:
            result = json.loads(completed.stdout or "")
        except json.JSONDecodeError as exc:
            raise AdapterError("agent adapter returned invalid JSON.") from exc
        if not isinstance(result, Mapping):
            raise AdapterError("agent adapter result must be a JSON object.")
        return result


class CommandEvidenceVerifier:
    def __init__(
        self,
        command: Sequence[str],
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = _default_runner,
    ) -> None:
        self.command = tuple(command)
        self.runner = runner

    def __call__(
        self,
        reference: EvidenceReference,
        event: CapabilityGapEvent,
    ) -> Mapping[str, Any]:
        payload = {
            "schema": "RDFlywheelEvidenceVerification/v1",
            "event": dict(event.payload),
            "evidence": reference.as_dict(),
        }
        completed = self.runner(
            self.command,
            input_text=canonical_json(payload),
            encoding="utf-8",
        )
        if completed.returncode != 0:
            raise AdapterError(
                "evidence verifier failed: "
                + (completed.stderr or completed.stdout or "unknown error").strip()
            )
        try:
            result = json.loads(completed.stdout or "")
        except json.JSONDecodeError as exc:
            raise AdapterError("evidence verifier returned invalid JSON.") from exc
        if not isinstance(result, Mapping) or type(result.get("verified")) is not bool:
            raise AdapterError(
                "evidence verifier must return a JSON object with a bool verified field."
            )
        return dict(result)


def load_runtime_adapters(
    config: RDFlywheelConfig,
    *,
    environ: Mapping[str, str] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = _default_runner,
) -> tuple[dict[str, CommandAgentAdapter], dict[str, CommandEvidenceVerifier]]:
    environment = os.environ if environ is None else environ
    agent_commands = _command_registry(
        environment.get(_AGENT_ENV),
        field_name=_AGENT_ENV,
    )
    verifier_commands = _command_registry(
        environment.get(_VERIFIER_ENV),
        field_name=_VERIFIER_ENV,
    )
    approved = set(config.approved_agent_profiles)
    agents = {
        profile: CommandAgentAdapter(command, runner=runner)
        for profile, command in agent_commands.items()
        if profile in approved
    }
    verifiers = {
        kind: CommandEvidenceVerifier(command, runner=runner)
        for kind, command in verifier_commands.items()
    }
    return agents, verifiers
