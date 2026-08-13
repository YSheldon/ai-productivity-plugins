from __future__ import annotations

import json
import os
import base64
import hashlib
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from rd_flywheel_config import RDFlywheelConfig
from rd_flywheel_decision import parse_decision_role_snapshot
from rd_flywheel_protocol import CapabilityGapEvent, EvidenceReference, canonical_json


_AGENT_ENV = "RD_FLYWHEEL_AGENT_COMMANDS_JSON"
_VERIFIER_ENV = "RD_FLYWHEEL_VERIFIER_COMMANDS_JSON"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAIL_ENTRYPOINT = Path("plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py")
_VERIFIER_ENTRYPOINT = Path(
    "plugins/release-approval-verifier/src/verifier_cli.py"
)
_COMMAND_TIMEOUT_ENV = "RD_FLYWHEEL_COMMAND_TIMEOUT_SECONDS"
_DEFAULT_COMMAND_TIMEOUT_SECONDS = 1800


class AdapterError(RuntimeError):
    """Raised when an external evidence-only adapter is unavailable or malformed."""


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _locked_entrypoint(
    config: RDFlywheelConfig,
    *,
    plugin_name: str,
    entrypoint_path: Path,
) -> Path:
    lock_path = config.dependency_lock.resolve(strict=True)
    if _sha256_file(lock_path) != config.dependency_lock_sha256:
        raise AdapterError("rd-flywheel dependency lock drift was detected.")
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AdapterError("rd-flywheel dependency lock is invalid JSON.") from exc
    plugins = lock.get("plugins") if isinstance(lock, Mapping) else None
    if not isinstance(plugins, list):
        raise AdapterError("rd-flywheel dependency lock has no plugins array.")
    expected_root = Path("plugins") / plugin_name
    try:
        entrypoint_path.relative_to(expected_root)
    except ValueError as exc:
        raise AdapterError("locked entrypoint is outside its plugin root.") from exc
    for plugin in plugins:
        if not isinstance(plugin, Mapping) or plugin.get("name") != plugin_name:
            continue
        if Path(str(plugin.get("plugin_root") or "")) != expected_root:
            raise AdapterError(f"locked {plugin_name} plugin root is invalid.")
        entrypoints = plugin.get("entrypoints")
        if not isinstance(entrypoints, list):
            raise AdapterError(f"locked {plugin_name} has no runtime entrypoints.")
        for item in entrypoints:
            if not isinstance(item, Mapping):
                continue
            if Path(str(item.get("path") or "")) != entrypoint_path:
                continue
            digest = str(item.get("sha256") or "").strip().lower()
            if not _SHA256_PATTERN.fullmatch(digest):
                raise AdapterError(f"locked {plugin_name} entrypoint digest is invalid.")
            resolved = (lock_path.parent / entrypoint_path).resolve(strict=True)
            root = (lock_path.parent / expected_root).resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise AdapterError(f"locked {plugin_name} entrypoint escaped its root.") from exc
            if _sha256_file(resolved) != digest:
                raise AdapterError(f"locked {plugin_name} entrypoint drift was detected.")
            return resolved
        raise AdapterError(
            f"dependency lock does not pin {entrypoint_path.as_posix()}."
        )
    raise AdapterError(f"dependency lock does not include {plugin_name}.")


def _lark_cli_command() -> tuple[str, ...]:
    if os.name != "nt":
        return (shutil.which("lark-cli") or "lark-cli",)
    native = shutil.which("lark-cli.exe")
    if native:
        return (native,)
    node = shutil.which("node.exe") or shutil.which("node")
    if node:
        for raw_directory in os.environ.get("PATH", "").split(os.pathsep):
            directory = raw_directory.strip().strip('"')
            if not directory:
                continue
            entry = (
                Path(directory)
                / "node_modules"
                / "@larksuite"
                / "cli"
                / "scripts"
                / "run.js"
            )
            if entry.is_file():
                return (node, str(entry.resolve()))
    return ("lark-cli",)


def _json_command(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    args: Sequence[str],
    *,
    input_payload: Mapping[str, Any] | None = None,
    operation: str,
) -> dict[str, Any]:
    completed = runner(
        tuple(args),
        input_text=(canonical_json(input_payload) if input_payload is not None else None),
        encoding="utf-8",
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        raise AdapterError(f"{operation} failed with exit {completed.returncode}: {detail}")
    lines = [line for line in (completed.stdout or "").splitlines() if line.strip()]
    if len(lines) != 1:
        raise AdapterError(f"{operation} returned an ambiguous JSON response.")
    try:
        payload = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise AdapterError(f"{operation} returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise AdapterError(f"{operation} response must be a JSON object.")
    return payload


class LarkDecisionRoleSnapshotFetcher:
    def __init__(
        self,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        command_prefix: Sequence[str] | None = None,
    ) -> None:
        self.runner = runner or _default_runner
        self.command_prefix = tuple(command_prefix or _lark_cli_command())

    def __call__(self, source: Any) -> Any:
        args = (
            *self.command_prefix,
            "docs",
            "+fetch",
            "--api-version",
            "v2",
            "--doc",
            source.document_url,
            "--doc-format",
            "markdown",
            "--as",
            "user",
            "--format",
            "pretty",
        )
        completed = self.runner(args, input_text=None, encoding="utf-8")
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "unknown error").strip()
            raise AdapterError(f"lark role snapshot fetch failed: {detail}")
        return parse_decision_role_snapshot(
            completed.stdout or "",
            document_url=source.document_url,
            heading=source.heading,
        )


class LockedGovernanceMailPresenter:
    def __init__(
        self,
        entrypoint: Path,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.entrypoint = entrypoint
        self.runner = runner or _default_runner
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def __call__(self, presentation: Mapping[str, Any]) -> Mapping[str, Any]:
        request = presentation.get("request")
        recipients = presentation.get("recipients")
        if not isinstance(request, Mapping) or not isinstance(recipients, list) or not recipients:
            raise AdapterError("governance presentation request or recipients are invalid.")
        governance_context = request.get("governance_context")
        if not isinstance(governance_context, Mapping):
            raise AdapterError("governance presentation is missing its frozen Visual Companion context.")
        required_evidence = governance_context.get("required_evidence")
        if not isinstance(required_evidence, list) or not required_evidence:
            raise AdapterError("governance presentation has no frozen completion evidence list.")
        encoded = base64.urlsafe_b64encode(
            canonical_json(request).encode("utf-8")
        ).decode("ascii").rstrip("=")
        requested_at = str(request.get("requested_at") or "").replace("-", "").replace(":", "")
        subject = f"【研发飞轮决策】{request['task']}-{request['module']}-{requested_at}"
        text = "\n".join(
            (
                "【研发飞轮治理决策】",
                f"能力缺口：{request['task']}",
                f"来源模块：{request['module']}",
                f"审批轮次：{request['round_id']}",
                f"权限域：{request['authority_scope']}",
                "权限边界：本决策只允许能力建设，不构成测试通过、发布授权或生产部署许可。",
                "生产完成证据：" + "、".join(str(item) for item in required_evidence),
                "Visual Companion 摘要："
                + str(governance_context.get("visual_companion_html_sha256") or ""),
                "确认方式：打开本机发布审批插件生成的决策页，或直接回复本邮件“同意/通过/待定/驳回”。",
                "Visual Companion 由审批插件依据冻结机器请求重建，页面摘要会写入最终决策证据。",
                "",
                "-----BEGIN RELEASE APPROVAL REQUEST-----",
                encoded,
                "-----END RELEASE APPROVAL REQUEST-----",
            )
        )
        headers = {
            "X-RD-Contract": str(request["contract"]),
            "X-RD-Authority-Scope": str(request["authority_scope"]),
            "X-RD-Event-Id": str(request["event_id"]),
            "X-RD-Round-Id": str(request["round_id"]),
            "X-RD-Task": str(request["task"]),
            "X-RD-Module": str(request["module"]),
            "X-RD-Manifest-S-Digest": str(request["manifest_s_digest"]),
            "X-RD-Manifest-R-Digest": str(request["manifest_r_digest"]),
            "X-RD-Manifest-Digest": str(request["manifest_digest"]),
            "X-RD-Request-Digest": str(request["request_digest"]),
            "X-RD-Role-Snapshot-Digest": str(request["role_snapshot_digest"]),
            "X-RD-Required-Roles": ",".join(request["required_roles"]),
            "X-RD-Expires-At": str(request["expires_at"]),
        }
        response = _json_command(
            self.runner,
            (sys.executable, str(self.entrypoint)),
            input_payload={
                "tool": "send_email",
                "arguments": {
                    "account": presentation["mail_profile"],
                    "to": list(recipients),
                    "subject": subject,
                    "text": text,
                    "message_id": request["original_message_id"],
                    "headers": headers,
                    "dry_run": False,
                    "atomic_recipients": True,
                },
            },
            operation="governance decision mail",
        )
        result = response.get("result") if response.get("ok") is True else None
        if not isinstance(result, Mapping):
            raise AdapterError(
                "governance decision mail failed: " + str(response.get("error") or "invalid result")
            )
        refused = result.get("refused")
        accepted = (
            result.get("sent") is True
            and refused == {}
            and result.get("message_id") == request["original_message_id"]
            and result.get("atomic_recipients") is True
            and result.get("data_submitted") is True
        )
        return {
            "status": "accepted" if accepted else "rejected",
            "message_id": result.get("message_id"),
            "refused": dict(refused) if isinstance(refused, Mapping) else refused,
            "atomic_recipients": result.get("atomic_recipients"),
            "data_submitted": result.get("data_submitted"),
            "recipients": list(recipients),
            "accepted_at": self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        }


class LockedGovernanceDecisionVerifier:
    def __init__(
        self,
        entrypoint: Path,
        config_path: Path,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self.entrypoint = entrypoint
        self.config_path = config_path
        self.runner = runner or _default_runner

    def _run(self, *arguments: str) -> dict[str, Any]:
        return _json_command(
            self.runner,
            (
                sys.executable,
                str(self.entrypoint),
                "--config",
                str(self.config_path),
                *arguments,
            ),
            operation="release approval verifier",
        )

    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self._run("run-once")
        event = self._run(
            "get-event",
            "--event-id",
            str(request["event_id"]),
            "--round-id",
            str(request["round_id"]),
        )
        receipt = event.get("receipt")
        if not isinstance(receipt, Mapping):
            return {"verified": False, "status": "APPROVAL_PAUSED"}
        status = str(receipt.get("status") or "APPROVAL_PAUSED")
        if status != "APPROVAL_VERIFIED":
            return {"verified": False, "status": status}
        receipt_path = str(receipt.get("receipt_path") or "").strip()
        if not receipt_path:
            raise AdapterError("verified decision receipt has no frozen receipt path.")
        verified = self._run("verify-receipt", "--path", receipt_path)
        if verified.get("verified") is not True or not isinstance(
            verified.get("receipt"), Mapping
        ):
            raise AdapterError("independent verifier did not validate the receipt.")
        return {
            "verified": True,
            "status": "APPROVAL_VERIFIED",
            "verifier": "release-approval-verifier",
            "receipt": dict(verified["receipt"]),
        }


def _default_runner(
    args: Sequence[str],
    *,
    input_text: str | None = None,
    encoding: str | None = None,
) -> subprocess.CompletedProcess[str]:
    raw_timeout = str(
        os.environ.get(
            _COMMAND_TIMEOUT_ENV,
            _DEFAULT_COMMAND_TIMEOUT_SECONDS,
        )
    ).strip()
    try:
        timeout = int(raw_timeout)
    except ValueError as exc:
        raise AdapterError(
            f"{_COMMAND_TIMEOUT_ENV} must be an integer in 30..86400."
        ) from exc
    if not 30 <= timeout <= 86400:
        raise AdapterError(
            f"{_COMMAND_TIMEOUT_ENV} must be an integer in 30..86400."
        )
    try:
        return subprocess.run(
            list(args),
            input=input_text,
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            encoding=encoding or "utf-8",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdapterError(
            f"adapter command exceeded the configured {timeout}-second timeout."
        ) from exc
    except OSError as exc:
        raise AdapterError(f"adapter command could not start: {exc}") from exc


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


def load_governance_adapters(
    config: RDFlywheelConfig,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = _default_runner,
    lark_command_prefix: Sequence[str] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> tuple[
    LarkDecisionRoleSnapshotFetcher | None,
    LockedGovernanceMailPresenter | None,
    LockedGovernanceDecisionVerifier | None,
]:
    if config.decision_role_source is None or config.notification is None:
        return None, None, None
    required_profiles = {
        "imap-smtp-mail",
        "lark-cli",
        "release-approval-verifier",
    }
    missing = sorted(required_profiles.difference(config.tool_profiles))
    if missing:
        raise AdapterError(
            "governance runtime is missing tool profiles: " + ", ".join(missing)
        )
    mail_entrypoint = _locked_entrypoint(
        config,
        plugin_name="imap-smtp-mail",
        entrypoint_path=_MAIL_ENTRYPOINT,
    )
    verifier_entrypoint = _locked_entrypoint(
        config,
        plugin_name="release-approval-verifier",
        entrypoint_path=_VERIFIER_ENTRYPOINT,
    )
    if not config.decision_verifier_config.is_file():
        raise AdapterError(
            "release approval verifier config is missing: "
            + str(config.decision_verifier_config)
        )
    return (
        LarkDecisionRoleSnapshotFetcher(
            runner=runner,
            command_prefix=lark_command_prefix,
        ),
        LockedGovernanceMailPresenter(
            mail_entrypoint,
            runner=runner,
            clock=clock,
        ),
        LockedGovernanceDecisionVerifier(
            verifier_entrypoint,
            config.decision_verifier_config,
            runner=runner,
        ),
    )
