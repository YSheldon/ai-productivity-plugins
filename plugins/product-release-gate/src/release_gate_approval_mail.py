from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable


Runner = Callable[..., subprocess.CompletedProcess[str]]
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAIL_PLUGIN_NAME = "imap-smtp-mail"
_MAIL_PLUGIN_ROOT = Path("plugins/imap-smtp-mail")
_MAIL_CLI_PATH = _MAIL_PLUGIN_ROOT / "src" / "imap_smtp_mail_cli.py"


class ApprovalMailError(RuntimeError):
    """Raised when the locked mail CLI cannot prove SMTP acceptance."""


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def resolve_locked_entrypoint(
    dependency_lock: str | Path,
    *,
    dependency_lock_sha256: str,
    plugin_name: str,
    plugin_root: str | Path,
    entrypoint_path: str | Path,
) -> Path:
    lock_path = Path(dependency_lock).expanduser().resolve(strict=True)
    expected_lock_digest = str(dependency_lock_sha256 or "").strip().lower()
    if not _SHA256_PATTERN.fullmatch(expected_lock_digest):
        raise ApprovalMailError("dependency lock SHA-256 is missing or invalid.")
    if sha256_file(lock_path) != expected_lock_digest:
        raise ApprovalMailError("dependency lock drift was detected.")

    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ApprovalMailError("dependency lock is invalid JSON.") from exc
    plugins = payload.get("plugins") if isinstance(payload, Mapping) else None
    if not isinstance(plugins, list):
        raise ApprovalMailError("dependency lock must contain a plugins array.")

    expected_root = Path(plugin_root)
    expected_entrypoint = Path(entrypoint_path)
    if expected_root.is_absolute() or expected_entrypoint.is_absolute():
        raise ApprovalMailError("locked plugin paths must be repository-relative.")
    if expected_entrypoint.parent != expected_root / "src":
        raise ApprovalMailError("locked runtime entrypoint must be under the expected plugin src directory.")

    for plugin in plugins:
        if not isinstance(plugin, Mapping) or plugin.get("name") != plugin_name:
            continue
        locked_root = Path(str(plugin.get("plugin_root") or ""))
        if locked_root.as_posix() != expected_root.as_posix():
            raise ApprovalMailError(f"dependency lock {plugin_name} root is invalid.")
        entrypoints = plugin.get("entrypoints")
        if not isinstance(entrypoints, list):
            raise ApprovalMailError(f"dependency lock does not pin {plugin_name} runtime entrypoints.")
        for entrypoint in entrypoints:
            if not isinstance(entrypoint, Mapping):
                continue
            locked_path = Path(str(entrypoint.get("path") or ""))
            if locked_path.as_posix() != expected_entrypoint.as_posix():
                continue
            expected_digest = str(entrypoint.get("sha256") or "").strip().lower()
            if not _SHA256_PATTERN.fullmatch(expected_digest):
                raise ApprovalMailError("locked runtime entrypoint SHA-256 is invalid.")
            resolved = (lock_path.parent / locked_path).resolve(strict=True)
            try:
                resolved.relative_to((lock_path.parent / expected_root).resolve(strict=True))
            except ValueError as exc:
                raise ApprovalMailError("locked runtime entrypoint escapes the plugin root.") from exc
            if sha256_file(resolved) != expected_digest:
                raise ApprovalMailError("locked runtime entrypoint drift was detected.")
            return resolved
        raise ApprovalMailError(
            f"dependency lock does not pin runtime entrypoint {expected_entrypoint.as_posix()}."
        )
    raise ApprovalMailError(f"dependency lock does not include {plugin_name}.")


class ImapSmtpMailCliGateway:
    def __init__(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: int = 120,
        runner: Runner = subprocess.run,
    ) -> None:
        if isinstance(command, (str, bytes)):
            raise ApprovalMailError(
                "mail CLI command must be an argument array, not a string."
            )
        normalized = tuple(str(item).strip() for item in command)
        if not normalized or any(
            not item or any(ord(character) < 32 for character in item)
            for item in normalized
        ):
            raise ApprovalMailError("mail CLI command must be a non-empty argument array.")
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds < 1
            or timeout_seconds > 600
        ):
            raise ApprovalMailError("mail CLI timeout must be between 1 and 600 seconds.")
        self.command = normalized
        self.timeout_seconds = timeout_seconds
        self.runner = runner

    def _invoke(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        request = {"tool": tool, "arguments": dict(arguments)}
        try:
            completed = self.runner(
                list(self.command),
                input=json.dumps(request, ensure_ascii=False),
                text=True,
                capture_output=True,
                shell=False,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ApprovalMailError(f"mail CLI execution failed: {exc}") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "mail CLI failed").strip()
            raise ApprovalMailError(detail[:1000])
        try:
            envelope = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ApprovalMailError("mail CLI returned invalid JSON.") from exc
        if not isinstance(envelope, dict) or envelope.get("ok") is not True:
            detail = str(envelope.get("error") if isinstance(envelope, dict) else "invalid response")
            raise ApprovalMailError(f"mail CLI rejected the request: {detail}")
        result = envelope.get("result")
        if not isinstance(result, dict):
            raise ApprovalMailError("mail CLI response is missing the result object.")
        return dict(result)

    def list_accounts(self) -> list[dict[str, Any]]:
        result = self._invoke("list_accounts", {})
        accounts = result.get("accounts")
        if not isinstance(accounts, list) or not all(
            isinstance(item, Mapping) for item in accounts
        ):
            raise ApprovalMailError("mail CLI list_accounts result is invalid.")
        return [dict(item) for item in accounts]

    def send_email(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self._invoke("send_email", payload)


class LockedImapSmtpMailCliGateway(ImapSmtpMailCliGateway):
    def __init__(
        self,
        dependency_lock: str | Path,
        *,
        dependency_lock_sha256: str,
        timeout_seconds: int = 120,
        runner: Runner = subprocess.run,
    ) -> None:
        cli_path = resolve_locked_entrypoint(
            dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            plugin_name=_MAIL_PLUGIN_NAME,
            plugin_root=_MAIL_PLUGIN_ROOT,
            entrypoint_path=_MAIL_CLI_PATH,
        )
        super().__init__(
            [sys.executable, str(cli_path)],
            timeout_seconds=timeout_seconds,
            runner=runner,
        )
        self.cli_path = cli_path
