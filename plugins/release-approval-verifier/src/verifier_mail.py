from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from verifier_dependency_lock import (
    DependencyLockError,
    resolve_locked_entrypoint,
    sha256_file,
)


_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EXPECTED_PLUGIN_NAME = "imap-smtp-mail"
_EXPECTED_PLUGIN_ROOT = Path("plugins/imap-smtp-mail")
_EXPECTED_CLI_PATH = _EXPECTED_PLUGIN_ROOT / "src" / "imap_smtp_mail_cli.py"
Runner = Callable[..., subprocess.CompletedProcess[str]]


class MailGatewayError(RuntimeError):
    """Raised when the locked IMAP/SMTP CLI cannot be trusted or executed."""


class MailCapabilityError(MailGatewayError):
    """Raised when the locked mail bridge lacks required safe capabilities."""


@dataclass(frozen=True)
class MailSendResult:
    sent: bool
    message_id: str
    refused: dict[str, Any]
    raw: Mapping[str, Any]


class MailGateway:
    def __init__(
        self,
        dependency_lock: str | Path,
        *,
        dependency_lock_sha256: str,
        runner: Runner | None = None,
        timeout_seconds: int = 30,
    ) -> None:
        self.dependency_lock = Path(dependency_lock)
        self.dependency_lock_sha256 = dependency_lock_sha256
        self.runner = runner or subprocess.run
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def sha256_file(path: str | Path) -> str:
        return sha256_file(path)

    def require_thread_reply_capability(self, payload: Mapping[str, Any]) -> None:
        reply_subject = str(payload.get("reply_subject") or "").strip()
        original_message_id = str(payload.get("original_message_id") or "").strip()
        references = payload.get("references")
        if not reply_subject or not self._is_message_id(original_message_id):
            raise MailCapabilityError("CAPABILITY_BLOCKED: thread reply fields are missing or invalid.")
        if not isinstance(references, (list, tuple)) or not references:
            raise MailCapabilityError("CAPABILITY_BLOCKED: thread reply fields are missing or invalid.")
        if not all(self._is_message_id(str(item)) for item in references):
            raise MailCapabilityError("CAPABILITY_BLOCKED: thread reply fields are missing or invalid.")

    def require_authenticated_readback_capability(self, payload: Mapping[str, Any]) -> None:
        message_id = str(payload.get("message_id") or "").strip()
        evidence = payload.get("evidence")
        if not self._is_message_id(message_id) or not isinstance(evidence, Mapping):
            raise MailCapabilityError("CAPABILITY_BLOCKED: authenticated readback fields are missing.")
        raw_headers_sha256 = str(evidence.get("raw_headers_sha256") or "").strip()
        in_reply_to = str(evidence.get("in_reply_to") or "").strip()
        references = evidence.get("references")
        if not _SHA256_PATTERN.fullmatch(raw_headers_sha256):
            raise MailCapabilityError("CAPABILITY_BLOCKED: authenticated readback fields are missing.")
        if not self._is_message_id(in_reply_to):
            raise MailCapabilityError("CAPABILITY_BLOCKED: authenticated readback fields are missing.")
        if not isinstance(references, list) or not references:
            raise MailCapabilityError("CAPABILITY_BLOCKED: authenticated readback fields are missing.")
        if not all(self._is_message_id(str(item)) for item in references):
            raise MailCapabilityError("CAPABILITY_BLOCKED: authenticated readback fields are missing.")

    def list_accounts(self) -> Mapping[str, Any]:
        completed_payload = self._invoke({"tool": "list_accounts", "arguments": {}})
        result = completed_payload.get("result")
        if not isinstance(result, Mapping):
            raise MailGatewayError("mail CLI result must be a JSON object.")
        accounts = result.get("accounts")
        if not isinstance(accounts, list):
            raise MailGatewayError("mail CLI list_accounts result must contain an accounts array.")
        return result

    def search_messages(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        completed_payload = self._invoke(
            payload if "tool" in payload else {"tool": "search_messages", "arguments": dict(payload)}
        )
        result = completed_payload.get("result")
        if not isinstance(result, Mapping):
            raise MailGatewayError("mail CLI result must be a JSON object.")
        messages = result.get("messages")
        if not isinstance(messages, list):
            raise MailGatewayError("mail CLI search_messages result must contain a messages array.")
        return result

    def send_email(self, payload: Mapping[str, Any]) -> MailSendResult:
        completed_payload = self._invoke(payload if "tool" in payload else {"tool": "send_email", "arguments": dict(payload)})
        result = completed_payload.get("result")
        if not isinstance(result, Mapping):
            raise MailGatewayError("mail CLI result must be a JSON object.")
        message_id = str(result.get("message_id") or "").strip()
        if not self._is_message_id(message_id):
            raise MailGatewayError("mail CLI did not return an exact RFC Message-ID.")
        refused = result.get("refused")
        if not isinstance(refused, Mapping):
            raise MailGatewayError("mail CLI refused map must be a JSON object.")
        return MailSendResult(
            sent=result.get("sent") is True,
            message_id=message_id,
            refused={str(key): value for key, value in refused.items()},
            raw=result,
        )

    def read_message(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        completed_payload = self._invoke(payload if "tool" in payload else {"tool": "read_message", "arguments": dict(payload)})
        result = completed_payload.get("result")
        if not isinstance(result, Mapping):
            raise MailGatewayError("mail CLI result must be a JSON object.")
        return result

    def _invoke(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        cli_path = self._locked_cli_path()
        command = [sys.executable, str(cli_path)]
        stdin_text = json.dumps(payload, ensure_ascii=False)
        try:
            completed = self.runner(
                args=command,
                input=stdin_text,
                text=True,
                capture_output=True,
                shell=False,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MailGatewayError(f"mail CLI timed out after {self.timeout_seconds} seconds.") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise MailGatewayError(f"mail CLI failed with exit code {completed.returncode}: {detail}")
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise MailGatewayError("mail CLI returned invalid JSON.") from exc
        if not isinstance(parsed, Mapping):
            raise MailGatewayError("mail CLI returned a non-object JSON payload.")
        if parsed.get("ok") is not True:
            raise MailGatewayError(str(parsed.get("error") or "mail CLI returned ok=false"))
        return parsed

    def _locked_cli_path(self) -> Path:
        try:
            return resolve_locked_entrypoint(
                self.dependency_lock,
                dependency_lock_sha256=self.dependency_lock_sha256,
                plugin_name=_EXPECTED_PLUGIN_NAME,
                plugin_root=_EXPECTED_PLUGIN_ROOT,
                entrypoint_path=_EXPECTED_CLI_PATH,
            )
        except (OSError, DependencyLockError) as exc:
            raise MailGatewayError(str(exc)) from exc

    @staticmethod
    def _is_message_id(value: str) -> bool:
        return bool(_MESSAGE_ID_PATTERN.fullmatch(value))
