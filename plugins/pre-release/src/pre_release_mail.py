from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable


Runner = Callable[..., subprocess.CompletedProcess[str]]
_BEGIN = "-----BEGIN PRODUCT MATERIAL EVENT-----"
_END = "-----END PRODUCT MATERIAL EVENT-----"
_GATE_PLUGIN_PARTS = ("product", "release", "gate")
_GATE_PLUGIN_NAME = "-".join(_GATE_PLUGIN_PARTS)
_GATE_PLUGIN_ROOT = Path("plugins") / _GATE_PLUGIN_NAME
_GATE_ENTRYPOINT = _GATE_PLUGIN_ROOT / "src" / f"{"_".join(("release", "gate", "cli"))}.py"


class PreReleaseMailError(RuntimeError):
    pass


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sha256_jsonable(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def resolve_locked_entrypoint(
    dependency_lock: str | Path,
    *,
    dependency_lock_sha256: str,
    plugin_name: str,
    plugin_root: str | Path,
    entrypoint_path: str | Path,
) -> Path:
    lock_path = Path(dependency_lock).expanduser().resolve(strict=True)
    if sha256_file(lock_path) != str(dependency_lock_sha256).strip().lower():
        raise PreReleaseMailError("dependency lock drift was detected")
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    plugins = payload.get("plugins") if isinstance(payload, Mapping) else None
    if not isinstance(plugins, list):
        raise PreReleaseMailError("dependency lock must contain plugins")
    expected_root = Path(plugin_root)
    expected_entrypoint = Path(entrypoint_path)
    for plugin in plugins:
        if not isinstance(plugin, Mapping) or plugin.get("name") != plugin_name:
            continue
        if Path(str(plugin.get("plugin_root") or "")).as_posix() != expected_root.as_posix():
            raise PreReleaseMailError(f"dependency lock {plugin_name} root is invalid")
        for entrypoint in plugin.get("entrypoints", []):
            if not isinstance(entrypoint, Mapping):
                continue
            if Path(str(entrypoint.get("path") or "")).as_posix() != expected_entrypoint.as_posix():
                continue
            expected_digest = str(entrypoint.get("sha256") or "").strip().lower()
            resolved = (lock_path.parent / expected_entrypoint).resolve(strict=True)
            if sha256_file(resolved) != expected_digest:
                raise PreReleaseMailError("locked runtime entrypoint drift was detected")
            return resolved
    raise PreReleaseMailError(f"dependency lock does not include {plugin_name}")


def sign_machine_event(payload: Mapping[str, Any], secret: bytes) -> dict[str, Any]:
    material = dict(payload)
    digest = hmac.new(secret, canonical_json(material).encode("utf-8"), hashlib.sha256).hexdigest()
    material["hmac_sha256"] = digest
    return material


def verify_machine_event(payload: Mapping[str, Any], secret: bytes) -> bool:
    material = dict(payload)
    expected = str(material.pop("hmac_sha256", "")).strip().lower()
    actual = hmac.new(secret, canonical_json(material).encode("utf-8"), hashlib.sha256).hexdigest()
    return bool(expected) and hmac.compare_digest(expected, actual)


def encode_machine_event(payload: Mapping[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(canonical_json(payload).encode("utf-8")).decode("ascii").rstrip("=")
    return f"{_BEGIN}\n{encoded}\n{_END}"


def decode_machine_event(text: str) -> dict[str, Any]:
    try:
        encoded = text.split(_BEGIN, 1)[1].split(_END, 1)[0].strip()
    except IndexError as exc:
        raise PreReleaseMailError("machine event block is missing") from exc
    padding = "=" * (-len(encoded) % 4)
    payload = json.loads(base64.urlsafe_b64decode((encoded + padding).encode("ascii")).decode("utf-8"))
    if not isinstance(payload, dict):
        raise PreReleaseMailError("machine event must be one object")
    return payload


def message_transport_evidence(message: Mapping[str, Any]) -> dict[str, Any]:
    evidence = message.get("evidence") if isinstance(message.get("evidence"), Mapping) else {}
    references: list[str] = []
    raw_references = evidence.get("references") if isinstance(evidence, Mapping) else None
    if isinstance(raw_references, list):
        references = [str(item).strip() for item in raw_references if str(item).strip()]
    elif isinstance(message.get("references"), list):
        references = [str(item).strip() for item in message.get("references", []) if str(item).strip()]
    return {
        "uid": str(message.get("uid") or ""),
        "message_id": str(message.get("message_id") or ""),
        "references": references,
        "raw_headers_sha256": str(evidence.get("raw_headers_sha256") or ""),
    }


class ImapSmtpMailCliGateway:
    def __init__(self, command: Sequence[str], *, timeout_seconds: int = 120, runner: Runner = subprocess.run) -> None:
        self.command = tuple(str(item).strip() for item in command)
        self.timeout_seconds = timeout_seconds
        self.runner = runner
        if not self.command:
            raise PreReleaseMailError("mail CLI command must be one argument array")

    def _invoke(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        completed = self.runner(
            list(self.command),
            input=json.dumps({"tool": tool, "arguments": dict(arguments)}, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise PreReleaseMailError((completed.stderr or completed.stdout or "mail CLI failed").strip())
        envelope = json.loads(completed.stdout)
        if not isinstance(envelope, dict) or envelope.get("ok") is not True:
            raise PreReleaseMailError(str(envelope))
        result = envelope.get("result")
        if not isinstance(result, dict):
            raise PreReleaseMailError("mail CLI response is missing result")
        return dict(result)

    def list_accounts(self) -> list[dict[str, Any]]:
        result = self._invoke("list_accounts", {})
        accounts = result.get("accounts")
        if not isinstance(accounts, list):
            raise PreReleaseMailError("accounts result is invalid")
        return [dict(item) for item in accounts if isinstance(item, Mapping)]

    def search_messages(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return self._invoke("search_messages", arguments)

    def read_message(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return self._invoke("read_message", arguments)

    def send_email(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return self._invoke("send_email", arguments)


class ProductGateCliGateway:
    def __init__(self, command: Sequence[str], *, timeout_seconds: int = 180, runner: Runner = subprocess.run) -> None:
        self.command = tuple(str(item).strip() for item in command)
        self.timeout_seconds = timeout_seconds
        self.runner = runner
        if not self.command:
            raise PreReleaseMailError("product-release-gate command must be one argument array")

    def call(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        command = list(self.command) + ["call", operation, "--input", json.dumps(dict(payload), ensure_ascii=False)]
        completed = self.runner(command, text=True, capture_output=True, timeout=self.timeout_seconds, check=False, shell=False)
        if completed.returncode not in {0, 3}:
            raise PreReleaseMailError((completed.stderr or completed.stdout or "product-release-gate call failed").strip())
        result = json.loads(completed.stdout)
        if not isinstance(result, dict):
            raise PreReleaseMailError("product-release-gate returned invalid JSON")
        return result


def locked_mail_gateway(
    dependency_lock: str | Path,
    *,
    dependency_lock_sha256: str,
    runner: Runner = subprocess.run,
) -> ImapSmtpMailCliGateway:
    cli_path = resolve_locked_entrypoint(
        dependency_lock,
        dependency_lock_sha256=dependency_lock_sha256,
        plugin_name="imap-smtp-mail",
        plugin_root=Path("plugins/imap-smtp-mail"),
        entrypoint_path=Path("plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py"),
    )
    return ImapSmtpMailCliGateway([sys.executable, str(cli_path)], runner=runner)


def locked_product_gate_gateway(
    dependency_lock: str | Path,
    *,
    dependency_lock_sha256: str,
    config_path: str | Path,
    runner: Runner = subprocess.run,
) -> ProductGateCliGateway:
    cli_path = resolve_locked_entrypoint(
        dependency_lock,
        dependency_lock_sha256=dependency_lock_sha256,
        plugin_name=_GATE_PLUGIN_NAME,
        plugin_root=_GATE_PLUGIN_ROOT,
        entrypoint_path=_GATE_ENTRYPOINT,
    )
    return ProductGateCliGateway([sys.executable, str(cli_path), "--config", str(Path(config_path).resolve(strict=False))], runner=runner)
