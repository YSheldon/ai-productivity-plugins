from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from release_workflow_core import (
    CORE_VERSION,
    JsonlAuditLog,
    MailContractError,
    binding_headers,
    freeze_policy,
    parse_message,
    render_message,
    validate_gitlab_gate_result,
)
from release_workflow_core.legacy_intake import LegacyIntakeError, parse_legacy_submission_mail
from release_workflow_core.mail_contract import canonical_json, provenance_badge
from submission_gate_lock import RunOnceLock


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_EVENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
_REVISION_RE = re.compile(r"^[1-9]\d*$")
_CANONICAL_SUBJECT_RE = re.compile(
    r"^【提测】(?P<task>.+)-(?P<module>kernel|client|server|内核|客户端|服务端)-(?P<date>\d{4}-\d{2}-\d{2})$",
    re.IGNORECASE,
)
_OLD_MACHINE_BEGIN = "-----BEGIN RD TEST SUBMISSION BLOCK-----"
_OLD_MACHINE_END = "-----END RD TEST SUBMISSION BLOCK-----"
_NEW_MACHINE_BEGIN = "-----BEGIN PRODUCT MATERIAL WORKFLOW-----"
_MAIL_PLUGIN_ROOT = Path("plugins/imap-smtp-mail")
_MAIL_CLI_PATH = _MAIL_PLUGIN_ROOT / "src" / "imap_smtp_mail_cli.py"
_MODULE_MAP = {
    "kernel": "kernel",
    "内核": "kernel",
    "client": "client",
    "客户端": "client",
    "server": "server",
    "服务端": "server",
}
_LOCAL_CANONICAL = {
    "kernel": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"],
    "client": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"],
    "server": ["artifacts_present", "hashes_match", "source_revision_present", "package_digest_present", "cloud_scan_required"],
}
_SVN_CANONICAL = [
    "provenance_locator_present",
    "fixed_revision_present",
    "trusted_retrieval_succeeded",
    "retrieved_nonempty",
    "audit_recorded",
]


class SubmissionGateError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def workflow_core_digest() -> str:
    root = Path(__file__).resolve().parent / "release_workflow_core"
    digest = hashlib.sha256()
    for child in sorted(path for path in root.rglob("*.py") if path.is_file()):
        digest.update(child.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\n")
        digest.update(child.read_bytes())
        digest.update(b"\n")
    return digest.hexdigest()


def default_config_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return (root / "submission-gate" / "config.json").resolve(strict=False)


def default_config() -> dict[str, Any]:
    root = default_config_path().parent
    return {
        "gate_mail_account": {"profile": "", "email": ""},
        "submission_group_address": "",
        "blocked_notice_address": "",
        "mailbox": "INBOX",
        "scan_limit": 100,
        "poll_minutes": 60,
        "scheduler_mode": "auto",
        "state_dir": str((root / "state").resolve(strict=False)),
        "event_store_dir": str((root / "events").resolve(strict=False)),
        "feishu_directory_url": "",
        "policy_profile": "submission-gate/v1",
        "enabled_optional_checks": [],
        "mandatory_checks_by_module": dict(_LOCAL_CANONICAL),
        "svn_mandatory_checks": list(_SVN_CANONICAL),
        "gate_adapter": {
            "command": [],
            "timeout_seconds": 900,
            "entrypoint_path": "",
            "entrypoint_sha256": "",
        },
        "auth": {"mode": "optional", "key_id": "default", "identity_id": "submission-gate"},
        "audit_key_path": str((root / "audit.key").resolve(strict=False)),
        "audit_log_path": str((root / "audit.jsonl").resolve(strict=False)),
        "dependency_lock": str((root / "dependency-lock.submission-gate.json").resolve(strict=False)),
        "dependency_lock_sha256": "",
    }


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve(strict=False)
    payload = default_config()
    if config_path.is_file():
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SubmissionGateError("CONFIG_ERROR", "configuration must be a JSON object")
        payload = _deep_merge(payload, raw)
    account = payload.get("gate_mail_account")
    if not isinstance(account, Mapping):
        raise SubmissionGateError("CONFIG_ERROR", "gate_mail_account must be an object")
    if not str(account.get("profile") or "").strip():
        raise SubmissionGateError("CONFIG_ERROR", "gate_mail_account.profile is required")
    if not _EMAIL_RE.fullmatch(str(account.get("email") or "").strip()):
        raise SubmissionGateError("CONFIG_ERROR", "gate_mail_account.email is required")
    for key in ("submission_group_address", "blocked_notice_address"):
        if not _EMAIL_RE.fullmatch(str(payload.get(key) or "").strip()):
            raise SubmissionGateError("CONFIG_ERROR", f"{key} must be one email address")
    digest = str(payload.get("dependency_lock_sha256") or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise SubmissionGateError("CONFIG_ERROR", "dependency_lock_sha256 must be one 64-hex SHA-256")
    adapter = payload.get("gate_adapter")
    if not isinstance(adapter, Mapping) or not isinstance(adapter.get("command", []), list):
        raise SubmissionGateError("CONFIG_ERROR", "gate_adapter.command must be an argument array")
    return payload


def _expand_path(value: str | Path) -> Path:
    return Path(os.path.expandvars(str(value))).expanduser().resolve(strict=False)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(dict(value), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


def _ensure_event_id(value: str) -> str:
    text = str(value or "").strip()
    if not _EVENT_RE.fullmatch(text):
        raise SubmissionGateError("INVALID_EVENT_ID", "event_id must match the stable workflow identifier pattern")
    return text


def _resolve_locked_entrypoint(
    dependency_lock: str | Path,
    *,
    dependency_lock_sha256: str,
    plugin_name: str,
    plugin_root: str | Path,
    entrypoint_path: str | Path,
) -> Path:
    lock_path = Path(dependency_lock).expanduser().resolve(strict=True)
    if sha256_file(lock_path) != dependency_lock_sha256:
        raise SubmissionGateError("DEPENDENCY_DRIFT", "dependency lock drift was detected")
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    plugins = payload.get("plugins") if isinstance(payload, dict) else None
    if not isinstance(plugins, list):
        raise SubmissionGateError("DEPENDENCY_DRIFT", "dependency lock must contain a plugins array")
    expected_root = Path(plugin_root).as_posix()
    expected_path = Path(entrypoint_path).as_posix()
    for plugin in plugins:
        if not isinstance(plugin, Mapping) or plugin.get("name") != plugin_name:
            continue
        if Path(str(plugin.get("plugin_root") or "")).as_posix() != expected_root:
            raise SubmissionGateError("DEPENDENCY_DRIFT", f"dependency lock {plugin_name} root is invalid")
        for entrypoint in plugin.get("entrypoints") or []:
            if not isinstance(entrypoint, Mapping):
                continue
            if Path(str(entrypoint.get("path") or "")).as_posix() != expected_path:
                continue
            entrypoint_file = (lock_path.parent / expected_path).resolve(strict=True)
            if sha256_file(entrypoint_file) != str(entrypoint.get("sha256") or "").strip().lower():
                raise SubmissionGateError("DEPENDENCY_DRIFT", "locked mail entrypoint drift was detected")
            return entrypoint_file
    raise SubmissionGateError("DEPENDENCY_DRIFT", f"dependency lock does not include {plugin_name}")


class LockedMailGateway:
    def __init__(
        self,
        dependency_lock: str | Path,
        *,
        dependency_lock_sha256: str,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.cli_path = _resolve_locked_entrypoint(
            dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            plugin_name="imap-smtp-mail",
            plugin_root=_MAIL_PLUGIN_ROOT,
            entrypoint_path=_MAIL_CLI_PATH,
        )
        self.runner = runner

    def list_accounts(self) -> dict[str, Any]:
        return self._invoke("list_accounts", {})

    def search_messages(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self._invoke("search_messages", payload)

    def read_message(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self._invoke("read_message", payload)

    def send_email(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self._invoke("send_email", payload)

    def _invoke(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        completed = self.runner(
            [sys.executable, str(self.cli_path)],
            input=json.dumps({"tool": tool, "arguments": dict(arguments)}, ensure_ascii=False),
            text=True,
            capture_output=True,
            shell=False,
            check=False,
        )
        if completed.returncode != 0:
            raise SubmissionGateError(
                "MAIL_GATEWAY_FAILED",
                (completed.stderr or completed.stdout or "mail cli failed").strip(),
            )
        envelope = json.loads(completed.stdout)
        if envelope.get("ok") is not True or not isinstance(envelope.get("result"), dict):
            raise SubmissionGateError("MAIL_GATEWAY_FAILED", str(envelope.get("error") or "invalid mail response"))
        return dict(envelope["result"])


class CommandGateAdapter:
    """Runs one locked, argv-only authoritative retrieval/gate adapter."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.command = tuple(str(item) for item in config.get("command") or [])
        self.timeout_seconds = int(config.get("timeout_seconds") or 900)
        self.entrypoint_path = _expand_path(str(config.get("entrypoint_path") or "")) if config.get("entrypoint_path") else None
        self.entrypoint_sha256 = str(config.get("entrypoint_sha256") or "").strip().lower()
        self.runner = runner

    def preflight(self) -> dict[str, Any]:
        if not self.command:
            return {"ready": False, "status": "CAPABILITY_BLOCKED", "reason": "gate_adapter.command is not configured"}
        try:
            self._verify_entrypoint()
        except SubmissionGateError as exc:
            return {"ready": False, "status": "CAPABILITY_BLOCKED", "reason": str(exc)}
        return {"ready": True, "status": "ready", "command_argv": True, "shell": False}

    def evaluate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        preflight = self.preflight()
        if not preflight.get("ready"):
            raise SubmissionGateError("CAPABILITY_BLOCKED", str(preflight.get("reason") or "gate adapter unavailable"))
        self._verify_entrypoint()
        completed = self.runner(
            list(self.command),
            input=json.dumps(dict(request), ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            shell=False,
            check=False,
        )
        if completed.returncode not in {0, 3}:
            raise SubmissionGateError(
                "GATE_ADAPTER_FAILED",
                (completed.stderr or completed.stdout or "gate adapter failed").strip(),
            )
        try:
            envelope = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SubmissionGateError("GATE_ADAPTER_FAILED", "gate adapter returned invalid JSON") from exc
        if not isinstance(envelope, Mapping):
            raise SubmissionGateError("GATE_ADAPTER_FAILED", "gate adapter result must be an object")
        if envelope.get("ok") is False:
            error = envelope.get("error") or {}
            raise SubmissionGateError(str(error.get("code") or "GATE_ADAPTER_FAILED"), str(error.get("message") or error))
        result = envelope.get("result", envelope)
        if not isinstance(result, Mapping):
            raise SubmissionGateError("GATE_ADAPTER_FAILED", "gate adapter result is missing")
        return dict(result)

    def _verify_entrypoint(self) -> None:
        if self.entrypoint_path is None:
            return
        if not self.entrypoint_path.is_file():
            raise SubmissionGateError("CAPABILITY_BLOCKED", "gate adapter entrypoint is unavailable")
        if not _SHA256_RE.fullmatch(self.entrypoint_sha256):
            raise SubmissionGateError("CAPABILITY_BLOCKED", "gate adapter entrypoint SHA-256 is not configured")
        if sha256_file(self.entrypoint_path) != self.entrypoint_sha256:
            raise SubmissionGateError("DEPENDENCY_DRIFT", "gate adapter entrypoint drift was detected")


def extract_machine_block(body_text: str) -> dict[str, Any]:
    parts = body_text.split(_OLD_MACHINE_BEGIN)
    if len(parts) != 2 or _OLD_MACHINE_END not in parts[1]:
        raise SubmissionGateError("REQUEST_BLOCK_INVALID", "legacy submission machine block is missing or ambiguous")
    try:
        payload = json.loads(parts[1].split(_OLD_MACHINE_END, 1)[0].strip())
    except json.JSONDecodeError as exc:
        raise SubmissionGateError("REQUEST_BLOCK_INVALID", "legacy submission machine block is invalid") from exc
    if not isinstance(payload, dict):
        raise SubmissionGateError("REQUEST_BLOCK_INVALID", "legacy submission machine block must be an object")
    return payload


def _extract_email(value: Any) -> str:
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, Mapping):
        return str(value.get("email") or "").strip().lower()
    return str(value or "").strip().lower()


def _normalize_module(value: Any) -> str:
    return _MODULE_MAP.get(str(value or "").strip().lower(), "")


def _normalize_submitter_email(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return text if _EMAIL_RE.fullmatch(text) else ""


def _sha256_json(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class SubmissionGateController:
    def __init__(
        self,
        config_path: str | Path,
        *,
        config: Mapping[str, Any] | None = None,
        mail_gateway: LockedMailGateway | Any | None = None,
        gate_adapter: CommandGateAdapter | Any | None = None,
        now_fn: Callable[[], datetime] | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.config_path = Path(config_path).resolve(strict=False)
        self.config = dict(load_config(self.config_path) if config is None else _deep_merge(default_config(), config))
        self.environ = dict(os.environ if environ is None else environ)
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.mail_gateway = mail_gateway or LockedMailGateway(
            self.config["dependency_lock"],
            dependency_lock_sha256=self.config["dependency_lock_sha256"],
        )
        self.gate_adapter = gate_adapter or CommandGateAdapter(self.config.get("gate_adapter") or {})
        self.state_dir = _expand_path(self.config["state_dir"])
        self.event_store_dir = _expand_path(self.config["event_store_dir"])
        self.audit = JsonlAuditLog(_expand_path(self.config["audit_log_path"]), audit_key=self._audit_key())
        self.run_lock = RunOnceLock(
            self.state_dir / "run-once.lock",
            owner=f"submission-gate.{os.getpid()}",
            now_fn=self.now_fn,
        )

    def preflight(self) -> dict[str, Any]:
        accounts = self.mail_gateway.list_accounts().get("accounts") or []
        profile = str(self.config["gate_mail_account"]["profile"])
        matched = any(isinstance(item, Mapping) and item.get("name") == profile for item in accounts)
        adapter = dict(self.gate_adapter.preflight())
        auth = self._auth_status()
        return {
            "ready": bool(matched) and bool(adapter.get("ready")) and not auth["invalid"],
            "mail_account_ready": bool(matched),
            "gate_adapter": adapter,
            "auth_optional": True,
            "auth_key_configured": auth["configured"],
            "auth_key_valid": not auth["invalid"],
            "core_version": CORE_VERSION,
            "workflow_core_digest": workflow_core_digest(),
            "config_path": str(self.config_path),
        }

    def run_once(self) -> dict[str, Any]:
        acquired = self.run_lock.acquire()
        if acquired.get("status") != "acquired":
            return {
                "status": "RUN_ALREADY_ACTIVE",
                "busy": True,
                "owner": acquired.get("owner"),
                "orphan_metadata": None,
            }
        retried, retry_sent = self._retry_pending_mail()
        try:
            search = self.mail_gateway.search_messages(
                {
                    "account": self.config["gate_mail_account"]["profile"],
                    "mailbox": self.config["mailbox"],
                    "query": {"subject": "提测"},
                    "scan_limit": int(self.config.get("scan_limit") or 100),
                    "limit": int(self.config.get("scan_limit") or 100),
                }
            )
            counters = {"processed": 0, "passed": 0, "blocked": 0, "capability_blocked": 0, "skipped": 0}
            for message in search.get("messages") or []:
                if not isinstance(message, Mapping) or not message.get("uid"):
                    continue
                read = self.mail_gateway.read_message(
                    {
                        "account": self.config["gate_mail_account"]["profile"],
                        "mailbox": self.config["mailbox"],
                        "uid": str(message["uid"]),
                    }
                )
                unique_key = self._unique_key(read)
                prior = self._processed_record(unique_key)
                if prior and prior.get("terminal", True):
                    counters["skipped"] += 1
                    continue
                counters["processed"] += 1
                sender = _extract_email(read.get("from"))
                try:
                    intake = self._parse_intake(read, unique_key=unique_key)
                    result = self._execute_gate(intake, source=read)
                    send_status = self._notify_pass(result)
                    status = "SUBMISSION_GATE_PASSED" if send_status == "sent" else "SEND_BLOCKED"
                    self._record(unique_key, result["event_id"], result["round_id"], status, terminal=True)
                    counters["passed"] += 1
                except SubmissionGateError as exc:
                    is_capability = exc.code == "CAPABILITY_BLOCKED"
                    status = "CAPABILITY_BLOCKED" if is_capability else "SUBMISSION_GATE_BLOCKED"
                    event_id = str(read.get("release_workflow_headers", {}).get("event_id") or "unknown")
                    round_id = int(read.get("release_workflow_headers", {}).get("round_id") or 1)
                    self._record(unique_key, event_id, round_id, status, terminal=is_capability, reason=str(exc))
                    if sender:
                        self._notify_block(sender, str(exc), status=status)
                    counters["capability_blocked" if is_capability else "blocked"] += 1
            payload: dict[str, Any] = {"status": "ready", **counters, "retried": retried, "retry_sent": retry_sent}
            recovered_owner = acquired.get("recovered_owner")
            if recovered_owner:
                payload["orphan_recovered_owner"] = recovered_owner
            return payload
        finally:
            self.run_lock.release()

    def status(self) -> dict[str, Any]:
        records = [json.loads(path.read_text(encoding="utf-8")) for path in self.state_dir.glob("processed/*.json")]
        by_status: dict[str, int] = {}
        for record in records:
            key = str(record.get("status") or "unknown")
            by_status[key] = by_status.get(key, 0) + 1
        return {
            "status": "ready",
            "processed_mail": len(records),
            "by_status": by_status,
            "pending_mail": len(list(self.state_dir.glob("pending-mail/*.json"))),
        }

    def doctor(self) -> dict[str, Any]:
        payload = self.preflight()
        payload["state_dir"] = str(self.state_dir)
        payload["event_store_dir"] = str(self.event_store_dir)
        payload["audit"] = self.verify_audit()
        return payload

    def verify_audit(self) -> dict[str, Any]:
        return {"status": "verified", **self.audit.verify()}

    def get_event(self, *, event_id: str, round_id: int) -> dict[str, Any]:
        path = self._event_dir(event_id, round_id) / "gate.json"
        return {"event": json.loads(path.read_text(encoding="utf-8"))}

    def _parse_intake(self, message: Mapping[str, Any], *, unique_key: str) -> dict[str, Any]:
        body = str(message.get("body_text") or "")
        if _NEW_MACHINE_BEGIN in body:
            try:
                payload = parse_message(body, secret=self._transport_secret())
            except MailContractError as exc:
                raise SubmissionGateError("AUTHENTICATION_FAILED", str(exc)) from exc
            return self._normalize_structured(payload, message=message, unique_key=unique_key)
        if _OLD_MACHINE_BEGIN in body:
            payload = extract_machine_block(body)
            payload = self._verify_old_machine_payload(payload)
            return self._normalize_structured(payload, message=message, unique_key=unique_key)
        try:
            legacy = parse_legacy_submission_mail(message, enabled_checks=tuple(self.config.get("enabled_optional_checks") or ()))
        except LegacyIntakeError:
            legacy = self._parse_plain_canonical(message)
        if legacy.get("state") == "CAPABILITY_BLOCKED":
            raise SubmissionGateError("INVALID_REQUEST", str(legacy.get("failure_reason") or "plain submission is incomplete"))
        event_id = "legacy-" + hashlib.sha256(unique_key.encode("utf-8")).hexdigest()[:20]
        normalized = {
            "event_id": event_id,
            "round_id": 1,
            "task": str(legacy.get("task") or "").strip(),
            "module": _normalize_module(legacy.get("module")),
            "retrieval_method": "svn",
            "source_locator": str(legacy.get("locator") or "").strip(),
            "revision": str(legacy.get("revision") or "").strip(),
            "version": str(legacy.get("version") or "legacy-unspecified").strip(),
            "retrieval_instructions": str(legacy.get("retrieval_instructions") or "").strip(),
            "change_summary": str(legacy.get("change_summary") or "").strip(),
            "provenance_classification": "PLAIN_EMAIL_UNVERIFIED",
            "provenance_badge": provenance_badge("PLAIN_EMAIL_UNVERIFIED"),
            "submitter_email": _normalize_submitter_email(legacy.get("submitter_email")),
            "submitter_email_status": str(legacy.get("submitter_email_status") or "missing_or_invalid"),
            "artifacts": [],
        }
        return self._finalize_intake(normalized, message=message, unique_key=unique_key)

    def _parse_plain_canonical(self, message: Mapping[str, Any]) -> dict[str, Any]:
        subject = str(message.get("subject") or "").strip()
        match = _CANONICAL_SUBJECT_RE.fullmatch(subject)
        if not match:
            raise SubmissionGateError("INVALID_REQUEST", "plain submission subject is not a supported canonical or legacy format")
        fields: dict[str, str] = {}
        for raw_line in str(message.get("body_text") or "").splitlines():
            if "：" in raw_line:
                label, value = raw_line.split("：", 1)
            elif ":" in raw_line:
                label, value = raw_line.split(":", 1)
            else:
                continue
            fields[re.sub(r"[-_\s]+", "", label).lower()] = value.strip()
        locator = fields.get("svn地址") or fields.get("目录") or fields.get("sourcelocator") or ""
        revision = fields.get("svnrevision") or fields.get("revision") or ""
        module = _normalize_module(fields.get("模块") or match.group("module"))
        missing = [name for name, value in (("locator", locator), ("revision", revision), ("module", module)) if not value]
        if revision and not _REVISION_RE.fullmatch(revision):
            missing.append("numeric revision")
        return {
            "state": "CAPABILITY_BLOCKED" if missing else "DRAFT",
            "failure_reason": "plain submission is missing " + ", ".join(missing) if missing else "",
            "task": fields.get("任务") or match.group("task"),
            "module": module,
            "locator": locator,
            "revision": revision,
            "version": fields.get("版本") or "legacy-unspecified",
            "retrieval_instructions": fields.get("获取方式") or fields.get("retrievalinstructions") or "",
            "change_summary": fields.get("修改说明") or fields.get("摘要") or "",
        }

    def _verify_old_machine_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        block = dict(payload)
        claimed = str(block.get("hmac_sha256") or "").strip().lower()
        if not claimed:
            block["provenance_classification"] = "STRUCTURED_UNVERIFIED"
            block["provenance_badge"] = provenance_badge("STRUCTURED_UNVERIFIED")
            return block
        secret = self._transport_secret()
        if secret is None:
            raise SubmissionGateError("AUTHENTICATION_FAILED", "message claims authentication but no verification key is configured")
        material = {key: value for key, value in block.items() if key != "hmac_sha256"}
        actual = hmac.new(secret, json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(claimed, actual):
            raise SubmissionGateError("AUTHENTICATION_FAILED", "legacy machine payload authentication failed")
        block["provenance_classification"] = "COMPLIANT_PLUGIN_VERIFIED"
        block["provenance_badge"] = provenance_badge("COMPLIANT_PLUGIN_VERIFIED")
        return block

    def _normalize_structured(self, payload: Mapping[str, Any], *, message: Mapping[str, Any], unique_key: str) -> dict[str, Any]:
        source = payload.get("submission") if isinstance(payload.get("submission"), Mapping) else payload
        retrieval_method = str(source.get("retrieval_method") or "").strip().lower()
        artifacts = source.get("artifacts") if isinstance(source.get("artifacts"), list) else []
        if not retrieval_method and artifacts:
            retrieval_method = str(artifacts[0].get("retrieval_method") or "local").strip().lower()
        retrieval_method = retrieval_method or "local"
        source_locator = str(source.get("source_locator") or source.get("repository_path") or "").strip()
        revision = str(source.get("revision") or "").strip()
        version = str(source.get("version") or "").strip()
        if retrieval_method == "svn" and artifacts:
            first = artifacts[0] if isinstance(artifacts[0], Mapping) else {}
            source_locator = source_locator or str(first.get("repository_path") or first.get("source_locator") or "").strip()
            revision = revision or str(first.get("revision") or "").strip()
            version = version or str(first.get("version") or "").strip()
        normalized = {
            "event_id": str(source.get("event_id") or payload.get("event_id") or "").strip(),
            "round_id": int(source.get("round_id") or payload.get("round_id") or 1),
            "task": str(source.get("task") or source.get("task_name") or payload.get("task") or "").strip(),
            "module": _normalize_module(source.get("module") or payload.get("module")),
            "submitter_email": _normalize_submitter_email(source.get("submitter_email") or source.get("sender_email")),
            "submitter_email_status": "valid" if _normalize_submitter_email(source.get("submitter_email") or source.get("sender_email")) else "missing_or_invalid",
            "retrieval_method": retrieval_method,
            "source_locator": source_locator,
            "revision": revision,
            "version": version,
            "retrieval_instructions": str(source.get("retrieval_instructions") or "").strip(),
            "change_summary": str(source.get("change_summary") or "").strip(),
            "provenance_classification": str(payload.get("provenance_classification") or "STRUCTURED_UNVERIFIED"),
            "provenance_badge": str(payload.get("provenance_badge") or provenance_badge("STRUCTURED_UNVERIFIED")),
            "artifacts": self._strip_sender_paths(artifacts),
        }
        return self._finalize_intake(normalized, message=message, unique_key=unique_key)

    @staticmethod
    def _strip_sender_paths(artifacts: Sequence[Any]) -> list[dict[str, Any]]:
        safe: list[dict[str, Any]] = []
        for item in artifacts:
            if not isinstance(item, Mapping):
                continue
            safe.append({key: value for key, value in item.items() if key not in {"local_path", "file_path"}})
        return safe

    def _finalize_intake(self, intake: Mapping[str, Any], *, message: Mapping[str, Any], unique_key: str) -> dict[str, Any]:
        result = dict(intake)
        result["event_id"] = _ensure_event_id(str(result.get("event_id") or ""))
        if int(result.get("round_id") or 0) < 1:
            raise SubmissionGateError("INVALID_REQUEST", "round_id must be positive")
        if not result.get("task") or not result.get("module"):
            raise SubmissionGateError("INVALID_REQUEST", "task and explicit module are required")
        if result.get("retrieval_method") == "svn":
            if not result.get("source_locator"):
                raise SubmissionGateError("INVALID_REQUEST", "SVN source locator is required")
            if not _REVISION_RE.fullmatch(str(result.get("revision") or "")):
                raise SubmissionGateError("INVALID_REQUEST", "SVN fixed numeric revision is required")
        result["source_transport"] = {
            "uid": str(message.get("uid") or ""),
            "message_id": str(message.get("message_id") or ""),
            "raw_headers_sha256": str((message.get("evidence") or {}).get("raw_headers_sha256") or ""),
            "unique_key": unique_key,
        }
        result["request_digest"] = _sha256_json({key: value for key, value in result.items() if key != "request_digest"})
        return result

    def _execute_gate(self, intake: Mapping[str, Any], *, source: Mapping[str, Any]) -> dict[str, Any]:
        retrieval_method = str(intake.get("retrieval_method") or "local")
        module = str(intake["module"])
        configured = self.config.get("svn_mandatory_checks") if retrieval_method == "svn" else (self.config.get("mandatory_checks_by_module") or {}).get(module)
        optional = list(self.config.get("enabled_optional_checks") or [])
        try:
            policy = freeze_policy(
                module,
                policy_profile=str(self.config.get("policy_profile") or "submission-gate/v1"),
                configured_mandatory=list(configured or []),
                enabled_optional=optional,
                retrieval_method=retrieval_method,
            )
        except Exception as exc:
            raise SubmissionGateError("GATE_POLICY_INVALID", str(exc)) from exc
        self._append_audit(
            {
                "event_type": "SUBMISSION_GATE_INTAKE",
                "event_id": intake["event_id"],
                "round_id": intake["round_id"],
                "request_digest": intake["request_digest"],
                "policy_digest": policy["policy_digest"],
                "provenance_classification": intake["provenance_classification"],
            }
        )
        adapter_request = {
            "schema": "SubmissionGateAdapterRequest/v1",
            "event_id": intake["event_id"],
            "round_id": intake["round_id"],
            "task": intake["task"],
            "module": module,
            "retrieval_method": retrieval_method,
            "source_locator": intake.get("source_locator", ""),
            "revision": intake.get("revision", ""),
            "version": intake.get("version", ""),
            "retrieval_instructions": intake.get("retrieval_instructions", ""),
            "request_digest": intake["request_digest"],
            "policy_digest": policy["policy_digest"],
            "effective_checks": list(policy["effective_checks"]),
            "sender_artifact_declarations": list(intake.get("artifacts") or []),
        }
        result = self.gate_adapter.evaluate(adapter_request)
        try:
            evidence = validate_gitlab_gate_result(
                result,
                expected_bindings={
                    "event_id": intake["event_id"],
                    "round_id": intake["round_id"],
                    "request_digest": intake["request_digest"],
                    "policy_digest": policy["policy_digest"],
                },
            )
        except Exception as exc:
            raise SubmissionGateError("GATE_EVIDENCE_INVALID", str(exc)) from exc
        mandatory = list(_SVN_CANONICAL if retrieval_method == "svn" else _LOCAL_CANONICAL[module])
        check_results = {item: "PASS" for item in mandatory}
        supplied_results = result.get("check_results") if isinstance(result.get("check_results"), Mapping) else {}
        for item in optional:
            status = str(supplied_results.get(item) or "NOT_APPLICABLE").strip().upper()
            if status not in {"PASS", "NOT_APPLICABLE"}:
                raise SubmissionGateError("SUBMISSION_GATE_BLOCKED", f"optional gate check failed: {item}={status}")
            check_results[item] = status
        now = self._timestamp()
        evidence_refs = list(evidence.evidence_refs)
        lark_evidence_ref = str(result.get("lark_evidence_ref") or self.config.get("feishu_directory_url") or (evidence_refs[0] if evidence_refs else ""))
        workflow = {
            "schema": "ProductMaterialWorkflow/v1",
            "event_type": "SUBMISSION_GATE_PASS",
            "state": "SUBMISSION_GATE_PASSED",
            "event_id": intake["event_id"],
            "round_id": intake["round_id"],
            "task": intake["task"],
            "module": module,
            "created_at": now,
            "policy_profile": policy["policy_profile"],
            "policy_digest": policy["policy_digest"],
            "evidence_refs": evidence_refs,
            "provenance_classification": intake["provenance_classification"],
            "manifest_s_digest": evidence.manifest_digest,
            "request_digest": intake["request_digest"],
            "submitter_email": intake.get("submitter_email", ""),
            "submitter_email_status": intake.get("submitter_email_status", "missing_or_invalid"),
            "gate_verdict": evidence.verdict,
            "retrieval_method": retrieval_method,
            "retrieval_provenance": {
                "repository_path": str(intake.get("source_locator") or ""),
                "revision": str(intake.get("revision") or ""),
                "version": str(intake.get("version") or ""),
            },
            "retrieval_provenance_digest": _sha256_json(
                {
                    "repository_path": str(intake.get("source_locator") or ""),
                    "revision": str(intake.get("revision") or ""),
                }
            ),
            "checked_items": [f"{key}:{value}" for key, value in check_results.items()],
            "check_results": check_results,
            "artifacts": list(result.get("artifacts") or []),
            "gitlab_evidence_ref": str(result.get("artifact_ref") or evidence.artifact_ref or (evidence_refs[0] if evidence_refs else "")),
            "gitlab_evidence_digest": _sha256_json(dict(result)),
            "lark_evidence_ref": lark_evidence_ref,
            "source_message_id": str((intake.get("source_transport") or {}).get("message_id") or ""),
            "thread_references": [str((intake.get("source_transport") or {}).get("message_id") or "")],
            "source_origin_badge": intake["provenance_badge"],
        }
        gate_event = {
            "event_id": intake["event_id"],
            "round_id": intake["round_id"],
            "status": "SUBMISSION_GATE_PASSED",
            "intake": dict(intake),
            "policy": policy,
            "gate_evidence": dict(result),
            "workflow": workflow,
        }
        self._write_gate_event(gate_event)
        self._append_audit(
            {
                "event_type": "SUBMISSION_GATE_PASS",
                "event_id": intake["event_id"],
                "round_id": intake["round_id"],
                "manifest_s_digest": evidence.manifest_digest,
                "evidence_refs": evidence_refs,
            }
        )
        return gate_event

    def _notify_pass(self, gate_event: Mapping[str, Any]) -> str:
        workflow = dict(gate_event["workflow"])
        secret = self._transport_secret()
        rendered = render_message(
            "test_submission",
            workflow,
            secret=secret,
            key_id=str((self.config.get("auth") or {}).get("key_id") or "default"),
            identity_id=str((self.config.get("auth") or {}).get("identity_id") or "submission-gate"),
            when=self.now_fn(),
            summary_lines=self._human_pass_lines(workflow),
        )
        message_id = f"<submission-gate-{workflow['event_id']}-r{workflow['round_id']}-{uuid.uuid4().hex[:8]}@local>"
        headers = {
            **rendered["headers"],
            "X-RD-Contract": "ProductMaterialWorkflow/v1",
            "X-RD-Request-Digest": workflow["request_digest"],
            "X-RD-Submitter-Email": workflow.get("submitter_email", ""),
            "X-RD-Manifest-S-Digest": workflow["manifest_s_digest"],
        }
        payload = {
            "account": self.config["gate_mail_account"]["profile"],
            "to": [self.config["submission_group_address"]],
            "subject": rendered["subject"],
            "body_text": rendered["body_text"],
            "text": rendered["body_text"],
            "headers": headers,
            "message_id": message_id,
            "dry_run": False,
        }
        try:
            result = self.mail_gateway.send_email(payload)
        except Exception as exc:
            self._store_pending_mail(gate_event, payload, reason=str(exc))
            return "pending"
        if result.get("refused"):
            self._store_pending_mail(gate_event, payload, reason=json.dumps(result.get("refused"), ensure_ascii=False))
            return "pending"
        self._append_audit(
            {
                "event_type": "SUBMISSION_GATE_PASS_SENT",
                "event_id": workflow["event_id"],
                "round_id": workflow["round_id"],
                "message_id": str(result.get("message_id") or message_id),
                "recipient": self.config["submission_group_address"],
            }
        )
        return "sent"

    @staticmethod
    def _human_pass_lines(workflow: Mapping[str, Any]) -> list[str]:
        provenance = workflow.get("retrieval_provenance") or {}
        lines = [
            f"事件：{workflow['event_id']}#{workflow['round_id']}",
            f"任务：{workflow['task']}",
            f"模块：{workflow['module']}",
            "状态：SUBMISSION_GATE_PASS",
            f"Manifest-S：{workflow['manifest_s_digest']}",
            f"- 提测门禁策略摘要：{workflow['policy_digest']}",
            f"- SVN：{provenance.get('repository_path', '')}@{provenance.get('revision', '')}" if workflow.get("retrieval_method") == "svn" else f"- GitLab：{workflow.get('gitlab_evidence_ref', '')}",
            f"- 飞书：{workflow.get('lark_evidence_ref', '')}",
            f"提测人邮箱：{workflow.get('submitter_email') or '未提供'}",
            f"发起标识：{workflow.get('source_origin_badge', '')}",
            "检查结果：",
        ]
        lines.extend(f"- {name}：{status}" for name, status in (workflow.get("check_results") or {}).items())
        return lines

    def _notify_block(self, sender: str, reason: str, *, status: str) -> None:
        recipient = sender if _EMAIL_RE.fullmatch(sender) else self.config["blocked_notice_address"]
        try:
            self.mail_gateway.send_email(
                {
                    "account": self.config["gate_mail_account"]["profile"],
                    "to": [recipient],
                    "subject": "【提测阻断】门禁未通过",
                    "body_text": f"状态：{status}\n原因：{reason}",
                    "text": f"状态：{status}\n原因：{reason}",
                    "dry_run": False,
                }
            )
        except Exception:
            return

    def _retry_pending_mail(self) -> tuple[int, int]:
        retried = 0
        sent = 0
        for path in sorted((self.state_dir / "pending-mail").glob("*.json")):
            retried += 1
            pending = json.loads(path.read_text(encoding="utf-8"))
            try:
                result = self.mail_gateway.send_email(pending["mail"])
            except Exception:
                continue
            if result.get("refused"):
                continue
            path.unlink()
            sent += 1
            self._append_audit(
                {
                    "event_type": "SUBMISSION_GATE_PASS_RETRY_SENT",
                    "event_id": pending["event_id"],
                    "round_id": pending["round_id"],
                    "message_id": str(result.get("message_id") or pending["mail"].get("message_id") or ""),
                }
            )
        return retried, sent

    def _store_pending_mail(self, gate_event: Mapping[str, Any], mail: Mapping[str, Any], *, reason: str) -> None:
        workflow = gate_event["workflow"]
        path = self.state_dir / "pending-mail" / f"{workflow['event_id']}-r{workflow['round_id']}.json"
        _write_json(
            path,
            {
                "event_id": workflow["event_id"],
                "round_id": workflow["round_id"],
                "reason": reason,
                "mail": dict(mail),
            },
        )

    def _event_dir(self, event_id: str, round_id: int) -> Path:
        return self.event_store_dir / _ensure_event_id(event_id) / f"round-{int(round_id)}"

    def _write_gate_event(self, event: Mapping[str, Any]) -> None:
        _write_json(self._event_dir(str(event["event_id"]), int(event["round_id"])) / "gate.json", event)

    def _unique_key(self, message: Mapping[str, Any]) -> str:
        evidence = message.get("evidence") or {}
        return "|".join(
            (
                str(message.get("uidvalidity") or ""),
                str(message.get("uid") or ""),
                str(message.get("message_id") or ""),
                str(evidence.get("raw_headers_sha256") or ""),
            )
        )

    def _processed_path(self, unique_key: str) -> Path:
        return self.state_dir / "processed" / f"{hashlib.sha256(unique_key.encode('utf-8')).hexdigest()}.json"

    def _processed_record(self, unique_key: str) -> dict[str, Any] | None:
        path = self._processed_path(unique_key)
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    def _record(
        self,
        unique_key: str,
        event_id: str,
        round_id: int,
        status: str,
        *,
        terminal: bool,
        reason: str = "",
    ) -> None:
        _write_json(
            self._processed_path(unique_key),
            {
                "event_id": event_id,
                "round_id": round_id,
                "status": status,
                "terminal": terminal,
                "reason": reason,
                "updated_at": self._timestamp(),
            },
        )

    def _append_audit(self, record: Mapping[str, Any]) -> dict[str, Any]:
        return self.audit.append(record, recorded_at=self._timestamp())

    def _timestamp(self) -> str:
        return self.now_fn().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _auth_status(self) -> dict[str, bool]:
        raw = self._raw_auth_secret()
        return {"configured": raw is not None, "invalid": raw is not None and len(raw) < 32}

    def _raw_auth_secret(self) -> bytes | None:
        auth = self.config.get("auth") or {}
        key_id = str(auth.get("key_id") or "default")
        value = self.environ.get(f"RELEASE_WORKFLOW_AUTH_KEY_{key_id.upper()}")
        if value is None:
            value = self.environ.get("TEST_SUBMISSION_HMAC_KEY")
        return value.encode("utf-8") if value is not None and value != "" else None

    def _transport_secret(self) -> bytes | None:
        secret = self._raw_auth_secret()
        if secret is not None and len(secret) < 32:
            raise SubmissionGateError("AUTH_CONFIG_INVALID", "configured workflow auth key must contain at least 32 bytes")
        return secret

    def _audit_key(self) -> bytes:
        path = _expand_path(self.config["audit_key_path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            try:
                with path.open("xb") as handle:
                    handle.write(os.urandom(32))
                try:
                    path.chmod(0o600)
                except OSError:
                    pass
            except FileExistsError:
                pass
        key = path.read_bytes()
        if len(key) < 32:
            raise SubmissionGateError("AUDIT_KEY_INVALID", "local audit key is invalid")
        return key


__all__ = [
    "CommandGateAdapter",
    "LockedMailGateway",
    "SubmissionGateController",
    "SubmissionGateError",
    "default_config",
    "default_config_path",
    "extract_machine_block",
    "load_config",
    "sha256_file",
    "workflow_core_digest",
]
