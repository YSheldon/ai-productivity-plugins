from __future__ import annotations

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

from test_submission_lock import RunOnceLock


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_EVENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
_MODULES = ("kernel", "client", "server")
_CANONICAL_MANDATORY = {
    "kernel": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"],
    "client": ["artifacts_present", "hashes_match", "version_present", "signature_present", "cloud_scan_required"],
    "server": ["artifacts_present", "hashes_match", "source_revision_present", "package_digest_present", "cloud_scan_required"],
}
_MACHINE_BEGIN = "-----BEGIN RD TEST SUBMISSION BLOCK-----"
_MACHINE_END = "-----END RD TEST SUBMISSION BLOCK-----"
_MAIL_PLUGIN_ROOT = Path("plugins/imap-smtp-mail")
_MAIL_CLI_PATH = _MAIL_PLUGIN_ROOT / "src" / "imap_smtp_mail_cli.py"
_GATE_PLUGIN_PARTS = ("product", "release", "gate")
_GATE_PLUGIN_NAME = "-".join(_GATE_PLUGIN_PARTS)
_PRODUCT_PLUGIN_ROOT = Path("plugins") / _GATE_PLUGIN_NAME
_PRODUCT_CLI_PATH = _PRODUCT_PLUGIN_ROOT / "src" / f"{'_'.join(('release', 'gate', 'cli'))}.py"
workflow_core_digest = "embedded-release-workflow-core"


class SubmissionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha1_file(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def default_config_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return (root / "test-submission" / "config.json").resolve(strict=False)


def default_config() -> dict[str, Any]:
    root = default_config_path().parent
    return {
        "mail_account": {"profile": "", "email": ""},
        "submission_gate_address": "",
        "feishu_directory_url": "",
        "state_dir": str((root / "state").resolve(strict=False)),
        "event_store_dir": str((root / "events").resolve(strict=False)),
        "poll_minutes": 60,
        "scheduler_mode": "auto",
        "default_optional_checks": [],
        "mandatory_checks_by_module": {
            "kernel": [
                "artifacts_present",
                "hashes_match",
                "version_present",
                "signature_present",
                "cloud_scan_required",
            ],
            "client": [
                "artifacts_present",
                "hashes_match",
                "version_present",
                "signature_present",
                "cloud_scan_required",
            ],
            "server": [
                "artifacts_present",
                "hashes_match",
                "source_revision_present",
                "package_digest_present",
                "cloud_scan_required",
            ],
        },
        "product_gate_preview_config": str((root / "product-release-gate.preview.json").resolve(strict=False)),
        "dependency_lock": str((root / "dependency-lock.test-submission.json").resolve(strict=False)),
        "dependency_lock_sha256": "",
    }


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _configured_mandatory_map(config: Mapping[str, Any]) -> dict[str, list[str]]:
    raw = config.get("mandatory_checks_by_module") or {}
    if not isinstance(raw, Mapping):
        raise SubmissionError("CONFIG_ERROR", "mandatory_checks_by_module must be an object")
    normalized: dict[str, list[str]] = {}
    for module in _MODULES:
        items = raw.get(module) or []
        if not isinstance(items, list):
            raise SubmissionError("CONFIG_ERROR", f"mandatory_checks_by_module.{module} must be an array")
        normalized[module] = [str(item).strip() for item in items if str(item).strip()]
    return normalized


def _missing_canonical_mandatory(config: Mapping[str, Any]) -> dict[str, list[str]]:
    configured = _configured_mandatory_map(config)
    return {module: [item for item in _CANONICAL_MANDATORY[module] if item not in configured[module]] for module in _MODULES if any(item not in configured[module] for item in _CANONICAL_MANDATORY[module])}


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve(strict=False)
    payload = default_config()
    if config_path.is_file():
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SubmissionError("CONFIG_ERROR", "configuration must be a JSON object")
        payload = _deep_merge(payload, raw)
    mail_account = payload.get("mail_account") or {}
    if not isinstance(mail_account, dict):
        raise SubmissionError("CONFIG_ERROR", "mail_account must be an object")
    if not _EMAIL_RE.fullmatch(str(mail_account.get("email") or "").strip()):
        raise SubmissionError("CONFIG_ERROR", "mail_account.email is required")
    if not str(mail_account.get("profile") or "").strip():
        raise SubmissionError("CONFIG_ERROR", "mail_account.profile is required")
    gate_address = str(payload.get("submission_gate_address") or "").strip()
    if not _EMAIL_RE.fullmatch(gate_address):
        raise SubmissionError("CONFIG_ERROR", "submission_gate_address must be one email address")
    lock_digest = str(payload.get("dependency_lock_sha256") or "").strip().lower()
    if not _SHA256_RE.fullmatch(lock_digest):
        raise SubmissionError("CONFIG_ERROR", "dependency_lock_sha256 must be one 64-hex SHA-256")
    return payload


def _ensure_event_id(value: str) -> str:
    text = str(value or "").strip()
    if not _EVENT_RE.fullmatch(text):
        raise SubmissionError("INVALID_EVENT_ID", "event_id must match the stable workflow identifier pattern")
    return text


def _expand_path(value: str | None) -> Path:
    return Path(os.path.expandvars(str(value or ""))).expanduser().resolve(strict=False)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
        raise SubmissionError("DEPENDENCY_DRIFT", "dependency lock drift was detected")
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    plugins = payload.get("plugins") if isinstance(payload, dict) else None
    if not isinstance(plugins, list):
        raise SubmissionError("DEPENDENCY_DRIFT", "dependency lock must contain a plugins array")
    expected_root = Path(plugin_root).as_posix()
    expected_path = Path(entrypoint_path).as_posix()
    for plugin in plugins:
        if not isinstance(plugin, dict) or plugin.get("name") != plugin_name:
            continue
        if Path(str(plugin.get("plugin_root") or "")).as_posix() != expected_root:
            raise SubmissionError("DEPENDENCY_DRIFT", f"dependency lock {plugin_name} root is invalid")
        for entrypoint in plugin.get("entrypoints") or []:
            if not isinstance(entrypoint, dict):
                continue
            if Path(str(entrypoint.get("path") or "")).as_posix() != expected_path:
                continue
            entrypoint_file = (lock_path.parent / expected_path).resolve(strict=True)
            if sha256_file(entrypoint_file) != str(entrypoint.get("sha256") or "").strip().lower():
                raise SubmissionError("DEPENDENCY_DRIFT", "locked runtime entrypoint drift was detected")
            return entrypoint_file
    raise SubmissionError("DEPENDENCY_DRIFT", f"dependency lock does not include {plugin_name}")


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
            raise SubmissionError("MAIL_GATEWAY_FAILED", (completed.stderr or completed.stdout or "mail cli failed").strip())
        payload = json.loads(completed.stdout)
        if payload.get("ok") is not True:
            raise SubmissionError("MAIL_GATEWAY_FAILED", str(payload.get("error") or "mail cli rejected the request"))
        result = payload.get("result")
        if not isinstance(result, dict):
            raise SubmissionError("MAIL_GATEWAY_FAILED", "mail cli returned an invalid payload")
        return result


class ProductGatePreviewBridge:
    def __init__(
        self,
        dependency_lock: str | Path,
        *,
        dependency_lock_sha256: str,
        config_path: str | Path,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.cli_path = _resolve_locked_entrypoint(
            dependency_lock,
            dependency_lock_sha256=dependency_lock_sha256,
            plugin_name=_GATE_PLUGIN_NAME,
            plugin_root=_PRODUCT_PLUGIN_ROOT,
            entrypoint_path=_PRODUCT_CLI_PATH,
        )
        self.config_path = Path(config_path).resolve(strict=False)
        self.runner = runner

    def preview_submission(
        self,
        *,
        event_id: str,
        task_id: str,
        artifacts: list[dict[str, Any]],
        source_ref: str,
        round_number: int,
    ) -> dict[str, Any]:
        request = {
            "event_id": event_id,
            "task_id": task_id,
            "artifacts": [
                {
                    "logical_name": item["logical_name"],
                    "file_path": item["local_path"],
                    "source_ref": item["source_ref"],
                }
                for item in artifacts
            ],
            "source_ref": source_ref,
            "rollback_ref": "preview-only",
            "risk_level": "standard",
            "round_number": round_number,
        }
        self._call("create_submission", request)
        event = self._call("get_event", {"event_id": event_id})
        result = event.get("event") if isinstance(event.get("event"), dict) else event
        if not isinstance(result, dict):
            raise SubmissionError("PRODUCT_GATE_FAILED", "product gate preview did not return an event")
        return result

    def preflight(self) -> dict[str, Any]:
        return self._call("preflight", {})

    def _call(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        command = [
            sys.executable,
            str(self.cli_path),
            "--config",
            str(self.config_path),
        ]
        if operation == "preflight":
            command.append("preflight")
        else:
            command.extend(["call", operation, "--input", json.dumps(dict(payload), ensure_ascii=False)])
        completed = self.runner(
            command,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
        if completed.returncode not in {0, 3}:
            raise SubmissionError("PRODUCT_GATE_FAILED", (completed.stderr or completed.stdout or "product gate cli failed").strip())
        envelope = json.loads(completed.stdout)
        if envelope.get("ok") is not True:
            error = envelope.get("error") or {}
            raise SubmissionError(str(error.get("code") or "PRODUCT_GATE_FAILED"), str(error.get("message") or "product gate rejected the request"))
        result = envelope.get("result")
        if not isinstance(result, dict):
            raise SubmissionError("PRODUCT_GATE_FAILED", "product gate cli returned an invalid result")
        return result


def _now_iso(now_fn: Callable[[], datetime]) -> str:
    return now_fn().astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _machine_hmac(payload: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def _message_id(event_id: str, round_id: int) -> str:
    return f"<submission-{event_id}-r{round_id}-{uuid.uuid4().hex[:8]}@local>"


def extract_machine_block(body_text: str) -> dict[str, Any]:
    parts = body_text.split(_MACHINE_BEGIN)
    if len(parts) != 2 or _MACHINE_END not in parts[1]:
        raise SubmissionError("REQUEST_BLOCK_INVALID", "submission machine block is missing or ambiguous")
    block_text = parts[1].split(_MACHINE_END, 1)[0].strip()
    payload = json.loads(block_text)
    if not isinstance(payload, dict):
        raise SubmissionError("REQUEST_BLOCK_INVALID", "submission machine block must decode to an object")
    return payload


class TestSubmissionController:
    def __init__(
        self,
        config_path: str | Path,
        *,
        config: Mapping[str, Any] | None = None,
        mail_gateway: LockedMailGateway | Any | None = None,
        product_gate: ProductGatePreviewBridge | Any | None = None,
        now_fn: Callable[[], datetime] | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.config_path = Path(config_path).resolve(strict=False)
        self.config = dict(load_config(self.config_path) if config is None else config)
        self.environ = dict(os.environ if environ is None else environ)
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.mail_gateway = mail_gateway or LockedMailGateway(
            self.config["dependency_lock"],
            dependency_lock_sha256=self.config["dependency_lock_sha256"],
        )
        self.product_gate = product_gate or ProductGatePreviewBridge(
            self.config["dependency_lock"],
            dependency_lock_sha256=self.config["dependency_lock_sha256"],
            config_path=self.config["product_gate_preview_config"],
        )
        self.state_dir = _expand_path(self.config["state_dir"])
        self.event_store_dir = _expand_path(self.config["event_store_dir"])
        self.run_lock = RunOnceLock(self.state_dir / "run-once.lock")

    def preflight(self) -> dict[str, Any]:
        accounts = self.mail_gateway.list_accounts().get("accounts") or []
        profile = str(self.config["mail_account"]["profile"])
        matched = [
            account
            for account in accounts
            if isinstance(account, dict) and account.get("name") == profile
        ]
        key_ready = bool(str(self.environ.get("TEST_SUBMISSION_HMAC_KEY") or "").strip())
        gate_ready = self.product_gate.preflight()
        missing_canonical = _missing_canonical_mandatory(self.config)
        gate_ready_flag = bool(gate_ready.get("ready", False)) if isinstance(gate_ready, Mapping) else False
        return {
            "ready": bool(matched) and key_ready and gate_ready_flag and not missing_canonical,
            "mail_account_ready": bool(matched),
            "hmac_key_ready": key_ready,
            "product_gate_preview": gate_ready,
            "missing_canonical_mandatory": missing_canonical,
            "config_path": str(self.config_path),
        }

    def submit(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        module = str(payload.get("module") or "").strip().lower()
        if module not in _MODULES:
            raise SubmissionError("MODULE_REQUIRED", "module must be one of kernel, client, or server")
        task_name = str(payload.get("task_name") or "").strip()
        if not task_name:
            raise SubmissionError("INVALID_ARGUMENT", "task_name is required")
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise SubmissionError("INVALID_ARGUMENT", "artifacts must be a non-empty array")
        round_id = int(payload.get("round_id") or 1)
        event_id = _ensure_event_id(str(payload.get("event_id") or f"evt-{uuid.uuid4().hex[:12]}"))
        created_at = _now_iso(self.now_fn)
        normalized = [self._normalize_artifact(item) for item in artifacts]
        preview = self.product_gate.preview_submission(
            event_id=event_id,
            task_id=task_name,
            artifacts=normalized,
            source_ref=str(payload.get("source_ref") or normalized[0]["source_ref"]),
            round_number=round_id,
        )
        effective_checks = self._effective_checks(module, payload.get("enabled_optional_checks"))
        if not effective_checks:
            raise SubmissionError("GATE_POLICY_INVALID", "effective submission checks cannot be empty")
        request = {
            "schema": "ProductMaterialSubmission/v1",
            "event_id": event_id,
            "round_id": round_id,
            "task_name": task_name,
            "module": module,
            "change_summary": str(payload.get("change_summary") or "").strip(),
            "expected_delivery_at": str(payload.get("expected_delivery_at") or "").strip(),
            "policy_profile": str(payload.get("policy_profile") or f"submission-{module}/v1"),
            "enabled_optional_checks": list(payload.get("enabled_optional_checks") or []),
            "effective_checks": effective_checks,
            "created_at": created_at,
            "submitter_email": self.config["mail_account"]["email"],
            "sender_email": self.config["mail_account"]["email"],
            "artifacts": normalized,
            "preview_manifest_digest": (
                (((preview.get("submission") or {}).get("manifest_s")) or {}).get("manifest_digest")
                or preview.get("manifest_digest")
                or ""
            ),
        }
        request_digest = hashlib.sha256(canonical_json(request).encode("utf-8")).hexdigest()
        block = dict(request)
        block["contract"] = "rd.test-submission.v1"
        block["request_digest"] = request_digest
        hmac_key = str(self.environ.get("TEST_SUBMISSION_HMAC_KEY") or "").encode("utf-8")
        if not hmac_key:
            raise SubmissionError("CAPABILITY_BLOCKED", "TEST_SUBMISSION_HMAC_KEY is required")
        block["hmac_sha256"] = _machine_hmac(block, hmac_key)
        subject = f"【提测】{task_name}-{module}-{created_at[:10]}"
        body_text = self._render_body(block)
        mail_result = self.mail_gateway.send_email(
            {
                "account": self.config["mail_account"]["profile"],
                "to": [self.config["submission_gate_address"]],
                "subject": subject,
                "text": body_text,
                "dry_run": False,
                "message_id": _message_id(event_id, round_id),
                "headers": {
                    "X-RD-Contract": block["contract"],
                    "X-RD-Event-Id": event_id,
                    "X-RD-Round-Id": str(round_id),
                    "X-RD-Task": task_name,
                    "X-RD-Module": module,
                    "X-RD-Request-Digest": request_digest,
                    "X-RD-Submitter-Email": block["submitter_email"],
                    "X-RD-Manifest-Digest": block["preview_manifest_digest"],
                },
            }
        )
        refused = mail_result.get("refused") or {}
        status = "SUBMITTED" if not refused else "SEND_BLOCKED"
        event = {
            "event_id": event_id,
            "round_id": round_id,
            "module": module,
            "status": status,
            "subject": subject,
            "request": block,
            "mail": {
                "message_id": str(mail_result.get("message_id") or ""),
                "refused": refused,
            },
        }
        self._write_event(event_id, round_id, event)
        return {
            "status": status,
            "event_id": event_id,
            "round_id": round_id,
            "request_digest": request_digest,
            "preview_manifest_digest": block["preview_manifest_digest"],
            "message_id": event["mail"]["message_id"],
        }

    def run_once(self) -> dict[str, Any]:
        acquired = self.run_lock.acquire()
        if acquired.get("status") != "acquired":
            return {
                "status": "RUN_ALREADY_ACTIVE",
                "busy": True,
                "owner": acquired.get("owner"),
                "orphan_metadata": acquired.get("orphan_metadata"),
            }
        retried = 0
        sent = 0
        try:
            for event_path in sorted(self.event_store_dir.glob("*/round-*/event.json")):
                event = json.loads(event_path.read_text(encoding="utf-8"))
                if event.get("status") != "SEND_BLOCKED":
                    continue
                retried += 1
                result = self.mail_gateway.send_email(
                    {
                        "account": self.config["mail_account"]["profile"],
                        "to": [self.config["submission_gate_address"]],
                        "subject": event["subject"],
                        "text": self._render_body(event["request"]),
                        "dry_run": False,
                        "message_id": event["mail"]["message_id"],
                        "headers": {
                            "X-RD-Contract": event["request"]["contract"],
                            "X-RD-Event-Id": event["event_id"],
                            "X-RD-Round-Id": str(event["round_id"]),
                            "X-RD-Task": event["request"]["task_name"],
                            "X-RD-Module": event["module"],
                            "X-RD-Request-Digest": event["request"]["request_digest"],
                            "X-RD-Submitter-Email": event["request"]["submitter_email"],
                            "X-RD-Manifest-Digest": event["request"]["preview_manifest_digest"],
                        },
                    }
                )
                if not (result.get("refused") or {}):
                    event["status"] = "SUBMITTED"
                    sent += 1
                    self._write_event(event["event_id"], int(event["round_id"]), event)
            return {"status": "ready", "retried": retried, "sent": sent}
        finally:
            self.run_lock.release()

    def status(self) -> dict[str, Any]:
        total = 0
        pending = 0
        for event_path in self.event_store_dir.glob("*/round-*/event.json"):
            total += 1
            event = json.loads(event_path.read_text(encoding="utf-8"))
            if event.get("status") == "SEND_BLOCKED":
                pending += 1
        return {"status": "ready", "events": total, "pending_mail": pending}

    def doctor(self) -> dict[str, Any]:
        preflight = self.preflight()
        preflight["config_path"] = str(self.config_path)
        preflight["event_store_dir"] = str(self.event_store_dir)
        return preflight

    def get_event(self, *, event_id: str, round_id: int) -> dict[str, Any]:
        return {"event": self._read_event(event_id, round_id)}

    def _effective_checks(self, module: str, optional: Any) -> list[str]:
        configured = _configured_mandatory_map(self.config)
        missing = [item for item in _CANONICAL_MANDATORY[module] if item not in configured[module]]
        if missing:
            raise SubmissionError("GATE_POLICY_INVALID", f"mandatory checks drifted for {module}: {", ".join(missing)}")
        enabled_optional = [str(item).strip() for item in list(optional or []) if str(item).strip()]
        seen: list[str] = []
        for item in _CANONICAL_MANDATORY[module] + configured[module] + enabled_optional:
            if item and item not in seen:
                seen.append(item)
        return seen

    def _normalize_artifact(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise SubmissionError("INVALID_ARGUMENT", "artifact entries must be objects")
        local_path = _expand_path(str(payload.get("local_path") or payload.get("file_path") or ""))
        if not local_path.is_file():
            raise SubmissionError("ARTIFACT_UNREACHABLE", f"artifact is not reachable: {local_path}")
        logical_name = str(payload.get("logical_name") or local_path.name).strip()
        retrieval_method = str(payload.get("retrieval_method") or "").strip().lower()
        if retrieval_method not in {"local", "unc", "https", "gitlab-package", "ssh", "svn"}:
            raise SubmissionError("INVALID_ARGUMENT", "retrieval_method is unsupported")
        source_ref = str(payload.get("source_ref") or payload.get("revision") or payload.get("repository_path") or local_path.name).strip()
        return {
            "logical_name": logical_name,
            "local_path": str(local_path),
            "retrieval_method": retrieval_method,
            "server_url": str(payload.get("server_url") or ""),
            "repository_path": str(payload.get("repository_path") or ""),
            "revision": str(payload.get("revision") or ""),
            "retrieval_instructions": str(payload.get("retrieval_instructions") or ""),
            "source_ref": source_ref,
            "size": local_path.stat().st_size,
            "sha1": sha1_file(local_path),
            "sha256": sha256_file(local_path),
            "version": str(payload.get("version") or ""),
        }

    def _render_body(self, block: Mapping[str, Any]) -> str:
        summary = [
            f"任务：{block['task_name']}",
            f"模块：{block['module']}",
            f"提测人邮箱：{block.get('submitter_email') or '未提供'}",
            f"轮次：{block['round_id']}",
            f"预计交付：{block.get('expected_delivery_at') or '未填写'}",
            f"摘要：{block.get('change_summary') or '未填写'}",
            "",
            _MACHINE_BEGIN,
            json.dumps(block, ensure_ascii=False, indent=2),
            _MACHINE_END,
        ]
        return "\n".join(summary)

    def _event_dir(self, event_id: str, round_id: int) -> Path:
        return self.event_store_dir / _ensure_event_id(event_id) / f"round-{round_id}"

    def _write_event(self, event_id: str, round_id: int, event: Mapping[str, Any]) -> None:
        _write_json(self._event_dir(event_id, round_id) / "event.json", event)

    def _read_event(self, event_id: str, round_id: int) -> dict[str, Any]:
        path = self._event_dir(event_id, round_id) / "event.json"
        return json.loads(path.read_text(encoding="utf-8"))
