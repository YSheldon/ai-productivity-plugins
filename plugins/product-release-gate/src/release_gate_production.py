from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from release_gate_core import (
    GateError,
    canonical_json,
    object_digest,
    read_json,
    sha1_file,
    utc_now,
    write_json,
    write_text_file,
)
from release_gate_hardened import HardenedReleaseGateController
from release_gate_credentials import (
    CredentialProviderError,
    RuntimePrincipalProvider,
    resolve_configured_secret,
    runtime_identity_binding_status,
)
from release_gate_approval_mail import (
    ApprovalMailError,
    ImapSmtpMailCliGateway,
    LockedImapSmtpMailCliGateway,
    resolve_locked_entrypoint,
    sha256_file,
)


_VERIFIER_PLUGIN_NAME = "release-approval-verifier"
_VERIFIER_PLUGIN_ROOT = Path("plugins/release-approval-verifier")
_VERIFIER_BRIDGE_PATH = (
    _VERIFIER_PLUGIN_ROOT / "src" / "verifier_product_gate_bridge.py"
)


REQUIRED_DEPLOYMENT_STAGES = (
    "preproduction",
    "production_canary",
    "production_full",
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_NON_PRODUCTION_ADAPTER_PATH_PARTS = frozenset(
    {
        "test",
        "tests",
        "fixture",
        "fixtures",
        "mock",
        "mocks",
        "demo",
        "demos",
        "example",
        "examples",
    }
)
# Compatibility fixtures must never be executable as production adapters.
_NON_PRODUCTION_ADAPTER_PATH = re.compile(
    r"(?:^|[\\/])(?:tests?|fixtures?|compat(?:ibility)?|mocks?|stubs?|demos?|fakes?)(?:[\\/]|$)"
    r"|first[_-]?practice[_-]?adapter[_-]?compat",
    re.IGNORECASE,
)
_DEPLOYMENT_LOCKED_COMMAND_IDS = (
    ("deploy", "deploy_command"),
    ("verify", "verify_command"),
    ("rollback", "rollback_command"),
    ("rollback_verify", "rollback_verify_command"),
)


class ProductionReleaseController(HardenedReleaseGateController):
    """Fail-closed production authorization and phased deployment controller."""

    def __init__(
        self,
        config_path: str | None = None,
        *,
        approval_mail_gateway: Any | None = None,
        report_mail_gateway: Any | None = None,
        allow_unlocked_test_adapters: bool = False,
        credential_reader: Callable[[str], str | None] | None = None,
        environ: Mapping[str, str] | None = None,
        runtime_principal_provider: RuntimePrincipalProvider | None = None,
    ) -> None:
        super().__init__(config_path)
        self._approval_mail_gateway_override = approval_mail_gateway
        self._report_mail_gateway_override = (
            report_mail_gateway
            if report_mail_gateway is not None
            else approval_mail_gateway
        )
        self._allow_unlocked_test_adapters = allow_unlocked_test_adapters
        self._credential_reader = credential_reader
        self._environ = os.environ if environ is None else environ
        self._runtime_principal_provider = runtime_principal_provider

    def _production_config(self) -> dict[str, Any]:
        config = self.config.get("production")
        if not isinstance(config, dict) or not config.get("enabled"):
            raise GateError("production.enabled must be true for production operations")
        return config

    def _runtime_identity_status(self) -> dict[str, object]:
        runtime = self.config.get("runtime")
        binding = (
            runtime.get("identity_binding")
            if isinstance(runtime, Mapping)
            else None
        )
        production = self.config.get("production")
        production_enabled = bool(
            isinstance(production, Mapping)
            and production.get("enabled") is True
        )
        return runtime_identity_binding_status(
            binding,
            required=production_enabled,
            principal_provider=self._runtime_principal_provider,
        )

    def _require_runtime_identity(self) -> None:
        status = self._runtime_identity_status()
        if status["required"] is True and status["ready"] is not True:
            raise GateError(
                "production runtime identity differs from the configured binding"
            )

    def _save_event(self, event: dict[str, Any]) -> None:
        self._require_runtime_identity()
        super()._save_event(event)

    @staticmethod
    def _valid_command(value: Any) -> bool:
        return (
            isinstance(value, list)
            and bool(value)
            and all(isinstance(item, str) and bool(item) for item in value)
        )

    @classmethod
    def _valid_production_command(cls, value: Any) -> bool:
        """Validate an adapter command and reject known test-only paths."""
        if not cls._valid_command(value):
            return False
        return not any(
            _NON_PRODUCTION_ADAPTER_PATH.search(item)
            for item in value
            if isinstance(item, str)
        )

    @staticmethod
    def _deployment_targets_isolated(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        references = [
            str(value.get(stage) or "").strip()
            for stage in REQUIRED_DEPLOYMENT_STAGES
        ]
        if any(not reference for reference in references):
            return False
        normalized_references = {
            os.path.normcase(reference) for reference in references
        }
        if len(normalized_references) != len(REQUIRED_DEPLOYMENT_STAGES):
            return False

        absolute_paths = [
            Path(os.path.abspath(os.path.normpath(reference)))
            for reference in references
            if Path(reference).is_absolute()
        ]
        for index, left in enumerate(absolute_paths):
            for right in absolute_paths[index + 1 :]:
                try:
                    left.relative_to(right)
                    return False
                except ValueError:
                    pass
                try:
                    right.relative_to(left)
                    return False
                except ValueError:
                    pass
        return True

    def _resolve_signing_secret(
        self,
        config: Mapping[str, object],
        label: str,
    ) -> str:
        try:
            value, _source = resolve_configured_secret(
                config,
                environ=self._environ,
                credential_reader=self._credential_reader,
            )
        except CredentialProviderError as exc:
            raise GateError(f"{label} signing credential is unavailable") from exc
        if not value:
            key_env = str(config.get("key_env") or "").strip()
            raise GateError(
                f"{label} signing credential is missing: "
                f"{key_env or 'unconfigured'}"
            )
        return value

    def _authorization_key(self) -> bytes:
        self._require_runtime_identity()
        production = self._production_config()
        authorization = production.get("authorization") or {}
        key_env = str(authorization.get("key_env") or "").strip()
        if not key_env:
            raise GateError("production.authorization.key_env is required")
        key = self._resolve_signing_secret(authorization, "authorization")
        encoded = key.encode("utf-8")
        if len(encoded) < 32:
            raise GateError("authorization signing key must be at least 32 bytes")
        return encoded

    def _audit_key(self) -> bytes:
        self._require_runtime_identity()
        production = self._production_config()
        authorization = production.get("authorization") or {}
        audit = production.get("audit") or {}
        key_env = str(audit.get("key_env") or "").strip()
        authorization_key_env = str(authorization.get("key_env") or "").strip()
        if not key_env:
            raise GateError("production.audit.key_env is required")
        if key_env == authorization_key_env:
            raise GateError("production audit and authorization keys must use different variables")
        key = self._resolve_signing_secret(audit, "audit")
        encoded = key.encode("utf-8")
        if len(encoded) < 32:
            raise GateError("audit signing key must be at least 32 bytes")
        authorization_value = self._resolve_signing_secret(
            authorization,
            "authorization",
        )
        if authorization_value and hmac.compare_digest(
            encoded,
            authorization_value.encode("utf-8"),
        ):
            raise GateError("production audit and authorization keys must be different")
        return encoded

    @staticmethod
    def _parse_target_scope(value: Any) -> tuple[str, ...]:
        if not isinstance(value, str):
            raise GateError("target_scope must be a comma-separated stage list")
        stages = tuple(item for item in re.split(r"[\s,]+", value.strip()) if item)
        if not stages:
            raise GateError("target_scope must contain at least one deployment stage")
        if len(set(stages)) != len(stages):
            raise GateError("target_scope contains duplicate deployment stages")
        unknown = sorted(set(stages) - set(REQUIRED_DEPLOYMENT_STAGES))
        if unknown:
            raise GateError(f"target_scope contains unknown stages: {', '.join(unknown)}")
        return stages

    def _control_event_path(self, event_id: str) -> Path:
        return self._event_dir(event_id) / "control-events.jsonl"

    def _control_event_anchor_path(self, event_id: str) -> Path:
        return self._event_dir(event_id) / "control-event-anchor.json"

    def _read_control_event_anchor(self, event_id: str) -> dict[str, Any] | None:
        path = self._control_event_anchor_path(event_id)
        if not path.exists():
            return None
        anchor = read_json(path)
        if not isinstance(anchor, dict):
            raise GateError("control event anchor is invalid")
        candidate = dict(anchor)
        signature = str(candidate.pop("anchor_hmac", ""))
        expected = hmac.new(
            self._audit_key(),
            canonical_json(candidate).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        valid = (
            candidate.get("algorithm") == "HMAC-SHA256"
            and candidate.get("event_id") == event_id
            and isinstance(candidate.get("event_count"), int)
            and int(candidate["event_count"]) >= 0
            and hmac.compare_digest(signature, expected)
        )
        if not valid:
            raise GateError("control event anchor signature is invalid")
        return candidate

    def _write_control_event_anchor(
        self,
        event_id: str,
        event_count: int,
        last_hash: str | None,
    ) -> dict[str, Any]:
        anchor = {
            "schema_version": 1,
            "algorithm": "HMAC-SHA256",
            "event_id": event_id,
            "event_count": int(event_count),
            "last_hash": last_hash,
            "updated_at": utc_now(),
        }
        anchor["anchor_hmac"] = hmac.new(
            self._audit_key(),
            canonical_json(anchor).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        write_json(self._control_event_anchor_path(event_id), anchor)
        return anchor

    def verify_control_event_chain(self, event_id: str) -> dict[str, Any]:
        audit_key = self._audit_key()
        path = self._control_event_path(event_id)
        try:
            anchor = self._read_control_event_anchor(event_id)
        except GateError as exc:
            return {
                "valid": False,
                "event_count": 0,
                "error": str(exc),
                "path": str(path),
            }
        if not path.exists():
            if anchor and (anchor.get("event_count") != 0 or anchor.get("last_hash") is not None):
                return {
                    "valid": False,
                    "event_count": 0,
                    "error": "control event ledger is missing but its signed anchor is non-empty",
                    "path": str(path),
                }
            return {
                "valid": True,
                "event_count": 0,
                "last_hash": None,
                "anchor_pending": False,
                "path": str(path),
            }

        previous_hash: str | None = None
        last_record_previous_hash: str | None = None
        count = 0
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                return {
                    "valid": False,
                    "event_count": count,
                    "error": f"invalid JSON at line {line_number}: {exc}",
                    "path": str(path),
                }
            claimed_hash = str(record.pop("hash", ""))
            if record.get("hash_algorithm") != "HMAC-SHA256":
                return {
                    "valid": False,
                    "event_count": count,
                    "error": f"unsupported hash algorithm at line {line_number}",
                    "path": str(path),
                }
            expected_hash = hmac.new(
                audit_key,
                canonical_json(record).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if claimed_hash != expected_hash:
                return {
                    "valid": False,
                    "event_count": count,
                    "error": f"hash mismatch at line {line_number}",
                    "path": str(path),
                }
            if record.get("previous_hash") != previous_hash:
                return {
                    "valid": False,
                    "event_count": count,
                    "error": f"previous hash mismatch at line {line_number}",
                    "path": str(path),
                }
            last_record_previous_hash = record.get("previous_hash")
            count += 1
            if record.get("sequence") != count:
                return {
                    "valid": False,
                    "event_count": count - 1,
                    "error": f"sequence mismatch at line {line_number}",
                    "path": str(path),
                }
            previous_hash = claimed_hash
        anchor_pending = False
        if anchor is None:
            if count == 1 and last_record_previous_hash is None:
                anchor_pending = True
            elif count != 0:
                return {
                    "valid": False,
                    "event_count": count,
                    "error": "control event signed anchor is missing",
                    "path": str(path),
                }
        elif anchor.get("event_count") == count and anchor.get("last_hash") == previous_hash:
            pass
        elif (
            int(anchor.get("event_count") or 0) + 1 == count
            and anchor.get("last_hash") == last_record_previous_hash
        ):
            anchor_pending = True
        else:
            return {
                "valid": False,
                "event_count": count,
                "error": "control event ledger diverges from its signed anchor",
                "path": str(path),
            }
        return {
            "valid": True,
            "event_count": count,
            "last_hash": previous_hash,
            "anchor_pending": anchor_pending,
            "path": str(path),
        }

    def _append_control_event(
        self,
        event: dict[str, Any],
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        chain = self.verify_control_event_chain(event["event_id"])
        if not chain["valid"]:
            raise GateError(f"control event chain is invalid: {chain.get('error')}")
        if chain.get("anchor_pending"):
            self._write_control_event_anchor(
                event["event_id"],
                int(chain["event_count"]),
                chain["last_hash"],
            )
        record = {
            "sequence": int(chain["event_count"]) + 1,
            "recorded_at": utc_now(),
            "event_id": event["event_id"],
            "event_type": event_type,
            "status": event["status"],
            "manifest_s_digest": event["manifest_s_digest"],
            "manifest_r_digest": event.get("manifest_r_digest"),
            "payload": payload,
            "previous_hash": chain["last_hash"],
            "hash_algorithm": "HMAC-SHA256",
        }
        record["hash"] = hmac.new(
            self._audit_key(),
            canonical_json(record).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        path = self._control_event_path(event["event_id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")
        self._write_control_event_anchor(
            event["event_id"],
            int(record["sequence"]),
            str(record["hash"]),
        )
        return record

    def production_preflight(
        self, *, include_report_delivery: bool = True
    ) -> dict[str, Any]:
        production = self._production_config()
        authorization = production.get("authorization") or {}
        deployment = production.get("deployment") or {}
        readback = production.get("readback") or {}
        stages = deployment.get("stages") or []
        targets = deployment.get("targets") or {}
        authorization_key_env = str(authorization.get("key_env") or "").strip()
        audit = production.get("audit") or {}
        runtime_identity = self._runtime_identity_status()
        audit_key_env = str(audit.get("key_env") or "").strip()
        try:
            authorization_value = self._resolve_signing_secret(
                authorization,
                "authorization",
            )
        except GateError:
            authorization_value = ""
        try:
            audit_value = self._resolve_signing_secret(audit, "audit")
        except GateError:
            audit_value = ""
        approval_workflow = production.get("approval_workflow") or {}
        workflow_mode = str(
            approval_workflow.get("mode") or "legacy_external"
        ).strip()
        requires_external_authorization_readback = (
            workflow_mode != "unified_multi_role"
        )
        checks = [
            {
                "name": "runtime.identity_binding",
                "required": runtime_identity["required"],
                "configured": runtime_identity["ready"],
                "detail": runtime_identity,
            },
            {
                "name": "authorization_signer",
                "configured": bool(
                    authorization_key_env
                    and authorization_value
                    and len(authorization_value.encode("utf-8")) >= 32
                ),
            },
            {
                "name": "audit_signer",
                "configured": bool(
                    audit_key_env
                    and audit_key_env != authorization_key_env
                    and audit_value
                    and authorization_value
                    and not hmac.compare_digest(audit_value, authorization_value)
                    and len(audit_value.encode("utf-8")) >= 32
                    and len(authorization_value.encode("utf-8")) >= 32
                ),
            },
            {
                "name": "authorization.verify_command",
                "required": requires_external_authorization_readback,
                "configured": (
                    not requires_external_authorization_readback
                    or self._valid_production_command(authorization.get("verify_command"))
                ),
            },
            {
                "name": "policy.require_signature",
                "configured": bool((self.config.get("policy") or {}).get("require_signature")),
            },
            {
                "name": "signature.expected_thumbprints",
                "configured": bool(
                    isinstance((self.config.get("signature") or {}).get("expected_thumbprints"), list)
                    and (self.config.get("signature") or {}).get("expected_thumbprints")
                    and all(
                        isinstance(value, str)
                        and re.fullmatch(r"[0-9A-Fa-f]{40}", re.sub(r"[^0-9A-Fa-f]", "", value))
                        for value in (self.config.get("signature") or {}).get("expected_thumbprints")
                    )
                ),
            },
            {
                "name": "policy.require_cloud_scan",
                "configured": bool((self.config.get("policy") or {}).get("require_cloud_scan")),
            },
            {
                "name": "cloud_scan.command",
                "configured": self._valid_production_command(
                    (self.config.get("cloud_scan") or {}).get("command")
                ),
            },
            {
                "name": "deployment_stages",
                "configured": list(stages) == list(REQUIRED_DEPLOYMENT_STAGES),
            },
            {
                "name": "deployment.targets",
                "configured": isinstance(targets, dict)
                and all(bool(str(targets.get(stage) or "").strip()) for stage in REQUIRED_DEPLOYMENT_STAGES),
            },
            {
                "name": "deployment.targets.isolated",
                "configured": self._deployment_targets_isolated(targets),
            },
            {
                "name": "deployment.deploy_command",
                "configured": self._valid_production_command(deployment.get("deploy_command")),
            },
            {
                "name": "deployment.verify_command",
                "configured": self._valid_production_command(deployment.get("verify_command")),
            },
            {
                "name": "deployment.rollback_command",
                "configured": self._valid_production_command(deployment.get("rollback_command")),
            },
            {
                "name": "deployment.rollback_verify_command",
                "configured": self._valid_production_command(deployment.get("rollback_verify_command")),
            },
            {
                "name": "deployment.adapter_lock",
                "configured": self._deployment_adapter_lock_ready(),
            },
            {
                "name": "readback.command",
                "configured": self._valid_production_command(readback.get("command")),
            },
        ]
        runtime = self.config.get("runtime") or {}
        delivery = production.get("report_delivery") or {}
        if include_report_delivery and (
            runtime.get("auto_deliver_production_report") is True
            or (isinstance(delivery, dict) and delivery.get("enabled") is True)
        ):
            delivery_check = self._production_report_delivery_preflight()
            checks.append(
                {
                    "name": "report_delivery",
                    "configured": delivery_check["ready"],
                    "detail": delivery_check,
                }
            )
        missing = [check["name"] for check in checks if not check["configured"]]
        return {"ready": not missing, "missing_capabilities": missing, "checks": checks}

    def ensure_deployment_capabilities(self, event_id: str) -> dict[str, Any]:
        self._require_runtime_identity()
        event = self._load_event(event_id)
        allowed_statuses = {
            "RELEASE_AUTHORIZED",
            "PREPRODUCTION_VERIFIED",
            "CANARY_VERIFIED",
            "CAPABILITY_BLOCKED",
        }
        if event.get("status") not in allowed_statuses:
            raise GateError(
                f"Deployment capabilities cannot be checked from status {event.get('status')}"
            )
        preflight = self.production_preflight(include_report_delivery=False)
        if preflight["ready"]:
            if event.get("status") == "CAPABILITY_BLOCKED":
                block = event.get("capability_block") or {}
                origin = str(block.get("origin_status") or "RELEASE_AUTHORIZED")
                self._transition(event, origin, "required deployment capabilities became available")
                block["resolved_at"] = utc_now()
                event["capability_block"] = block
                self._append_control_event(event, "CAPABILITY_RESTORED", {"origin_status": origin})
                self._save_event(event)
            return {"ready": True, "status": event["status"], "missing_capabilities": []}

        prior_block = event.get("capability_block") or {}
        origin_status = str(prior_block.get("origin_status") or event.get("status"))
        request = {
            "schema_version": 1,
            "event_id": event_id,
            "origin_status": origin_status,
            "origin_manifest_r_digest": event.get("manifest_r_digest"),
            "missing_capabilities": preflight["missing_capabilities"],
            "requested_at": utc_now(),
            "required_recovery": "build, review, merge, deploy, then replay the origin checkpoint",
        }
        path = self._event_dir(event_id) / "capability-request.json"
        write_json(path, request)
        event["capability_block"] = {**request, "request_path": str(path)}
        if event.get("status") != "CAPABILITY_BLOCKED":
            self._transition(event, "CAPABILITY_BLOCKED", "required deployment capability is missing")
        self._append_control_event(event, "CAPABILITY_BLOCKED", request)
        self._save_event(event)
        return {
            "ready": False,
            "status": event["status"],
            "missing_capabilities": preflight["missing_capabilities"],
            "capability_request_path": str(path),
        }


    def _approval_workflow_config(self, required_mode: str | None = None) -> dict[str, Any]:
        production = self._production_config()
        workflow = production.get("approval_workflow") or {}
        if not isinstance(workflow, dict):
            raise GateError("production.approval_workflow must be an object")
        mode = str(workflow.get("mode") or "legacy_external").strip()
        if mode not in {"legacy_external", "unified_multi_role"}:
            raise GateError(
                "production.approval_workflow.mode must be legacy_external or unified_multi_role"
            )
        if required_mode and mode != required_mode:
            raise GateError(
                f"production.approval_workflow.mode must be {required_mode} for this operation"
            )
        return {**workflow, "mode": mode}

    def _locked_unified_verifier_command(
        self,
        workflow: dict[str, Any],
    ) -> list[str]:
        command = workflow.get("verify_command")
        if self._allow_unlocked_test_adapters:
            if not self._valid_command(command):
                raise GateError("production.approval_workflow.verify_command is required")
            return list(command)

        lock_path = str(workflow.get("dependency_lock") or "").strip()
        lock_digest = str(workflow.get("dependency_lock_sha256") or "").strip()
        verifier_config = str(workflow.get("verifier_config_path") or "").strip()
        if not lock_path or not lock_digest or not verifier_config:
            raise GateError(
                "production.approval_workflow requires dependency_lock, "
                "dependency_lock_sha256, and verifier_config_path"
            )
        try:
            bridge_path = resolve_locked_entrypoint(
                lock_path,
                dependency_lock_sha256=lock_digest,
                plugin_name=_VERIFIER_PLUGIN_NAME,
                plugin_root=_VERIFIER_PLUGIN_ROOT,
                entrypoint_path=_VERIFIER_BRIDGE_PATH,
            )
            verifier_config_path = Path(verifier_config).expanduser().resolve(strict=True)
        except (OSError, ApprovalMailError) as exc:
            raise GateError(str(exc)) from exc
        expected = [
            sys.executable,
            str(bridge_path),
            "--config",
            str(verifier_config_path),
            "--verification-ref",
            "{verification_ref}",
        ]
        if command is not None and list(command) != expected:
            raise GateError(
                "production.approval_workflow.verify_command differs from the locked verifier bridge"
            )
        return expected

    def unified_approval_preflight(self) -> dict[str, Any]:
        checks: dict[str, dict[str, Any]] = {}
        missing: list[str] = []
        try:
            workflow = self._approval_workflow_config("unified_multi_role")
            command = self._locked_unified_verifier_command(workflow)
            timeout_seconds = int(workflow.get("timeout_seconds") or 120)
            timeout_ready = 1 <= timeout_seconds <= 600
            checks["verification_adapter"] = {
                "status": "ready" if command and timeout_ready else "CAPABILITY_BLOCKED",
                "locked": not self._allow_unlocked_test_adapters,
            }
            if not timeout_ready:
                missing.append("approval_workflow.timeout_seconds")
        except (GateError, TypeError, ValueError) as exc:
            checks["verification_adapter"] = {
                "status": "CAPABILITY_BLOCKED",
                "reason": str(exc),
            }
            missing.append("approval_workflow.verifier_bridge")

        try:
            mail = self._approval_mail_config()
            gateway = self._approval_mail_gateway()
            if hasattr(gateway, "list_accounts"):
                accounts = gateway.list_accounts()
                configured_profiles = {
                    str(item.get("name") or "").strip()
                    for item in accounts
                    if isinstance(item, dict)
                }
                if mail["profile"] not in configured_profiles:
                    raise GateError(
                        "production approval mail profile was not found in the locked mail configuration"
                    )
            checks["approval_mail"] = {
                "status": "ready",
                "profile": mail["profile"],
                "release_group": mail["release_group"],
                "locked": (
                    self._approval_mail_gateway_override is None
                    and not self._allow_unlocked_test_adapters
                ),
            }
        except (GateError, TypeError, ValueError) as exc:
            checks["approval_mail"] = {
                "status": "CAPABILITY_BLOCKED",
                "reason": str(exc),
            }
            missing.append("approval_workflow.mail")

        try:
            self._audit_key()
            checks["audit_signer"] = {"status": "ready"}
        except GateError as exc:
            checks["audit_signer"] = {
                "status": "CAPABILITY_BLOCKED",
                "reason": str(exc),
            }
            missing.append("production.audit")

        missing = sorted(dict.fromkeys(missing))
        return {
            "status": "ready" if not missing else "CAPABILITY_BLOCKED",
            "ready": not missing,
            "checks": checks,
            "missing_capabilities": missing,
        }
    def _approval_mail_config(self) -> dict[str, Any]:
        workflow = self._approval_workflow_config("unified_multi_role")
        mail = workflow.get("mail") or {}
        if not isinstance(mail, dict):
            raise GateError("production.approval_workflow.mail must be an object")
        profile = str(mail.get("profile") or "").strip()
        release_group = str(mail.get("release_group") or "").strip().lower()
        module = str(mail.get("module") or "").strip()
        if not profile:
            raise GateError("production.approval_workflow.mail.profile is required")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", release_group):
            raise GateError("production.approval_workflow.mail.release_group must be an email")
        if not module or len(module) > 80 or any(ord(char) < 32 for char in module):
            raise GateError("production.approval_workflow.mail.module is required and must be safe")
        timeout_seconds = int(mail.get("timeout_seconds") or 120)
        if timeout_seconds < 1 or timeout_seconds > 600:
            raise GateError("production.approval_workflow.mail.timeout_seconds must be between 1 and 600")
        return {
            **mail,
            "profile": profile,
            "release_group": release_group,
            "module": module,
            "timeout_seconds": timeout_seconds,
        }

    def _approval_mail_gateway(self) -> Any:
        if self._approval_mail_gateway_override is not None:
            return self._approval_mail_gateway_override
        mail = self._approval_mail_config()
        try:
            if self._allow_unlocked_test_adapters:
                command = mail.get("command")
                if not self._valid_command(command):
                    raise GateError(
                        "production.approval_workflow.mail.command is required"
                    )
                return ImapSmtpMailCliGateway(
                    command,
                    timeout_seconds=int(mail["timeout_seconds"]),
                )
            return LockedImapSmtpMailCliGateway(
                str(mail.get("dependency_lock") or ""),
                dependency_lock_sha256=str(
                    mail.get("dependency_lock_sha256") or ""
                ),
                timeout_seconds=int(mail["timeout_seconds"]),
            )
        except ApprovalMailError as exc:
            raise GateError(str(exc)) from exc

    @staticmethod
    def _contract_digest(value: Any, label: str) -> str:
        text = str(value or "").strip().lower()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", text):
            return text
        if re.fullmatch(r"[0-9a-f]{64}", text):
            return "sha256:" + text
        raise GateError(f"{label} must be a SHA-256 digest")

    @staticmethod
    def _request_digest(payload: dict[str, Any]) -> str:
        digest_payload = {
            key: value for key, value in payload.items() if key != "request_digest"
        }
        encoded = json.dumps(
            digest_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _request_message_id(event_id: str, round_id: int, requester: str) -> str:
        domain = requester.rsplit("@", 1)[-1].lower()
        suffix = object_digest({"event_id": event_id, "round_id": round_id, "requester": requester})[:24]
        return f"<release-approval-{event_id}-{round_id}-{suffix}@{domain}>"

    def _send_unified_approval_request(self, request: dict[str, Any]) -> dict[str, Any]:
        mail = self._approval_mail_config()
        encoded = base64.urlsafe_b64encode(
            canonical_json(request).encode("utf-8")
        ).decode("ascii").rstrip("=")
        timestamp = str(request["requested_at"]).replace("-", "").replace(":", "")
        subject = f"【发布申请】{request['task']}-{request['module']}-{timestamp}"
        text = "\n".join(
            (
                "【发布申请】",
                f"任务：{request['task']}",
                f"模块：{request['module']}",
                f"轮次：{request['round_id']}",
                f"最终物料摘要：{request['manifest_digest']}",
                f"有效期：{request['expires_at']}",
                "",
                "-----BEGIN RELEASE APPROVAL REQUEST-----",
                encoded,
                "-----END RELEASE APPROVAL REQUEST-----",
            )
        )
        payload = {
            "account": mail["profile"],
            "to": [mail["release_group"]],
            "subject": subject,
            "text": text,
            "message_id": request["original_message_id"],
            "headers": {
                "X-RD-Contract": request["contract"],
                "X-RD-Event-Id": request["event_id"],
                "X-RD-Round-Id": str(request["round_id"]),
                "X-RD-Task": request["task"],
                "X-RD-Module": request["module"],
                "X-RD-Manifest-S-Digest": request["manifest_s_digest"],
                "X-RD-Manifest-R-Digest": request["manifest_r_digest"],
                "X-RD-Manifest-Digest": request["manifest_digest"],
                "X-RD-Request-Digest": request["request_digest"],
                "X-RD-Role-Snapshot-Digest": request["role_snapshot_digest"],
                "X-RD-Required-Roles": ",".join(request["required_roles"]),
                "X-RD-Expires-At": request["expires_at"],
            },
            "dry_run": False,
        }
        try:
            result = self._approval_mail_gateway().send_email(payload)
        except (ApprovalMailError, OSError, RuntimeError) as exc:
            raise GateError(f"approval request mail delivery failed: {exc}") from exc
        if not isinstance(result, dict):
            raise GateError("approval request mail gateway returned an invalid result")
        refused = result.get("refused")
        accepted = (
            result.get("sent") is True
            and isinstance(refused, dict)
            and not refused
            and str(result.get("message_id") or "") == request["original_message_id"]
        )
        if not accepted:
            raise GateError("SMTP delivery was not accepted with the frozen Message-ID")
        return {
            "status": "accepted",
            "message_id": request["original_message_id"],
            "refused": {},
            "accepted_at": utc_now(),
        }

    @staticmethod
    def _normalize_approval_roles(required_roles: Any) -> list[dict[str, Any]]:
        if not isinstance(required_roles, list) or not required_roles:
            raise GateError("required_roles must be a non-empty array")
        normalized: list[dict[str, Any]] = []
        seen_role_ids: set[str] = set()
        seen_emails: set[str] = set()
        for raw in required_roles:
            if not isinstance(raw, dict):
                raise GateError("each required role must be an object")
            role_id = str(raw.get("role_id") or "").strip()
            email = str(raw.get("email") or "").strip().lower()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", role_id):
                raise GateError("required role_id contains unsupported characters or length")
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                raise GateError("required role email is invalid")
            if raw.get("required") is not True:
                raise GateError("every required_roles entry must set required=true")
            if role_id in seen_role_ids or email in seen_emails:
                raise GateError("required_roles contains a duplicate role_id or email")
            seen_role_ids.add(role_id)
            seen_emails.add(email)
            normalized.append({"role_id": role_id, "email": email, "required": True})
        return sorted(normalized, key=lambda item: (item["role_id"], item["email"]))

    @staticmethod
    def _parse_approval_expiry(expires_at: Any) -> tuple[str, datetime]:
        value = str(expires_at or "").strip()
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise GateError("expires_at must be a valid ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise GateError("expires_at must include a timezone")
        normalized = parsed.astimezone(timezone.utc).replace(microsecond=0)
        if normalized <= datetime.now(timezone.utc):
            raise GateError("expires_at must be in the future")
        return normalized.isoformat().replace("+00:00", "Z"), normalized

    def request_unified_release_approval(
        self,
        event_id: str,
        requested_by: str,
        target_scope: str,
        round_id: int,
        required_roles: list[dict[str, Any]],
        role_snapshot_digest: str,
        expires_at: str,
    ) -> dict[str, Any]:
        self._require_runtime_identity()
        self._approval_workflow_config("unified_multi_role")
        event = self._load_event(event_id)
        requester = str(requested_by or "").strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", requester):
            raise GateError("requested_by must be an email address")
        if not isinstance(round_id, int) or isinstance(round_id, bool) or round_id < 1:
            raise GateError("round_id must be a positive integer")

        role_digest = self._contract_digest(role_snapshot_digest, "role_snapshot_digest")
        normalized_scope = ",".join(self._parse_target_scope(target_scope))
        role_bindings = self._normalize_approval_roles(required_roles)
        role_ids = [binding["role_id"] for binding in role_bindings]
        normalized_expiry, _expiry = self._parse_approval_expiry(expires_at)
        mail = self._approval_mail_config()
        task = str(event.get("task_id") or "").strip()
        if not task:
            raise GateError("release event task_id is required")

        manifest_s_digest = self._contract_digest(
            event.get("manifest_s_digest"), "manifest_s_digest"
        )
        manifest_r_digest = self._contract_digest(
            event.get("manifest_r_digest"), "manifest_r_digest"
        )
        manifest_digest = "sha256:" + object_digest(
            {
                "manifest_s_digest": manifest_s_digest,
                "manifest_r_digest": manifest_r_digest,
            }
        )
        request_base = {
            "contract": "ReleaseAuthorizationRequest/v1",
            "schema": "ReleaseAuthorizationRequest/v1",
            "event_id": event_id,
            "round_id": round_id,
            "requested_by": requester,
            "target_scope": normalized_scope,
            "task_id": task,
            "task": task,
            "module": mail["module"],
            "source_ref": event.get("source_ref"),
            "risk_level": event.get("risk_level"),
            "manifest_s_digest": manifest_s_digest,
            "manifest_r_digest": manifest_r_digest,
            "manifest_digest": manifest_digest,
            "role_snapshot_digest": role_digest,
            "required_roles": role_ids,
            "required_role_bindings": role_bindings,
            "original_message_id": self._request_message_id(event_id, round_id, requester),
            "references": [],
            "expires_at": normalized_expiry,
            "idempotency_key": f"release-approval:{event_id}:{round_id}",
        }
        path = self._event_dir(event_id) / "release-approval-request.json"
        existing = read_json(path) if path.is_file() else None
        if isinstance(existing, dict):
            same_request = all(
                existing.get(key) == value for key, value in request_base.items()
            )
            existing_valid = existing.get("request_digest") == self._request_digest(existing)
            if same_request and not existing_valid:
                raise GateError("persisted unified approval request digest is invalid")
            if same_request and event.get("status") == "APPROVAL_COLLECTING":
                delivery = (event.get("unified_release_approval") or {}).get("delivery")
                if not isinstance(delivery, dict) or delivery.get("status") != "accepted":
                    raise GateError(
                        "approval collection state has no accepted mail delivery evidence"
                    )
                return {
                    "status": event["status"],
                    "request_path": str(path),
                    "request": existing,
                    "delivery": delivery,
                    "idempotent": True,
                }
            if existing.get("round_id") == round_id and not same_request:
                raise GateError("frozen unified approval fields changed; create a new round")
            if same_request:
                request = existing
            else:
                request = {**request_base, "requested_at": utc_now()}
                request["request_digest"] = self._request_digest(request)
        else:
            request = {**request_base, "requested_at": utc_now()}
            request["request_digest"] = self._request_digest(request)

        if event.get("status") != "RELEASE_READY":
            raise GateError(
                f"Unified release approval cannot be requested from status {event.get('status')}"
            )
        write_json(path, request)
        event["unified_release_approval"] = {
            "status": "DELIVERY_PENDING",
            "request_path": str(path),
            **request,
        }
        self._save_event(event)
        try:
            delivery = self._send_unified_approval_request(request)
        except GateError as exc:
            event = self._load_event(event_id)
            event["unified_release_approval"] = {
                **(event.get("unified_release_approval") or {}),
                "status": "DELIVERY_FAILED",
                "delivery": {
                    "status": "failed",
                    "error": str(exc),
                    "failed_at": utc_now(),
                },
            }
            self._save_event(event)
            raise

        event["unified_release_approval"] = {
            "status": "APPROVAL_COLLECTING",
            "request_path": str(path),
            **request,
            "delivery": delivery,
        }
        self._transition(
            event,
            "APPROVAL_COLLECTING",
            "release gate passed and frozen multi-role approval is collecting",
        )
        self._append_control_event(event, "UNIFIED_RELEASE_APPROVAL_REQUESTED", request)
        self._save_event(event)
        return {
            "status": event["status"],
            "request_path": str(path),
            "request": request,
            "delivery": delivery,
            "idempotent": False,
        }
    def _signed_unified_approval_request(self, event: dict[str, Any]) -> dict[str, Any]:
        chain = self.verify_control_event_chain(event["event_id"])
        if not chain["valid"]:
            raise GateError(f"control event chain is invalid: {chain.get('error')}")
        request: dict[str, Any] | None = None
        path = self._control_event_path(event["event_id"])
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("event_type") == "UNIFIED_RELEASE_APPROVAL_REQUESTED":
                    payload = record.get("payload")
                    if isinstance(payload, dict):
                        request = payload
        if request is None:
            raise GateError("signed unified release approval request is missing")

        persisted_path = self._event_dir(event["event_id"]) / "release-approval-request.json"
        persisted = read_json(persisted_path)
        if persisted != request:
            raise GateError(
                "persisted unified release approval request differs from the signed request"
            )

        expected_manifest_s = self._contract_digest(
            event.get("manifest_s_digest"), "manifest_s_digest"
        )
        expected_manifest_r = self._contract_digest(
            event.get("manifest_r_digest"), "manifest_r_digest"
        )
        expected_manifest = "sha256:" + object_digest(
            {
                "manifest_s_digest": expected_manifest_s,
                "manifest_r_digest": expected_manifest_r,
            }
        )
        expected_message_id = self._request_message_id(
            event["event_id"], int(request.get("round_id") or 0), str(request.get("requested_by") or "")
        )
        delivery = (event.get("unified_release_approval") or {}).get("delivery")
        valid = (
            request.get("contract") == "ReleaseAuthorizationRequest/v1"
            and request.get("schema") == "ReleaseAuthorizationRequest/v1"
            and request.get("event_id") == event.get("event_id")
            and request.get("task") == event.get("task_id")
            and request.get("task_id") == event.get("task_id")
            and request.get("manifest_s_digest") == expected_manifest_s
            and request.get("manifest_r_digest") == expected_manifest_r
            and request.get("manifest_digest") == expected_manifest
            and request.get("original_message_id") == expected_message_id
            and request.get("references") == []
            and request.get("request_digest") == self._request_digest(request)
            and isinstance(delivery, dict)
            and delivery.get("status") == "accepted"
            and delivery.get("message_id") == request.get("original_message_id")
            and delivery.get("refused") == {}
        )
        if not valid:
            raise GateError(
                "signed unified release approval request is not bound to the current event"
            )
        return request
    @staticmethod
    def _normalized_timestamp(value: Any, label: str) -> tuple[str, datetime]:
        text = str(value or "").strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise GateError(f"{label} must be a valid ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise GateError(f"{label} must include a timezone")
        normalized = parsed.astimezone(timezone.utc).replace(microsecond=0)
        return normalized.isoformat().replace("+00:00", "Z"), normalized

    def _verify_unified_receipt(
        self,
        *,
        workflow: dict[str, Any],
        event: dict[str, Any],
        request: dict[str, Any],
        reference: str,
        normalized_expiry: str,
    ) -> dict[str, Any]:
        timeout_seconds = int(workflow.get("timeout_seconds") or 120)
        if timeout_seconds < 1 or timeout_seconds > 600:
            raise GateError(
                "production.approval_workflow.timeout_seconds must be between 1 and 600"
            )
        payload, error = self._run_json_adapter(
            self._locked_unified_verifier_command(workflow),
            {
                "verification_ref": reference,
                "event_id": str(event["event_id"]),
                "round_id": str(request["round_id"]),
                "manifest_s_digest": str(request["manifest_s_digest"]),
                "manifest_r_digest": str(request["manifest_r_digest"]),
                "role_snapshot_digest": str(request["role_snapshot_digest"]),
                "target_scope": str(request["target_scope"]),
                "expires_at": normalized_expiry,
                "request_digest": str(request["request_digest"]),
            },
            timeout_seconds,
        )
        aggregate_status = str(
            (payload or {}).get("aggregate_status") or ""
        ).strip().upper()
        allowed_statuses = {
            "APPROVAL_VERIFIED",
            "APPROVAL_PAUSED",
            "APPROVAL_REJECTED",
        }
        evidence_ref = str((payload or {}).get("evidence_ref") or "").strip()
        payload_expiry = ""
        try:
            payload_expiry, _payload_expiry_value = self._normalized_timestamp(
                (payload or {}).get("expires_at"),
                "verifier expires_at",
            )
        except GateError:
            payload_expiry = ""
        valid = (
            payload is not None
            and aggregate_status in allowed_statuses
            and payload.get("verification_ref") == reference
            and payload.get("event_id") == event["event_id"]
            and payload.get("round_id") == request["round_id"]
            and payload.get("manifest_s_digest") == request["manifest_s_digest"]
            and payload.get("manifest_r_digest") == request["manifest_r_digest"]
            and payload.get("role_snapshot_digest")
            == request["role_snapshot_digest"]
            and payload.get("target_scope") == request["target_scope"]
            and payload_expiry == normalized_expiry
            and bool(evidence_ref)
        )
        if not valid:
            detail = error or (
                "verifier receipt is not bound to the event, round, manifests, "
                "role snapshot, scope, evidence, and expiry"
            )
            raise GateError(
                f"unified approval verification is not bound: {detail}"
            )
        return payload

    def record_unified_release_approval(
        self,
        event_id: str,
        verification_ref: str,
    ) -> dict[str, Any]:
        self._require_runtime_identity()
        workflow = self._approval_workflow_config("unified_multi_role")
        event = self._load_event(event_id)
        reference = str(verification_ref or "").strip()
        if not reference:
            raise GateError("verification_ref is required")

        handoff_path = self._event_dir(event_id) / "pre-release-request.json"
        if event.get("status") == "PRE_RELEASE_REQUESTED":
            handoff = read_json(handoff_path)
            if (
                isinstance(handoff, dict)
                and handoff.get("verification_ref") == reference
                and handoff.get("event_id") == event_id
                and handoff.get("manifest_s_digest")
                == self._contract_digest(event.get("manifest_s_digest"), "manifest_s_digest")
                and handoff.get("manifest_r_digest")
                == self._contract_digest(event.get("manifest_r_digest"), "manifest_r_digest")
            ):
                return {
                    "status": event["status"],
                    "pre_release_request_path": str(handoff_path),
                    "pre_release_request": handoff,
                    "idempotent": True,
                }
            raise GateError("a different unified approval receipt was already recorded")
        if event.get("status") not in {"APPROVAL_COLLECTING", "APPROVAL_PAUSED"}:
            raise GateError(
                f"Unified release approval cannot be recorded from status {event.get('status')}"
            )
        if (self._event_dir(event_id) / "release-authorization.json").exists():
            raise GateError("unified approval cannot proceed when an authorization credential exists")

        request = self._signed_unified_approval_request(event)
        normalized_expiry, expiry = self._normalized_timestamp(
            request.get("expires_at"), "request expires_at"
        )
        if datetime.now(timezone.utc) >= expiry:
            event["unified_release_approval"] = {
                **(event.get("unified_release_approval") or {}),
                "status": "APPROVAL_EXPIRED",
                "expired_at": utc_now(),
            }
            self._transition(event, "APPROVAL_EXPIRED", "unified approval request expired")
            self._append_control_event(
                event,
                "UNIFIED_RELEASE_APPROVAL_EXPIRED",
                {"round_id": request["round_id"], "expires_at": normalized_expiry},
            )
            self._save_event(event)
            return {"status": event["status"], "idempotent": False}

        payload = self._verify_unified_receipt(
            workflow=workflow,
            event=event,
            request=request,
            reference=reference,
            normalized_expiry=normalized_expiry,
        )
        aggregate_status = str(payload["aggregate_status"]).strip().upper()
        evidence_ref = str(payload["evidence_ref"]).strip()

        prior = event.get("unified_release_approval") or {}
        if (
            event.get("status") == aggregate_status
            and prior.get("verification_ref") == reference
            and prior.get("evidence_ref") == evidence_ref
        ):
            return {"status": event["status"], "verification": payload, "idempotent": True}

        event["unified_release_approval"] = {
            **prior,
            "status": aggregate_status,
            "verification_ref": reference,
            "evidence_ref": evidence_ref,
            "verified_at": utc_now(),
        }
        if aggregate_status != "APPROVAL_VERIFIED":
            self._transition(
                event,
                aggregate_status,
                "independent verifier did not authorize a pre-release handoff",
            )
            self._append_control_event(
                event,
                f"UNIFIED_RELEASE_{aggregate_status}",
                {
                    "round_id": request["round_id"],
                    "verification_ref": reference,
                    "evidence_ref": evidence_ref,
                },
            )
            self._save_event(event)
            return {
                "status": event["status"],
                "verification": payload,
                "idempotent": False,
            }

        handoff = {
            "schema": "PreReleaseRequest/v1",
            "event_id": event_id,
            "round_id": request["round_id"],
            "target_scope": request["target_scope"],
            "manifest_s_digest": request["manifest_s_digest"],
            "manifest_r_digest": request["manifest_r_digest"],
            "role_snapshot_digest": request["role_snapshot_digest"],
            "request_digest": request["request_digest"],
            "verification_ref": reference,
            "evidence_ref": evidence_ref,
            "expires_at": normalized_expiry,
            "requested_at": utc_now(),
        }
        handoff["handoff_digest"] = object_digest(handoff)
        write_json(handoff_path, handoff)
        event["unified_release_approval"]["pre_release_request_path"] = str(handoff_path)
        event["unified_release_approval"]["pre_release_request_digest"] = object_digest(handoff)
        self._transition(
            event,
            "PRE_RELEASE_REQUESTED",
            "independent multi-role approval verified for pre-release handoff",
        )
        self._append_control_event(
            event,
            "UNIFIED_RELEASE_APPROVAL_VERIFIED",
            {
                "round_id": request["round_id"],
                "verification_ref": reference,
                "evidence_ref": evidence_ref,
            },
        )
        self._append_control_event(event, "PRE_RELEASE_REQUESTED", handoff)
        self._save_event(event)
        return {
            "status": event["status"],
            "pre_release_request_path": str(handoff_path),
            "pre_release_request": handoff,
            "idempotent": False,
        }

    def _verified_pre_release_handoff(
        self,
        event: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        request = self._signed_unified_approval_request(event)
        approval = event.get("unified_release_approval") or {}
        handoff_path = Path(
            str(
                approval.get("pre_release_request_path")
                or self._event_dir(event["event_id"]) / "pre-release-request.json"
            )
        )
        handoff = read_json(handoff_path)
        if not isinstance(handoff, dict):
            raise GateError("pre-release handoff is missing")
        claimed_handoff_digest = str(handoff.get("handoff_digest") or "")
        unsigned_handoff = {
            key: value for key, value in handoff.items() if key != "handoff_digest"
        }
        valid = (
            handoff.get("schema") == "PreReleaseRequest/v1"
            and handoff.get("event_id") == event.get("event_id")
            and handoff.get("round_id") == request.get("round_id")
            and handoff.get("manifest_s_digest")
            == request.get("manifest_s_digest")
            and handoff.get("manifest_r_digest")
            == request.get("manifest_r_digest")
            and handoff.get("role_snapshot_digest")
            == request.get("role_snapshot_digest")
            and handoff.get("request_digest") == request.get("request_digest")
            and handoff.get("verification_ref")
            == approval.get("verification_ref")
            and handoff.get("evidence_ref") == approval.get("evidence_ref")
            and claimed_handoff_digest == object_digest(unsigned_handoff)
            and approval.get("pre_release_request_digest")
            == object_digest(handoff)
        )
        if not valid:
            raise GateError(
                "pre-release handoff is not bound to the verified approval request"
            )
        return handoff, request

    def request_release_authorization(
        self,
        event_id: str,
        requested_by: str,
        target_scope: str,
    ) -> dict[str, Any]:
        self._require_runtime_identity()
        event = self._load_event(event_id)
        if event.get("status") == "RELEASE_AUTHORIZATION_REQUIRED":
            existing = self._signed_authorization_request(event)
            normalized_scope = ",".join(self._parse_target_scope(target_scope))
            if (
                existing.get("requested_by") == str(requested_by or "").strip()
                and existing.get("target_scope") == normalized_scope
            ):
                return {
                    "status": event["status"],
                    "request_path": str(
                        (event.get("release_authorization") or {}).get(
                            "request_path"
                        )
                    ),
                    "request": existing,
                    "idempotent": True,
                }
            raise GateError("a different release authorization request already exists")
        if event.get("status") not in {
            "RELEASE_READY",
            "PRE_RELEASE_REQUESTED",
        }:
            raise GateError(
                f"Release authorization cannot be requested from status {event.get('status')}"
            )
        requester = str(requested_by or "").strip()
        if not requester or not str(target_scope or "").strip():
            raise GateError("requested_by and target_scope are required")
        normalized_scope = ",".join(self._parse_target_scope(target_scope))
        upstream: dict[str, Any] = {
            "authorization_source": "legacy_external",
        }
        if event.get("status") == "PRE_RELEASE_REQUESTED":
            handoff, unified_request = self._verified_pre_release_handoff(event)
            expected_scope = ",".join(
                self._parse_target_scope(unified_request.get("target_scope"))
            )
            if normalized_scope != expected_scope:
                raise GateError(
                    "release authorization scope differs from the verified pre-release handoff"
                )
            normalized_expiry, expiry = self._normalized_timestamp(
                unified_request.get("expires_at"),
                "request expires_at",
            )
            if datetime.now(timezone.utc) >= expiry:
                raise GateError(
                    "verified pre-release handoff expired before authorization"
                )
            workflow = self._approval_workflow_config("unified_multi_role")
            verification = self._verify_unified_receipt(
                workflow=workflow,
                event=event,
                request=unified_request,
                reference=str(handoff["verification_ref"]),
                normalized_expiry=normalized_expiry,
            )
            if (
                str(verification.get("aggregate_status") or "").strip().upper()
                != "APPROVAL_VERIFIED"
            ):
                raise GateError(
                    "latest independent verifier state does not permit authorization"
                )
            upstream = {
                "authorization_source": "unified_multi_role_receipt",
                "round_id": unified_request["round_id"],
                "request_digest": unified_request["request_digest"],
                "role_snapshot_digest": unified_request[
                    "role_snapshot_digest"
                ],
                "verification_ref": handoff["verification_ref"],
                "approval_evidence_ref": verification["evidence_ref"],
                "pre_release_handoff_digest": object_digest(handoff),
            }

        request = {
            "schema_version": 2,
            "event_id": event_id,
            "requested_by": requester,
            "target_scope": normalized_scope,
            "source_ref": event.get("source_ref"),
            "risk_level": event.get("risk_level"),
            "manifest_s_digest": event["manifest_s_digest"],
            "manifest_r_digest": event.get("manifest_r_digest"),
            **upstream,
            "requested_at": utc_now(),
        }
        path = self._event_dir(event_id) / "release-authorization-request.json"
        write_json(path, request)
        event["release_authorization"] = {
            "status": "PENDING",
            "request_path": str(path),
            **request,
        }
        self._transition(
            event,
            "RELEASE_AUTHORIZATION_REQUIRED",
            "independent release authorization is required",
        )
        self._append_control_event(
            event,
            "RELEASE_AUTHORIZATION_REQUESTED",
            request,
        )
        self._save_event(event)
        return {
            "status": event["status"],
            "request_path": str(path),
            "request": request,
            "idempotent": False,
        }

    def _signed_authorization_request(self, event: dict[str, Any]) -> dict[str, Any]:
        chain = self.verify_control_event_chain(event["event_id"])
        if not chain["valid"]:
            raise GateError(f"control event chain is invalid: {chain.get('error')}")
        request: dict[str, Any] | None = None
        path = self._control_event_path(event["event_id"])
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("event_type") == "RELEASE_AUTHORIZATION_REQUESTED":
                payload = record.get("payload")
                if isinstance(payload, dict):
                    request = payload
        if request is None:
            raise GateError("signed release authorization request is missing")
        if (
            request.get("event_id") != event.get("event_id")
            or request.get("manifest_s_digest") != event.get("manifest_s_digest")
            or request.get("manifest_r_digest") != event.get("manifest_r_digest")
        ):
            raise GateError(
                "signed release authorization request does not match the current event"
            )
        if request.get("authorization_source") == "unified_multi_role_receipt":
            handoff, unified_request = self._verified_pre_release_handoff(event)
            expected_scope = ",".join(
                self._parse_target_scope(unified_request.get("target_scope"))
            )
            valid = (
                request.get("target_scope") == expected_scope
                and request.get("round_id") == unified_request.get("round_id")
                and request.get("request_digest")
                == unified_request.get("request_digest")
                and request.get("role_snapshot_digest")
                == unified_request.get("role_snapshot_digest")
                and request.get("verification_ref")
                == handoff.get("verification_ref")
                and request.get("pre_release_handoff_digest")
                == object_digest(handoff)
            )
            if not valid:
                raise GateError(
                    "signed release authorization request is not bound to the pre-release handoff"
                )
        return request

    def record_release_authorization(
        self,
        event_id: str,
        decision: str,
        approval_ref: str,
        approved_by: str,
        manifest_s_digest: str,
        manifest_r_digest: str,
    ) -> dict[str, Any]:
        self._require_runtime_identity()
        event = self._load_event(event_id)
        if event.get("status") != "RELEASE_AUTHORIZATION_REQUIRED":
            raise GateError(
                f"Release authorization cannot be recorded from status {event.get('status')}"
            )
        normalized = str(decision or "").strip().upper()
        if normalized not in {"APPROVE", "REJECT"}:
            raise GateError("decision must be APPROVE or REJECT")
        if not str(approval_ref or "").strip() or not str(approved_by or "").strip():
            raise GateError("approval_ref and approved_by are required")
        if manifest_s_digest != event.get("manifest_s_digest"):
            raise GateError("approval Manifest-S digest does not match the current event")
        if manifest_r_digest != event.get("manifest_r_digest"):
            raise GateError("approval Manifest-R digest does not match the current event")
        signed_request = self._signed_authorization_request(event)
        requested_scope = ",".join(
            self._parse_target_scope(signed_request.get("target_scope"))
        )

        production = self._production_config()
        authorization_config = production.get("authorization") or {}
        approval_payload, approval_error = self._run_json_adapter(
            authorization_config.get("verify_command"),
            {
                "event_id": event_id,
                "decision": normalized,
                "approval_ref": str(approval_ref).strip(),
                "approved_by": str(approved_by).strip(),
                "manifest_s_digest": str(event["manifest_s_digest"]),
                "manifest_r_digest": str(event["manifest_r_digest"]),
                "target_scope": requested_scope,
            },
            int(authorization_config.get("timeout_seconds") or 120),
        )
        approval_valid = (
            approval_payload is not None
            and str(approval_payload.get("result") or "").strip().upper() == normalized
            and approval_payload.get("approval_ref") == str(approval_ref).strip()
            and approval_payload.get("approved_by") == str(approved_by).strip()
            and approval_payload.get("manifest_s_digest") == event["manifest_s_digest"]
            and approval_payload.get("manifest_r_digest") == event["manifest_r_digest"]
            and approval_payload.get("target_scope") == requested_scope
            and bool(str(approval_payload.get("evidence_ref") or "").strip())
        )
        if not approval_valid:
            detail = approval_error or (
                "approval readback is not bound to the current decision, manifests, and target scope"
            )
            raise GateError(f"release authorization verification failed: {detail}")
        approval_evidence_ref = str(approval_payload["evidence_ref"]).strip()

        if normalized == "REJECT":
            event["release_authorization"] = {
                **(event.get("release_authorization") or {}),
                **signed_request,
                "target_scope": requested_scope,
                "status": "REJECTED",
                "approval_ref": str(approval_ref).strip(),
                "approved_by": str(approved_by).strip(),
                "approval_evidence_ref": approval_evidence_ref,
                "recorded_at": utc_now(),
            }
            self._transition(event, "RELEASE_BLOCKED", "production authorization was rejected")
            self._append_control_event(
                event,
                "RELEASE_AUTHORIZATION_REJECTED",
                {"approval_ref": str(approval_ref).strip(), "approved_by": str(approved_by).strip()},
            )
            self._save_event(event)
            return {"status": event["status"], "authorization": event["release_authorization"]}

        return self._issue_release_authorization(
            event=event,
            signed_request=signed_request,
            approval_ref=str(approval_ref).strip(),
            approved_by=str(approved_by).strip(),
            approval_evidence_ref=approval_evidence_ref,
            authorization_config=authorization_config,
        )

    def finalize_verified_release_authorization(
        self,
        event_id: str,
    ) -> dict[str, Any]:
        self._require_runtime_identity()
        event = self._load_event(event_id)
        if event.get("status") == "RELEASE_AUTHORIZED":
            credential = self._verify_authorization_credential(event)
            return {
                "status": event["status"],
                "authorization": event["release_authorization"],
                "credential_path": str(
                    event["release_authorization"]["credential_path"]
                ),
                "credential": credential,
                "idempotent": True,
            }
        if event.get("status") != "RELEASE_AUTHORIZATION_REQUIRED":
            raise GateError(
                "Verified release authorization cannot be finalized from "
                f"status {event.get('status')}"
            )
        signed_request = self._signed_authorization_request(event)
        if (
            signed_request.get("authorization_source")
            != "unified_multi_role_receipt"
        ):
            raise GateError(
                "automatic finalization requires a unified multi-role receipt"
            )
        handoff, unified_request = self._verified_pre_release_handoff(event)
        normalized_expiry, expiry = self._normalized_timestamp(
            unified_request.get("expires_at"),
            "request expires_at",
        )
        if datetime.now(timezone.utc) >= expiry:
            raise GateError(
                "verified pre-release handoff expired before credential issuance"
            )
        workflow = self._approval_workflow_config("unified_multi_role")
        verification = self._verify_unified_receipt(
            workflow=workflow,
            event=event,
            request=unified_request,
            reference=str(handoff["verification_ref"]),
            normalized_expiry=normalized_expiry,
        )
        aggregate_status = str(
            verification.get("aggregate_status") or ""
        ).strip().upper()
        if aggregate_status != "APPROVAL_VERIFIED":
            event["release_authorization"] = {
                **(event.get("release_authorization") or {}),
                "status": "BLOCKED",
                "latest_aggregate_status": aggregate_status,
                "blocked_at": utc_now(),
            }
            self._transition(
                event,
                "RELEASE_BLOCKED",
                "latest independent verifier state revoked release authorization",
            )
            self._append_control_event(
                event,
                "RELEASE_AUTHORIZATION_BLOCKED",
                {
                    "aggregate_status": aggregate_status,
                    "verification_ref": handoff["verification_ref"],
                    "evidence_ref": verification["evidence_ref"],
                },
            )
            self._save_event(event)
            return {
                "status": event["status"],
                "authorization": event["release_authorization"],
                "verification": verification,
                "idempotent": False,
            }
        authorization_config = self._production_config().get(
            "authorization"
        ) or {}
        return self._issue_release_authorization(
            event=event,
            signed_request=signed_request,
            approval_ref=str(handoff["verification_ref"]),
            approved_by="release-approval-verifier",
            approval_evidence_ref=str(verification["evidence_ref"]),
            authorization_config=authorization_config,
        )

    def _issue_release_authorization(
        self,
        *,
        event: dict[str, Any],
        signed_request: dict[str, Any],
        approval_ref: str,
        approved_by: str,
        approval_evidence_ref: str,
        authorization_config: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_runtime_identity()
        ttl_seconds = int(authorization_config.get("ttl_seconds") or 3600)
        if ttl_seconds < 60 or ttl_seconds > 86400:
            raise GateError(
                "authorization ttl_seconds must be between 60 and 86400"
            )
        issued = datetime.now(timezone.utc).replace(microsecond=0)
        expires = issued + timedelta(seconds=ttl_seconds)
        requested_scope = ",".join(
            self._parse_target_scope(signed_request.get("target_scope"))
        )
        request = {
            **(event.get("release_authorization") or {}),
            **signed_request,
            "target_scope": requested_scope,
        }
        claims = {
            "credential_id": f"auth-{secrets.token_hex(8)}",
            "event_id": event["event_id"],
            "approval_ref": approval_ref,
            "approved_by": approved_by,
            "approval_evidence_ref": approval_evidence_ref,
            "manifest_s_digest": event["manifest_s_digest"],
            "manifest_r_digest": event["manifest_r_digest"],
            "target_scope": requested_scope,
            "issued_at": issued.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
        }
        for key in (
            "authorization_source",
            "round_id",
            "request_digest",
            "role_snapshot_digest",
            "verification_ref",
            "pre_release_handoff_digest",
        ):
            if key in signed_request:
                claims[key] = signed_request[key]
        signature = hmac.new(
            self._authorization_key(),
            canonical_json(claims).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        credential = {
            "schema_version": (
                2
                if signed_request.get("authorization_source")
                == "unified_multi_role_receipt"
                else 1
            ),
            "algorithm": "HMAC-SHA256",
            "claims": claims,
            "signature": signature,
        }
        event_id = str(event["event_id"])
        credential_path = (
            self._event_dir(event_id) / "release-authorization.json"
        )
        write_json(credential_path, credential)
        event["release_authorization"] = {
            **request,
            "status": "APPROVED",
            "approval_ref": approval_ref,
            "approved_by": approved_by,
            "approval_evidence_ref": approval_evidence_ref,
            "credential_path": str(credential_path),
            "credential_digest": object_digest(credential),
            "issued_at": claims["issued_at"],
            "expires_at": claims["expires_at"],
        }
        event["deployment"] = {
            "stages": {
                "test": {
                    "result": "PASS",
                    "evidence_ref": (event.get("test") or {}).get("report_ref"),
                    "manifest_s_digest": event["manifest_s_digest"],
                },
                **{
                    stage: {
                        "result": "PENDING",
                        "manifest_r_digest": event["manifest_r_digest"],
                    }
                    for stage in REQUIRED_DEPLOYMENT_STAGES
                },
            }
        }
        self._transition(
            event,
            "RELEASE_AUTHORIZED",
            "bound production authorization recorded",
        )
        self._append_control_event(
            event,
            "RELEASE_AUTHORIZED",
            {
                "approval_ref": approval_ref,
                "credential_digest": event["release_authorization"][
                    "credential_digest"
                ],
                "target_scope": claims["target_scope"],
                "authorization_source": claims.get(
                    "authorization_source",
                    "legacy_external",
                ),
            },
        )
        self._save_event(event)
        return {
            "status": event["status"],
            "authorization": event["release_authorization"],
            "credential_path": str(credential_path),
            "idempotent": False,
        }
    def _verify_authorization_credential(self, event: dict[str, Any]) -> dict[str, Any]:
        authorization = event.get("release_authorization") or {}
        if authorization.get("status") != "APPROVED":
            raise GateError("release authorization credential is not active")
        path = Path(str(authorization.get("credential_path") or ""))
        credential = read_json(path)
        if not isinstance(credential, dict) or not isinstance(credential.get("claims"), dict):
            raise GateError("release authorization credential is invalid")
        claims = credential["claims"]
        expected = hmac.new(
            self._authorization_key(),
            canonical_json(claims).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(str(credential.get("signature") or ""), expected):
            raise GateError("release authorization credential signature is invalid")
        if claims.get("event_id") != event.get("event_id"):
            raise GateError("release authorization credential event binding is invalid")
        if claims.get("manifest_s_digest") != event.get("manifest_s_digest"):
            raise GateError("release authorization credential Manifest-S binding is invalid")
        if claims.get("manifest_r_digest") != event.get("manifest_r_digest"):
            raise GateError("release authorization credential Manifest-R binding is invalid")
        expires_text = str(claims.get("expires_at") or "").replace("Z", "+00:00")
        try:
            expires = datetime.fromisoformat(expires_text)
        except ValueError as exc:
            raise GateError("release authorization credential expiry is invalid") from exc
        if datetime.now(timezone.utc) >= expires:
            raise GateError("release authorization credential has expired")
        return credential


    def _revalidate_unified_approval_for_deployment(
        self,
        event: dict[str, Any],
        credential: dict[str, Any],
        stage: str,
    ) -> dict[str, Any] | None:
        claims = credential.get("claims") or {}
        if (
            credential.get("schema_version") != 2
            or claims.get("authorization_source")
            != "unified_multi_role_receipt"
        ):
            return None

        handoff, request = self._verified_pre_release_handoff(event)
        valid = (
            claims.get("round_id") == request.get("round_id")
            and claims.get("request_digest") == request.get("request_digest")
            and claims.get("role_snapshot_digest")
            == request.get("role_snapshot_digest")
            and claims.get("verification_ref")
            == handoff.get("verification_ref")
            and claims.get("pre_release_handoff_digest")
            == object_digest(handoff)
        )
        if not valid:
            raise GateError(
                "release authorization credential is not bound to the current "
                "unified approval handoff"
            )

        normalized_expiry, expiry = self._normalized_timestamp(
            request.get("expires_at"),
            "request expires_at",
        )
        if datetime.now(timezone.utc) >= expiry:
            self._revoke_authorization_after_approval_change(
                event,
                stage=stage,
                aggregate_status="APPROVAL_EXPIRED",
                verification_ref=str(handoff["verification_ref"]),
                evidence_ref="",
            )
            raise GateError(
                "deployment blocked because approval is no longer verified"
            )

        verification = self._verify_unified_receipt(
            workflow=self._approval_workflow_config("unified_multi_role"),
            event=event,
            request=request,
            reference=str(handoff["verification_ref"]),
            normalized_expiry=normalized_expiry,
        )
        aggregate_status = str(
            verification.get("aggregate_status") or ""
        ).strip().upper()
        if aggregate_status != "APPROVAL_VERIFIED":
            self._revoke_authorization_after_approval_change(
                event,
                stage=stage,
                aggregate_status=aggregate_status,
                verification_ref=str(handoff["verification_ref"]),
                evidence_ref=str(verification.get("evidence_ref") or ""),
            )
            raise GateError(
                "deployment blocked because approval is no longer verified"
            )
        return verification

    def _revoke_authorization_after_approval_change(
        self,
        event: dict[str, Any],
        *,
        stage: str,
        aggregate_status: str,
        verification_ref: str,
        evidence_ref: str,
    ) -> None:
        revoked_at = utc_now()
        event["release_authorization"] = {
            **(event.get("release_authorization") or {}),
            "status": "BLOCKED",
            "credential_status": "REVOKED",
            "latest_aggregate_status": aggregate_status,
            "revoked_at": revoked_at,
            "revocation_evidence_ref": evidence_ref,
        }
        self._transition(
            event,
            "RELEASE_BLOCKED",
            "latest independent verifier state revoked deployment authorization",
        )
        self._append_control_event(
            event,
            "RELEASE_AUTHORIZATION_REVOKED",
            {
                "stage": stage,
                "aggregate_status": aggregate_status,
                "verification_ref": verification_ref,
                "evidence_ref": evidence_ref,
                "credential_digest": event["release_authorization"].get(
                    "credential_digest"
                ),
                "revoked_at": revoked_at,
            },
        )
        self._save_event(event)

    def _verify_frozen_final_material(self, event: dict[str, Any]) -> None:
        manifest_r = self._load_manifest(event["event_id"], "manifest-r.json")
        artifacts = manifest_r.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise GateError("Manifest-R contains no artifacts")
        expected_digest = object_digest(
            {
                "source_manifest_s_digest": manifest_r.get("source_manifest_s_digest"),
                "artifacts": artifacts,
            }
        )
        if expected_digest != event.get("manifest_r_digest") or expected_digest != manifest_r.get("digest"):
            raise GateError("Manifest-R digest drifted after release authorization")
        output_dir = Path(str(manifest_r.get("output_dir") or "")).resolve()
        expected_names = {str(item.get("logical_name")) for item in artifacts}
        actual_names = {
            path.relative_to(output_dir).as_posix()
            for path in output_dir.rglob("*")
            if path.is_file()
        }
        if actual_names != expected_names:
            raise GateError("final material file set drifted after release authorization")
        computed_manifest_digest = object_digest(
            {
                "source_manifest_s_digest": manifest_r.get(
                    "source_manifest_s_digest"
                ),
                "artifacts": artifacts,
            }
        )
        if (
            computed_manifest_digest != event.get("manifest_r_digest")
            or manifest_r.get("source_manifest_s_digest")
            != event.get("manifest_s_digest")
            or manifest_r.get("digest") != computed_manifest_digest
        ):
            raise GateError(
                "final material Manifest-R digest drifted after release authorization"
            )
        for artifact in artifacts:
            path = Path(str(artifact.get("file_path") or ""))
            if (
                not path.is_file()
                or sha1_file(path) != artifact.get("sha1")
                or sha256_file(path) != artifact.get("sha256")
            ):
                raise GateError(
                    "final material SHA1/SHA256 drifted: "
                    + str(artifact.get("logical_name"))
                )

    def _deployment_adapter_lock_ready(self) -> bool:
        try:
            self._validate_deployment_adapter_lock()
        except GateError:
            return False
        return True

    def _deployment_adapter_lock_binding(self) -> tuple[Path, str]:
        deployment = (self._production_config().get("deployment") or {})
        lock_path = str(deployment.get("dependency_lock") or "").strip()
        lock_digest = str(deployment.get("dependency_lock_sha256") or "").strip().lower()
        if not lock_path or not lock_digest:
            raise GateError(
                "production.deployment requires dependency_lock and dependency_lock_sha256"
            )
        if not _SHA256_PATTERN.fullmatch(lock_digest):
            raise GateError("production.deployment.dependency_lock_sha256 is invalid")
        try:
            resolved = Path(os.path.expandvars(lock_path)).expanduser().resolve(strict=True)
        except OSError as exc:
            raise GateError("production deployment dependency lock is missing") from exc
        return resolved, lock_digest

    def _load_deployment_adapter_lock(self) -> tuple[Path, Path, dict[str, Any]]:
        lock_path, expected_digest = self._deployment_adapter_lock_binding()
        if sha256_file(lock_path) != expected_digest:
            raise GateError("deployment adapter lock drift was detected")
        try:
            payload = json.loads(lock_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise GateError("production deployment dependency lock is invalid JSON") from exc
        if not isinstance(payload, dict):
            raise GateError("production deployment dependency lock must be one JSON object")
        base_dir = lock_path.parent.resolve(strict=True)
        root_text = str(payload.get("root") or ".").strip() or "."
        root_candidate = Path(os.path.expandvars(root_text)).expanduser()
        try:
            lock_root = (
                root_candidate.resolve(strict=True)
                if root_candidate.is_absolute()
                else (base_dir / root_candidate).resolve(strict=True)
            )
        except OSError as exc:
            raise GateError("production deployment lock root is missing") from exc
        if not root_candidate.is_absolute():
            try:
                lock_root.relative_to(base_dir)
            except ValueError as exc:
                raise GateError("production deployment lock root escapes the lock directory") from exc
        commands = payload.get("commands")
        if not isinstance(commands, dict):
            raise GateError("production deployment dependency lock must contain a commands object")
        return lock_path, lock_root, commands

    def _resolve_locked_adapter_entrypoint(
        self,
        *,
        lock_root: Path,
        raw_path: str,
        command_id: str,
        entrypoint_index: int,
    ) -> Path:
        candidate = Path(os.path.expandvars(raw_path)).expanduser()
        try:
            resolved = (
                candidate.resolve(strict=True)
                if candidate.is_absolute()
                else (lock_root / candidate).resolve(strict=True)
            )
        except OSError as exc:
            raise GateError(
                f"deployment adapter entrypoint is missing for {command_id}: argv[{entrypoint_index}]"
            ) from exc
        if not candidate.is_absolute():
            try:
                resolved.relative_to(lock_root)
            except ValueError as exc:
                raise GateError(
                    f"deployment adapter entrypoint escapes its lock root for {command_id}: argv[{entrypoint_index}]"
                ) from exc
        if not resolved.is_file():
            raise GateError(
                f"deployment adapter entrypoint is missing for {command_id}: argv[{entrypoint_index}]"
            )
        return resolved

    def _resolve_adapter_command_entrypoint(
        self,
        *,
        token: str,
        lock_root: Path,
        command_id: str,
        entrypoint_index: int,
        allow_path_lookup: bool,
    ) -> Path:
        candidate = Path(os.path.expandvars(token)).expanduser()
        if candidate.is_absolute():
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise GateError(
                    f"deployment adapter command entrypoint is missing for {command_id}: argv[{entrypoint_index}]"
                ) from exc
            if not resolved.is_file():
                raise GateError(
                    f"deployment adapter command entrypoint is missing for {command_id}: argv[{entrypoint_index}]"
                )
            return resolved
        relative = (lock_root / candidate).resolve(strict=False)
        if relative.exists():
            resolved = relative.resolve(strict=True)
            try:
                resolved.relative_to(lock_root)
            except ValueError as exc:
                raise GateError(
                    f"deployment adapter command entrypoint escapes its lock root for {command_id}: argv[{entrypoint_index}]"
                ) from exc
            if not resolved.is_file():
                raise GateError(
                    f"deployment adapter command entrypoint is missing for {command_id}: argv[{entrypoint_index}]"
                )
            return resolved
        if allow_path_lookup:
            located = shutil.which(token)
            if located:
                resolved = Path(located).resolve(strict=True)
                if resolved.is_file():
                    return resolved
        raise GateError(
            f"deployment adapter command entrypoint is missing for {command_id}: argv[{entrypoint_index}]"
        )

    def _reject_non_production_adapter_path(
        self,
        path: Path,
        *,
        command_id: str,
        entrypoint_index: int,
    ) -> None:
        if self._allow_unlocked_test_adapters:
            return
        path_parts = {part.casefold() for part in path.parts}
        stem_parts = {
            part
            for part in re.split(r"[^a-z0-9]+", path.stem.casefold())
            if part
        }
        disallowed = sorted(
            (path_parts | stem_parts) & _NON_PRODUCTION_ADAPTER_PATH_PARTS
        )
        if disallowed:
            raise GateError(
                f"production adapter entrypoint is test-only for {command_id}: "
                f"argv[{entrypoint_index}] contains {', '.join(disallowed)}"
            )

    def _validate_locked_deployment_command(
        self,
        command_id: str,
        command: Any,
    ) -> list[str]:
        if not self._valid_command(command):
            raise GateError(f"deployment adapter command is not configured for {command_id}")
        _, lock_root, commands = self._load_deployment_adapter_lock()
        locked = commands.get(command_id)
        if not isinstance(locked, dict):
            raise GateError(f"deployment adapter lock does not define {command_id}")
        locked_template = locked.get("argv_template")
        if not self._valid_command(locked_template):
            raise GateError(f"deployment adapter lock argv_template is invalid for {command_id}")
        template = list(command)
        if template != list(locked_template):
            raise GateError(f"deployment adapter command drift was detected for {command_id}")
        entrypoints = locked.get("entrypoints")
        if not isinstance(entrypoints, list) or not entrypoints:
            raise GateError(f"deployment adapter lock entrypoints are missing for {command_id}")
        indices: list[int] = []
        for entry in entrypoints:
            if not isinstance(entry, dict):
                raise GateError(f"deployment adapter lock entrypoints are invalid for {command_id}")
            index = entry.get("argv_index")
            if not isinstance(index, int) or isinstance(index, bool) or not (0 <= index < len(template)):
                raise GateError(f"deployment adapter lock argv_index is invalid for {command_id}")
            if index in indices:
                raise GateError(f"deployment adapter lock duplicates argv_index for {command_id}")
            raw_path = str(entry.get("path") or "").strip()
            expected_digest = str(entry.get("sha256") or "").strip().lower()
            if not raw_path or not _SHA256_PATTERN.fullmatch(expected_digest):
                raise GateError(f"deployment adapter lock entrypoint digest is invalid for {command_id}")
            locked_path = self._resolve_locked_adapter_entrypoint(
                lock_root=lock_root,
                raw_path=raw_path,
                command_id=command_id,
                entrypoint_index=index,
            )
            self._reject_non_production_adapter_path(
                locked_path,
                command_id=command_id,
                entrypoint_index=index,
            )
            configured_path = self._resolve_adapter_command_entrypoint(
                token=template[index],
                lock_root=lock_root,
                command_id=command_id,
                entrypoint_index=index,
                allow_path_lookup=index == 0,
            )
            if configured_path != locked_path:
                raise GateError(
                    f"deployment adapter command entrypoint differs from the locked path for {command_id}: argv[{index}]"
                )
            if sha256_file(locked_path) != expected_digest:
                raise GateError(f"deployment adapter entrypoint drift was detected for {command_id}")
            indices.append(index)
        shape = tuple(sorted(indices))
        if shape not in {(0,), (0, 1)}:
            raise GateError(f"deployment adapter command shape is unknown for {command_id}")
        return template

    def _validate_deployment_adapter_lock(self) -> None:
        production = self._production_config()
        deployment = production.get("deployment") or {}
        readback = production.get("readback") or {}
        for command_id, config_key in _DEPLOYMENT_LOCKED_COMMAND_IDS:
            self._validate_locked_deployment_command(command_id, deployment.get(config_key))
        self._validate_locked_deployment_command("readback", readback.get("command"))

    def _run_json_adapter(
        self,
        command: Any,
        context: dict[str, str],
        timeout_seconds: int,
        *,
        command_id: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        if not self._valid_command(command):
            return None, "adapter command is not configured"
        try:
            template = (
                self._validate_locked_deployment_command(command_id, command)
                if command_id is not None
                else list(command)
            )
        except GateError as exc:
            return None, f"adapter integrity check failed: {exc}"
        try:
            expanded = [item.format_map(context) for item in template]
        except KeyError as exc:
            return None, f"adapter command uses an unknown placeholder: {exc}"
        try:
            child_environment = None
            if command_id == "deploy":
                production = self._production_config()
                authorization = production.get("authorization") or {}
                key_env = str(authorization.get("key_env") or "").strip()
                if not key_env:
                    return None, "adapter credential is unavailable"
                try:
                    self._require_runtime_identity()
                    authorization_value = self._resolve_signing_secret(
                        authorization,
                        "authorization",
                    )
                except GateError:
                    return None, "adapter credential is unavailable"
                child_environment = dict(os.environ)
                child_environment.update(self._environ)
                child_environment[key_env] = authorization_value
            completed = subprocess.run(
                expanded,
                capture_output=True,
                text=True,
                shell=False,
                env=child_environment,
                timeout=max(1, int(timeout_seconds)),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, f"adapter failed: {exc}"
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or f"exit code {completed.returncode}").strip()
            return None, f"adapter failed: {detail[:1000]}"
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return None, "adapter must write one JSON object to stdout"
        if not isinstance(payload, dict):
            return None, "adapter must write one JSON object to stdout"
        return payload, None

    def _deployment_context(self, event: dict[str, Any], stage: str) -> dict[str, str]:
        production = self._production_config()
        deployment = production.get("deployment") or {}
        targets = deployment.get("targets") or {}
        return {
            "event_id": str(event["event_id"]),
            "stage": stage,
            "target_ref": str(targets.get(stage) or ""),
            "manifest_s_path": str(self._event_dir(event["event_id"]) / "manifest-s.json"),
            "manifest_r_path": str(self._event_dir(event["event_id"]) / "manifest-r.json"),
            "manifest_s_digest": str(event["manifest_s_digest"]),
            "manifest_r_digest": str(event["manifest_r_digest"]),
            "authorization_path": str(
                (event.get("release_authorization") or {}).get("credential_path") or ""
            ),
            "idempotency_key": object_digest(
                {
                    "event_id": event["event_id"],
                    "stage": stage,
                    "manifest_r_digest": event["manifest_r_digest"],
                }
            ),
        }

    def _require_stage_authorization(
        self,
        credential: dict[str, Any],
        stage: str,
    ) -> None:
        claims = credential.get("claims") or {}
        allowed_stages = set(self._parse_target_scope(claims.get("target_scope")))
        if stage not in allowed_stages:
            raise GateError(f"release authorization does not permit deployment stage: {stage}")

    def _seal_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        sealed = dict(receipt)
        sealed["receipt_algorithm"] = "HMAC-SHA256"
        sealed["receipt_hmac"] = hmac.new(
            self._audit_key(),
            canonical_json(sealed).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return sealed

    def _verify_receipt_seal(self, receipt: dict[str, Any]) -> bool:
        candidate = dict(receipt)
        claimed = str(candidate.pop("receipt_hmac", ""))
        if candidate.get("receipt_algorithm") != "HMAC-SHA256" or not claimed:
            return False
        expected = hmac.new(
            self._audit_key(),
            canonical_json(candidate).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(claimed, expected)

    def _validate_stage_receipt(
        self,
        event: dict[str, Any],
        stage: str,
        context: dict[str, str],
        receipt: Any,
    ) -> dict[str, Any]:
        if not isinstance(receipt, dict) or not self._verify_receipt_seal(receipt):
            raise GateError(f"{stage} deployment receipt signature is invalid")
        deployment = receipt.get("deployment")
        verification = receipt.get("verification")
        valid = (
            receipt.get("event_id") == event.get("event_id")
            and receipt.get("stage") == stage
            and str(receipt.get("result") or "").upper() == "PASS"
            and receipt.get("manifest_r_digest") == event.get("manifest_r_digest")
            and receipt.get("idempotency_key") == context.get("idempotency_key")
            and isinstance(deployment, dict)
            and str(deployment.get("result") or "").upper() == "PASS"
            and deployment.get("target_ref") == context.get("target_ref")
            and deployment.get("deployed_manifest_r_digest") == event.get("manifest_r_digest")
            and bool(str(deployment.get("deployment_ref") or "").strip())
            and bool(str(deployment.get("rollback_ref") or "").strip())
            and isinstance(verification, dict)
            and str(verification.get("result") or "").upper() == "PASS"
            and verification.get("target_ref") == context.get("target_ref")
            and verification.get("observed_manifest_r_digest") == event.get("manifest_r_digest")
            and bool(str(verification.get("verification_ref") or "").strip())
        )
        if not valid:
            raise GateError(f"{stage} deployment receipt is not bound to the current release")
        return receipt

    def _validate_production_readback_receipt(
        self,
        event: dict[str, Any],
        context: dict[str, str],
        receipt: Any,
    ) -> dict[str, Any]:
        if not isinstance(receipt, dict) or not self._verify_receipt_seal(receipt):
            raise GateError("production readback receipt signature is invalid")
        payload = receipt.get("payload")
        valid = (
            receipt.get("event_id") == event.get("event_id")
            and str(receipt.get("result") or "").upper() == "PASS"
            and receipt.get("manifest_r_digest") == event.get("manifest_r_digest")
            and receipt.get("target_ref") == context.get("target_ref")
            and isinstance(payload, dict)
            and str(payload.get("result") or "").upper() == "PASS"
            and payload.get("target_ref") == context.get("target_ref")
            and payload.get("observed_manifest_r_digest") == event.get("manifest_r_digest")
            and bool(str(payload.get("readback_ref") or "").strip())
        )
        if not valid:
            raise GateError("production readback receipt is not bound to the current release")
        return receipt

    def _rollback_stage(
        self,
        event: dict[str, Any],
        stage: str,
        context: dict[str, str],
        failure: dict[str, Any],
    ) -> dict[str, Any]:
        production = self._production_config()
        deployment = production.get("deployment") or {}
        payload, error = self._run_json_adapter(
            deployment.get("rollback_command"),
            context,
            int(deployment.get("timeout_seconds") or 300),
            command_id="rollback",
        )
        rollback_ok = (
            payload is not None
            and str(payload.get("result") or "").upper() == "PASS"
            and payload.get("deployment_ref") == context.get("deployment_ref")
            and payload.get("rollback_ref") == context.get("rollback_ref")
            and payload.get("target_ref") == context.get("target_ref")
            and bool(str(payload.get("restored_ref") or "").strip())
            and bool(str(payload.get("rollback_receipt_ref") or "").strip())
        )
        verification: dict[str, Any] | None = None
        verification_error: str | None = None
        if rollback_ok:
            verification_context = {
                **context,
                "restored_ref": str(payload["restored_ref"]),
                "rollback_receipt_ref": str(payload["rollback_receipt_ref"]),
            }
            verification, verification_error = self._run_json_adapter(
                deployment.get("rollback_verify_command"),
                verification_context,
                int(deployment.get("timeout_seconds") or 300),
                command_id="rollback_verify",
            )
        verification_ok = (
            verification is not None
            and str(verification.get("result") or "").upper() == "PASS"
            and verification.get("deployment_ref") == context.get("deployment_ref")
            and verification.get("rollback_ref") == context.get("rollback_ref")
            and verification.get("target_ref") == context.get("target_ref")
            and payload is not None
            and verification.get("restored_ref") == payload.get("restored_ref")
            and bool(str(verification.get("verification_ref") or "").strip())
        )
        passed = rollback_ok and verification_ok
        rollback = {
            **(payload or {}),
            "result": "PASS" if passed else "FAIL",
            "adapter_error": error,
            "verification": verification,
            "verification_error": verification_error,
        }
        rollback_path = self._event_dir(event["event_id"]) / "deployments" / f"{stage}-rollback.json"
        rollback_receipt = self._seal_receipt(
            {
                "schema_version": 1,
                "event_id": event["event_id"],
                "stage": stage,
                "result": rollback["result"],
                "manifest_r_digest": event["manifest_r_digest"],
                "failure": failure,
                "rollback": rollback,
                "recorded_at": utc_now(),
            }
        )
        write_json(rollback_path, rollback_receipt)
        if passed:
            self._transition(event, "ROLLED_BACK", f"{stage} failed and rollback passed")
        else:
            self._transition(event, "ROLLBACK_FAILED", f"{stage} failed and rollback failed")
        event.setdefault("deployment", {}).setdefault("stages", {})[stage] = {
            "result": "ROLLED_BACK" if event["status"] == "ROLLED_BACK" else "ROLLBACK_FAILED",
            "manifest_r_digest": event["manifest_r_digest"],
            "rollback_path": str(rollback_path),
            "rollback_receipt_digest": object_digest(rollback_receipt),
        }
        self._append_control_event(
            event,
            "DEPLOYMENT_ROLLBACK_COMPLETED",
            {
                "stage": stage,
                "result": rollback["result"],
                "rollback_path": str(rollback_path),
                "rollback_receipt_digest": object_digest(rollback_receipt),
                "failure": failure,
            },
        )
        self._save_event(event)
        return rollback

    def run_deployment_stage(self, event_id: str, stage: str) -> dict[str, Any]:
        self._require_runtime_identity()
        stage = str(stage or "").strip()
        if stage not in REQUIRED_DEPLOYMENT_STAGES:
            raise GateError(f"stage must be one of: {', '.join(REQUIRED_DEPLOYMENT_STAGES)}")
        event = self._load_event(event_id)
        expected_status = {
            "preproduction": "RELEASE_AUTHORIZED",
            "production_canary": "PREPRODUCTION_VERIFIED",
            "production_full": "CANARY_VERIFIED",
        }[stage]
        next_status = {
            "preproduction": "PREPRODUCTION_VERIFIED",
            "production_canary": "CANARY_VERIFIED",
            "production_full": "PRODUCTION_DEPLOYED",
        }[stage]
        if event.get("status") not in {expected_status, next_status}:
            raise GateError(
                f"{stage} cannot run from status {event.get('status')}; "
                f"expected {expected_status} or {next_status}"
            )

        credential = self._verify_authorization_credential(event)
        self._require_stage_authorization(credential, stage)
        self._revalidate_unified_approval_for_deployment(
            event,
            credential,
            stage,
        )
        self._verify_frozen_final_material(event)
        context = self._deployment_context(event, stage)
        if not context["target_ref"]:
            raise GateError(f"deployment target is not configured for stage: {stage}")

        receipt_path = self._event_dir(event_id) / "deployments" / f"{stage}.json"
        if receipt_path.exists():
            receipt = self._validate_stage_receipt(
                event,
                stage,
                context,
                read_json(receipt_path),
            )
            if event.get("status") == expected_status:
                event.setdefault("deployment", {}).setdefault("stages", {})[stage] = {
                    "result": "PASS",
                    "manifest_r_digest": event["manifest_r_digest"],
                    "receipt_path": str(receipt_path),
                    "receipt_digest": object_digest(receipt),
                }
                self._transition(
                    event,
                    next_status,
                    f"{stage} state recovered from a valid signed receipt",
                )
                self._append_control_event(
                    event,
                    "DEPLOYMENT_STAGE_REPLAYED",
                    {
                        "stage": stage,
                        "receipt_path": str(receipt_path),
                        "receipt_digest": object_digest(receipt),
                    },
                )
                self._save_event(event)
            return {
                "status": event["status"],
                "result": "PASS",
                "receipt": receipt,
                "idempotent": True,
            }

        if event.get("status") != expected_status:
            raise GateError(f"{stage} signed receipt is missing from status {event.get('status')}")
        capability = self.ensure_deployment_capabilities(event_id)
        if not capability["ready"]:
            return capability
        event = self._load_event(event_id)
        credential = self._verify_authorization_credential(event)
        self._require_stage_authorization(credential, stage)
        self._revalidate_unified_approval_for_deployment(
            event,
            credential,
            stage,
        )
        self._verify_frozen_final_material(event)

        production = self._production_config()
        deployment = production.get("deployment") or {}
        timeout_seconds = int(deployment.get("timeout_seconds") or 300)
        context = self._deployment_context(event, stage)
        deployed, deploy_error = self._run_json_adapter(
            deployment.get("deploy_command"),
            context,
            timeout_seconds,
            command_id="deploy",
        )
        deploy_ok = (
            deployed is not None
            and str(deployed.get("result") or "").upper() == "PASS"
            and deployed.get("target_ref") == context["target_ref"]
            and deployed.get("deployed_manifest_r_digest") == event["manifest_r_digest"]
            and bool(str(deployed.get("deployment_ref") or "").strip())
            and bool(str(deployed.get("rollback_ref") or "").strip())
        )
        operation_context = {
            **context,
            "deployment_ref": str((deployed or {}).get("deployment_ref") or ""),
            "rollback_ref": str((deployed or {}).get("rollback_ref") or ""),
        }
        if not deploy_ok:
            failure = {"phase": "deploy", "error": deploy_error, "payload": deployed}
            self._transition(event, "ROLLBACK_REQUIRED", f"{stage} deployment failed")
            rollback = self._rollback_stage(event, stage, operation_context, failure)
            return {"status": event["status"], "result": "BLOCKED", "failure": failure, "rollback": rollback}

        verified, verify_error = self._run_json_adapter(
            deployment.get("verify_command"),
            operation_context,
            timeout_seconds,
            command_id="verify",
        )
        verify_ok = (
            verified is not None
            and str(verified.get("result") or "").upper() == "PASS"
            and verified.get("target_ref") == context["target_ref"]
            and verified.get("observed_manifest_r_digest") == event["manifest_r_digest"]
            and bool(str(verified.get("verification_ref") or "").strip())
        )
        if not verify_ok:
            failure = {"phase": "verify", "error": verify_error, "payload": verified}
            self._transition(event, "ROLLBACK_REQUIRED", f"{stage} verification failed")
            rollback = self._rollback_stage(event, stage, operation_context, failure)
            return {"status": event["status"], "result": "BLOCKED", "failure": failure, "rollback": rollback}

        receipt = self._seal_receipt(
            {
                "schema_version": 1,
                "event_id": event_id,
                "stage": stage,
                "result": "PASS",
                "manifest_r_digest": event["manifest_r_digest"],
                "idempotency_key": context["idempotency_key"],
                "deployment": deployed,
                "verification": verified,
                "recorded_at": utc_now(),
            }
        )
        write_json(receipt_path, receipt)
        event.setdefault("deployment", {}).setdefault("stages", {})[stage] = {
            "result": "PASS",
            "manifest_r_digest": event["manifest_r_digest"],
            "receipt_path": str(receipt_path),
            "receipt_digest": object_digest(receipt),
        }
        self._transition(event, next_status, f"{stage} deployment and readback passed")
        self._append_control_event(
            event,
            "DEPLOYMENT_STAGE_VERIFIED",
            {
                "stage": stage,
                "receipt_path": str(receipt_path),
                "receipt_digest": object_digest(receipt),
                "idempotency_key": context["idempotency_key"],
            },
        )
        self._save_event(event)
        return {"status": event["status"], "result": "PASS", "receipt": receipt, "idempotent": False}

    def _rollback_production_full(
        self,
        event: dict[str, Any],
        context: dict[str, str],
        failure: dict[str, Any],
    ) -> dict[str, Any]:
        stage_receipt_path = (
            self._event_dir(event["event_id"])
            / "deployments"
            / "production_full.json"
        )
        stage_receipt = self._validate_stage_receipt(
            event,
            "production_full",
            context,
            read_json(stage_receipt_path),
        )
        deployment_receipt = stage_receipt["deployment"]
        return self._rollback_stage(
            event,
            "production_full",
            {
                **context,
                "deployment_ref": str(deployment_receipt["deployment_ref"]),
                "rollback_ref": str(deployment_receipt["rollback_ref"]),
            },
            failure,
        )
    def run_production_readback(self, event_id: str) -> dict[str, Any]:
        self._require_runtime_identity()
        event = self._load_event(event_id)
        if event.get("status") != "PRODUCTION_DEPLOYED":
            raise GateError(
                f"Production readback cannot run from status {event.get('status')}"
            )
        production = self._production_config()
        readback_config = production.get("readback") or {}
        context = self._deployment_context(event, "production_full")
        path = self._event_dir(event_id) / "production-readback.json"
        try:
            credential = self._verify_authorization_credential(event)
            self._revalidate_unified_approval_for_deployment(
                event,
                credential,
                "production_readback",
            )
            self._verify_frozen_final_material(event)
        except GateError as exc:
            failure = {
                "phase": "production_readback_precondition",
                "error": str(exc),
                "payload": None,
            }
            authorization = event.setdefault("release_authorization", {})
            if authorization.get("status") == "APPROVED":
                authorization.update(
                    {
                        "status": "BLOCKED",
                        "credential_status": "INVALID_OR_EXPIRED",
                        "blocked_at": utc_now(),
                    }
                )
            self._transition(
                event,
                "ROLLBACK_REQUIRED",
                "production readback precondition failed",
            )
            self._append_control_event(
                event,
                "PRODUCTION_READBACK_PRECONDITION_BLOCKED",
                {"failure": failure},
            )
            rollback = self._rollback_production_full(
                event,
                context,
                failure,
            )
            return {
                "status": event["status"],
                "result": "BLOCKED",
                "failure": failure,
                "rollback": rollback,
            }
        if path.exists():
            receipt = self._validate_production_readback_receipt(
                event,
                context,
                read_json(path),
            )
            event["production_readback_path"] = str(path)
            self._transition(
                event,
                "PRODUCTION_VERIFIED",
                "production readback state recovered from a valid signed receipt",
            )
            self._append_control_event(
                event,
                "PRODUCTION_READBACK_REPLAYED",
                {
                    "receipt_path": str(path),
                    "receipt_digest": object_digest(receipt),
                },
            )
            self._save_event(event)
            return {
                "status": event["status"],
                "result": "PASS",
                "receipt_path": str(path),
                "receipt": receipt,
                "idempotent": True,
            }
        payload, error = self._run_json_adapter(
            readback_config.get("command"),
            context,
            int(readback_config.get("timeout_seconds") or 120),
            command_id="readback",
        )
        passed = (
            payload is not None
            and str(payload.get("result") or "").upper() == "PASS"
            and payload.get("target_ref") == context["target_ref"]
            and payload.get("observed_manifest_r_digest") == event["manifest_r_digest"]
            and bool(str(payload.get("readback_ref") or "").strip())
        )
        receipt = self._seal_receipt(
            {
                "schema_version": 1,
                "event_id": event_id,
                "result": "PASS" if passed else "BLOCKED",
                "manifest_r_digest": event["manifest_r_digest"],
                "target_ref": context["target_ref"],
                "payload": payload,
                "error": error,
                "recorded_at": utc_now(),
            }
        )
        path = self._event_dir(event_id) / "production-readback.json"
        write_json(path, receipt)
        if passed:
            self._transition(event, "PRODUCTION_VERIFIED", "production readback matched Manifest-R")
            event["production_readback_path"] = str(path)
            self._append_control_event(
                event,
                "PRODUCTION_VERIFIED",
                {
                    "receipt_path": str(path),
                    "receipt_digest": object_digest(receipt),
                },
            )
            self._save_event(event)
            return {
                "status": event["status"],
                "result": receipt["result"],
                "receipt_path": str(path),
                "receipt": receipt,
            }

        failure = {"phase": "production_readback", "error": error, "payload": payload}
        self._transition(
            event,
            "ROLLBACK_REQUIRED",
            "production readback did not match Manifest-R",
        )
        self._append_control_event(
            event,
            "PRODUCTION_READBACK_BLOCKED",
            {
                "receipt_path": str(path),
                "receipt_digest": object_digest(receipt),
                "failure": failure,
            },
        )
        rollback = self._rollback_production_full(
            event,
            context,
            failure,
        )
        return {
            "status": event["status"],
            "result": receipt["result"],
            "receipt_path": str(path),
            "receipt": receipt,
            "rollback": rollback,
        }

    def _has_control_event(
        self,
        event_id: str,
        event_type: str,
        required_payload: dict[str, Any],
    ) -> bool:
        chain = self.verify_control_event_chain(event_id)
        if not chain.get("valid"):
            raise GateError(
                "control event chain is invalid: " + str(chain.get("error") or "unknown error")
            )
        path = self._control_event_path(event_id)
        if not path.is_file():
            return False
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise GateError("control event ledger contains invalid JSON") from exc
            payload = record.get("payload")
            if (
                record.get("event_type") == event_type
                and isinstance(payload, dict)
                and all(payload.get(key) == value for key, value in required_payload.items())
            ):
                return True
        return False

    @staticmethod
    def _production_report_delivery_metadata(
        intent_path: Path,
        smtp_path: Path,
        receipt_path: Path,
        intent: dict[str, Any],
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "intent_path": str(intent_path),
            "smtp_receipt_path": str(smtp_path) if smtp_path.exists() else None,
            "delivery_receipt_path": str(receipt_path),
            "delivery_receipt_digest": object_digest(receipt),
            "message_id": intent["message_id"],
            "recipients": intent["recipients"],
        }

    def _reconcile_production_report_delivery_metadata(
        self,
        event: dict[str, Any],
        metadata: dict[str, Any],
    ) -> None:
        existing = event.get("production_report_delivery")
        if existing is not None and existing != metadata:
            raise GateError("production report delivery event metadata drift was detected")
        event_payload = {
            "message_id": metadata["message_id"],
            "recipients": metadata["recipients"],
            "delivery_receipt_digest": metadata["delivery_receipt_digest"],
        }
        changed = existing is None
        if not self._has_control_event(
            event["event_id"], "PRODUCTION_REPORT_DELIVERED", event_payload
        ):
            self._append_control_event(event, "PRODUCTION_REPORT_DELIVERED", event_payload)
            changed = True
        if changed:
            event["production_report_delivery"] = metadata
            self._save_event(event)

    @staticmethod
    def _safe_report_mail_label(value: Any, label: str) -> str:
        text = str(value or "").strip()
        if (
            not text
            or len(text) > 120
            or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in text)
        ):
            raise GateError(f"{label} is required and must be a safe single-line value")
        return text

    def _production_report_delivery_config(self) -> dict[str, Any]:
        production = self._production_config()
        delivery = production.get("report_delivery")
        if not isinstance(delivery, dict) or delivery.get("enabled") is not True:
            raise GateError("production.report_delivery.enabled must be true")
        profile = self._safe_report_mail_label(
            delivery.get("profile"), "production.report_delivery.profile"
        )
        sender_email = str(delivery.get("sender_email") or "").strip().lower()
        if not _EMAIL_PATTERN.fullmatch(sender_email):
            raise GateError("production.report_delivery.sender_email must be an email")
        raw_recipients = delivery.get("recipients")
        if not isinstance(raw_recipients, list) or not raw_recipients:
            raise GateError("production.report_delivery.recipients must be a non-empty array")
        recipients: list[str] = []
        seen: set[str] = set()
        for value in raw_recipients:
            email = str(value or "").strip().lower()
            if not _EMAIL_PATTERN.fullmatch(email):
                raise GateError("production.report_delivery.recipients contains an invalid email")
            if email not in seen:
                recipients.append(email)
                seen.add(email)
        module = self._safe_report_mail_label(
            delivery.get("module") or "all", "production.report_delivery.module"
        )
        mailbox = self._safe_report_mail_label(
            delivery.get("mailbox") or "INBOX", "production.report_delivery.mailbox"
        )
        timeout_seconds = int(delivery.get("timeout_seconds") or 120)
        if timeout_seconds < 1 or timeout_seconds > 600:
            raise GateError("production.report_delivery.timeout_seconds must be between 1 and 600")
        readback_timeout_seconds = int(
            delivery.get("readback_timeout_seconds") or 86400
        )
        if readback_timeout_seconds < 60 or readback_timeout_seconds > 604800:
            raise GateError(
                "production.report_delivery.readback_timeout_seconds must be between 60 and 604800"
            )
        return {
            **delivery,
            "profile": profile,
            "sender_email": sender_email,
            "recipients": recipients,
            "module": module,
            "mailbox": mailbox,
            "timeout_seconds": timeout_seconds,
            "readback_timeout_seconds": readback_timeout_seconds,
        }

    def _production_report_mail_gateway(self, delivery: dict[str, Any]) -> Any:
        if self._report_mail_gateway_override is not None:
            return self._report_mail_gateway_override
        try:
            if self._allow_unlocked_test_adapters:
                command = delivery.get("command")
                if not self._valid_command(command):
                    raise GateError("production.report_delivery.command is required")
                return ImapSmtpMailCliGateway(
                    command,
                    timeout_seconds=int(delivery["timeout_seconds"]),
                )
            return LockedImapSmtpMailCliGateway(
                str(delivery.get("dependency_lock") or ""),
                dependency_lock_sha256=str(
                    delivery.get("dependency_lock_sha256") or ""
                ),
                timeout_seconds=int(delivery["timeout_seconds"]),
            )
        except ApprovalMailError as exc:
            raise GateError(str(exc)) from exc

    def _production_report_delivery_preflight(self) -> dict[str, Any]:
        try:
            delivery = self._production_report_delivery_config()
            gateway = self._production_report_mail_gateway(delivery)
            accounts = gateway.list_accounts()
            matching = [
                account
                for account in accounts
                if isinstance(account, dict)
                and str(account.get("name") or "").strip() == delivery["profile"]
                and str(account.get("email") or "").strip().lower()
                == delivery["sender_email"]
            ]
            if len(matching) != 1:
                raise GateError(
                    "production report mail profile and sender email were not found exactly once"
                )
            connection = gateway.test_connection(
                {
                    "account": delivery["profile"],
                    "mailbox": delivery["mailbox"],
                    "check_imap": True,
                    "check_smtp": True,
                }
            )
            connection_checks = connection.get("checks")
            if (
                not isinstance(connection_checks, dict)
                or connection_checks.get("imap") != "ok"
                or connection_checks.get("smtp") != "ok"
            ):
                raise GateError(
                    "production report mail requires live IMAP and SMTP connectivity"
                )
            return {
                "ready": True,
                "status": "ready",
                "profile": delivery["profile"],
                "sender_email": delivery["sender_email"],
                "recipients": delivery["recipients"],
                "mailbox": delivery["mailbox"],
                "connection": {"imap": "ok", "smtp": "ok"},
            }
        except (ApprovalMailError, GateError, TypeError, ValueError, OSError) as exc:
            return {
                "ready": False,
                "status": "CAPABILITY_BLOCKED",
                "reason": str(exc),
            }

    @staticmethod
    def _report_mail_addresses(value: Any) -> set[str]:
        if not isinstance(value, list):
            return set()
        addresses: set[str] = set()
        for item in value:
            if isinstance(item, dict):
                candidate = item.get("email")
            else:
                candidate = item
            email = str(candidate or "").strip().lower()
            if _EMAIL_PATTERN.fullmatch(email):
                addresses.add(email)
        return addresses

    @staticmethod
    def _report_delivery_timestamp(value: Any) -> str:
        digits = re.sub(r"[^0-9]", "", str(value or ""))
        if len(digits) < 14:
            raise GateError("production report generated_at is invalid")
        return digits[:14]

    def _production_report_delivery_contract(
        self,
        event: dict[str, Any],
        report_receipt: dict[str, Any],
        delivery: dict[str, Any],
        *,
        frozen_chain: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        approval = event.get("unified_release_approval") or {}
        task = self._safe_report_mail_label(
            approval.get("task") or event.get("task_id") or event["event_id"],
            "production report task",
        )
        module = self._safe_report_mail_label(
            delivery.get("module") or approval.get("module") or "all",
            "production report module",
        )
        stamp = self._report_delivery_timestamp(report_receipt.get("generated_at"))
        subject = f"【发布完成】{task}-{module}-{stamp}"
        message_id_digest = object_digest(
            {
                "event_id": event["event_id"],
                "report_sha256": report_receipt["report_sha256"],
                "recipients": delivery["recipients"],
            }
        )
        domain = delivery["sender_email"].rsplit("@", 1)[1]
        message_id = f"<production-report-{message_id_digest[:32]}@{domain}>"
        if _MESSAGE_ID_PATTERN.fullmatch(message_id) is None:
            raise GateError("production report Message-ID is invalid")
        current_chain = self.verify_control_event_chain(event["event_id"])
        if not current_chain.get("valid") or not current_chain.get("last_hash"):
            raise GateError("production report delivery requires a valid control event chain")
        chain = frozen_chain or current_chain
        if (
            not isinstance(chain.get("event_count"), int)
            or int(chain["event_count"]) < 1
            or _SHA256_PATTERN.fullmatch(str(chain.get("last_hash") or "")) is None
            or int(current_chain.get("event_count") or 0) < int(chain["event_count"])
        ):
            raise GateError("production report delivery chain snapshot is invalid")
        body_lines = [
            "【发布完成】",
            f"任务：{task}",
            f"模块：{module}",
            "状态：PRODUCTION_VERIFIED",
            f"Manifest-S：{event['manifest_s_digest']}",
            f"Manifest-R：{event['manifest_r_digest']}",
            "发布阶段：预生产、生产灰度、生产全量均已验证",
            f"生产证据链：VALID（{chain['event_count']} 条）",
            f"生产报告 SHA-256：{report_receipt['report_sha256']}",
            f"发布事件：{event['event_id']}",
            "说明：本邮件不包含本地路径、密钥或内部适配器参数。",
        ]
        body_text = "\n".join(body_lines)
        core = {
            "schema": "ProductionReleaseReportDeliveryIntent/v1",
            "event_id": event["event_id"],
            "status": "PRODUCTION_VERIFIED",
            "task": task,
            "module": module,
            "manifest_s_digest": event["manifest_s_digest"],
            "manifest_r_digest": event["manifest_r_digest"],
            "report_sha256": report_receipt["report_sha256"],
            "control_event_count": int(chain["event_count"]),
            "control_event_last_hash": str(chain["last_hash"]),
            "profile": delivery["profile"],
            "sender_email": delivery["sender_email"],
            "recipients": list(delivery["recipients"]),
            "mailbox": delivery["mailbox"],
            "subject": subject,
            "message_id": message_id,
            "body_text": body_text,
        }
        core["request_digest"] = "sha256:" + object_digest(core)
        return core

    def _validate_report_delivery_intent(
        self,
        event: dict[str, Any],
        expected: dict[str, Any],
        intent: Any,
    ) -> dict[str, Any]:
        if not isinstance(intent, dict) or not self._verify_receipt_seal(intent):
            raise GateError("production report delivery intent signature is invalid")
        candidate = dict(intent)
        candidate.pop("receipt_algorithm", None)
        candidate.pop("receipt_hmac", None)
        if candidate != expected:
            raise GateError("production report delivery intent drift was detected")
        if intent.get("event_id") != event.get("event_id"):
            raise GateError("production report delivery intent is not bound to the event")
        return intent

    def _validate_report_smtp_receipt(
        self,
        intent: dict[str, Any],
        receipt: Any,
    ) -> dict[str, Any]:
        if not isinstance(receipt, dict) or not self._verify_receipt_seal(receipt):
            raise GateError("production report SMTP receipt signature is invalid")
        valid = (
            receipt.get("schema") == "ProductionReleaseReportSmtpReceipt/v1"
            and receipt.get("event_id") == intent.get("event_id")
            and receipt.get("status") == "accepted"
            and receipt.get("message_id") == intent.get("message_id")
            and receipt.get("request_digest") == intent.get("request_digest")
            and receipt.get("report_sha256") == intent.get("report_sha256")
            and receipt.get("recipients") == intent.get("recipients")
            and receipt.get("refused") == {}
            and bool(str(receipt.get("accepted_at") or "").strip())
        )
        if not valid:
            raise GateError("production report SMTP receipt is not bound to the intent")
        return receipt

    def _validate_report_delivery_receipt(
        self,
        intent: dict[str, Any],
        receipt: Any,
    ) -> dict[str, Any]:
        if not isinstance(receipt, dict) or not self._verify_receipt_seal(receipt):
            raise GateError("production report delivery receipt signature is invalid")
        valid = (
            receipt.get("schema") == "ProductionReleaseReportDeliveryReceipt/v1"
            and receipt.get("event_id") == intent.get("event_id")
            and receipt.get("status") == "DELIVERED"
            and receipt.get("message_id") == intent.get("message_id")
            and receipt.get("request_digest") == intent.get("request_digest")
            and receipt.get("report_sha256") == intent.get("report_sha256")
            and receipt.get("recipients") == intent.get("recipients")
            and receipt.get("profile") == intent.get("profile")
            and receipt.get("mailbox") == intent.get("mailbox")
            and bool(re.fullmatch(r"[0-9]+", str(receipt.get("uid") or "")))
            and bool(re.fullmatch(r"[0-9]+", str(receipt.get("uidvalidity") or "")))
            and _SHA256_PATTERN.fullmatch(
                str(receipt.get("raw_headers_sha256") or "").lower()
            )
            is not None
        )
        if not valid:
            raise GateError("production report delivery receipt is not bound to the intent")
        return receipt

    def _readback_production_report_delivery(
        self,
        gateway: Any,
        intent: dict[str, Any],
    ) -> dict[str, Any] | None:
        generated = datetime.fromisoformat(
            str(intent["created_at"]).replace("Z", "+00:00")
        )
        search = gateway.search_messages(
            {
                "account": intent["profile"],
                "mailbox": intent["mailbox"],
                "query": {
                    "subject": intent["subject"],
                    "since": (generated - timedelta(days=1)).date().isoformat(),
                },
                "limit": 50,
                "scan_limit": 500,
            }
        )
        matches = [
            summary
            for summary in search.get("messages") or []
            if isinstance(summary, dict)
            and str(summary.get("message_id") or "").strip()
            == intent["message_id"]
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise GateError("production report readback found duplicate Message-ID values")
        uid = str(matches[0].get("uid") or "").strip()
        if not re.fullmatch(r"[0-9]+", uid):
            raise GateError("production report readback summary has an invalid uid")
        message = gateway.read_message(
            {
                "account": intent["profile"],
                "mailbox": intent["mailbox"],
                "uid": uid,
            }
        )
        evidence = message.get("evidence")
        headers = message.get("release_workflow_headers")
        raw_headers_sha256 = str(
            (evidence or {}).get("raw_headers_sha256") or ""
        ).strip().lower()
        expected_headers = {
            "contract": "rd.production-report.v1",
            "event_id": intent["event_id"],
            "task": intent["task"],
            "module": intent["module"],
            "manifest_s_digest": intent["manifest_s_digest"],
            "manifest_r_digest": intent["manifest_r_digest"],
            "manifest_digest": "sha256:" + intent["manifest_r_digest"],
            "request_digest": intent["request_digest"],
        }
        valid = (
            str(message.get("message_id") or "").strip() == intent["message_id"]
            and isinstance(evidence, dict)
            and str(evidence.get("message_id") or "").strip()
            == intent["message_id"]
            and _SHA256_PATTERN.fullmatch(raw_headers_sha256) is not None
            and isinstance(headers, dict)
            and headers == expected_headers
            and str(message.get("subject") or "").strip() == intent["subject"]
            and intent["sender_email"] in self._report_mail_addresses(message.get("from"))
            and set(intent["recipients"]).issubset(
                self._report_mail_addresses(message.get("to"))
                | self._report_mail_addresses(message.get("cc"))
            )
            and re.fullmatch(r"[0-9]+", str(message.get("uidvalidity") or ""))
        )
        if not valid:
            raise GateError("production report IMAP readback is not bound to the delivery intent")
        return {
            "uid": uid,
            "uidvalidity": str(message["uidvalidity"]),
            "raw_headers_sha256": raw_headers_sha256,
        }

    def deliver_production_report(self, event_id: str) -> dict[str, Any]:
        self._require_runtime_identity()
        report = self.generate_production_report(event_id)
        event = self._load_event(event_id)
        delivery = self._production_report_delivery_config()
        gateway = self._production_report_mail_gateway(delivery)
        report_receipt = read_json(Path(report["receipt_path"]))
        event_dir = self._event_dir(event_id)
        intent_path = event_dir / "production-report-delivery-intent.json"
        receipt_path = event_dir / "production-report-delivery.json"
        smtp_path = event_dir / "production-report-smtp.json"
        attempt_path = event_dir / "production-report-send-attempt.json"
        if not any(
            path.exists() for path in (intent_path, receipt_path, smtp_path, attempt_path)
        ):
            preflight = self._production_report_delivery_preflight()
            if preflight.get("ready") is not True:
                raise GateError(
                    "production report delivery preflight failed: "
                    + str(preflight.get("reason") or "unknown capability")
                )
        frozen_intent: dict[str, Any] | None = None
        if intent_path.exists():
            candidate = read_json(intent_path)
            if not isinstance(candidate, dict) or not self._verify_receipt_seal(candidate):
                raise GateError("production report delivery intent signature is invalid")
            frozen_intent = candidate
        expected_intent = self._production_report_delivery_contract(
            event,
            report_receipt,
            delivery,
            frozen_chain=(
                {
                    "event_count": frozen_intent.get("control_event_count"),
                    "last_hash": frozen_intent.get("control_event_last_hash"),
                }
                if frozen_intent is not None
                else None
            ),
        )
        expected_intent["created_at"] = str(
            report_receipt.get("generated_at") or ""
        )
        if frozen_intent is not None:
            intent = self._validate_report_delivery_intent(
                event, expected_intent, frozen_intent
            )
        else:
            intent = self._seal_receipt(expected_intent)
            write_json(intent_path, intent)
        if receipt_path.exists():
            receipt = self._validate_report_delivery_receipt(
                intent, read_json(receipt_path)
            )
            metadata = self._production_report_delivery_metadata(
                intent_path, smtp_path, receipt_path, intent, receipt
            )
            self._reconcile_production_report_delivery_metadata(event, metadata)
            return {
                "event_id": event_id,
                "status": "DELIVERED",
                "message_id": intent["message_id"],
                "recipients": intent["recipients"],
                "receipt_path": str(receipt_path),
                "receipt_digest": object_digest(receipt),
                "idempotent": True,
            }

        smtp_receipt: dict[str, Any] | None = None
        if smtp_path.exists():
            smtp_receipt = self._validate_report_smtp_receipt(
                intent, read_json(smtp_path)
            )
        elif attempt_path.exists():
            attempt = read_json(attempt_path)
            if not isinstance(attempt, dict) or not self._verify_receipt_seal(attempt):
                raise GateError("production report send-attempt signature is invalid")
            if (
                attempt.get("event_id") != intent["event_id"]
                or attempt.get("message_id") != intent["message_id"]
                or attempt.get("request_digest") != intent["request_digest"]
            ):
                raise GateError("production report send-attempt is not bound to the intent")
        else:
            attempt = self._seal_receipt(
                {
                    "schema": "ProductionReleaseReportSendAttempt/v1",
                    "event_id": event_id,
                    "message_id": intent["message_id"],
                    "request_digest": intent["request_digest"],
                    "attempted_at": utc_now(),
                }
            )
            write_json(attempt_path, attempt)
            payload = {
                "account": intent["profile"],
                "to": intent["recipients"],
                "subject": intent["subject"],
                "text": intent["body_text"],
                "message_id": intent["message_id"],
                "headers": {
                    "X-RD-Contract": "rd.production-report.v1",
                    "X-RD-Event-Id": intent["event_id"],
                    "X-RD-Task": intent["task"],
                    "X-RD-Module": intent["module"],
                    "X-RD-Manifest-S-Digest": intent["manifest_s_digest"],
                    "X-RD-Manifest-R-Digest": intent["manifest_r_digest"],
                    "X-RD-Manifest-Digest": "sha256:" + intent["manifest_r_digest"],
                    "X-RD-Request-Digest": intent["request_digest"],
                },
                "dry_run": False,
            }
            try:
                sent = gateway.send_email(payload)
            except (ApprovalMailError, OSError, RuntimeError) as exc:
                raise GateError(
                    "production report SMTP outcome is unknown; exact Message-ID readback is required before retry: "
                    + str(exc)
                ) from exc
            refused = sent.get("refused")
            accepted = (
                sent.get("sent") is True
                and isinstance(refused, dict)
                and not refused
                and str(sent.get("message_id") or "") == intent["message_id"]
            )
            if not accepted:
                raise GateError(
                    "production report SMTP delivery was not fully accepted; automatic resend is disabled"
                )
            smtp_receipt = self._seal_receipt(
                {
                    "schema": "ProductionReleaseReportSmtpReceipt/v1",
                    "event_id": event_id,
                    "status": "accepted",
                    "message_id": intent["message_id"],
                    "request_digest": intent["request_digest"],
                    "report_sha256": intent["report_sha256"],
                    "recipients": intent["recipients"],
                    "refused": {},
                    "accepted_at": utc_now(),
                }
            )
            write_json(smtp_path, smtp_receipt)

        readback = self._readback_production_report_delivery(gateway, intent)
        if readback is None:
            accepted_at = str(
                (smtp_receipt or {}).get("accepted_at")
                or (read_json(attempt_path) or {}).get("attempted_at")
                or ""
            )
            try:
                start = datetime.fromisoformat(accepted_at.replace("Z", "+00:00"))
                expired = datetime.now(timezone.utc) - start > timedelta(
                    seconds=int(delivery["readback_timeout_seconds"])
                )
            except (TypeError, ValueError):
                expired = True
            return {
                "event_id": event_id,
                "status": "READBACK_TIMEOUT" if expired else "READBACK_PENDING",
                "message_id": intent["message_id"],
                "recipients": intent["recipients"],
                "smtp_accepted": smtp_receipt is not None,
                "idempotent": True,
            }

        receipt = self._seal_receipt(
            {
                "schema": "ProductionReleaseReportDeliveryReceipt/v1",
                "event_id": event_id,
                "status": "DELIVERED",
                "message_id": intent["message_id"],
                "request_digest": intent["request_digest"],
                "report_sha256": intent["report_sha256"],
                "recipients": intent["recipients"],
                "profile": intent["profile"],
                "mailbox": intent["mailbox"],
                **readback,
                "readback_at": utc_now(),
            }
        )
        write_json(receipt_path, receipt)
        metadata = self._production_report_delivery_metadata(
            intent_path, smtp_path, receipt_path, intent, receipt
        )
        event = self._load_event(event_id)
        self._reconcile_production_report_delivery_metadata(event, metadata)
        return {
            "event_id": event_id,
            "status": "DELIVERED",
            "message_id": intent["message_id"],
            "recipients": intent["recipients"],
            "receipt_path": str(receipt_path),
            "receipt_digest": metadata["delivery_receipt_digest"],
            "idempotent": False,
        }
    def _validate_production_report_receipt(
        self,
        event: dict[str, Any],
        report_path: Path,
        receipt: Any,
    ) -> dict[str, Any]:
        if not isinstance(receipt, dict) or not self._verify_receipt_seal(receipt):
            raise GateError("production report receipt signature is invalid")
        report_sha256 = str(receipt.get("report_sha256") or "")
        valid = (
            receipt.get("schema") == "ProductionReleaseReportReceipt/v1"
            and receipt.get("event_id") == event.get("event_id")
            and receipt.get("status") == "PRODUCTION_VERIFIED"
            and receipt.get("manifest_s_digest") == event.get("manifest_s_digest")
            and receipt.get("manifest_r_digest") == event.get("manifest_r_digest")
            and _SHA256_PATTERN.fullmatch(report_sha256) is not None
            and isinstance(receipt.get("control_event_count"), int)
            and int(receipt["control_event_count"]) >= 1
            and bool(str(receipt.get("control_event_last_hash") or "").strip())
        )
        if not valid:
            raise GateError("production report receipt is not bound to the release")
        if not report_path.is_file() or sha256_file(report_path) != report_sha256:
            raise GateError("production report content drift was detected")
        return receipt

    def _verify_completed_release_evidence(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        if event.get("status") != "PRODUCTION_VERIFIED":
            raise GateError(
                "production report requires status PRODUCTION_VERIFIED"
            )
        self._verify_frozen_final_material(event)
        for stage in REQUIRED_DEPLOYMENT_STAGES:
            context = self._deployment_context(event, stage)
            receipt_path = (
                self._event_dir(event["event_id"])
                / "deployments"
                / f"{stage}.json"
            )
            if not receipt_path.is_file():
                raise GateError(f"production report is missing {stage} receipt")
            self._validate_stage_receipt(
                event,
                stage,
                context,
                read_json(receipt_path),
            )
        readback_path = self._event_dir(event["event_id"]) / "production-readback.json"
        if not readback_path.is_file():
            raise GateError("production report is missing production readback receipt")
        self._validate_production_readback_receipt(
            event,
            self._deployment_context(event, "production_full"),
            read_json(readback_path),
        )
        chain = self.verify_control_event_chain(event["event_id"])
        if not chain.get("valid"):
            raise GateError(
                "production report requires a valid control event chain: "
                + str(chain.get("error") or "unknown error")
            )
        if int(chain.get("event_count") or 0) < 1 or not chain.get("last_hash"):
            raise GateError("production report requires non-empty control evidence")
        return chain

    def generate_production_report(self, event_id: str) -> dict[str, Any]:
        self._require_runtime_identity()
        event = self._load_event(event_id)
        chain = self._verify_completed_release_evidence(event)
        event_dir = self._event_dir(event_id)
        report_path = event_dir / "production-report.md"
        receipt_path = event_dir / "production-report-receipt.json"
        if report_path.exists() or receipt_path.exists():
            if not report_path.is_file() or not receipt_path.is_file():
                raise GateError("production report artifact set is incomplete")
            receipt = self._validate_production_report_receipt(
                event,
                report_path,
                read_json(receipt_path),
            )
            metadata = event.get("production_report")
            expected_metadata = {
                "report_path": str(report_path),
                "receipt_path": str(receipt_path),
                "report_sha256": receipt["report_sha256"],
                "receipt_digest": object_digest(receipt),
            }
            if metadata is not None and metadata != expected_metadata:
                raise GateError("production report event metadata drift was detected")
            report_event_payload = {
                "report_sha256": receipt["report_sha256"],
                "receipt_digest": expected_metadata["receipt_digest"],
            }
            changed = metadata is None
            if not self._has_control_event(
                event_id, "PRODUCTION_REPORT_GENERATED", report_event_payload
            ):
                self._append_control_event(
                    event, "PRODUCTION_REPORT_GENERATED", report_event_payload
                )
                changed = True
            if changed:
                event["production_report"] = expected_metadata
                self._save_event(event)
            return {
                "event_id": event_id,
                "status": event["status"],
                **expected_metadata,
                "report": report_path.read_text(encoding="utf-8"),
                "idempotent": True,
            }

        authorization = event.get("release_authorization") or {}
        stages = (event.get("deployment") or {}).get("stages") or {}
        lines = [
            "# Production Release Report",
            "",
            f"- Event: {event_id}",
            f"- State: {event.get('status')}",
            f"- Source: {event.get('source_ref')}",
            f"- Manifest-S: {event.get('manifest_s_digest')}",
            f"- Manifest-R: {event.get('manifest_r_digest')}",
            f"- Approval: {authorization.get('approval_ref') or 'not recorded'}",
            f"- Authorization credential digest: {authorization.get('credential_digest') or 'not issued'}",
            f"- Control event chain: VALID ({chain.get('event_count')} records)",
            "",
            "## Rollout",
            "",
        ]
        for stage in ("test", *REQUIRED_DEPLOYMENT_STAGES):
            stage_result = stages.get(stage) or {}
            lines.append(f"- {stage}: {stage_result.get('result') or 'NOT_RUN'}")
        lines.extend(
            [
                "",
                "## Evidence",
                "",
                f"- Event directory: {event_dir}",
                f"- Production readback: {event.get('production_readback_path') or 'not recorded'}",
                f"- Control ledger: {self._control_event_path(event_id)}",
            ]
        )
        report = "\n".join(lines) + "\n"
        write_text_file(report_path, report)
        report_sha256 = sha256_file(report_path)
        receipt = self._seal_receipt(
            {
                "schema": "ProductionReleaseReportReceipt/v1",
                "event_id": event_id,
                "status": "PRODUCTION_VERIFIED",
                "manifest_s_digest": event["manifest_s_digest"],
                "manifest_r_digest": event["manifest_r_digest"],
                "report_sha256": report_sha256,
                "control_event_count": int(chain["event_count"]),
                "control_event_last_hash": str(chain["last_hash"]),
                "generated_at": utc_now(),
            }
        )
        write_json(receipt_path, receipt)
        metadata = {
            "report_path": str(report_path),
            "receipt_path": str(receipt_path),
            "report_sha256": report_sha256,
            "receipt_digest": object_digest(receipt),
        }
        event["production_report"] = metadata
        self._append_control_event(
            event,
            "PRODUCTION_REPORT_GENERATED",
            {
                "report_sha256": report_sha256,
                "receipt_digest": metadata["receipt_digest"],
            },
        )
        self._save_event(event)
        return {
            "event_id": event_id,
            "status": event["status"],
            **metadata,
            "report": report,
            "idempotent": False,
        }
