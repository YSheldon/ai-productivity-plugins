from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from release_gate_core import (
    GateError,
    canonical_json,
    object_digest,
    read_json,
    sha1_file,
    utc_now,
    write_json,
)
from release_gate_hardened import HardenedReleaseGateController


REQUIRED_DEPLOYMENT_STAGES = (
    "preproduction",
    "production_canary",
    "production_full",
)


class ProductionReleaseController(HardenedReleaseGateController):
    """Fail-closed production authorization and phased deployment controller."""

    def _production_config(self) -> dict[str, Any]:
        config = self.config.get("production")
        if not isinstance(config, dict) or not config.get("enabled"):
            raise GateError("production.enabled must be true for production operations")
        return config

    @staticmethod
    def _valid_command(value: Any) -> bool:
        return (
            isinstance(value, list)
            and bool(value)
            and all(isinstance(item, str) and bool(item) for item in value)
        )

    def _authorization_key(self) -> bytes:
        production = self._production_config()
        authorization = production.get("authorization") or {}
        key_env = str(authorization.get("key_env") or "").strip()
        if not key_env:
            raise GateError("production.authorization.key_env is required")
        key = os.environ.get(key_env, "")
        if not key:
            raise GateError(f"authorization signing key environment variable is missing: {key_env}")
        encoded = key.encode("utf-8")
        if len(encoded) < 32:
            raise GateError("authorization signing key must be at least 32 bytes")
        return encoded

    def _audit_key(self) -> bytes:
        production = self._production_config()
        authorization = production.get("authorization") or {}
        audit = production.get("audit") or {}
        key_env = str(audit.get("key_env") or "").strip()
        authorization_key_env = str(authorization.get("key_env") or "").strip()
        if not key_env:
            raise GateError("production.audit.key_env is required")
        if key_env == authorization_key_env:
            raise GateError("production audit and authorization keys must use different variables")
        key = os.environ.get(key_env, "")
        if not key:
            raise GateError(f"audit signing key environment variable is missing: {key_env}")
        encoded = key.encode("utf-8")
        if len(encoded) < 32:
            raise GateError("audit signing key must be at least 32 bytes")
        if hmac.compare_digest(encoded, self._authorization_key()):
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

    def production_preflight(self) -> dict[str, Any]:
        production = self._production_config()
        authorization = production.get("authorization") or {}
        deployment = production.get("deployment") or {}
        readback = production.get("readback") or {}
        stages = deployment.get("stages") or []
        targets = deployment.get("targets") or {}
        authorization_key_env = str(authorization.get("key_env") or "").strip()
        audit = production.get("audit") or {}
        audit_key_env = str(audit.get("key_env") or "").strip()
        checks = [
            {
                "name": "authorization_signer",
                "configured": bool(
                    str(authorization.get("key_env") or "").strip()
                    and os.environ.get(str(authorization.get("key_env") or ""), "")
                ),
            },
            {
                "name": "audit_signer",
                "configured": bool(
                    audit_key_env
                    and audit_key_env != authorization_key_env
                    and os.environ.get(audit_key_env, "")
                    and os.environ.get(audit_key_env, "")
                    != os.environ.get(authorization_key_env, "")
                    and len(os.environ.get(audit_key_env, "").encode("utf-8")) >= 32
                    and len(os.environ.get(authorization_key_env, "").encode("utf-8")) >= 32
                ),
            },
            {
                "name": "authorization.verify_command",
                "configured": self._valid_command(authorization.get("verify_command")),
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
                "name": "deployment.deploy_command",
                "configured": self._valid_command(deployment.get("deploy_command")),
            },
            {
                "name": "deployment.verify_command",
                "configured": self._valid_command(deployment.get("verify_command")),
            },
            {
                "name": "deployment.rollback_command",
                "configured": self._valid_command(deployment.get("rollback_command")),
            },
            {
                "name": "deployment.rollback_verify_command",
                "configured": self._valid_command(deployment.get("rollback_verify_command")),
            },
            {
                "name": "readback.command",
                "configured": self._valid_command(readback.get("command")),
            },
        ]
        missing = [check["name"] for check in checks if not check["configured"]]
        return {"ready": not missing, "missing_capabilities": missing, "checks": checks}

    def ensure_deployment_capabilities(self, event_id: str) -> dict[str, Any]:
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
        preflight = self.production_preflight()
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

    def request_release_authorization(
        self,
        event_id: str,
        requested_by: str,
        target_scope: str,
    ) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") != "RELEASE_READY":
            raise GateError(
                f"Release authorization cannot be requested from status {event.get('status')}"
            )
        if not str(requested_by or "").strip() or not str(target_scope or "").strip():
            raise GateError("requested_by and target_scope are required")
        normalized_scope = ",".join(self._parse_target_scope(target_scope))
        request = {
            "schema_version": 1,
            "event_id": event_id,
            "requested_by": str(requested_by).strip(),
            "target_scope": normalized_scope,
            "source_ref": event.get("source_ref"),
            "risk_level": event.get("risk_level"),
            "manifest_s_digest": event["manifest_s_digest"],
            "manifest_r_digest": event.get("manifest_r_digest"),
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
            "release gate passed and bound production approval is required",
        )
        self._append_control_event(event, "RELEASE_AUTHORIZATION_REQUESTED", request)
        self._save_event(event)
        return {"status": event["status"], "request_path": str(path), "request": request}

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
            raise GateError("signed release authorization request does not match the current event")
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

        ttl_seconds = int(authorization_config.get("ttl_seconds") or 3600)
        if ttl_seconds < 60 or ttl_seconds > 86400:
            raise GateError("authorization ttl_seconds must be between 60 and 86400")
        issued = datetime.now(timezone.utc).replace(microsecond=0)
        expires = issued + timedelta(seconds=ttl_seconds)
        request = {
            **(event.get("release_authorization") or {}),
            **signed_request,
            "target_scope": requested_scope,
        }
        claims = {
            "credential_id": f"auth-{secrets.token_hex(8)}",
            "event_id": event_id,
            "approval_ref": str(approval_ref).strip(),
            "approved_by": str(approved_by).strip(),
            "approval_evidence_ref": approval_evidence_ref,
            "manifest_s_digest": event["manifest_s_digest"],
            "manifest_r_digest": event["manifest_r_digest"],
            "target_scope": requested_scope,
            "issued_at": issued.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
        }
        signature = hmac.new(
            self._authorization_key(),
            canonical_json(claims).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        credential = {
            "schema_version": 1,
            "algorithm": "HMAC-SHA256",
            "claims": claims,
            "signature": signature,
        }
        credential_path = self._event_dir(event_id) / "release-authorization.json"
        write_json(credential_path, credential)
        event["release_authorization"] = {
            **request,
            "status": "APPROVED",
            "approval_ref": str(approval_ref).strip(),
            "approved_by": str(approved_by).strip(),
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
                    stage: {"result": "PENDING", "manifest_r_digest": event["manifest_r_digest"]}
                    for stage in REQUIRED_DEPLOYMENT_STAGES
                },
            }
        }
        self._transition(event, "RELEASE_AUTHORIZED", "bound production authorization recorded")
        self._append_control_event(
            event,
            "RELEASE_AUTHORIZED",
            {
                "approval_ref": str(approval_ref).strip(),
                "credential_digest": event["release_authorization"]["credential_digest"],
                "target_scope": claims["target_scope"],
            },
        )
        self._save_event(event)
        return {
            "status": event["status"],
            "authorization": event["release_authorization"],
            "credential_path": str(credential_path),
        }

    def _verify_authorization_credential(self, event: dict[str, Any]) -> dict[str, Any]:
        authorization = event.get("release_authorization") or {}
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
        for artifact in artifacts:
            path = Path(str(artifact.get("file_path") or ""))
            if not path.is_file() or sha1_file(path) != artifact.get("sha1"):
                raise GateError(f"final material SHA1 drifted: {artifact.get('logical_name')}")

    def _run_json_adapter(
        self,
        command: Any,
        context: dict[str, str],
        timeout_seconds: int,
    ) -> tuple[dict[str, Any] | None, str | None]:
        if not self._valid_command(command):
            return None, "adapter command is not configured"
        try:
            expanded = [item.format_map(context) for item in command]
        except KeyError as exc:
            return None, f"adapter command uses an unknown placeholder: {exc}"
        try:
            completed = subprocess.run(
                expanded,
                capture_output=True,
                text=True,
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
        self._verify_frozen_final_material(event)

        production = self._production_config()
        deployment = production.get("deployment") or {}
        timeout_seconds = int(deployment.get("timeout_seconds") or 300)
        context = self._deployment_context(event, stage)
        deployed, deploy_error = self._run_json_adapter(
            deployment.get("deploy_command"), context, timeout_seconds
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
            deployment.get("verify_command"), operation_context, timeout_seconds
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

    def run_production_readback(self, event_id: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") != "PRODUCTION_DEPLOYED":
            raise GateError(
                f"Production readback cannot run from status {event.get('status')}"
            )
        self._verify_authorization_credential(event)
        self._verify_frozen_final_material(event)
        production = self._production_config()
        readback_config = production.get("readback") or {}
        context = self._deployment_context(event, "production_full")
        payload, error = self._run_json_adapter(
            readback_config.get("command"),
            context,
            int(readback_config.get("timeout_seconds") or 120),
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
        stage_receipt_path = self._event_dir(event_id) / "deployments" / "production_full.json"
        stage_receipt = self._validate_stage_receipt(
            event,
            "production_full",
            context,
            read_json(stage_receipt_path),
        )
        deployment_receipt = stage_receipt["deployment"]
        rollback_context = {
            **context,
            "deployment_ref": str(deployment_receipt["deployment_ref"]),
            "rollback_ref": str(deployment_receipt["rollback_ref"]),
        }
        rollback = self._rollback_stage(
            event,
            "production_full",
            rollback_context,
            failure,
        )
        return {
            "status": event["status"],
            "result": receipt["result"],
            "receipt_path": str(path),
            "receipt": receipt,
            "rollback": rollback,
        }

    def generate_production_report(self, event_id: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        chain = self.verify_control_event_chain(event_id)
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
            f"- Control event chain: {'VALID' if chain.get('valid') else 'INVALID'} ({chain.get('event_count')} records)",
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
                f"- Event directory: {self._event_dir(event_id)}",
                f"- Production readback: {event.get('production_readback_path') or 'not recorded'}",
                f"- Control ledger: {self._control_event_path(event_id)}",
            ]
        )
        report = "\n".join(lines) + "\n"
        path = self._event_dir(event_id) / "production-report.md"
        path.write_text(report, encoding="utf-8")
        return {"event_id": event_id, "status": event.get("status"), "report_path": str(path), "report": report}
