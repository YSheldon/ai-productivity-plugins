from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from pre_release_audit import AuditChain, canonical_json
from pre_release_config import PreReleaseConfig
from pre_release_fallback import parse_fallback_mail
from pre_release_lock import RunOnceLock
from pre_release_mail import (
    ImapSmtpMailCliGateway,
    ProductGateCliGateway,
    PreReleaseMailError,
    decode_machine_event,
    encode_machine_event,
    message_transport_evidence,
    sha256_jsonable,
    sign_machine_event,
    verify_machine_event,
)
from release_workflow_core import (
    MailContractError,
    ValidationError,
    parse_message,
    validate_manifest_s,
)
from release_workflow_core.mail_contract import AuthenticationFailedError


VERIFIED_BADGE = "合规插件发起（已验证）"
PLAIN_BADGE = "普通邮件发起（未验证）"
_ALLOWED_TRANSPORT_BADGES = frozenset({VERIFIED_BADGE, PLAIN_BADGE})
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_TASK_STATE_HMAC_FIELD = "state_hmac_sha256"


class PreReleaseError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _absolute_path(value: str) -> str:
    return str(
        Path(
            os.path.abspath(
                os.path.expanduser(os.path.expandvars(str(value or "").strip()))
            )
        )
    )


def _operation_status(value: Mapping[str, Any]) -> str:
    direct = str(value.get("status") or "").strip()
    if direct:
        return direct
    event = value.get("event")
    return (
        str(event.get("status") or "").strip()
        if isinstance(event, Mapping)
        else ""
    )


def _deterministic_message_id(idempotency_key: str, *, sender_email: str) -> str:
    domain = str(sender_email or "").strip().rsplit("@", 1)[-1].lower()
    if not domain or domain == str(sender_email or "").strip().lower():
        raise PreReleaseError(
            "CONFIG_ERROR", "mail account email must provide a Message-ID domain"
        )
    digest = hashlib.sha256(str(idempotency_key).encode("utf-8")).hexdigest()
    return f"<pmg-prerelease-{digest}@{domain}>"


class PreReleaseController:
    def __init__(
        self,
        config: PreReleaseConfig,
        *,
        mail_gateway: ImapSmtpMailCliGateway,
        product_gate: ProductGateCliGateway,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self.mail_gateway = mail_gateway
        self.product_gate = product_gate
        self.now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self.state_dir = config.state_dir
        self.tasks_dir = self.state_dir / "tasks"
        self.lock_path = self.state_dir / "run-once.lock"
        self.secret_path = config.shared_hmac_secret_path
        self.audit = AuditChain(self.state_dir, self.secret_path)

    def verify_audit(self) -> dict[str, Any]:
        return self.audit.verify()

    def preflight(self) -> dict[str, Any]:
        issues: list[str] = []

        if not self.config.dependency_lock.exists():
            issues.append("dependency_lock")
        if not self.config.product_gate.config_path.exists():
            issues.append("product_gate_config")
        if not self.config.mail_command:
            issues.append("mail_command")
        if not self.secret_path.is_file():
            issues.append("state_hmac_secret")
        audit = self.verify_audit()
        if audit["valid"] is not True:
            issues.append("audit_chain")
        task_state = self._verify_task_states()
        if task_state["valid"] is not True:
            issues.append("task_state_integrity")
        return {"status": "ready" if not issues else "CAPABILITY_BLOCKED", "ready": not issues, "missing_capabilities": issues, "audit": audit, "task_state": task_state}

    def run_once(self) -> dict[str, Any]:
        audit = self.verify_audit()
        if audit["valid"] is not True:
            return {"status": "CAPABILITY_BLOCKED", "reason": "audit_chain_invalid", "audit": audit}
        task_state = self._verify_task_states()
        if task_state["valid"] is not True:
            return {
                "status": "CAPABILITY_BLOCKED",
                "reason": "task_state_integrity_invalid",
                "task_state": task_state,
                "audit": audit,
            }
        lock = RunOnceLock(self.lock_path)
        acquired = lock.acquire()
        if acquired["status"] != "acquired":
            return {"status": "RUN_ALREADY_ACTIVE", "busy": True}
        processed = 0
        blocked = 0
        retry_attempted = 0
        retry_sent = 0
        retry_pending = 0
        try:
            self.tasks_dir.mkdir(parents=True, exist_ok=True)
            for path in sorted(self.tasks_dir.glob("*.json")):
                task = self._read_task_path(path)
                if (
                    task.get("status") != "PRERELEASE_GATE_RUNNING"
                    or not isinstance(task.get("request_payload"), Mapping)
                ):
                    continue
                retry_attempted += 1
                try:
                    self._send_prerelease_request(task)
                    retry_sent += 1
                except PreReleaseError as exc:
                    if exc.code not in {
                        "OUTBOUND_RETRY_PENDING",
                        "OUTBOUND_RECEIPT_INVALID",
                    }:
                        raise
                    retry_pending += 1
            search = self.mail_gateway.search_messages({"mailbox": self.config.mailbox, "to": self.config.submission_group})
            for message_stub in search.get("messages", []):
                if not isinstance(message_stub, Mapping):
                    continue
                message = self.mail_gateway.read_message({"mailbox": self.config.mailbox, "uid": message_stub.get("uid")})
                result = self._store_submission_message(message)
                if result == "processed":
                    processed += 1
                elif result == "blocked":
                    blocked += 1
            return {
                "status": "ready",
                "matched_events": processed,
                "blocked": blocked,
                "pending_count": len(self._pending_tasks()),
                "retry_attempted": retry_attempted,
                "retry_sent": retry_sent,
                "retry_pending": retry_pending,
                "audit": self.verify_audit(),
            }
        finally:
            lock.release()

    def list_tasks(self) -> dict[str, Any]:
        audit = self.verify_audit()
        if audit["valid"] is not True:
            return {"status": "CAPABILITY_BLOCKED", "reason": "audit_chain_invalid", "audit": audit}
        task_state = self._verify_task_states()
        if task_state["valid"] is not True:
            return {
                "status": "CAPABILITY_BLOCKED",
                "reason": "task_state_integrity_invalid",
                "task_state": task_state,
                "audit": audit,
            }
        return {"status": "ready", "tasks": self._pending_tasks()}

    def create_request(
        self,
        *,
        event_id: str,
        round_id: int,
        test_result: str,
        summary: str,
        output_dir: str | None = None,
        tested_material_dir: str | None = None,
        report_ref: str | None = None,
        failure_reason: str | None = None,
    ) -> dict[str, Any]:
        audit = self.verify_audit()
        if audit["valid"] is not True:
            raise PreReleaseError("CAPABILITY_BLOCKED", "audit chain is invalid")
        task = self._load_task(event_id, round_id)
        if task.get("status") == "PRERELEASE_SENT":
            return {
                "status": "PRERELEASE_SENT",
                "event_id": event_id,
                "round_id": round_id,
                "manifest_r_digest": task.get("manifest_r_digest"),
                "message_id": task.get("request_message_id"),
            }
        normalized = str(test_result).strip().upper()
        summary_value = str(summary or "").strip()
        report_ref = str(report_ref or "").strip() or None
        if normalized not in {"PASS", "FAIL"}:
            raise PreReleaseError("INVALID_ARGUMENT", "test_result must be PASS or FAIL")
        if normalized == "FAIL" and not str(failure_reason or "").strip():
            raise PreReleaseError("INVALID_ARGUMENT", "FAIL requires failure_reason")
        if normalized == "FAIL":
            if task.get("request_intent"):
                raise PreReleaseError(
                    "REQUEST_INTENT_CONFLICT",
                    "a frozen PASS request cannot be changed to FAIL",
                )
            completed_at = self._timestamp()
            task["status"] = "TESTING"
            task["updated_at"] = completed_at
            self._save_task(task)
            self.audit.append(
                event_type="task_status_changed",
                status="TESTING",
                payload={
                    "event_id": event_id,
                    "round_id": round_id,
                    "summary": summary_value,
                },
            )
            task["test_result"] = {
                "result": "FAIL",
                "summary": summary_value,
                "failure_reason": str(failure_reason).strip(),
                "report_ref": report_ref,
                "completed_at": completed_at,
            }
            task["status"] = "TEST_FAILED"
            self._save_task(task)
            self.audit.append(
                event_type="task_status_changed",
                status="TEST_FAILED",
                payload={
                    "event_id": event_id,
                    "round_id": round_id,
                    "failure_reason": str(failure_reason).strip(),
                },
            )
            return {
                "status": "TEST_FAILED",
                "event_id": event_id,
                "round_id": round_id,
                "completed_at": completed_at,
            }

        if normalized == "PASS":
            if not str(output_dir or "").strip():
                raise PreReleaseError("INVALID_ARGUMENT", "PASS requires output_dir")
            if not str(tested_material_dir or "").strip():
                raise PreReleaseError(
                    "INVALID_ARGUMENT",
                    "PASS requires tested_material_dir",
                )
            if not isinstance(task.get("manifest_s"), Mapping):
                raise PreReleaseError(
                    "MISSING_MANIFEST_S",
                    "PASS requires the full verified Manifest-S from submission gate",
                )

        output_path = _absolute_path(str(output_dir))
        tested_path = _absolute_path(str(tested_material_dir))
        intent_values = {
            "test_result": "PASS",
            "summary": summary_value,
            "report_ref": report_ref or "",
            "output_dir": output_path,
            "tested_material_dir": tested_path,
        }
        existing_intent = task.get("request_intent")
        if existing_intent is not None:
            if not isinstance(existing_intent, Mapping) or any(
                existing_intent.get(key) != value
                for key, value in intent_values.items()
            ):
                raise PreReleaseError(
                    "REQUEST_INTENT_CONFLICT",
                    "pre-release request inputs differ from the frozen intent",
                )
            completed_at = str(existing_intent.get("completed_at") or "").strip()
            if not completed_at:
                raise PreReleaseError(
                    "STATE_INVALID",
                    "frozen pre-release request is missing completed_at",
                )
        else:
            completed_at = self._timestamp()
            task["request_intent"] = {
                **intent_values,
                "completed_at": completed_at,
            }
            self._save_task(task)
            self.audit.append(
                event_type="request_intent_frozen",
                status=str(task.get("status") or "TEST_READY"),
                payload={
                    "event_id": event_id,
                    "round_id": round_id,
                    "intent_digest": hashlib.sha256(
                        canonical_json(intent_values).encode("utf-8")
                    ).hexdigest(),
                },
            )

        if (
            task.get("status") == "PRERELEASE_GATE_RUNNING"
            and isinstance(task.get("request_payload"), Mapping)
        ):
            return self._send_prerelease_request(task)

        artifacts = task["manifest_s"].get("artifacts")
        first_source_ref = ""
        if isinstance(artifacts, list):
            for artifact in artifacts:
                if isinstance(artifact, Mapping) and str(artifact.get("source_ref") or "").strip():
                    first_source_ref = str(artifact["source_ref"]).strip()
                    break
        source_ref = str(task.get("source_ref") or first_source_ref).strip()
        if not source_ref and task.get("retrieval_method") == "svn":
            provenance = task.get("retrieval_provenance") or {}
            source_ref = (
                f"{provenance.get('repository_path', '')}@{provenance.get('revision', '')}"
            ).strip("@")
        if not source_ref:
            source_ref = str(task.get("gitlab_evidence_ref") or "").strip()
        import_payload = {
            "event_id": event_id,
            "round_number": round_id,
            "task_id": task["task"],
            "module": task["module"],
            "manifest_s": task["manifest_s"],
            "tested_material_dir": tested_path,
            "source_ref": source_ref,
            "rollback_ref": str(task.get("rollback_ref") or "").strip(),
            "risk_level": str(task.get("risk_level") or "standard"),
            "rule_snapshot_id": task["submission_policy_digest"],
        }
        try:
            imported = self.product_gate.call(
                "import_submission_gate_handoff",
                import_payload,
            )
        except Exception as exc:
            task["status"] = "PRERELEASE_BLOCKED"
            task["blocked_reason"] = "SUBMISSION_IMPORT_FAILED"
            self._save_task(task)
            self.audit.append(
                event_type="task_status_changed",
                status="PRERELEASE_BLOCKED",
                payload={
                    "event_id": event_id,
                    "round_id": round_id,
                    "reason": "SUBMISSION_IMPORT_FAILED",
                },
            )
            raise PreReleaseError("SUBMISSION_IMPORT_FAILED", str(exc)) from exc
        authoritative_status = _operation_status(imported)
        if not authoritative_status:
            task["status"] = "PRERELEASE_BLOCKED"
            task["blocked_reason"] = "SUBMISSION_IMPORT_STATUS_MISSING"
            self._save_task(task)
            raise PreReleaseError(
                "SUBMISSION_IMPORT_STATUS_MISSING",
                "product-release-gate did not return an authoritative workflow status",
            )
        if authoritative_status == "TESTING":
            task["status"] = "TESTING"
            task["updated_at"] = completed_at
            self._save_task(task)
            self.audit.append(
                event_type="task_status_changed",
                status="TESTING",
                payload={
                    "event_id": event_id,
                    "round_id": round_id,
                    "summary": summary_value,
                },
            )
            recorded = self.product_gate.call(
                "record_test_result",
                {
                    "event_id": event_id,
                    "test_result": "PASS",
                    "report_ref": report_ref
                    or f"pre-release:{event_id}:{round_id}",
                    "summary": summary_value,
                },
            )
            authoritative_status = _operation_status(recorded)

        task["test_result"] = {
            "result": "PASS",
            "summary": summary_value,
            "report_ref": report_ref,
            "completed_at": completed_at,
        }
        if authoritative_status == "TEST_APPROVAL_REQUIRED":
            task["status"] = "TEST_APPROVAL_REQUIRED"
            task["updated_at"] = self._timestamp()
            self._save_task(task)
            self.audit.append(
                event_type="task_status_changed",
                status="TEST_APPROVAL_REQUIRED",
                payload={
                    "event_id": event_id,
                    "round_id": round_id,
                    "report_ref": report_ref,
                },
            )
            return {
                "status": "TEST_APPROVAL_REQUIRED",
                "event_id": event_id,
                "round_id": round_id,
                "next_action": "record test approval, then rerun this frozen request",
            }
        if authoritative_status not in {"RELEASE_PREPARING", "RELEASE_GATING"}:
            task["status"] = "PRERELEASE_BLOCKED"
            task["blocked_reason"] = (
                f"UNSUPPORTED_AUTHORITATIVE_STATUS:{authoritative_status or 'missing'}"
            )
            self._save_task(task)
            raise PreReleaseError(
                "AUTHORITATIVE_STATE_BLOCKED",
                "product-release-gate is not ready to freeze final material: "
                + (authoritative_status or "missing status"),
            )

        task["status"] = "TEST_PASSED"
        self._save_task(task)
        self.audit.append(
            event_type="task_status_changed",
            status="TEST_PASSED",
            payload={
                "event_id": event_id,
                "round_id": round_id,
                "report_ref": report_ref,
            },
        )
        built = self.product_gate.call(
            "build_final_release",
            {"event_id": event_id, "output_dir": output_path},
        )
        manifest_r_digest = str(built.get("manifest_r_digest") or built.get("final_manifest_digest") or "").strip()
        if not manifest_r_digest:
            raise PreReleaseError("MISSING_MANIFEST_R_DIGEST", "build_final_release must return one manifest_r_digest")
        manifest_r_ref = str(built.get("manifest_r_ref") or built.get("final_manifest_path") or built.get("output_ref") or output_path).strip()
        task["manifest_r_digest"] = manifest_r_digest
        task["manifest_r_ref"] = manifest_r_ref
        task["status"] = "PRERELEASE_GATE_RUNNING"
        task["request_idempotency_key"] = "sha256:" + hashlib.sha256(
            canonical_json(
                {
                    "event_id": event_id,
                    "round_id": round_id,
                    "manifest_r_digest": manifest_r_digest,
                    "intent": intent_values,
                }
            ).encode("utf-8")
        ).hexdigest()
        task["request_message_id"] = _deterministic_message_id(
            task["request_idempotency_key"],
            sender_email=self.config.mail_account.email,
        )
        task["request_payload"] = self._build_request_payload(task, summary=summary_value, report_ref=report_ref, completed_at=completed_at, manifest_r_digest=manifest_r_digest, manifest_r_ref=manifest_r_ref)
        task["request_subject"] = f"【发布门禁检查】{task['task']}-{task['module']}-{completed_at[:10]}"
        self._save_task(task)
        self.audit.append(event_type="task_status_changed", status="PRERELEASE_GATE_RUNNING", payload={"event_id": event_id, "round_id": round_id, "manifest_r_digest": manifest_r_digest, "origin_badge": task["origin_badge"]})
        return self._send_prerelease_request(task)

    def status(self) -> dict[str, Any]:
        audit = self.verify_audit()
        if audit["valid"] is not True:
            return {"status": "CAPABILITY_BLOCKED", "reason": "audit_chain_invalid", "audit": audit}
        task_state = self._verify_task_states()
        if task_state["valid"] is not True:
            return {
                "status": "CAPABILITY_BLOCKED",
                "reason": "task_state_integrity_invalid",
                "task_state": task_state,
                "audit": audit,
            }
        return {"status": "ready", "pending_count": len(self._pending_tasks()), "scheduler_mode": "os", "audit": audit, "task_state": task_state}

    def doctor(self) -> dict[str, Any]:
        preflight = self.preflight()
        return {"status": preflight["status"], "ready": preflight["ready"], "checks": preflight["missing_capabilities"], "codex_required": False, "audit": preflight["audit"]}

    def _store_submission_message(self, message: Mapping[str, Any]) -> str:
        parsed = self._parse_submission_message(message)
        if parsed is None:
            return "ignored"
        if parsed.get("blocked_reason"):
            self.audit.append(event_type="submission_blocked", status="TEST_READY", payload={"reason": parsed["blocked_reason"], "message_id": parsed["transport"]["message_id"]})
            return "blocked"
        task = dict(parsed["task"])
        path = self._task_path(str(task["event_id"]), int(task["round_id"]))
        if path.exists():
            self._read_task_path(path)
            return "ignored"
        self._save_task(task)
        self.audit.append(
            event_type="submission_synced",
            status="TEST_READY",
            payload={
                "event_id": task["event_id"],
                "round_id": task["round_id"],
                "source_transport_digest": task["source_transport_digest"],
                "machine_event_digest": task["machine_event_digest"],
                "submission_policy_digest": task["submission_policy_digest"],
                "retrieval_method": task["retrieval_method"],
                "origin_badge": task["origin_badge"],
            },
        )
        return "processed"

    def _parse_submission_message(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        body_text = str(message.get("body_text") or "")
        evidence = message_transport_evidence(message)
        payload: dict[str, Any] | None = None
        verified = False
        if "-----BEGIN PRODUCT MATERIAL WORKFLOW-----" in body_text:
            headers = message.get("headers")
            try:
                payload = parse_message(
                    body_text,
                    secret=self._secret_bytes() if self.secret_path.exists() else None,
                    headers=headers if isinstance(headers, Mapping) else None,
                )
            except AuthenticationFailedError:
                return {
                    "blocked_reason": "AUTHENTICATION_FAILED",
                    "transport": evidence,
                }
            except MailContractError:
                return {
                    "blocked_reason": "MACHINE_EVENT_INVALID",
                    "transport": evidence,
                }
            verified = (
                payload.get("provenance_classification")
                == "COMPLIANT_PLUGIN_VERIFIED"
            )
        else:
            try:
                payload = decode_machine_event(body_text)
            except PreReleaseMailError:
                payload = None
        if payload is not None:
            if "mail_contract" not in payload:
                claimed_hmac = str(payload.get("hmac_sha256") or "").strip()
                if claimed_hmac:
                    if not self.secret_path.exists():
                        return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
                    if not verify_machine_event(payload, self._secret_bytes()):
                        return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
                    verified = True
            source = dict(payload)
        else:
            source = parse_fallback_mail(body_text)
        if source.get("event_type") not in {None, "SUBMISSION_GATE_PASS"}:
            return None
        required_fields = ("event_id", "round_id", "task", "module", "manifest_s_digest")
        if any(not str(source.get(field) or "").strip() for field in required_fields):
            return None
        retrieval_method = str(source.get("retrieval_method") or "build").strip().lower()
        if retrieval_method == "svn":
            retrieval_provenance = source.get("retrieval_provenance")
            if not isinstance(retrieval_provenance, Mapping):
                return None
            if not str(retrieval_provenance.get("repository_path") or "").strip():
                return None
            if not str(retrieval_provenance.get("revision") or "").strip():
                return None
            retrieval_provenance_digest = str(source.get("retrieval_provenance_digest") or sha256_jsonable({"repository_path": str(retrieval_provenance.get("repository_path")), "revision": str(retrieval_provenance.get("revision"))}))
            gitlab_evidence_digest = ""
            gitlab_evidence_ref = ""
        else:
            gitlab_evidence_ref = str(source.get("gitlab_evidence_ref") or "").strip()
            if not gitlab_evidence_ref:
                return None
            gitlab_evidence_digest = str(source.get("gitlab_evidence_digest") or sha256_jsonable({"gitlab_evidence_ref": gitlab_evidence_ref}))
            retrieval_provenance_digest = ""
            retrieval_provenance = {}
        policy_digest = str(source.get("policy_digest") or source.get("submission_policy_digest") or "").strip()
        if not policy_digest:
            return None
        raw_manifest_s = source.get("manifest_s")
        manifest_s: dict[str, Any] | None = None
        if isinstance(raw_manifest_s, Mapping):
            try:
                manifest_s = validate_manifest_s(
                    raw_manifest_s,
                    expected_bindings={
                        "event_id": str(source["event_id"]),
                        "round_id": int(source["round_id"]),
                        "task": str(source["task"]),
                        "module": str(source["module"]),
                        "policy_digest": policy_digest,
                        "manifest_s_digest": str(
                            source["manifest_s_digest"]
                        ).strip().lower(),
                    },
                )
            except (ValidationError, TypeError, ValueError):
                return {
                    "blocked_reason": "MANIFEST_S_INVALID",
                    "transport": evidence,
                }
        thread_references = source.get("thread_references")
        if verified:
            if not isinstance(thread_references, list) or not thread_references:
                return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
            source_message_id = str(source.get("source_message_id") or "").strip()
            actual_references = list(evidence["references"])
            if not source_message_id or (
                source_message_id != evidence["message_id"]
                and source_message_id not in actual_references
            ):
                return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
            if actual_references != [str(item).strip() for item in thread_references]:
                return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
            origin_badge = VERIFIED_BADGE
        else:
            actual_references = list(evidence["references"]) or [evidence["message_id"]]
            origin_badge = PLAIN_BADGE
        checked_items = source.get("checked_items")
        if isinstance(checked_items, list) and checked_items:
            normalized_checks = [str(item).strip() for item in checked_items if str(item).strip()]
        else:
            normalized_checks = ["human_mail_reviewed"]
        policy_snapshot = self._policy_snapshot()
        source_message_id = str(source.get("source_message_id") or evidence["message_id"]).strip()
        submitter_email = str(source.get("submitter_email") or source.get("sender_email") or "").strip().lower()
        if submitter_email and not _EMAIL_RE.fullmatch(submitter_email):
            submitter_email = ""
        task = {
            "event_id": str(source["event_id"]),
            "round_id": int(source["round_id"]),
            "task": str(source["task"]),
            "module": str(source["module"]),
            "manifest_s_digest": str(source["manifest_s_digest"]),
            "manifest_s": manifest_s,
            "manifest_s_status": "verified" if manifest_s is not None else "missing",
            "artifacts": (
                manifest_s.get("artifacts", [])
                if manifest_s is not None
                else source.get("artifacts", [])
            ),
            "source_uid": evidence["uid"],
            "source_message_id": source_message_id,
            "thread_references": actual_references,
            "source_transport_digest": sha256_jsonable(evidence),
            "machine_event_digest": sha256_jsonable(payload) if payload is not None else "",
            "submission_policy_digest": policy_digest,
            "pre_release_policy_digest": policy_snapshot["policy_digest"],
            "policy_profile": policy_snapshot["policy_profile"],
            "retrieval_method": retrieval_method,
            "retrieval_provenance_digest": retrieval_provenance_digest,
            "retrieval_provenance": dict(retrieval_provenance) if isinstance(retrieval_provenance, Mapping) else {},
            "gitlab_evidence_digest": gitlab_evidence_digest,
            "gitlab_evidence_ref": gitlab_evidence_ref,
            "lark_evidence_ref": str(source.get("lark_evidence_ref") or "").strip(),
            "checked_items": normalized_checks,
            "submitter_email": submitter_email,
            "submitter_email_status": "valid" if submitter_email else "missing_or_invalid",
            "source_ref": str(source.get("source_ref") or "").strip(),
            "rollback_ref": str(source.get("rollback_ref") or "").strip(),
            "risk_level": str(source.get("risk_level") or "standard").strip(),
            "status": "TEST_READY",
            "origin_badge": origin_badge,
            "transport_badge": VERIFIED_BADGE if verified else PLAIN_BADGE,
            "synced_at": self._timestamp(),
        }
        if not task["lark_evidence_ref"]:
            return None
        return {"task": task, "transport": evidence}

    def _send_prerelease_request(self, task: dict[str, Any]) -> dict[str, Any]:
        payload = dict(task["request_payload"])
        persisted_badge = self._validate_outbound_transport_badge(task, payload)
        body_lines = [
            f"事件：{task['event_id']}#{task['round_id']}",
            f"任务：{task['task']}",
            f"模块：{task['module']}",
            f"状态：PRERELEASE_SENT",
            "策略冻结：",
            f"- 提测门禁策略摘要：{task['submission_policy_digest']}",
            f"- 预发布策略摘要：{task['pre_release_policy_digest']}",
            "检查结果：",
            ("- HMAC：PASS" if persisted_badge == VERIFIED_BADGE else "- 人工回退：PASS"),
            f"- 来源标识：{persisted_badge}",
            f"- 传输标识：{persisted_badge}",
            "- Manifest：PASS",
            *([f"- SVN 固定版本：PASS"] if task.get("retrieval_method") == "svn" else [f"- GitLab 构建证据：PASS"]),
            "证据引用：",
            f"- Manifest-S：{task['manifest_s_digest']}",
            f"- Manifest-R：{task['manifest_r_digest']}",
            f"- Manifest-R Ref：{task['manifest_r_ref']}",
            *([f"- SVN：{task['retrieval_provenance'].get('repository_path')}@{task['retrieval_provenance'].get('revision')}"] if task.get("retrieval_method") == "svn" else [f"- GitLab：{task['gitlab_evidence_ref']}"]),
            f"- 飞书：{task['lark_evidence_ref']}",
            f"提测人邮箱：{task.get('submitter_email') or '未提供'}",
            f"发起标识：{task['origin_badge']}",
            encode_machine_event(payload),
        ]
        try:
            references = [
                str(item).strip()
                for item in task.get("thread_references", [])
                if str(item).strip()
            ]
            send_result = self.mail_gateway.send_email(
                {
                    "profile": self.config.mail_account.profile,
                    "to": [self.config.release_gate_group],
                    "subject": task["request_subject"],
                    "body_text": "\n".join(body_lines),
                    "headers": (
                        {"X-RD-Submitter-Email": task["submitter_email"]}
                        if task.get("submitter_email")
                        else {}
                    ),
                    "references": references,
                    "in_reply_to": references[-1] if references else "",
                    "message_id": task["request_message_id"],
                }
            )
        except Exception as exc:
            self.audit.append(event_type="outbound_request_retry_pending", status="PRERELEASE_GATE_RUNNING", payload={"event_id": task["event_id"], "round_id": task["round_id"], "idempotency_key": task["request_idempotency_key"]})
            raise PreReleaseError("OUTBOUND_RETRY_PENDING", str(exc)) from exc
        returned_message_id = str(send_result.get("message_id") or "").strip()
        if returned_message_id != task["request_message_id"]:
            self.audit.append(
                event_type="outbound_receipt_invalid",
                status="PRERELEASE_GATE_RUNNING",
                payload={
                    "event_id": task["event_id"],
                    "round_id": task["round_id"],
                    "expected_message_id": task["request_message_id"],
                    "returned_message_id": returned_message_id,
                },
            )
            raise PreReleaseError(
                "OUTBOUND_RECEIPT_INVALID",
                "mail gateway did not confirm the deterministic Message-ID",
            )
        task["status"] = "PRERELEASE_SENT"
        task["outbound_receipt"] = {
            "message_id": returned_message_id,
            "idempotency_key": task["request_idempotency_key"],
        }
        self._save_task(task)
        self.audit.append(event_type="outbound_request_sent", status="PRERELEASE_SENT", payload={"event_id": task["event_id"], "round_id": task["round_id"], "message_id": returned_message_id, "origin_badge": task["origin_badge"]})
        return {"status": "PRERELEASE_SENT", "event_id": task["event_id"], "round_id": task["round_id"], "manifest_r_digest": task["manifest_r_digest"], "message_id": returned_message_id}

    def _build_request_payload(self, task: Mapping[str, Any], *, summary: str, report_ref: str | None, completed_at: str, manifest_r_digest: str, manifest_r_ref: str) -> dict[str, Any]:
        checked = list(task["checked_items"]) + ["tester_pass", "manifest_r_built"]
        payload = {
            "contract": "ProductMaterialWorkflow/v1",
            "event_type": "PRERELEASE_REQUEST",
            "event_id": task["event_id"],
            "round_id": task["round_id"],
            "task": task["task"],
            "module": task["module"],
            "source_message_id": task["source_message_id"],
            "thread_references": list(task["thread_references"]),
            "manifest_s_digest": task["manifest_s_digest"],
            "manifest_r_digest": manifest_r_digest,
            "manifest_r_ref": manifest_r_ref,
            "tested_manifest_digest": task["manifest_s_digest"],
            "test_result": "PASS",
            "summary": summary,
            "report_ref": report_ref,
            "completed_at": completed_at,
            "submission_policy_digest": task["submission_policy_digest"],
            "pre_release_policy_digest": task["pre_release_policy_digest"],
            "policy_digest": task["pre_release_policy_digest"],
            "policy_profile": task["policy_profile"],
            "retrieval_method": task["retrieval_method"],
            "retrieval_provenance_digest": task["retrieval_provenance_digest"],
            "retrieval_provenance": dict(task.get("retrieval_provenance") or {}),
            "gitlab_evidence_digest": task["gitlab_evidence_digest"],
            "gitlab_evidence_ref": task["gitlab_evidence_ref"],
            "lark_evidence_ref": task["lark_evidence_ref"],
            "checked_items": checked,
            "submitter_email": task.get("submitter_email", ""),
            "source_origin_badge": task["origin_badge"],
            "transport_badge": self._validated_task_transport_badge(task),
        }
        if self.secret_path.exists():
            return sign_machine_event(payload, self._secret_bytes())
        return payload

    def _validated_task_transport_badge(self, task: Mapping[str, Any]) -> str:
        transport_badge = str(task.get("transport_badge") or "").strip()
        origin_badge = str(task.get("origin_badge") or "").strip()
        if transport_badge not in _ALLOWED_TRANSPORT_BADGES or origin_badge not in _ALLOWED_TRANSPORT_BADGES:
            raise PreReleaseError("TRANSPORT_BADGE_MISMATCH", "persisted transport badge is missing or invalid")
        if origin_badge != transport_badge:
            raise PreReleaseError("TRANSPORT_BADGE_MISMATCH", "persisted origin and transport badges differ")
        return transport_badge

    def _validate_outbound_transport_badge(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
        persisted_task = self._load_task(str(task["event_id"]), int(task["round_id"]))
        persisted_badge = self._validated_task_transport_badge(persisted_task)
        in_memory_badge = self._validated_task_transport_badge(task)
        outbound_badge = str(payload.get("transport_badge") or "").strip()
        outbound_origin_badge = str(payload.get("source_origin_badge") or "").strip()
        if not (
            persisted_badge
            == in_memory_badge
            == outbound_badge
            == outbound_origin_badge
        ):
            raise PreReleaseError(
                "TRANSPORT_BADGE_MISMATCH",
                "persisted, in-memory, and outbound transport badges differ",
            )
        return persisted_badge

    def _policy_snapshot(self) -> dict[str, str]:
        payload = {"profile": self.config.policy_profile, "enabled_optional_checks": list(self.config.enabled_optional_checks)}
        return {"policy_profile": self.config.policy_profile, "policy_digest": hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()}

    def _pending_tasks(self) -> list[dict[str, Any]]:
        tasks = []
        for path in sorted(self.tasks_dir.glob("*.json")):
            payload = self._read_task_path(path)
            if payload.get("status") == "PRERELEASE_SENT":
                continue
            tasks.append({"event_id": payload["event_id"], "round_id": payload["round_id"], "task": payload["task"], "module": payload["module"], "manifest_s_digest": payload["manifest_s_digest"], "status": payload["status"], "source_uid": payload["source_uid"]})
        return tasks

    def _load_task(self, event_id: str, round_id: int) -> dict[str, Any]:
        path = self._task_path(event_id, round_id)
        if not path.exists():
            raise PreReleaseError("NOT_FOUND", f"task not found: {event_id}#{round_id}")
        return self._read_task_path(path)

    def _save_task(self, task: Mapping[str, Any]) -> None:
        path = self._task_path(str(task["event_id"]), int(task["round_id"]))
        path.parent.mkdir(parents=True, exist_ok=True)
        if not self.secret_path.is_file():
            raise PreReleaseError(
                "CAPABILITY_BLOCKED",
                "task state HMAC secret is unavailable",
            )
        sealed = dict(task)
        sealed.pop(_TASK_STATE_HMAC_FIELD, None)
        sealed[_TASK_STATE_HMAC_FIELD] = hmac.new(
            self._secret_bytes(),
            canonical_json(sealed).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        temporary.write_text(json.dumps(sealed, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)

    def _read_task_path(self, path: Path) -> dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PreReleaseError(
                "STATE_INTEGRITY_INVALID",
                f"task state is unreadable: {path.name}",
            ) from exc
        if not isinstance(payload, dict) or not self.secret_path.is_file():
            raise PreReleaseError(
                "STATE_INTEGRITY_INVALID",
                f"task state cannot be authenticated: {path.name}",
            )
        claimed = str(payload.pop(_TASK_STATE_HMAC_FIELD, "")).strip().lower()
        expected = hmac.new(
            self._secret_bytes(),
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not claimed or not hmac.compare_digest(claimed, expected):
            raise PreReleaseError(
                "STATE_INTEGRITY_INVALID",
                f"task state HMAC differs: {path.name}",
            )
        payload[_TASK_STATE_HMAC_FIELD] = claimed
        return payload

    def _verify_task_states(self) -> dict[str, Any]:
        if not self.secret_path.is_file():
            return {
                "valid": False,
                "reason": "state_hmac_secret_unavailable",
                "checked": 0,
            }
        checked = 0
        try:
            for path in sorted(self.tasks_dir.glob("*.json")):
                self._read_task_path(path)
                checked += 1
        except PreReleaseError as exc:
            return {
                "valid": False,
                "reason": str(exc),
                "checked": checked,
            }
        return {"valid": True, "checked": checked}

    def _task_path(self, event_id: str, round_id: int) -> Path:
        return self.tasks_dir / f"{event_id}--{round_id}.json"

    def _secret_bytes(self) -> bytes:
        return self.secret_path.read_bytes()

    def _timestamp(self) -> str:
        return self.now_fn().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
