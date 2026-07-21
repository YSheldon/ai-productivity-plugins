from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from release_gate_audit import AuditChain, canonical_json
from release_gate_config import CANONICAL_REQUIRED_CHECKS, ReleaseGateConfig, missing_canonical_required_checks
from release_gate_fallback import parse_fallback_mail
from release_workflow_gate_lock import RunOnceLock
from release_workflow_core.version import CORE_VERSION

WORKFLOW_CORE_DIGEST = hashlib.sha256(CORE_VERSION.encode("utf-8")).hexdigest()
from release_gate_mail import (
    ImapSmtpMailCliGateway,
    ProductGateCliGateway,
    ReleaseGateMailError,
    decode_machine_event,
    encode_machine_event,
    message_transport_evidence,
    sha256_jsonable,
    sign_machine_event,
    verify_machine_event,
)


VERIFIED_BADGE = "合规插件发起（已验证）"
PLAIN_BADGE = "普通邮件发起（未验证）"
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SHA256_RE = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")
_AUTHORITATIVE_PROVENANCE_ERROR = "AUTHORITATIVE_PROVENANCE_UNAVAILABLE"


class ReleaseGateError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReleaseGateController:
    def __init__(
        self,
        config: ReleaseGateConfig,
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
        self.events_dir = self.state_dir / "events"
        self.lock_path = self.state_dir / "run-once.lock"
        self.audit = AuditChain(self.state_dir, config.shared_hmac_secret_path)

    def coordination_lock_path(self) -> Path:
        """Return the host-level lock shared by duplicate configurations.

        A host-level singleton is the safe default: duplicate mailbox or task
        registrations must not fan out into concurrent IMAP and gate scans.
        Set RELEASE_GATE_COORDINATION_SCOPE=mailbox only when deliberate
        per-mailbox parallelism is provisioned and capacity-tested.
        """
        root_value = str(os.environ.get("RELEASE_GATE_COORDINATION_DIR") or "").strip()
        if root_value:
            root = Path(os.path.expandvars(root_value)).expanduser()
        elif os.name == "nt":
            root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "ProductMaterialGate" / "locks"
        else:
            root = Path(os.environ.get("XDG_RUNTIME_DIR") or Path.home() / ".cache") / "product-material-gate" / "locks"
        scope_mode = str(os.environ.get("RELEASE_GATE_COORDINATION_SCOPE") or "host").strip().lower()
        if scope_mode not in {"host", "mailbox"}:
            scope_mode = "host"
        scope_payload: dict[str, str] = {"host": socket.gethostname()}
        if scope_mode == "mailbox":
            scope_payload.update({"mailbox": self.config.mailbox, "release_gate_group": self.config.release_gate_group})
        scope = json.dumps(scope_payload, sort_keys=True, separators=(",", ":"))
        suffix = "host" if scope_mode == "host" else "mailbox"
        digest = hashlib.sha256(scope.encode("utf-8")).hexdigest()[:32]
        return (root / f"release-gate-{suffix}-{digest}.lock").resolve(strict=False)

    def verify_audit(self) -> dict[str, Any]:
        return self.audit.verify()

    def preflight(self) -> dict[str, Any]:
        issues: list[str] = []

        if not self.config.dependency_lock.exists():
            issues.append("dependency_lock")
        if not self.config.product_gate.config_path.exists():
            issues.append("product_gate_config")
        missing = missing_canonical_required_checks(self.config.required_checks)
        if missing:
            issues.append("missing_required_checks:" + ",".join(missing))
        if not self._policy_valid():
            issues.append("effective_checks")
        audit = self.verify_audit()
        if audit["valid"] is not True:
            issues.append("audit_chain")
        return {"status": "ready" if not issues else "CAPABILITY_BLOCKED", "ready": not issues, "missing_capabilities": issues, "audit": audit}

    def run_once(self) -> dict[str, Any]:
        audit = self.verify_audit()
        if audit["valid"] is not True:
            return {"status": "CAPABILITY_BLOCKED", "reason": "audit_chain_invalid", "audit": audit}
        if not self._policy_valid():
            return {"status": "CAPABILITY_BLOCKED", "reason": "gate_policy_invalid", "audit": audit}
        coordination_lock = RunOnceLock(self.coordination_lock_path())
        coordination_acquired = coordination_lock.acquire()
        if coordination_acquired["status"] != "acquired":
            return {"status": "RUN_ALREADY_ACTIVE", "busy": True, "scope": "mailbox"}
        lock = RunOnceLock(self.lock_path)
        acquired = lock.acquire()
        if acquired["status"] != "acquired":
            coordination_lock.release()
            return {"status": "RUN_ALREADY_ACTIVE", "busy": True, "scope": "configuration"}
        processed = 0
        blocked = 0
        retried = 0
        try:
            self.events_dir.mkdir(parents=True, exist_ok=True)
            retried += self._retry_pending_outbound()
            search = self.mail_gateway.search_messages({"mailbox": self.config.mailbox, "to": self.config.release_gate_group})
            for stub in search.get("messages", []):
                if not isinstance(stub, Mapping):
                    continue
                message = self.mail_gateway.read_message({"mailbox": self.config.mailbox, "uid": stub.get("uid")})
                result = self._process_message(message)
                if result == "processed":
                    processed += 1
                elif result == "blocked":
                    blocked += 1
            return {"status": "ready", "processed": processed, "blocked": blocked, "retried": retried, "audit": self.verify_audit()}
        finally:
            lock.release()
            coordination_lock.release()

    def status(self) -> dict[str, Any]:
        audit = self.verify_audit()
        if audit["valid"] is not True:
            return {"status": "CAPABILITY_BLOCKED", "reason": "audit_chain_invalid", "audit": audit}
        events = [path for path in self.events_dir.glob("*.json")] if self.events_dir.exists() else []
        return {"status": "ready", "event_count": len(events), "scheduler_mode": "os", "audit": audit}

    def doctor(self) -> dict[str, Any]:
        preflight = self.preflight()
        return {"status": preflight["status"], "ready": preflight["ready"], "checks": preflight["missing_capabilities"], "codex_required": False, "audit": preflight["audit"]}

    def _process_message(self, message: Mapping[str, Any]) -> str:
        parsed = self._parse_prerelease_request(message)
        if parsed is None:
            return "ignored"
        if parsed.get("blocked_reason"):
            self.audit.append(event_type="release_gate_authentication_failed", status="RELEASE_GATE_RUNNING", payload={"reason": parsed["blocked_reason"], "message_id": parsed["transport"]["message_id"]})
            return "blocked"
        record = dict(parsed["record"])
        record_path = self._event_path(str(record["event_id"]), int(record["round_id"]))
        if record_path.exists():
            existing = json.loads(record_path.read_text(encoding="utf-8"))
            if existing.get("status") == "RELEASE_READY" and existing.get("pending_notice"):
                self._retry_notice(existing)
            return "ignored"
        self._save_event(record)
        self.audit.append(event_type="release_gate_received", status="RELEASE_GATE_RUNNING", payload={"event_id": record["event_id"], "round_id": record["round_id"], "source_transport_digest": record["source_transport_digest"], "machine_event_digest": record["machine_event_digest"], "retrieval_method": record["retrieval_method"], "origin_badge": record["origin_badge"]})

        gate_result = self.product_gate.call("run_release_gate", {"event_id": record["event_id"]})
        gate_status = str(gate_result.get("status") or "")
        if gate_status not in {"RELEASE_GATE_PASSED", "ready", "RELEASE_READY"}:
            record["status"] = "RELEASE_GATE_BLOCKED"
            record["decision"] = "RELEASE_GATE_BLOCKED"
            record["blocked_reason"] = gate_status or "RELEASE_GATE_BLOCKED"
            record["release_gate_result"] = dict(gate_result)
            if record.get("transport_badge") == VERIFIED_BADGE:
                record["pending_notice"] = self._build_outbound_notice(record, success=False)
            else:
                record.pop("pending_notice", None)
            self._save_event(record)
            self.audit.append(event_type="release_gate_blocked", status="RELEASE_GATE_BLOCKED", payload={"event_id": record["event_id"], "round_id": record["round_id"], "blocked_reason": record["blocked_reason"]})
            if record.get("transport_badge") == VERIFIED_BADGE:
                self._retry_notice(record)
            return "blocked"

        record["status"] = "RELEASE_READY"
        record["release_gate_result"] = dict(gate_result)
        if record.get("transport_badge") != VERIFIED_BADGE:
            try:
                authoritative_state = self.product_gate.call("get_event", {"event_id": record["event_id"]})
                self._rebind_fallback_provenance(record, authoritative_state)
            except Exception:
                record["status"] = "RELEASE_GATE_BLOCKED"
                record["decision"] = "RELEASE_GATE_BLOCKED"
                record["blocked_reason"] = _AUTHORITATIVE_PROVENANCE_ERROR
                record.pop("pending_notice", None)
                self._save_event(record)
                self.audit.append(
                    event_type="release_gate_authoritative_provenance_failed",
                    status="RELEASE_GATE_BLOCKED",
                    payload={
                        "event_id": record["event_id"],
                        "round_id": record["round_id"],
                        "blocked_reason": _AUTHORITATIVE_PROVENANCE_ERROR,
                    },
                )
                return "blocked"
        record["pending_notice"] = self._build_outbound_notice(record, success=True)
        self._save_event(record)
        self.audit.append(event_type="release_gate_passed", status="RELEASE_READY", payload={"event_id": record["event_id"], "round_id": record["round_id"], "origin_badge": record["origin_badge"]})
        self._retry_notice(record)
        return "processed"

    def _retry_pending_outbound(self) -> int:
        count = 0
        for path in sorted(self.events_dir.glob("*.json")) if self.events_dir.exists() else []:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("pending_notice"):
                self._retry_notice(payload)
                count += 1
        return count

    def _retry_notice(self, record: dict[str, Any]) -> None:
        notice = dict(record.get("pending_notice") or {})
        if not notice:
            return
        try:
            send_result = self.mail_gateway.send_email(notice["mail"])
        except Exception:
            self.audit.append(event_type="outbound_notice_retry_pending", status=str(record.get("status") or "RELEASE_GATE_RUNNING"), payload={"event_id": record["event_id"], "round_id": record["round_id"], "decision": record.get("decision", "RELEASE_GATE_PASS")})
            self._save_event(record)
            return
        if notice.get("success"):
            record["status"] = "RELEASE_READY_NOTIFIED"
        record["notice_message_id"] = send_result.get("message_id")
        record["outbound_receipt"] = {"message_id": send_result.get("message_id"), "decision": record.get("decision", "RELEASE_GATE_PASS")}
        record.pop("pending_notice", None)
        self._save_event(record)
        self.audit.append(event_type="outbound_notice_sent", status=str(record.get("status") or "RELEASE_GATE_RUNNING"), payload={"event_id": record["event_id"], "round_id": record["round_id"], "message_id": send_result.get("message_id")})

    def _parse_prerelease_request(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        body_text = str(message.get("body_text") or "")
        evidence = message_transport_evidence(message)
        payload: dict[str, Any] | None = None
        verified = False
        try:
            payload = decode_machine_event(body_text)
        except ReleaseGateMailError:
            payload = None
        if payload is not None:
            claimed_hmac = str(payload.get("hmac_sha256") or "").strip()
            if claimed_hmac:
                if not self.config.shared_hmac_secret_path.exists():
                    return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
                if not verify_machine_event(payload, self.config.shared_hmac_secret_path.read_bytes()):
                    return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
                verified = True
            source = dict(payload)
        else:
            source = parse_fallback_mail(body_text)
        if source.get("event_type") not in {None, "PRERELEASE_REQUEST"}:
            return None
        required_fields = ("event_id", "round_id", "task", "module")
        if verified:
            required_fields += ("manifest_s_digest", "manifest_r_digest")
        if any(not str(source.get(field) or "").strip() for field in required_fields):
            return None
        thread_references = source.get("thread_references")
        if verified:
            if not isinstance(thread_references, list) or not thread_references:
                return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
            actual_references = list(evidence["references"])
            if actual_references != [str(item).strip() for item in thread_references]:
                return {"blocked_reason": "AUTHENTICATION_FAILED", "transport": evidence}
            origin_badge = str(source.get("source_origin_badge") or VERIFIED_BADGE)
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
                retrieval_provenance = {}
                retrieval_provenance_digest = ""
            manifest_s_digest = str(source["manifest_s_digest"])
            manifest_r_digest = str(source["manifest_r_digest"])
            lark_evidence_ref = str(source.get("lark_evidence_ref") or "").strip()
            if not lark_evidence_ref:
                return None
        else:
            actual_references = list(evidence["references"]) or [evidence["message_id"]]
            origin_badge = PLAIN_BADGE
            retrieval_method = "authoritative_pending"
            retrieval_provenance = {}
            retrieval_provenance_digest = ""
            gitlab_evidence_digest = ""
            gitlab_evidence_ref = ""
            manifest_s_digest = ""
            manifest_r_digest = ""
            lark_evidence_ref = ""
        if verified:
            checked_items = source.get("checked_items")
            if isinstance(checked_items, list) and checked_items:
                normalized_checks = [str(item).strip() for item in checked_items if str(item).strip()]
            else:
                normalized_checks = ["human_mail_reviewed"]
            submission_policy_digest = str(source.get("submission_policy_digest") or "").strip()
            pre_release_policy_digest = str(source.get("pre_release_policy_digest") or "").strip()
            if not submission_policy_digest or not pre_release_policy_digest:
                return None
        else:
            normalized_checks = []
            submission_policy_digest = "unverified"
            pre_release_policy_digest = "unverified"
        if str(source.get("test_result") or "").upper() != "PASS":
            return None
        submitter_email = str(source.get("submitter_email") or source.get("sender_email") or "").strip().lower()
        if submitter_email and not _EMAIL_RE.fullmatch(submitter_email):
            submitter_email = ""
        record = {
            "event_id": str(source["event_id"]),
            "round_id": int(source["round_id"]),
            "task": str(source["task"]),
            "module": str(source["module"]),
            "status": "RELEASE_GATE_RUNNING",
            "source_uid": evidence["uid"],
            "source_message_id": str(source.get("source_message_id") or evidence["message_id"]),
            "thread_references": actual_references,
            "source_transport_digest": sha256_jsonable(evidence),
            "machine_event_digest": sha256_jsonable(payload) if payload is not None else "",
            "submission_policy_digest": submission_policy_digest,
            "pre_release_policy_digest": pre_release_policy_digest,
            "gate_policy_digest": self._policy_snapshot()["policy_digest"],
            "retrieval_method": retrieval_method,
            "retrieval_provenance_digest": retrieval_provenance_digest,
            "retrieval_provenance": dict(retrieval_provenance) if isinstance(retrieval_provenance, Mapping) else {},
            "gitlab_evidence_digest": gitlab_evidence_digest,
            "gitlab_evidence_ref": gitlab_evidence_ref,
            "lark_evidence_ref": lark_evidence_ref,
            "manifest_s_digest": manifest_s_digest,
            "manifest_r_digest": manifest_r_digest,
            "checked_items": normalized_checks,
            "submitter_email": submitter_email,
            "submitter_email_status": "valid" if submitter_email else "missing_or_invalid",
            "origin_badge": origin_badge,
            "transport_badge": VERIFIED_BADGE if verified else PLAIN_BADGE,
            "updated_at": self._timestamp(),
        }
        return {"record": record}

    @staticmethod
    def _normalized_sha256(value: Any, field_name: str) -> str:
        match = _SHA256_RE.fullmatch(str(value or "").strip())
        if not match:
            raise ReleaseGateError(_AUTHORITATIVE_PROVENANCE_ERROR, f"{field_name} is unavailable")
        return "sha256:" + match.group(1).lower()

    def _rebind_fallback_provenance(
        self,
        record: dict[str, Any],
        authoritative_state: Mapping[str, Any],
    ) -> None:
        event = authoritative_state.get("event")
        manifest_s = authoritative_state.get("manifest_s")
        manifest_r = authoritative_state.get("manifest_r")
        if not isinstance(event, Mapping) or not isinstance(manifest_s, Mapping) or not isinstance(manifest_r, Mapping):
            raise ReleaseGateError(_AUTHORITATIVE_PROVENANCE_ERROR, "authoritative event or manifests are unavailable")
        if str(event.get("event_id") or "") != str(record["event_id"]):
            raise ReleaseGateError(_AUTHORITATIVE_PROVENANCE_ERROR, "authoritative event_id differs")
        authority_round = event.get("round_id", event.get("round_number"))
        if isinstance(authority_round, bool) or not isinstance(authority_round, int) or authority_round != int(record["round_id"]):
            raise ReleaseGateError(_AUTHORITATIVE_PROVENANCE_ERROR, "authoritative round differs")
        authoritative_status = str(event.get("status") or "").strip()
        if authoritative_status != "RELEASE_READY":
            raise ReleaseGateError(_AUTHORITATIVE_PROVENANCE_ERROR, "authoritative event is not release ready")

        manifest_s_digest = self._normalized_sha256(event.get("manifest_s_digest"), "manifest_s_digest")
        manifest_r_digest = self._normalized_sha256(event.get("manifest_r_digest"), "manifest_r_digest")
        if manifest_s_digest != self._normalized_sha256(manifest_s.get("digest"), "manifest_s.digest"):
            raise ReleaseGateError(_AUTHORITATIVE_PROVENANCE_ERROR, "Manifest-S authority differs")
        if manifest_r_digest != self._normalized_sha256(manifest_r.get("digest"), "manifest_r.digest"):
            raise ReleaseGateError(_AUTHORITATIVE_PROVENANCE_ERROR, "Manifest-R authority differs")
        if manifest_s_digest != self._normalized_sha256(manifest_r.get("source_manifest_s_digest"), "manifest_r.source_manifest_s_digest"):
            raise ReleaseGateError(_AUTHORITATIVE_PROVENANCE_ERROR, "Manifest-R source binding differs")

        record.update(
            {
                "event_id": str(event["event_id"]),
                "round_id": authority_round,
                "status": authoritative_status,
                "manifest_s_digest": manifest_s_digest,
                "manifest_r_digest": manifest_r_digest,
                "origin_badge": PLAIN_BADGE,
                "lark_evidence_ref": "",
                "retrieval_method": "unverified",
                "retrieval_provenance": {},
                "retrieval_provenance_digest": "",
                "gitlab_evidence_ref": "",
                "gitlab_evidence_digest": "",
                "submission_policy_digest": "unverified",
                "pre_release_policy_digest": "unverified",
                "checked_items": [],
                "provenance_classification": "UNVERIFIED_FALLBACK",
                "authoritative_provenance_rebound": True,
            }
        )

    def _build_outbound_notice(self, record: Mapping[str, Any], *, success: bool) -> dict[str, Any]:
        if record.get("transport_badge") == VERIFIED_BADGE:
            check_results = [
                {"check": "hmac", "result": "PASS"},
                {"check": "thread", "result": "PASS"},
                {"check": "manifest", "result": "PASS"},
                {"check": "retrieval_provenance" if record.get("retrieval_method") == "svn" else "gitlab_evidence", "result": "PASS"},
            ]
        else:
            check_results = [
                {"check": "hmac", "result": "UNVERIFIED"},
                {"check": "thread", "result": "PASS"},
                {"check": "manifest", "result": "PASS" if success else "NOT_EVALUATED"},
                {"check": "upstream_body_evidence", "result": "NOT_PROPAGATED"},
            ]
        machine_event = {
            "contract": "ProductMaterialWorkflow/v1",
            "event_type": "RELEASE_GATE_PASS" if success else "RELEASE_GATE_BLOCKED",
            "event_id": record["event_id"],
            "round_id": record["round_id"],
            "task": record["task"],
            "module": record["module"],
            "manifest_s_digest": record["manifest_s_digest"],
            "manifest_r_digest": record["manifest_r_digest"],
            "submission_policy_digest": record["submission_policy_digest"],
            "pre_release_policy_digest": record["pre_release_policy_digest"],
            "gate_policy_digest": record["gate_policy_digest"],
            "retrieval_method": record["retrieval_method"],
            "retrieval_provenance_digest": record["retrieval_provenance_digest"],
            "retrieval_provenance": dict(record.get("retrieval_provenance") or {}),
            "gitlab_evidence_digest": record["gitlab_evidence_digest"],
            "gitlab_evidence_ref": record["gitlab_evidence_ref"],
            "lark_evidence_ref": record["lark_evidence_ref"],
            "checked_items": list(record["checked_items"]),
            "check_results": check_results,
            "submitter_email": record.get("submitter_email", ""),
            "status": "RELEASE_READY_NOTIFIED" if success else "RELEASE_GATE_BLOCKED",
            "blocked_reason": record.get("blocked_reason"),
            "source_origin_badge": record["origin_badge"],
            "transport_badge": record["transport_badge"],
        }
        if self.config.shared_hmac_secret_path.exists():
            machine_event = sign_machine_event(machine_event, self.config.shared_hmac_secret_path.read_bytes())
        title = "【发布申请】" if success else "【发布阻断】"
        state_text = "RELEASE_READY_NOTIFIED" if success else "RELEASE_GATE_BLOCKED"
        if record.get("transport_badge") == VERIFIED_BADGE:
            upstream_evidence_lines = [f"- SVN：{record['retrieval_provenance'].get('repository_path')}@{record['retrieval_provenance'].get('revision')}"] if record.get("retrieval_method") == "svn" else [f"- GitLab：{record['gitlab_evidence_ref']}"]
            upstream_evidence_lines.append(f"- 飞书：{record['lark_evidence_ref']}")
        else:
            upstream_evidence_lines = ["- 上游正文证据：未验证来源，未传播；请在审批页独立核验"]
        body = "\n".join(
            [
                f"事件：{record['event_id']}#{record['round_id']}",
                f"任务：{record['task']}",
                f"模块：{record['module']}",
                f"状态：{state_text}",
                "策略冻结：",
                f"- 提测门禁策略摘要：{record['submission_policy_digest']}",
                f"- 预发布策略摘要：{record['pre_release_policy_digest']}",
                f"- 发布门禁策略摘要：{record['gate_policy_digest']}",
                "检查结果：",
                *[f"- {item['check']}：{item['result']}" for item in check_results],
                "证据引用：",
                f"- Manifest-S：{record['manifest_s_digest']}",
                f"- Manifest-R：{record['manifest_r_digest']}",
                *upstream_evidence_lines,
                f"提测人邮箱：{record.get('submitter_email') or '未提供'}",
                f"发起标识：{record['origin_badge']}",
                f"传输标识：{record['transport_badge']}",
                encode_machine_event(machine_event),
            ]
        )
        return {"success": success, "mail": {"profile": self.config.mail_account.profile, "to": [self.config.release_group], "subject": f"{title}{record['task']}-{record['module']}-{self.now_fn().astimezone(timezone.utc).strftime('%Y-%m-%d')}", "body_text": body, "headers": ({"X-RD-Submitter-Email": record["submitter_email"]} if record.get("submitter_email") else {})}}

    def _policy_valid(self) -> bool:
        required = tuple(self.config.required_checks)
        enabled_optional = tuple(self.config.enabled_optional_checks)
        effective = required + enabled_optional
        if missing_canonical_required_checks(required):
            return False
        return all(check in effective for check in CANONICAL_REQUIRED_CHECKS)

    def _policy_snapshot(self) -> dict[str, str]:
        payload = {"profile": self.config.policy_profile, "required_checks": list(self.config.required_checks), "enabled_optional_checks": list(self.config.enabled_optional_checks)}
        return {"policy_profile": self.config.policy_profile, "policy_digest": hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()}

    def _save_event(self, payload: Mapping[str, Any]) -> None:
        path = self._event_path(str(payload["event_id"]), int(payload["round_id"]))
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        temporary.write_text(json.dumps(dict(payload), ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)

    def _event_path(self, event_id: str, round_id: int) -> Path:
        path = self.events_dir / f"{event_id}--{round_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _timestamp(self) -> str:
        return self.now_fn().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
