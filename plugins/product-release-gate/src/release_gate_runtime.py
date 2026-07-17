from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from release_gate_core import GateError, read_json, safe_event_id, utc_now, write_json
from release_gate_lock import RunOnceLock


LockFactory = Callable[..., RunOnceLock]


class ReleaseGateWorkflowRuntime:
    """Durable headless reconciliation for verified approval handoffs."""

    def __init__(
        self,
        controller: Any,
        config_path: str | Path,
        *,
        lock_factory: LockFactory = RunOnceLock,
    ) -> None:
        self.controller = controller
        self.config_path = Path(config_path).resolve(strict=False)
        runtime = controller.config.get("runtime") or {}
        state_value = runtime.get("state_dir")
        if not state_value:
            state_value = controller.storage_dir.parent / "state"
        self.state_dir = Path(os.path.expandvars(str(state_value))).expanduser().resolve()
        self.inbox_dir = self.state_dir / "handoff-inbox"
        self.lock_path = self.state_dir / "locks" / "run-once.lock"
        self.audit_path = self.state_dir / "audit" / "runtime.jsonl"
        self.auto_authorize_verified_pre_release = (
            runtime.get("auto_authorize_verified_pre_release") is True
        )
        self.authorization_requester = str(
            runtime.get("authorization_requester") or "rd-flywheel"
        ).strip()
        if not self.authorization_requester:
            raise GateError("runtime.authorization_requester must be non-empty")
        self.lock_factory = lock_factory

    def enqueue_handoff(self, event_id: str, verification_ref: str) -> dict[str, Any]:
        identifier = safe_event_id(event_id)
        reference = str(verification_ref or "").strip()
        if not reference:
            raise GateError("verification_ref is required")
        digest = hashlib.sha256(f"{identifier}\0{reference}".encode("utf-8")).hexdigest()
        path = self.inbox_dir / f"handoff-{digest}.json"
        if path.is_file():
            pointer = read_json(path)
            if (
                isinstance(pointer, dict)
                and pointer.get("event_id") == identifier
                and pointer.get("verification_ref") == reference
            ):
                return {
                    "status": pointer.get("status"),
                    "pointer_path": str(path),
                    "pointer": pointer,
                    "idempotent": True,
                }
            raise GateError("handoff pointer digest collision")
        pointer = {
            "schema": "ReleaseApprovalHandoffPointer/v1",
            "event_id": identifier,
            "verification_ref": reference,
            "status": "queued",
            "attempts": 0,
            "queued_at": utc_now(),
        }
        write_json(path, pointer)
        return {
            "status": "queued",
            "pointer_path": str(path),
            "pointer": pointer,
            "idempotent": False,
        }

    def run_once(self) -> dict[str, Any]:
        owner = f"pid-{os.getpid()}"
        lock = self.lock_factory(self.lock_path, owner=owner)
        acquired = lock.acquire()
        if acquired.get("status") != "acquired":
            return {"status": "RUN_ALREADY_ACTIVE", "busy": True}
        try:
            recovered_owner = acquired.get("recovered_owner")
            if recovered_owner:
                self._append_audit(
                    "lock_orphan_recovered",
                    {"recovered_owner": recovered_owner, "new_owner": owner},
                )
            processed = 0
            failed = 0
            authorization_finalized, authorization_finalize_failed = (
                self._finalize_pending_authorizations()
            )
            failed += authorization_finalize_failed
            for path in sorted(self.inbox_dir.glob("handoff-*.json")) if self.inbox_dir.is_dir() else []:
                pointer = read_json(path)
                if not isinstance(pointer, dict) or pointer.get("status") != "queued":
                    continue
                try:
                    result = self.controller.record_unified_release_approval(
                        str(pointer["event_id"]),
                        str(pointer["verification_ref"]),
                    )
                    pointer["status"] = "processed"
                    pointer["processed_at"] = utc_now()
                    pointer["result_status"] = result.get("status")
                    pointer["result"] = result
                    pointer["attempts"] = int(pointer.get("attempts") or 0) + 1
                    pointer.pop("last_error", None)
                    write_json(path, pointer)
                    processed += 1
                except (GateError, KeyError, TypeError, ValueError) as exc:
                    pointer["attempts"] = int(pointer.get("attempts") or 0) + 1
                    pointer["last_error"] = str(exc)
                    pointer["last_attempt_at"] = utc_now()
                    write_json(path, pointer)
                    failed += 1
            authorization_requested, authorization_request_failed = (
                self._request_pending_pre_releases()
            )
            failed += authorization_request_failed
            result = {
                "status": "ready" if failed == 0 else "CAPABILITY_BLOCKED",
                "processed": processed,
                "failed": failed,
                "authorization_requested": authorization_requested,
                "authorization_finalized": authorization_finalized,
                "pending_events": self._pending_event_count(),
            }
            self._append_audit("run_once_completed", result)
            return result
        finally:
            lock.release()

    def _load_event_state(self, event_id: str) -> dict[str, Any]:
        loader = getattr(self.controller, "_load_event", None)
        if callable(loader):
            event = loader(event_id)
        else:
            event = self.controller.get_event(event_id)
            if isinstance(event, dict) and isinstance(event.get("event"), dict):
                event = event["event"]
        if not isinstance(event, dict):
            raise GateError("controller did not return an event state object")
        return event

    def _finalize_pending_authorizations(self) -> tuple[int, int]:
        if not self.auto_authorize_verified_pre_release:
            return 0, 0
        finalized = 0
        failed = 0
        for summary in self.list_events()["events"]:
            if summary.get("status") != "RELEASE_AUTHORIZATION_REQUIRED":
                continue
            event = self._load_event_state(str(summary["event_id"]))
            authorization = event.get("release_authorization") or {}
            if (
                authorization.get("authorization_source")
                != "unified_multi_role_receipt"
            ):
                continue
            try:
                result = (
                    self.controller.finalize_verified_release_authorization(
                        str(summary["event_id"])
                    )
                )
                if result.get("status") != "RELEASE_AUTHORIZED":
                    failed += 1
                else:
                    finalized += 1
            except (GateError, KeyError, TypeError, ValueError) as exc:
                failed += 1
                self._append_audit(
                    "authorization_finalize_failed",
                    {
                        "event_id": summary.get("event_id"),
                        "error": str(exc),
                    },
                )
        return finalized, failed

    def _request_pending_pre_releases(self) -> tuple[int, int]:
        if not self.auto_authorize_verified_pre_release:
            return 0, 0
        requested = 0
        failed = 0
        for summary in self.list_events()["events"]:
            if summary.get("status") != "PRE_RELEASE_REQUESTED":
                continue
            event = self._load_event_state(str(summary["event_id"]))
            approval = event.get("unified_release_approval") or {}
            handoff_path = Path(
                str(approval.get("pre_release_request_path") or "")
            )
            try:
                handoff = read_json(handoff_path)
                if not isinstance(handoff, dict):
                    raise GateError("pre-release handoff is missing")
                result = self.controller.request_release_authorization(
                    str(summary["event_id"]),
                    self.authorization_requester,
                    str(handoff.get("target_scope") or ""),
                )
                if result.get("status") != "RELEASE_AUTHORIZATION_REQUIRED":
                    failed += 1
                else:
                    requested += 1
            except (GateError, KeyError, TypeError, ValueError) as exc:
                failed += 1
                self._append_audit(
                    "authorization_request_failed",
                    {
                        "event_id": summary.get("event_id"),
                        "error": str(exc),
                    },
                )
        return requested, failed

    def status(self) -> dict[str, Any]:
        queued = 0
        processed = 0
        if self.inbox_dir.is_dir():
            for path in self.inbox_dir.glob("handoff-*.json"):
                try:
                    pointer = read_json(path)
                except GateError:
                    continue
                if isinstance(pointer, dict) and pointer.get("status") == "queued":
                    queued += 1
                elif isinstance(pointer, dict) and pointer.get("status") == "processed":
                    processed += 1
        return {
            "status": "ready",
            "config_path": str(self.config_path),
            "state_dir": str(self.state_dir),
            "queued_handoffs": queued,
            "processed_handoffs": processed,
            "pending_events": self._pending_event_count(),
        }

    def doctor(self) -> dict[str, Any]:
        workflow = self.controller.unified_approval_preflight()
        return {
            "ready": bool(workflow.get("ready")),
            "config_path": str(self.config_path),
            "workflow": workflow,
            "runtime": self.status(),
        }

    def list_events(self) -> dict[str, Any]:
        events: list[dict[str, Any]] = []
        if self.controller.storage_dir.is_dir():
            for path in sorted(self.controller.storage_dir.glob("*/event.json")):
                try:
                    event = read_json(path)
                except GateError:
                    continue
                if isinstance(event, dict):
                    events.append(
                        {
                            "event_id": event.get("event_id"),
                            "status": event.get("status"),
                            "round_id": (event.get("unified_release_approval") or {}).get("round_id"),
                        }
                    )
        return {"events": events, "count": len(events)}

    def _pending_event_count(self) -> int:
        pending = {
            "APPROVAL_COLLECTING",
            "APPROVAL_PAUSED",
            "PRE_RELEASE_REQUESTED",
            "RELEASE_AUTHORIZATION_REQUIRED",
        }
        return sum(1 for event in self.list_events()["events"] if event.get("status") in pending)

    def _append_audit(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "recorded_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "event_type": event_type,
            "payload": payload,
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
