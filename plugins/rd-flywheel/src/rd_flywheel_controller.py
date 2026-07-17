from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from rd_flywheel_config import RDFlywheelConfig
from rd_flywheel_lock import KernelRunLock
from rd_flywheel_protocol import (
    CapabilityGapEvent,
    EvidenceReference,
    ProtocolError,
    canonical_json,
    missing_completion_evidence,
)
from rd_flywheel_store import RDFlywheelStore, StoreError, StoredEvent


AgentAdapter = Callable[[Mapping[str, Any]], Mapping[str, Any]]
EvidenceVerifier = Callable[[EvidenceReference, CapabilityGapEvent], bool | Mapping[str, Any]]
Notifier = Callable[[Mapping[str, Any]], None]


class ControllerError(RuntimeError):
    """Raised when the deterministic controller cannot safely continue."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class RDFlywheelController:
    def __init__(
        self,
        config: RDFlywheelConfig,
        *,
        agent_adapters: Mapping[str, AgentAdapter] | None = None,
        evidence_verifiers: Mapping[str, EvidenceVerifier] | None = None,
        notifier: Notifier | None = None,
        store_factory: Callable[..., RDFlywheelStore] = RDFlywheelStore,
        lock_factory: Callable[[Path], KernelRunLock] = KernelRunLock,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self.config = config
        self.agent_adapters = dict(agent_adapters or {})
        self.evidence_verifiers = dict(evidence_verifiers or {})
        self.notifier = notifier
        self.store_factory = store_factory
        self.lock_factory = lock_factory
        self.clock = clock

    def preflight(self) -> dict[str, Any]:
        self._ensure_directories()
        store = self.store_factory(self.config.database_path)
        try:
            audit = store.verify_audit_chain()
            reasons = self._preflight_reasons()
            if reasons:
                payload = {
                    "status": "CAPABILITY_BLOCKED",
                    "blocked_reasons": reasons,
                    "audit": audit,
                }
                store.append_audit_event(
                    "preflight_capability_blocked",
                    payload,
                    created_at=self.clock(),
                )
                self._notify(store, payload)
                return payload
            payload = {
                "status": "ready",
                "tool_profiles": list(self.config.tool_profiles),
                "agent_profile": self.config.agent_profile,
                "audit": audit,
            }
            store.append_audit_event(
                "preflight_ready",
                payload,
                created_at=self.clock(),
            )
            return payload
        finally:
            store.close()

    def run_once(self) -> dict[str, Any]:
        lock = self.lock_factory(self.config.run_lock_path)
        if not lock.acquire():
            return {"status": "RUN_ALREADY_ACTIVE", "busy": True}
        try:
            self._ensure_directories()
            store = self.store_factory(self.config.database_path)
            try:
                if lock.orphan_metadata:
                    store.append_audit_event(
                        "orphan_lock_metadata_recovered",
                        {"metadata": lock.orphan_metadata},
                        created_at=self.clock(),
                    )
                return self._run_locked(store)
            finally:
                store.close()
        finally:
            lock.release()

    def _run_locked(self, store: RDFlywheelStore) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        rejected = 0
        for source in sorted(self.config.governance_inbox.glob("*.json")):
            content = source.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            source_name = str(source.resolve(strict=False))
            if store.has_input(source=source_name, content_digest=digest):
                continue
            try:
                payload = json.loads(content.decode("utf-8"))
                event = CapabilityGapEvent.from_mapping(payload)
                existing = store.get_event(event.idempotency_key)
                store.record_event(event, recorded_at=self.clock())
                store.record_input(
                    source=source_name,
                    content_digest=digest,
                    outcome="ACCEPTED",
                    recorded_at=self.clock(),
                )
                if existing is None:
                    store.transition(
                        event.idempotency_key,
                        "VALIDATED",
                        (),
                        changed_at=self.clock(),
                        detail="schema, digest, production evidence, and idempotency bindings validated",
                    )
                    results.append(self._advance_validated(store, event))
            except (UnicodeDecodeError, json.JSONDecodeError, ProtocolError, StoreError) as exc:
                recorded = store.record_input(
                    source=source_name,
                    content_digest=digest,
                    outcome="REJECTED",
                    recorded_at=self.clock(),
                )
                if recorded:
                    rejected += 1
                    store.append_audit_event(
                        "input_rejected",
                        {
                            "source": source_name,
                            "content_digest": digest,
                            "error": str(exc),
                        },
                        created_at=self.clock(),
                    )

        for stored in store.list_events(states=("EVIDENCE_PENDING",)):
            if not any(item.get("idempotency_key") == stored.idempotency_key for item in results):
                event = CapabilityGapEvent.from_mapping(stored.payload)
                results.append(self._verify_pending(store, event))

        reasons = self._preflight_reasons()
        if not results and reasons:
            payload = {
                "status": "CAPABILITY_BLOCKED",
                "blocked_reasons": reasons,
                "processed": 0,
                "rejected": rejected,
            }
            store.append_audit_event(
                "run_capability_blocked",
                payload,
                created_at=self.clock(),
            )
            self._notify(store, payload)
            return payload

        statuses = Counter(item["status"] for item in results)
        if statuses["CAPABILITY_BLOCKED"]:
            status = "CAPABILITY_BLOCKED"
        elif statuses["EVIDENCE_PENDING"]:
            status = "EVIDENCE_PENDING"
        elif results and statuses["COMPLETE"] == len(results):
            status = "COMPLETE"
        else:
            status = "ready"
        blocked_reasons = [
            reason
            for item in results
            for reason in item.get("blocked_reasons", [])
        ]
        missing_evidence = sorted({
            kind
            for item in results
            for kind in item.get("missing_evidence", [])
        })
        return {
            "status": status,
            "processed": len(results),
            "rejected": rejected,
            "completed": statuses["COMPLETE"],
            "blocked": statuses["CAPABILITY_BLOCKED"],
            "pending": statuses["EVIDENCE_PENDING"],
            "blocked_reasons": blocked_reasons,
            "missing_evidence": missing_evidence,
            "events": results,
        }

    def _advance_validated(
        self,
        store: RDFlywheelStore,
        event: CapabilityGapEvent,
    ) -> dict[str, Any]:
        missing_tools = [
            profile
            for profile in event.allowed_tool_profiles
            if profile not in self.config.tool_profiles
        ]
        if missing_tools:
            return self._block(
                store,
                event,
                [
                    "required tool profiles are not configured and allowlisted: "
                    + ", ".join(missing_tools)
                ],
            )

        profile = self.config.agent_profile
        adapter = self.agent_adapters.get(profile or "")
        if profile is None or profile not in self.config.approved_agent_profiles or adapter is None:
            return self._block(
                store,
                event,
                ["no approved agent adapter is available for capability construction"],
            )

        selection = self._controller_evidence(
            "adapter_selection",
            {
                "agent_profile": profile,
                "allowed": True,
                "event": event.idempotency_key,
            },
        )
        store.transition(
            event.idempotency_key,
            "WAITING_AGENT",
            (selection,),
            changed_at=self.clock(),
            detail="approved agent adapter selected from the frozen configuration",
            adapter_profile=profile,
        )
        invocation = self._controller_evidence(
            "adapter_invocation",
            {
                "agent_profile": profile,
                "canonical_input_sha256": event.payload_digest,
            },
        )
        store.transition(
            event.idempotency_key,
            "BUILDING",
            (invocation,),
            changed_at=self.clock(),
            detail="canonical capability-gap payload delivered to the adapter",
        )

        try:
            result = adapter(dict(event.payload))
            untrusted = self._parse_agent_result(result)
        except Exception as exc:
            return self._block(
                store,
                event,
                [f"approved agent adapter failed: {type(exc).__name__}: {exc}"],
            )

        response_digest = hashlib.sha256(
            canonical_json(result).encode("utf-8")
        ).hexdigest()
        response_receipt = EvidenceReference(
            kind="adapter_response",
            uri=f"urn:rd-flywheel:adapter-response:{response_digest}",
            sha256=response_digest,
            verifier="deterministic-adapter-response-parser",
            verified=True,
        )
        store.transition(
            event.idempotency_key,
            "EVIDENCE_PENDING",
            (response_receipt, *untrusted),
            changed_at=self.clock(),
            detail="adapter output recorded as untrusted evidence references; authority remains pending",
        )
        return self._verify_pending(store, event)

    def _parse_agent_result(
        self,
        result: Mapping[str, Any],
    ) -> tuple[EvidenceReference, ...]:
        if not isinstance(result, Mapping):
            raise ControllerError("agent adapter result must be an object.")
        canonical_json(result)
        raw_evidence = result.get("evidence", [])
        if not isinstance(raw_evidence, list):
            raise ControllerError("agent adapter evidence must be a list.")
        references: list[EvidenceReference] = []
        for item in raw_evidence:
            if not isinstance(item, Mapping):
                raise ControllerError("agent adapter evidence entries must be objects.")
            references.append(
                EvidenceReference(
                    kind=str(item.get("kind") or ""),
                    uri=str(item.get("uri") or ""),
                    sha256=str(item.get("sha256") or ""),
                    verifier="agent-output",
                    verified=False,
                )
            )
        return tuple(references)

    def _verify_pending(
        self,
        store: RDFlywheelStore,
        event: CapabilityGapEvent,
    ) -> dict[str, Any]:
        current = store.get_event(event.idempotency_key)
        if current is None:
            raise ControllerError("event disappeared during evidence verification.")
        if current.state == "COMPLETE":
            return {"status": "COMPLETE", "idempotency_key": event.idempotency_key}
        if current.state != "EVIDENCE_PENDING":
            return {
                "status": current.state,
                "idempotency_key": event.idempotency_key,
            }

        evidence = list(store.list_evidence(event.idempotency_key))
        verified_additions: list[EvidenceReference] = []
        for kind in event.required_evidence:
            if any(
                item.kind == kind
                and item.verified
                and item.verifier != "agent-output"
                for item in evidence
            ):
                continue
            verifier = self.evidence_verifiers.get(kind)
            candidate = next(
                (
                    item
                    for item in reversed(evidence)
                    if item.kind == kind and not item.verified
                ),
                None,
            )
            if verifier is None or candidate is None:
                continue
            try:
                outcome = verifier(candidate, event)
            except Exception as exc:
                store.append_audit_event(
                    "evidence_verifier_failed",
                    {
                        "idempotency_key": event.idempotency_key,
                        "kind": kind,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                    created_at=self.clock(),
                )
                continue
            verified = (
                bool(outcome.get("verified"))
                if isinstance(outcome, Mapping)
                else outcome is True
            )
            if verified:
                verified_additions.append(
                    EvidenceReference(
                        kind=candidate.kind,
                        uri=candidate.uri,
                        sha256=candidate.sha256,
                        verifier=f"independent:{kind}",
                        verified=True,
                    )
                )
        if verified_additions:
            store.record_evidence(
                event.idempotency_key,
                verified_additions,
                recorded_at=self.clock(),
            )
            evidence.extend(verified_additions)

        missing = missing_completion_evidence(event, evidence)
        if missing:
            return {
                "status": "EVIDENCE_PENDING",
                "idempotency_key": event.idempotency_key,
                "missing_evidence": list(missing),
            }

        completion_proof = tuple(
            item
            for item in evidence
            if item.kind in event.required_evidence and item.verified
        )
        store.transition(
            event.idempotency_key,
            "COMPLETE",
            completion_proof,
            changed_at=self.clock(),
            detail="all configured independent evidence verifiers passed",
        )
        return {
            "status": "COMPLETE",
            "idempotency_key": event.idempotency_key,
            "checkpoint_digest": event.checkpoint_digest,
        }

    def _block(
        self,
        store: RDFlywheelStore,
        event: CapabilityGapEvent,
        reasons: Sequence[str],
    ) -> dict[str, Any]:
        current = store.get_event(event.idempotency_key)
        if current is None:
            raise ControllerError("cannot block a missing event.")
        proof = self._controller_evidence(
            "capability_preflight",
            {
                "event": event.idempotency_key,
                "state": current.state,
                "reasons": list(reasons),
            },
        )
        if current.state != "CAPABILITY_BLOCKED":
            store.transition(
                event.idempotency_key,
                "CAPABILITY_BLOCKED",
                (proof,),
                changed_at=self.clock(),
                detail="; ".join(reasons),
            )
        payload = {
            "status": "CAPABILITY_BLOCKED",
            "idempotency_key": event.idempotency_key,
            "checkpoint_digest": event.checkpoint_digest,
            "blocked_reasons": list(reasons),
        }
        self._notify(store, payload)
        return payload

    def retry_event(self, idempotency_key: str) -> dict[str, Any]:
        lock = self.lock_factory(self.config.run_lock_path)
        if not lock.acquire():
            return {"status": "RUN_ALREADY_ACTIVE", "busy": True}
        try:
            store = self.store_factory(self.config.database_path)
            try:
                stored = store.get_event(idempotency_key)
                if stored is None:
                    return {
                        "status": "error",
                        "error": {
                            "code": "EVENT_NOT_FOUND",
                            "message": "event does not exist",
                        },
                    }
                event = CapabilityGapEvent.from_mapping(stored.payload)
                if stored.state == "CAPABILITY_BLOCKED":
                    retry_proof = self._controller_evidence(
                        "retry_authorization",
                        {
                            "idempotency_key": idempotency_key,
                            "checkpoint_digest": stored.checkpoint_digest,
                        },
                    )
                    store.transition(
                        idempotency_key,
                        "VALIDATED",
                        (retry_proof,),
                        changed_at=self.clock(),
                        detail="same frozen event authorized for deterministic retry",
                    )
                    return self._advance_validated(store, event)
                if stored.state == "EVIDENCE_PENDING":
                    return self._verify_pending(store, event)
                return {
                    "status": stored.state,
                    "idempotency_key": idempotency_key,
                }
            finally:
                store.close()
        finally:
            lock.release()

    def status(self) -> dict[str, Any]:
        if not self.config.database_path.exists():
            return {
                "status": "not_initialized",
                "counts": {},
                "config_state_dir": str(self.config.state_dir),
            }
        store = self.store_factory(self.config.database_path)
        try:
            events = store.list_events()
            counts = Counter(item.state for item in events)
            audit = store.verify_audit_chain()
            return {
                "status": "ready",
                "counts": dict(sorted(counts.items())),
                "events": len(events),
                "audit": audit,
            }
        finally:
            store.close()

    def doctor(self) -> dict[str, Any]:
        checks: dict[str, Any] = {
            "config_loaded": True,
            "governance_inbox": str(self.config.governance_inbox),
            "state_dir": str(self.config.state_dir),
            "agent_profile": self.config.agent_profile,
            "tool_profiles": list(self.config.tool_profiles),
        }
        try:
            self._ensure_directories()
            store = self.store_factory(self.config.database_path)
            try:
                checks["audit"] = store.verify_audit_chain()
            finally:
                store.close()
        except Exception as exc:
            return {
                "status": "CAPABILITY_BLOCKED",
                "checks": checks,
                "blocked_reasons": [f"{type(exc).__name__}: {exc}"],
            }
        reasons = self._preflight_reasons()
        return {
            "status": "ready" if not reasons else "CAPABILITY_BLOCKED",
            "checks": checks,
            "blocked_reasons": reasons,
        }

    def list_events(self, state: str | None = None) -> dict[str, Any]:
        if not self.config.database_path.exists():
            return {"status": "ready", "events": []}
        store = self.store_factory(self.config.database_path)
        try:
            events = store.list_events(states=(state,) if state else None)
            return {
                "status": "ready",
                "events": [self._stored_event_payload(store, item) for item in events],
            }
        finally:
            store.close()

    def get_event(self, idempotency_key: str) -> dict[str, Any]:
        if not self.config.database_path.exists():
            return {
                "status": "error",
                "error": {"code": "EVENT_NOT_FOUND", "message": "event does not exist"},
            }
        store = self.store_factory(self.config.database_path)
        try:
            event = store.get_event(idempotency_key)
            if event is None:
                return {
                    "status": "error",
                    "error": {
                        "code": "EVENT_NOT_FOUND",
                        "message": "event does not exist",
                    },
                }
            return self._stored_event_payload(store, event)
        finally:
            store.close()

    def verify_audit(self) -> dict[str, Any]:
        if not self.config.database_path.exists():
            return {"status": "ready", "ok": True, "count": 0, "head_hash": "0" * 64}
        store = self.store_factory(self.config.database_path, verify_chain_on_open=False)
        try:
            return {"status": "ready", **store.verify_audit_chain()}
        finally:
            store.close()

    def _stored_event_payload(
        self,
        store: RDFlywheelStore,
        event: StoredEvent,
    ) -> dict[str, Any]:
        return {
            "idempotency_key": event.idempotency_key,
            "payload_digest": event.payload_digest,
            "originating_plugin": event.originating_plugin,
            "originating_event_id": event.originating_event_id,
            "originating_round_id": event.originating_round_id,
            "checkpoint_digest": event.checkpoint_digest,
            "missing_capability": event.missing_capability,
            "state": event.state,
            "adapter_profile": event.adapter_profile,
            "last_detail": event.last_detail,
            "created_at": event.created_at,
            "updated_at": event.updated_at,
            "evidence": [item.as_dict() for item in store.list_evidence(event.idempotency_key)],
            "transitions": [
                {
                    "from_state": item.from_state,
                    "to_state": item.to_state,
                    "detail": item.detail,
                    "changed_at": item.changed_at,
                }
                for item in store.list_transitions(event.idempotency_key)
            ],
        }

    def _preflight_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.config.agent_profile is None:
            reasons.append("no approved agent adapter is selected")
        elif self.config.agent_profile not in self.config.approved_agent_profiles:
            reasons.append("selected agent profile is not allowlisted")
        elif self.config.agent_profile not in self.agent_adapters:
            reasons.append("approved agent adapter is not available in this runtime")
        if not self.config.protected_merge.protected_branch_required:
            reasons.append("protected-branch merge policy is disabled")
        return reasons

    def _ensure_directories(self) -> None:
        self.config.governance_inbox.mkdir(parents=True, exist_ok=True)
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        self.config.audit_dir.mkdir(parents=True, exist_ok=True)

    def _notify(
        self,
        store: RDFlywheelStore,
        payload: Mapping[str, Any],
    ) -> None:
        if self.notifier is None or self.config.notification is None:
            return
        try:
            self.notifier(payload)
            store.append_audit_event(
                "notification_sent",
                {
                    "status": payload.get("status"),
                    "recipients": list(self.config.notification.recipients),
                },
                created_at=self.clock(),
            )
        except Exception as exc:
            store.append_audit_event(
                "notification_failed",
                {
                    "status": payload.get("status"),
                    "error": f"{type(exc).__name__}: {exc}",
                },
                created_at=self.clock(),
            )

    @staticmethod
    def _controller_evidence(
        kind: str,
        payload: Mapping[str, Any],
    ) -> EvidenceReference:
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return EvidenceReference(
            kind=kind,
            uri=f"urn:rd-flywheel:{kind}:{digest}",
            sha256=digest,
            verifier="deterministic-controller",
            verified=True,
        )
