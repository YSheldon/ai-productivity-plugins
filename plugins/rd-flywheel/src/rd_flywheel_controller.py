from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from rd_flywheel_config import RDFlywheelConfig
from rd_flywheel_decision import (
    DecisionError,
    DecisionRoleSnapshot,
    GovernanceDecisionPackage,
    build_governance_decision_request,
    decision_role_snapshot_from_mapping,
    decision_role_snapshot_payload,
    validate_governance_decision_verification,
)
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
RoleSnapshotFetcher = Callable[[Any], DecisionRoleSnapshot]
DecisionPresenter = Callable[[Mapping[str, Any]], Mapping[str, Any]]
DecisionVerifier = Callable[[Mapping[str, Any]], Mapping[str, Any]]


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
        role_snapshot_fetcher: RoleSnapshotFetcher | None = None,
        decision_presenter: DecisionPresenter | None = None,
        decision_verifier: DecisionVerifier | None = None,
        store_factory: Callable[..., RDFlywheelStore] = RDFlywheelStore,
        lock_factory: Callable[[Path], KernelRunLock] = KernelRunLock,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self.config = config
        self.agent_adapters = dict(agent_adapters or {})
        self.evidence_verifiers = dict(evidence_verifiers or {})
        self.notifier = notifier
        self.role_snapshot_fetcher = role_snapshot_fetcher
        self.decision_presenter = decision_presenter
        self.decision_verifier = decision_verifier
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

        for stored in store.list_events(states=("DECISION_PENDING",)):
            if not any(item.get("idempotency_key") == stored.idempotency_key for item in results):
                event = CapabilityGapEvent.from_mapping(stored.payload)
                results.append(self._verify_decision(store, event))

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
        elif statuses["DECISION_PENDING"]:
            status = "DECISION_PENDING"
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
            "decision_pending": statuses["DECISION_PENDING"],
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

        if self.config.decision_role_source is None:
            return self._block(
                store,
                event,
                ["live Feishu decision role source is not configured"],
            )
        if self.config.notification is None:
            return self._block(
                store,
                event,
                ["governance decision mail profile and request group are not configured"],
            )
        if self.role_snapshot_fetcher is None:
            return self._block(
                store,
                event,
                ["live Feishu decision role snapshot fetcher is unavailable"],
            )
        if self.decision_presenter is None or self.decision_verifier is None:
            return self._block(
                store,
                event,
                ["governance decision presenter or independent verifier is unavailable"],
            )

        try:
            snapshot = self.role_snapshot_fetcher(self.config.decision_role_source)
            package, paths = self._freeze_decision_package(event, snapshot)
            recipients = self._decision_recipients(snapshot)
            presentation_reused = paths["presentation"].is_file()
            if presentation_reused:
                presentation = json.loads(
                    paths["presentation"].read_text(encoding="utf-8")
                )
                self._validate_presentation(package.request, recipients, presentation)
            else:
                presentation = self.decision_presenter(
                    {
                        "schema": "RDFlywheelGovernanceDecisionPresentation/v1",
                        "request": dict(package.request),
                        "screen_path": str(paths["screen"]),
                        "screen_sha256": package.screen_sha256,
                        "request_path": str(paths["request"]),
                        "role_snapshot_path": str(paths["snapshot"]),
                        "mail_profile": self.config.notification.mail_profile,
                        "recipients": recipients,
                    }
                )
                self._validate_presentation(package.request, recipients, presentation)
                self._write_frozen_text(
                    paths["presentation"],
                    canonical_json(dict(presentation)) + "\n",
                )
        except Exception as exc:
            return self._block(
                store,
                event,
                [f"governance decision presentation failed: {type(exc).__name__}: {exc}"],
            )

        request_evidence = EvidenceReference(
            kind="governance_decision_request",
            uri=paths["request"].resolve(strict=False).as_uri(),
            sha256=str(package.request["request_digest"]).removeprefix("sha256:"),
            verifier="deterministic-controller+smtp-acceptance",
            verified=True,
        )
        presentation_digest = hashlib.sha256(
            canonical_json(dict(presentation)).encode("utf-8")
        ).hexdigest()
        store.transition(
            event.idempotency_key,
            "DECISION_PENDING",
            (request_evidence,),
            changed_at=self.clock(),
            detail=(
                "frozen Feishu role snapshot, Visual Companion HTML, request digest, "
                "and SMTP acceptance recorded; waiting for all required roles"
            ),
        )
        store.append_audit_event(
            "governance_decision_presented",
            {
                "idempotency_key": event.idempotency_key,
                "request_digest": package.request["request_digest"],
                "role_snapshot_digest": snapshot.digest,
                "screen_sha256": "sha256:" + package.screen_sha256,
                "message_id": presentation["message_id"],
                "accepted_at": presentation["accepted_at"],
                "recipients": recipients,
                "request_path": str(paths["request"]),
                "screen_path": str(paths["screen"]),
                "role_snapshot_path": str(paths["snapshot"]),
                "presentation_receipt_path": str(paths["presentation"]),
                "presentation_receipt_sha256": "sha256:" + presentation_digest,
                "presentation_reused": presentation_reused,
            },
            created_at=self.clock(),
        )
        return {
            "status": "DECISION_PENDING",
            "idempotency_key": event.idempotency_key,
            "request_digest": package.request["request_digest"],
            "required_roles": list(package.request["required_roles"]),
        }

    def _verify_decision(
        self,
        store: RDFlywheelStore,
        event: CapabilityGapEvent,
    ) -> dict[str, Any]:
        current = store.get_event(event.idempotency_key)
        if current is None:
            raise ControllerError("event disappeared during governance decision verification.")
        if current.state != "DECISION_PENDING":
            return {
                "status": current.state,
                "idempotency_key": event.idempotency_key,
            }
        if self.config.decision_role_source is None or self.role_snapshot_fetcher is None:
            return self._block(
                store,
                event,
                ["live Feishu decision role source is unavailable while approval is pending"],
            )
        if self.decision_verifier is None:
            return self._block(
                store,
                event,
                ["independent governance decision verifier is unavailable"],
            )
        try:
            request = self._load_frozen_decision_request(event)
            snapshot = self.role_snapshot_fetcher(self.config.decision_role_source)
            if snapshot.digest != request.get("role_snapshot_digest"):
                raise DecisionError(
                    "live Feishu decision role snapshot drifted from the frozen request"
                )
            verification = self.decision_verifier(request)
            if verification.get("verified") is not True:
                status = str(verification.get("status") or "APPROVAL_PAUSED")
                if status in {"APPROVAL_REJECTED", "APPROVAL_EXPIRED"}:
                    return self._block(
                        store,
                        event,
                        [f"governance decision did not approve capability construction: {status}"],
                    )
                return {
                    "status": "DECISION_PENDING",
                    "idempotency_key": event.idempotency_key,
                    "required_roles": list(request["required_roles"]),
                    "decision_status": status,
                }
            receipt = validate_governance_decision_verification(request, verification)
        except Exception as exc:
            return self._block(
                store,
                event,
                [f"governance decision verification failed: {type(exc).__name__}: {exc}"],
            )

        receipt_evidence = EvidenceReference(
            kind="governance_decision_receipt",
            uri=f"urn:rd-flywheel:governance-receipt:{receipt['receipt_id']}",
            sha256=str(receipt["verification_digest"]).removeprefix("sha256:"),
            verifier="independent:release-approval-verifier",
            verified=True,
        )
        profile = self.config.agent_profile
        adapter = self.agent_adapters.get(profile or "")
        if profile is None or profile not in self.config.approved_agent_profiles or adapter is None:
            return self._block(
                store,
                event,
                ["approved agent adapter became unavailable after governance approval"],
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
            (receipt_evidence, selection),
            changed_at=self.clock(),
            detail=(
                "all frozen required roles approved the hash-bound governance request; "
                "approved agent adapter selected"
            ),
            adapter_profile=profile,
        )
        store.append_audit_event(
            "governance_decision_verified",
            {
                "idempotency_key": event.idempotency_key,
                "receipt_id": receipt["receipt_id"],
                "request_digest": request["request_digest"],
                "role_snapshot_digest": request["role_snapshot_digest"],
                "screen_sha256": request["visual_companion"]["html_sha256"],
                "authority_scope": receipt["authority_scope"],
            },
            created_at=self.clock(),
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

    def _freeze_decision_package(
        self,
        event: CapabilityGapEvent,
        snapshot: DecisionRoleSnapshot,
    ) -> tuple[Any, dict[str, Path]]:
        paths = self._decision_paths(event)
        directory = paths["request"].parent
        primary = (paths["request"], paths["screen"], paths["snapshot"])
        if any(path.exists() for path in primary):
            if not all(path.is_file() for path in primary):
                raise DecisionError("frozen governance decision package is incomplete")
            return self._load_frozen_decision_package(event, expected_snapshot=snapshot)
        requested_at = self.clock()
        requested = datetime.fromisoformat(requested_at.replace("Z", "+00:00"))
        expires_at = (requested + timedelta(hours=24)).astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        domain = self.config.notification.recipients[0].rsplit("@", 1)[-1]
        message_id = (
            f"<rd-flywheel-{event.idempotency_key[:32]}-"
            f"r{event.originating_round_id}@{domain}>"
        )
        package = build_governance_decision_request(
            event,
            snapshot,
            requested_at=requested_at,
            expires_at=expires_at,
            original_message_id=message_id,
        )
        snapshot_payload = decision_role_snapshot_payload(snapshot)
        directory.mkdir(parents=True, exist_ok=False)
        self._write_frozen_text(paths["screen"], package.screen_html)
        self._write_frozen_text(
            paths["request"],
            canonical_json(package.request) + "\n",
        )
        self._write_frozen_text(
            paths["snapshot"],
            canonical_json(snapshot_payload) + "\n",
        )
        return package, paths

    def _decision_paths(self, event: CapabilityGapEvent) -> dict[str, Path]:
        directory = self.config.audit_dir / "decisions" / event.idempotency_key
        return {
            "request": directory / "governance-decision-request.json",
            "screen": directory / "visual-companion.html",
            "snapshot": directory / "role-snapshot.json",
            "presentation": directory / "presentation-receipt.json",
        }

    def _load_frozen_decision_package(
        self,
        event: CapabilityGapEvent,
        *,
        expected_snapshot: DecisionRoleSnapshot | None = None,
    ) -> tuple[GovernanceDecisionPackage, dict[str, Path]]:
        paths = self._decision_paths(event)
        payload = json.loads(paths["request"].read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise DecisionError("frozen governance decision request is not an object")
        expected_digest = "sha256:" + hashlib.sha256(
            canonical_json(
                {key: value for key, value in payload.items() if key != "request_digest"}
            ).encode("utf-8")
        ).hexdigest()
        if payload.get("request_digest") != expected_digest:
            raise DecisionError("frozen governance decision request digest is invalid")
        if payload.get("event_id") != event.idempotency_key:
            raise DecisionError("frozen governance decision request event binding is invalid")
        if payload.get("round_id") != event.originating_round_id:
            raise DecisionError("frozen governance decision request round binding is invalid")
        if payload.get("authority_scope") != "RD_FLYWHEEL_GOVERNANCE":
            raise DecisionError("frozen governance decision authority scope is invalid")

        screen_html = paths["screen"].read_text(encoding="utf-8")
        screen_sha256 = hashlib.sha256(screen_html.encode("utf-8")).hexdigest()
        visual_digest = "sha256:" + screen_sha256
        visual = payload.get("visual_companion")
        if not isinstance(visual, Mapping) or visual != {
            "html_sha256": visual_digest,
            "authority": "DESIGN_CONSENT_ONLY",
        }:
            raise DecisionError("frozen Visual Companion digest is invalid")

        snapshot_payload = json.loads(paths["snapshot"].read_text(encoding="utf-8"))
        frozen_snapshot = decision_role_snapshot_from_mapping(snapshot_payload)
        if frozen_snapshot.digest != payload.get("role_snapshot_digest"):
            raise DecisionError("frozen role snapshot is not bound to the request")
        if expected_snapshot is not None and frozen_snapshot.digest != expected_snapshot.digest:
            raise DecisionError("live Feishu role snapshot drifted from the frozen package")
        required_roles = [role for role in frozen_snapshot.roles if role.required]
        expected_manifest_s = "sha256:" + event.payload_digest
        expected_manifest = "sha256:" + hashlib.sha256(
            canonical_json(
                {
                    "manifest_s_digest": expected_manifest_s,
                    "manifest_r_digest": visual_digest,
                }
            ).encode("utf-8")
        ).hexdigest()
        expected_context = {
            "authority_boundary": "DESIGN_CONSENT_ONLY",
            "missing_capability": event.missing_capability,
            "originating_plugin": event.originating_plugin,
            "originating_event_id": event.originating_event_id,
            "checkpoint_digest": event.checkpoint_digest,
            "required_evidence": list(event.required_evidence),
            "visual_companion_html_sha256": visual_digest,
        }
        expected_bindings = {
            "contract": "ReleaseAuthorizationRequest/v1",
            "schema": "ReleaseAuthorizationRequest/v1",
            "target_scope": "rd-flywheel:capability-construction",
            "task_id": event.missing_capability,
            "task": event.missing_capability,
            "module": event.originating_plugin,
            "source_ref": event.originating_event_id,
            "checkpoint_digest": event.checkpoint_digest,
            "manifest_s_digest": expected_manifest_s,
            "manifest_r_digest": visual_digest,
            "manifest_digest": expected_manifest,
            "role_snapshot_digest": frozen_snapshot.digest,
            "required_roles": [role.role_id for role in required_roles],
            "required_role_bindings": [
                {
                    "role_id": role.role_id,
                    "email": role.email,
                    "required": True,
                }
                for role in required_roles
            ],
            "governance_context": expected_context,
        }
        drifted = [
            field_name
            for field_name, expected_value in expected_bindings.items()
            if payload.get(field_name) != expected_value
        ]
        if drifted:
            raise DecisionError(
                "frozen governance decision request drifted from the capability event: "
                + ", ".join(drifted)
            )
        return (
            GovernanceDecisionPackage(
                request=payload,
                screen_html=screen_html,
                screen_sha256=screen_sha256,
            ),
            paths,
        )

    def _load_frozen_decision_request(
        self,
        event: CapabilityGapEvent,
    ) -> dict[str, Any]:
        package, _ = self._load_frozen_decision_package(event)
        return dict(package.request)

    def _decision_recipients(self, snapshot: DecisionRoleSnapshot) -> list[str]:
        recipients: list[str] = []
        seen: set[str] = set()
        for address in (
            *self.config.notification.recipients,
            *(role.email for role in snapshot.roles if role.required),
        ):
            normalized = address.casefold()
            if normalized not in seen:
                seen.add(normalized)
                recipients.append(address)
        return recipients

    @staticmethod
    def _validate_presentation(
        request: Mapping[str, Any],
        recipients: Sequence[str],
        presentation: Mapping[str, Any],
    ) -> None:
        if not isinstance(presentation, Mapping):
            raise DecisionError("decision presenter returned a non-object result")
        if presentation.get("status") != "accepted":
            raise DecisionError("decision notification was not accepted by SMTP")
        if presentation.get("refused") != {}:
            raise DecisionError("decision notification refused one or more recipients")
        if presentation.get("atomic_recipients") is not True:
            raise DecisionError("decision notification did not use atomic recipients")
        if presentation.get("data_submitted") is not True:
            raise DecisionError("decision notification has no confirmed DATA submission")
        if presentation.get("message_id") != request.get("original_message_id"):
            raise DecisionError("decision notification Message-ID drifted")
        if presentation.get("recipients") != list(recipients):
            raise DecisionError("decision notification recipient order drifted")
        accepted_at = presentation.get("accepted_at")
        if not isinstance(accepted_at, str) or not accepted_at.strip():
            raise DecisionError("decision notification acceptance timestamp is missing")
        try:
            parsed = datetime.fromisoformat(accepted_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise DecisionError("decision notification acceptance timestamp is invalid") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise DecisionError("decision notification acceptance timestamp has no timezone")
        canonical_json(dict(presentation))

    @staticmethod
    def _write_frozen_text(path: Path, content: str) -> None:
        if path.exists():
            raise DecisionError(f"frozen decision artifact already exists: {path.name}")
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.replace(path)

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
        if self.config.decision_role_source is None:
            reasons.append("live Feishu decision role source is not configured")
        if self.config.notification is None:
            reasons.append("governance decision notification profile is not configured")
        if self.role_snapshot_fetcher is None:
            reasons.append("live decision role snapshot fetcher is unavailable")
        if self.decision_presenter is None:
            reasons.append("governance decision presenter is unavailable")
        if self.decision_verifier is None:
            reasons.append("independent governance decision verifier is unavailable")
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
