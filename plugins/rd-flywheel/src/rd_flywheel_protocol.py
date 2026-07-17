from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping, Sequence


SCHEMA_NAME = "CapabilityGapEvent/v1"
STATES = (
    "RECEIVED",
    "VALIDATED",
    "WAITING_AGENT",
    "BUILDING",
    "EVIDENCE_PENDING",
    "COMPLETE",
    "REJECTED",
    "CAPABILITY_BLOCKED",
)
PRODUCTION_EVIDENCE_TYPES = (
    "tests",
    "independent_review",
    "protected_merge",
    "package_publication",
    "installation",
    "first_practice",
    "rollback",
    "checkpoint_replay",
)
_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_ALLOWED_TRANSITIONS = {
    "RECEIVED": frozenset({"VALIDATED", "REJECTED"}),
    "VALIDATED": frozenset({"WAITING_AGENT", "CAPABILITY_BLOCKED", "REJECTED"}),
    "WAITING_AGENT": frozenset({"BUILDING", "CAPABILITY_BLOCKED", "REJECTED"}),
    "BUILDING": frozenset({"EVIDENCE_PENDING", "CAPABILITY_BLOCKED", "REJECTED"}),
    "EVIDENCE_PENDING": frozenset({"COMPLETE", "CAPABILITY_BLOCKED", "REJECTED"}),
    "CAPABILITY_BLOCKED": frozenset({"VALIDATED"}),
    "REJECTED": frozenset(),
    "COMPLETE": frozenset(),
}
_UNTRUSTED_VERIFIERS = frozenset(
    {
        "agent",
        "agent-output",
        "agent-self-report",
        "command-exit",
        "queued-job",
        "generated-patch",
    }
)


class ProtocolError(ValueError):
    """Raised when a capability-gap contract or transition is invalid."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def compute_idempotency_key(payload: Mapping[str, Any]) -> str:
    bound = {key: value for key, value in payload.items() if key != "idempotency_key"}
    return sha256_text(canonical_json(bound))


def _required_string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(f"{key} is required.")
    return value.strip()


def _unique_strings(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise ProtocolError(f"{key} must be a non-empty list.")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ProtocolError(f"{key} must contain non-empty strings.")
    normalized = tuple(item.strip() for item in value)
    if len(set(normalized)) != len(normalized):
        raise ProtocolError(f"{key} must contain unique values.")
    return normalized


def _validate_timestamp(value: str) -> str:
    if not value.endswith("Z"):
        raise ProtocolError("created_at must be an RFC3339 UTC timestamp ending in Z.")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ProtocolError("created_at must be an RFC3339 UTC timestamp.") from exc
    if "T" not in value:
        raise ProtocolError("created_at must be an RFC3339 UTC timestamp.")
    return value


@dataclass(frozen=True)
class EvidenceReference:
    kind: str
    uri: str
    sha256: str
    verifier: str
    verified: bool

    def __post_init__(self) -> None:
        if not self.kind.strip() or not self.uri.strip():
            raise ProtocolError("evidence kind and uri are required.")
        if not _HASH_PATTERN.fullmatch(self.sha256):
            raise ProtocolError("evidence sha256 must be 64 lowercase hexadecimal characters.")
        if type(self.verified) is not bool:
            raise ProtocolError("evidence verified must be a bool.")
        if not self.verifier.strip():
            raise ProtocolError("evidence verifier is required.")

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "uri": self.uri,
            "sha256": self.sha256,
            "verifier": self.verifier,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class CapabilityGapEvent:
    schema: str
    originating_plugin: str
    originating_event_id: str
    originating_round_id: int
    checkpoint_digest: str
    missing_capability: str
    required_evidence: tuple[str, ...]
    allowed_tool_profiles: tuple[str, ...]
    created_at: str
    idempotency_key: str
    payload: Mapping[str, Any]
    payload_digest: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "CapabilityGapEvent":
        if not isinstance(payload, Mapping):
            raise ProtocolError("capability-gap event must be an object.")
        required_keys = {
            "schema",
            "originating_plugin",
            "originating_event_id",
            "originating_round_id",
            "checkpoint_digest",
            "missing_capability",
            "required_evidence",
            "allowed_tool_profiles",
            "created_at",
            "idempotency_key",
        }
        unexpected = set(payload).difference(required_keys)
        missing = required_keys.difference(payload)
        if missing:
            raise ProtocolError(f"missing required fields: {', '.join(sorted(missing))}.")
        if unexpected:
            raise ProtocolError(f"unexpected fields: {', '.join(sorted(unexpected))}.")

        schema = _required_string(payload, "schema")
        if schema != SCHEMA_NAME:
            raise ProtocolError(f"schema must be {SCHEMA_NAME}.")
        plugin = _required_string(payload, "originating_plugin")
        event_id = _required_string(payload, "originating_event_id")
        capability = _required_string(payload, "missing_capability")
        for field_name, value in (
            ("originating_plugin", plugin),
            ("originating_event_id", event_id),
            ("missing_capability", capability),
        ):
            if not _IDENTIFIER_PATTERN.fullmatch(value):
                raise ProtocolError(f"{field_name} contains unsupported characters.")

        round_id = payload.get("originating_round_id")
        if type(round_id) is not int or round_id < 1:
            raise ProtocolError("originating_round_id must be a positive integer.")
        checkpoint = _required_string(payload, "checkpoint_digest")
        if not _HASH_PATTERN.fullmatch(checkpoint):
            raise ProtocolError("checkpoint_digest must be 64 lowercase hexadecimal characters.")
        required_evidence = _unique_strings(payload, "required_evidence")
        missing_production = set(PRODUCTION_EVIDENCE_TYPES).difference(required_evidence)
        if missing_production:
            raise ProtocolError(
                "required production evidence is missing: "
                + ", ".join(sorted(missing_production))
                + "."
            )
        allowed_tools = _unique_strings(payload, "allowed_tool_profiles")
        created_at = _validate_timestamp(_required_string(payload, "created_at"))
        idempotency_key = _required_string(payload, "idempotency_key")
        if not _HASH_PATTERN.fullmatch(idempotency_key):
            raise ProtocolError("idempotency_key must be 64 lowercase hexadecimal characters.")
        expected_key = compute_idempotency_key(payload)
        if idempotency_key != expected_key:
            raise ProtocolError("idempotency_key does not bind the canonical event payload.")

        normalized = {
            "schema": schema,
            "originating_plugin": plugin,
            "originating_event_id": event_id,
            "originating_round_id": round_id,
            "checkpoint_digest": checkpoint,
            "missing_capability": capability,
            "required_evidence": list(required_evidence),
            "allowed_tool_profiles": list(allowed_tools),
            "created_at": created_at,
            "idempotency_key": idempotency_key,
        }
        return cls(
            schema=schema,
            originating_plugin=plugin,
            originating_event_id=event_id,
            originating_round_id=round_id,
            checkpoint_digest=checkpoint,
            missing_capability=capability,
            required_evidence=required_evidence,
            allowed_tool_profiles=allowed_tools,
            created_at=created_at,
            idempotency_key=idempotency_key,
            payload=MappingProxyType(normalized),
            payload_digest=sha256_text(canonical_json(normalized)),
        )


def validate_transition(
    from_state: str,
    to_state: str,
    evidence: Sequence[EvidenceReference],
) -> None:
    if from_state not in _ALLOWED_TRANSITIONS or to_state not in STATES:
        raise ProtocolError("unknown flywheel state.")
    if to_state not in _ALLOWED_TRANSITIONS[from_state]:
        raise ProtocolError(f"illegal state transition: {from_state} -> {to_state}.")
    if from_state != "RECEIVED":
        if not evidence or not any(item.verified for item in evidence):
            raise ProtocolError(
                f"{from_state} -> {to_state} requires durable evidence from a verifier."
            )


def missing_completion_evidence(
    event: CapabilityGapEvent,
    evidence: Sequence[EvidenceReference],
) -> tuple[str, ...]:
    satisfied = {
        item.kind
        for item in evidence
        if item.verified and item.verifier.casefold() not in _UNTRUSTED_VERIFIERS
    }
    return tuple(kind for kind in event.required_evidence if kind not in satisfied)
