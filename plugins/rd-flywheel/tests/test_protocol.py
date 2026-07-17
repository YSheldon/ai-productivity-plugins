import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rd_flywheel_protocol import (  # noqa: E402
    PRODUCTION_EVIDENCE_TYPES,
    CapabilityGapEvent,
    EvidenceReference,
    ProtocolError,
    canonical_json,
    compute_idempotency_key,
    missing_completion_evidence,
    validate_transition,
)


def valid_payload() -> dict:
    payload = {
        "schema": "CapabilityGapEvent/v1",
        "originating_plugin": "release-approval",
        "originating_event_id": "release-20260716-001",
        "originating_round_id": 2,
        "checkpoint_digest": "a" * 64,
        "missing_capability": "mail.raw_thread_headers",
        "required_evidence": list(PRODUCTION_EVIDENCE_TYPES),
        "allowed_tool_profiles": ["imap-smtp-mail", "gitlab", "lark-cli"],
        "created_at": "2026-07-16T08:00:00Z",
    }
    payload["idempotency_key"] = compute_idempotency_key(payload)
    return payload


def test_capability_gap_event_binds_all_required_fields():
    event = CapabilityGapEvent.from_mapping(valid_payload())
    assert event.originating_plugin == "release-approval"
    assert event.originating_round_id == 2
    assert event.checkpoint_digest == "a" * 64
    assert set(event.required_evidence) == set(PRODUCTION_EVIDENCE_TYPES)
    assert event.payload_digest == hashlib.sha256(canonical_json(valid_payload()).encode()).hexdigest()


def test_idempotency_key_rejects_payload_tampering():
    payload = valid_payload()
    payload["missing_capability"] = "mail.thread_reply"
    with pytest.raises(ProtocolError, match="idempotency_key"):
        CapabilityGapEvent.from_mapping(payload)


@pytest.mark.parametrize(("field", "value"), [
    ("checkpoint_digest", "short"),
    ("originating_round_id", 0),
    ("created_at", "2026-07-16 08:00:00"),
    ("allowed_tool_profiles", []),
])
def test_protocol_rejects_malformed_security_fields(field, value):
    payload = valid_payload()
    payload[field] = value
    payload["idempotency_key"] = compute_idempotency_key(payload)
    with pytest.raises(ProtocolError):
        CapabilityGapEvent.from_mapping(payload)


def test_production_evidence_cannot_be_omitted():
    payload = valid_payload()
    payload["required_evidence"] = ["tests", "protected_merge"]
    payload["idempotency_key"] = compute_idempotency_key(payload)
    with pytest.raises(ProtocolError, match="required production evidence"):
        CapabilityGapEvent.from_mapping(payload)


def evidence(kind="adapter_selection", verified=True):
    return EvidenceReference(
        kind=kind,
        uri=f"urn:evidence:{kind}",
        sha256="b" * 64,
        verifier="independent-verifier",
        verified=verified,
    )


def test_state_after_validated_requires_durable_evidence():
    with pytest.raises(ProtocolError, match="durable evidence"):
        validate_transition("VALIDATED", "WAITING_AGENT", ())
    validate_transition("VALIDATED", "WAITING_AGENT", (evidence(),))


def test_illegal_state_transition_is_rejected():
    with pytest.raises(ProtocolError, match="illegal state transition"):
        validate_transition("RECEIVED", "COMPLETE", (evidence("tests"),))


def test_ai_or_command_claims_do_not_satisfy_completion():
    event = CapabilityGapEvent.from_mapping(valid_payload())
    refs = tuple(
        EvidenceReference(
            kind=kind,
            uri=f"urn:agent:{kind}",
            sha256=hashlib.sha256(kind.encode()).hexdigest(),
            verifier="agent-self-report",
            verified=False,
        )
        for kind in event.required_evidence
    )
    assert set(missing_completion_evidence(event, refs)) == set(PRODUCTION_EVIDENCE_TYPES)


def test_each_required_evidence_must_be_independently_verified():
    event = CapabilityGapEvent.from_mapping(valid_payload())
    refs = tuple(evidence(kind) for kind in event.required_evidence)
    assert missing_completion_evidence(event, refs) == ()


def test_canonical_json_is_stable():
    assert canonical_json({"b": 2, "a": [1, {"x": True}]}) == canonical_json(
        json.loads('{"a":[1,{"x":true}],"b":2}')
    )
