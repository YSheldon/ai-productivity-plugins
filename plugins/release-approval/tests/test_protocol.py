from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_protocol import (
    ProtocolError,
    build_request_digest,
    canonical_json,
    prepare_page_request,
    validate_release_request,
)


def _payload() -> dict[str, object]:
    payload = json.loads(
        (PLUGIN_ROOT / "contracts" / "release-authorization-request-v1.json").read_text(
            encoding="utf-8"
        )
    )
    payload["request_digest"] = build_request_digest(payload)
    return payload


def _governance_payload() -> dict[str, object]:
    payload = _payload()
    payload.update(
        {
            "authority_scope": "RD_FLYWHEEL_GOVERNANCE",
            "task": "cloud_scan.real_api",
            "module": "submission-gate",
            "source_ref": "capability-17",
            "checkpoint_digest": "a" * 64,
            "manifest_r_digest": "sha256:" + "2" * 64,
            "visual_companion": {
                "html_sha256": "sha256:" + "2" * 64,
                "authority": "DESIGN_CONSENT_ONLY",
            },
            "governance_context": {
                "authority_boundary": "DESIGN_CONSENT_ONLY",
                "missing_capability": "cloud_scan.real_api",
                "originating_plugin": "submission-gate",
                "originating_event_id": "capability-17",
                "checkpoint_digest": "a" * 64,
                "required_evidence": ["tests", "security_review", "release_readback"],
                "visual_companion_html_sha256": "sha256:" + "2" * 64,
            },
        }
    )
    payload["request_digest"] = build_request_digest(payload)
    return payload


def test_request_digest_is_deterministic_and_validation_returns_frozen_request() -> None:
    payload = _payload()
    validated = validate_release_request(
        payload,
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
        now=datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
    )

    assert validated.request_digest == build_request_digest(payload)
    assert validated.authority_scope == "PRODUCTION_RELEASE"
    assert validated.required_roles == ("release-manager", "security-reviewer")
    assert validated.installed_role_id == "release-manager"
    assert validated.installed_role_email == "release-manager@example.com"
    assert validated.governance_context is None
    assert validated.wire_payload_json == canonical_json(payload)

    with pytest.raises(Exception):
        validated.round_id = 2  # type: ignore[misc]


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda payload: payload.__setitem__("contract", "ReleaseAuthorizationRequest/v2"), "exact"),
        (lambda payload: payload.pop("authority_scope"), "authority_scope"),
        (lambda payload: payload.__setitem__("authority_scope", "UNSCOPED"), "authority_scope"),
        (lambda payload: payload.__setitem__("round_id", 0), "positive round"),
        (lambda payload: payload.__setitem__("original_message_id", "invalid@example.com"), "RFC Message-ID"),
        (lambda payload: payload.__setitem__("request_digest", "sha256:" + "0" * 64), "request digest"),
        (lambda payload: payload.__setitem__("required_roles", []), "required_roles"),
        (
            lambda payload: payload.__setitem__("expires_at", "2026-07-14T12:00:00Z"),
            "expired",
        ),
        (
            lambda payload: payload.__setitem__("required_roles", ["security-reviewer"]),
            "required_roles",
        ),
    ],
)
def test_invalid_requests_raise_protocol_error(mutator, message: str) -> None:
    payload = _payload()
    mutator(payload)
    if payload.get("request_digest") == build_request_digest(_payload()):
        payload["request_digest"] = build_request_digest(payload)

    with pytest.raises(ProtocolError, match=message):
        validate_release_request(
            payload,
            installed_role_id="release-manager",
            installed_role_email="release-manager@example.com",
            now=datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    "expires_at",
    [
        "2026-07-16",
        "2026-07-16T00:00:00",
        "2026-07-16 00:00:00Z",
        "2026-07-16T00:00:00+0000",
    ],
)
def test_rfc3339_requires_canonical_timezone_bearing_timestamps(expires_at: str) -> None:
    payload = _payload()
    payload["expires_at"] = expires_at
    payload["request_digest"] = build_request_digest(payload)

    with pytest.raises(ProtocolError, match="RFC 3339 timestamp"):
        validate_release_request(
            payload,
            installed_role_id="release-manager",
            installed_role_email="release-manager@example.com",
            now=datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
        )


def test_invalid_request_fails_before_page_creation() -> None:
    payload = _payload()
    payload["request_digest"] = "sha256:" + "0" * 64
    called = {"value": False}

    def page_factory(_request):
        called["value"] = True
        return {"page": "should not happen"}

    with pytest.raises(ProtocolError):
        prepare_page_request(
            payload,
            installed_role_id="release-manager",
            installed_role_email="release-manager@example.com",
            now=datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
            page_factory=page_factory,
        )

    assert called["value"] is False


def test_governance_request_freezes_visual_companion_context_and_wire_payload() -> None:
    payload = _governance_payload()

    validated = validate_release_request(
        payload,
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
        now=datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
    )

    assert validated.governance_context is not None
    assert validated.governance_context.missing_capability == "cloud_scan.real_api"
    assert validated.governance_context.required_evidence == (
        "tests",
        "security_review",
        "release_readback",
    )
    assert json.loads(validated.wire_payload_json) == payload


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda payload: payload.pop("governance_context"), "governance_context is required"),
        (
            lambda payload: payload["governance_context"].__setitem__(  # type: ignore[union-attr]
                "missing_capability", "different.capability"
            ),
            "binding mismatch",
        ),
        (
            lambda payload: payload["governance_context"].__setitem__(  # type: ignore[union-attr]
                "required_evidence", ["tests", "tests"]
            ),
            "duplicates",
        ),
        (
            lambda payload: payload["visual_companion"].__setitem__(  # type: ignore[union-attr]
                "authority", "PRODUCTION_RELEASE"
            ),
            "binding mismatch",
        ),
    ],
)
def test_governance_context_drift_fails_closed(mutator, message: str) -> None:
    payload = _governance_payload()
    mutator(payload)
    payload["request_digest"] = build_request_digest(payload)

    with pytest.raises(ProtocolError, match=message):
        validate_release_request(
            payload,
            installed_role_id="release-manager",
            installed_role_email="release-manager@example.com",
            now=datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
        )


def test_production_request_cannot_smuggle_governance_context() -> None:
    payload = _payload()
    payload["governance_context"] = _governance_payload()["governance_context"]
    payload["request_digest"] = build_request_digest(payload)

    with pytest.raises(ProtocolError, match="only valid"):
        validate_release_request(
            payload,
            installed_role_id="release-manager",
            installed_role_email="release-manager@example.com",
            now=datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
        )
