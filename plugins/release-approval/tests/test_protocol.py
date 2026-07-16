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


def test_request_digest_is_deterministic_and_validation_returns_frozen_request() -> None:
    payload = _payload()
    validated = validate_release_request(
        payload,
        installed_role_id="release-manager",
        installed_role_email="release-manager@example.com",
        now=datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc),
    )

    assert validated.request_digest == build_request_digest(payload)
    assert validated.required_roles == ("release-manager", "security-reviewer")
    assert validated.installed_role_id == "release-manager"
    assert validated.installed_role_email == "release-manager@example.com"

    with pytest.raises(Exception):
        validated.round_id = 2  # type: ignore[misc]


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda payload: payload.__setitem__("contract", "ReleaseAuthorizationRequest/v2"), "exact"),
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
