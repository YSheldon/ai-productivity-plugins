from __future__ import annotations

import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from message_validator import MessageValidationError, validate_and_record_message
from role_snapshot import RoleRecord
from verifier_config import AuthenticationPolicyConfig
from verifier_store import VerifierStore


FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures"


def _request_binding() -> dict[str, object]:
    return {
        "event_id": "evt-2026-07-16",
        "round_id": 2,
        "manifest_digest": "sha256:" + "a" * 64,
        "role_snapshot_digest": "sha256:" + "b" * 64,
        "original_message_id": "<release-request@example.com>",
        "references": ("<thread-root@example.com>", "<release-request@example.com>"),
        "expires_at": "2026-07-17T00:00:00Z",
    }


def _expected_role() -> RoleRecord:
    return RoleRecord(
        role_id="security-reviewer",
        email="security-reviewer@example.com",
        required=False,
        enabled=True,
    )


def _auth_policy() -> AuthenticationPolicyConfig:
    return AuthenticationPolicyConfig(
        accepted_paths=("dmarc", "dkim", "spf"),
        allowed_authserv_ids=("mx.example.com",),
        trusted_internal_header="X-Trusted-Relay",
        trusted_internal_value="release-gateway",
    )


def _parse_fixture(name: str):
    return BytesParser(policy=policy.default).parsebytes((FIXTURE_ROOT / name).read_bytes())


def test_validate_and_record_message_accepts_matching_sender_thread_and_authenticated_path(
    tmp_path: Path,
) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    message = _parse_fixture("valid-approval.eml")

    validated = validate_and_record_message(
        message,
        request_binding=_request_binding(),
        expected_role=_expected_role(),
        authentication_policy=_auth_policy(),
        store=store,
        now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
    )

    assert validated.decision == "APPROVE"
    assert validated.approver_email == "security-reviewer@example.com"
    assert validated.authentication_path == "dmarc"
    assert store.get_current_decision("evt-2026-07-16", 2, "security-reviewer").decision == "APPROVE"


def test_spf_path_requires_trusted_results_and_received_spf_corroboration(
    tmp_path: Path,
) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    message = _parse_fixture("valid-approval.eml")
    message.replace_header(
        "Authentication-Results",
        "mx.example.com; dmarc=fail; dkim=fail; spf=pass "
        "smtp.mailfrom=security-reviewer@example.com",
    )

    validated = validate_and_record_message(
        message,
        request_binding=_request_binding(),
        expected_role=_expected_role(),
        authentication_policy=_auth_policy(),
        store=store,
        now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
    )

    assert validated.authentication_path == "spf"


def test_untrusted_authserv_id_cannot_supply_a_passing_result(
    tmp_path: Path,
) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    message = _parse_fixture("valid-approval.eml")
    message.replace_header(
        "Authentication-Results",
        "mx.example.com; dmarc=fail; dkim=fail; spf=fail",
    )
    message["Authentication-Results"] = (
        "attacker.example; dmarc=pass header.from=example.com; "
        "dkim=pass header.d=example.com; spf=pass"
    )

    with pytest.raises(MessageValidationError, match="authenticated path"):
        validate_and_record_message(
            message,
            request_binding=_request_binding(),
            expected_role=_expected_role(),
            authentication_policy=_auth_policy(),
            store=store,
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )

    assert store.get_current_decision(
        "evt-2026-07-16", 2, "security-reviewer"
    ) is None


def test_duplicate_message_id_is_rejected_without_overwriting_current_decision(tmp_path: Path) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    message = _parse_fixture("valid-approval.eml")

    first = validate_and_record_message(
        message,
        request_binding=_request_binding(),
        expected_role=_expected_role(),
        authentication_policy=_auth_policy(),
        store=store,
        now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
    )

    with pytest.raises(MessageValidationError, match="duplicate Message-ID"):
        validate_and_record_message(
            message,
            request_binding=_request_binding(),
            expected_role=_expected_role(),
            authentication_policy=_auth_policy(),
            store=store,
            now=datetime(2026, 7, 16, 4, 5, tzinfo=timezone.utc),
        )

    current = store.get_current_decision("evt-2026-07-16", 2, "security-reviewer")
    assert current is not None
    assert current.decision_id == first.decision_id


def test_authserv_id_must_be_allowlisted_for_reply_authentication(
    tmp_path: Path,
) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    message = _parse_fixture("valid-approval.eml")
    message.replace_header(
        "Authentication-Results",
        "evil.example.net; dkim=pass header.d=example.com; dmarc=pass action=none header.from=example.com; spf=pass",
    )

    with pytest.raises(MessageValidationError, match="authenticated path"):
        validate_and_record_message(
            message,
            request_binding=_request_binding(),
            expected_role=_expected_role(),
            authentication_policy=_auth_policy(),
            store=store,
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    ("fixture_name", "mutator", "message"),
    [
        ("spoofed-approval.eml", None, "Return-Path"),
        ("valid-approval.eml", lambda msg: msg.replace_header("X-RD-Round-Id", "3"), "round"),
        (
            "valid-approval.eml",
            lambda msg: msg.replace_header("Authentication-Results", "mx.example.com; dkim=fail"),
            "authenticated",
        ),
    ],
)
def test_invalid_messages_are_quarantined_and_do_not_create_decisions(
    tmp_path: Path,
    fixture_name: str,
    mutator,
    message: str,
) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    parsed = _parse_fixture(fixture_name)
    if mutator is not None:
        mutator(parsed)

    with pytest.raises(MessageValidationError, match=message):
        validate_and_record_message(
            parsed,
            request_binding=_request_binding(),
            expected_role=_expected_role(),
            authentication_policy=_auth_policy(),
            store=store,
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )

    processed = store.get_processed_message(parsed["Message-ID"])
    assert processed is not None
    assert processed.status == "QUARANTINED"
    assert store.get_current_decision("evt-2026-07-16", 2, "security-reviewer") is None


def test_trusted_internal_header_is_rejected_when_path_is_not_enabled(
    tmp_path: Path,
) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    message = _parse_fixture("valid-approval.eml")
    message.replace_header(
        "Authentication-Results",
        "mx.example.com; dmarc=fail; dkim=fail; spf=fail",
    )
    message.replace_header("Received-SPF", "fail")
    message["X-Trusted-Relay"] = "release-gateway"

    with pytest.raises(MessageValidationError, match="no configured authenticated path"):
        validate_and_record_message(
            message,
            request_binding=_request_binding(),
            expected_role=_expected_role(),
            authentication_policy=_auth_policy(),
            store=store,
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )

    assert store.get_current_decision(
        "evt-2026-07-16", 2, "security-reviewer"
    ) is None


def test_trusted_internal_header_is_accepted_only_when_explicitly_enabled(
    tmp_path: Path,
) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    message = _parse_fixture("valid-approval.eml")
    message.replace_header(
        "Authentication-Results",
        "mx.example.com; dmarc=fail; dkim=fail; spf=fail",
    )
    message.replace_header("Received-SPF", "fail")
    message["X-Trusted-Relay"] = "release-gateway"
    policy = AuthenticationPolicyConfig(
        accepted_paths=("trusted_internal",),
        allowed_authserv_ids=("mx.example.com",),
        trusted_internal_header="X-Trusted-Relay",
        trusted_internal_value="release-gateway",
    )

    decision = validate_and_record_message(
        message,
        request_binding=_request_binding(),
        expected_role=_expected_role(),
        authentication_policy=policy,
        store=store,
        now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
    )

    assert decision.authentication_path == "trusted_internal"


def test_expired_request_is_quarantined_as_failure_isolation(tmp_path: Path) -> None:
    store = VerifierStore(tmp_path / "state.sqlite3")
    message = _parse_fixture("valid-approval.eml")
    request_binding = _request_binding()
    request_binding["expires_at"] = "2026-07-16T03:59:00Z"

    with pytest.raises(MessageValidationError, match="expired"):
        validate_and_record_message(
            message,
            request_binding=request_binding,
            expected_role=_expected_role(),
            authentication_policy=_auth_policy(),
            store=store,
            now=datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc),
        )

    processed = store.get_processed_message(message["Message-ID"])
    assert processed is not None
    assert processed.status == "QUARANTINED"
