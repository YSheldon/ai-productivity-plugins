from __future__ import annotations

import email
import hashlib
import importlib.util
from email.policy import default
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "src" / "imap_smtp_mail_mcp.py"
SPEC = importlib.util.spec_from_file_location("imap_smtp_mail_mcp", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "threaded-approval.eml"


def load_fixture_message() -> tuple[email.message.EmailMessage, bytes, bytes]:
    raw = FIXTURE_PATH.read_bytes()
    raw_headers, separator, _body = raw.partition(b"\n\n")
    assert separator == b"\n\n"
    raw_headers = raw_headers.replace(b"\n", b"\r\n") + b"\r\n\r\n"
    message = email.message_from_bytes(raw.replace(b"\n", b"\r\n"), policy=default)
    return message, raw_headers, raw


class FakeImap:
    def __init__(self, raw_message: bytes, raw_headers: bytes) -> None:
        self.raw_message = raw_message.replace(b"\n", b"\r\n")
        self.raw_headers = raw_headers
        self.logged_out = False

    def select(self, mailbox: str, readonly: bool = True) -> tuple[str, list[bytes]]:
        assert mailbox == "INBOX"
        assert readonly is True
        return "OK", [b"1 [UIDVALIDITY 777]"]

    def uid(self, command: str, uid: str, query: str) -> tuple[str, list[object]]:
        assert command == "FETCH"
        assert uid == "42"
        if query == "(BODY.PEEK[])":
            return "OK", [(b"42 (BODY[] {512}", self.raw_message), b")"]
        if query == "(BODY.PEEK[HEADER])":
            return "OK", [(b"42 (BODY[HEADER] {256}", self.raw_headers), b")"]
        raise AssertionError(f"Unexpected FETCH query: {query}")

    def logout(self) -> None:
        self.logged_out = True


def test_message_evidence_extracts_authenticated_thread_fields() -> None:
    message, raw_headers, _raw = load_fixture_message()

    evidence = MODULE.message_evidence(message, raw_headers)

    assert evidence["message_id"] == "<decision-1@example.com>"
    assert evidence["in_reply_to"] == "<request-1@example.com>"
    assert evidence["references"] == ["<root@example.com>", "<request-1@example.com>"]
    assert evidence["return_path"] == "approver@example.com"
    assert "dkim=pass" in evidence["authentication_results"]
    assert "spf=pass" in evidence["received_spf"]
    assert evidence["raw_headers_sha256"] == hashlib.sha256(raw_headers).hexdigest()
    assert len(evidence["raw_headers_sha256"]) == 64


def test_read_message_returns_uidvalidity_and_evidence_without_regressing_existing_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    message, raw_headers, raw = load_fixture_message()
    fake_imap = FakeImap(raw, raw_headers)
    account = {
        "name": "work",
        "provider": "custom",
        "email": "approver@example.com",
        "username": "approver@example.com",
        "password": "secret",
        "imap": {"host": "imap.example.com", "port": 993, "secure": True},
        "smtp": {"host": "smtp.example.com", "port": 465, "secure": True},
    }

    monkeypatch.setattr(MODULE, "resolve_account", lambda name=None: account)
    monkeypatch.setattr(MODULE, "connect_imap", lambda _: fake_imap)

    result = MODULE.read_message({"account": "work", "mailbox": "INBOX", "uid": "42"})["structuredContent"]

    assert result["account"]["name"] == "work"
    assert result["mailbox"] == "INBOX"
    assert result["uid"] == "42"
    assert result["uidvalidity"] == "777"
    assert result["subject"] == "Re: Release approval"
    assert result["from"] == [{"name": "Approver Example", "email": "approver@example.com"}]
    assert result["to"] == [{"name": "Requester Example", "email": "requester@example.com"}]
    assert result["cc"] == []
    assert result["date"] == "2026-07-15T09:30:00+00:00"
    assert result["message_id"] == "<decision-1@example.com>"
    assert result["body_text"].strip() == "Approved."
    assert result["attachments"] == []
    assert result["evidence"]["message_id"] == "<decision-1@example.com>"
    assert result["evidence"]["in_reply_to"] == "<request-1@example.com>"
    assert result["evidence"]["references"] == ["<root@example.com>", "<request-1@example.com>"]
    assert fake_imap.logged_out is True


def test_compose_email_message_sets_safe_threading_headers() -> None:
    account = {
        "name": "work",
        "provider": "custom",
        "email": "approver@example.com",
        "username": "approver@example.com",
        "password": "secret",
        "display_name": "Approver Example",
        "imap": {"host": "imap.example.com", "port": 993, "secure": True},
        "smtp": {"host": "smtp.example.com", "port": 465, "secure": True},
    }

    message, preview, recipients = MODULE.compose_email_message(
        account,
        {
            "to": ["requester@example.com"],
            "subject": "Re: Release approval",
            "text": "Approved.",
            "in_reply_to": "<request-1@example.com>",
            "references": ["noise <root@example.com>", "<request-1@example.com>", "<root@example.com>"],
            "headers": {"X-RD-Event-Id": "evt-123"},
        },
    )

    assert message["In-Reply-To"] == "<request-1@example.com>"
    assert message["References"] == "<root@example.com> <request-1@example.com>"
    assert message["X-RD-Event-Id"] == "evt-123"
    assert preview["subject"] == "Re: Release approval"
    assert recipients == ["requester@example.com"]


@pytest.mark.parametrize(
    ("args", "expected_message"),
    [
        (
            {
                "to": ["requester@example.com"],
                "subject": "Re: Release approval",
                "text": "Approved.",
                "headers": {"X-RD-Event-Id": "evt-123\r\nBcc: attacker@example.com"},
            },
            "single-line",
        ),
        (
            {
                "to": ["requester@example.com"],
                "subject": "Re: Release approval",
                "text": "Approved.",
                "headers": {"Subject": "Injected"},
            },
            "Reserved header",
        ),
        (
            {
                "to": ["requester@example.com"],
                "subject": "Re: Release approval",
                "text": "Approved.",
                "headers": {"X-RD-": "evt-123"},
            },
            "header name suffix",
        ),
        (
            {
                "to": ["requester@example.com"],
                "subject": "Re: Release approval",
                "text": "Approved.",
                "headers": {"X-RD-Event-Id\nBcc": "evt-123"},
            },
            "single-line header name",
        ),
        (
            {
                "to": ["requester@example.com"],
                "subject": "Re: Release approval",
                "text": "Approved.",
                "headers": {"X-RD-Event Id": "evt-123"},
            },
            "valid header token",
        ),
        (
            {
                "to": ["requester@example.com"],
                "subject": "Re: Release approval",
                "text": "Approved.",
                "headers": {"X-RD-" + ("A" * 2048): "evt-123"},
            },
            "header name must be 2048 characters or fewer",
        ),
        (
            {
                "to": ["requester@example.com"],
                "subject": "Re: Release approval",
                "text": "Approved.",
                "in_reply_to": "request-1@example.com",
            },
            "Message-ID",
        ),
    ],
)
def test_compose_email_message_rejects_unsafe_reply_headers(args: dict[str, object], expected_message: str) -> None:
    account = {
        "name": "work",
        "provider": "custom",
        "email": "approver@example.com",
        "username": "approver@example.com",
        "password": "secret",
        "imap": {"host": "imap.example.com", "port": 993, "secure": True},
        "smtp": {"host": "smtp.example.com", "port": 465, "secure": True},
    }

    with pytest.raises(MODULE.ToolError, match=expected_message):
        MODULE.compose_email_message(account, args)


def test_send_email_returns_message_id_and_json_safe_refused_map(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSmtp:
        def __init__(self) -> None:
            self.quit_called = False

        def send_message(self, message, from_addr=None, to_addrs=None):  # noqa: ANN001
            assert message["X-RD-Event-Id"] == "evt-123"
            return {"blocked@example.com": (550, b"Rejected")}

        def quit(self) -> None:
            self.quit_called = True

    account = {
        "name": "work",
        "provider": "custom",
        "email": "approver@example.com",
        "username": "approver@example.com",
        "password": "secret",
        "imap": {"host": "imap.example.com", "port": 993, "secure": True},
        "smtp": {"host": "smtp.example.com", "port": 465, "secure": True},
    }
    fake_smtp = FakeSmtp()

    monkeypatch.setattr(MODULE, "resolve_account", lambda name=None: account)
    monkeypatch.setattr(MODULE, "connect_smtp", lambda _: fake_smtp)

    result = MODULE.send_email(
        {
            "account": "work",
            "to": ["requester@example.com"],
            "subject": "Re: Release approval",
            "text": "Approved.",
            "dry_run": False,
            "headers": {"X-RD-Event-Id": "evt-123"},
        }
    )["structuredContent"]

    assert result["sent"] is True
    assert result["message_id"].startswith("<")
    assert result["message_id"].endswith(">")
    assert result["refused"] == {"blocked@example.com": [550, "Rejected"]}
    assert fake_smtp.quit_called is True
