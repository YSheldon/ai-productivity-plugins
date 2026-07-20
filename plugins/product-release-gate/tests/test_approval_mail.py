from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_approval_mail import (  # noqa: E402
    ApprovalMailError,
    ImapSmtpMailCliGateway,
    LockedImapSmtpMailCliGateway,
)


def _locked_mail_fixture(tmp_path: Path) -> tuple[Path, str, Path]:
    cli = (
        tmp_path
        / "plugins"
        / "imap-smtp-mail"
        / "src"
        / "imap_smtp_mail_cli.py"
    )
    cli.parent.mkdir(parents=True)
    cli.write_text("print('mail')\n", encoding="utf-8")
    lock = tmp_path / "dependency-lock.product-release-gate.json"
    lock.write_text(
        json.dumps(
            {
                "plugins": [
                    {
                        "name": "imap-smtp-mail",
                        "plugin_root": "plugins/imap-smtp-mail",
                        "entrypoints": [
                            {
                                "kind": "runtime_entrypoint",
                                "path": (
                                    "plugins/imap-smtp-mail/src/"
                                    "imap_smtp_mail_cli.py"
                                ),
                                "sha256": hashlib.sha256(
                                    cli.read_bytes()
                                ).hexdigest(),
                            }
                        ],
                    }
                ]
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return lock, hashlib.sha256(lock.read_bytes()).hexdigest(), cli


class ApprovalMailTests(unittest.TestCase):
    def test_gateway_uses_json_stdin_argument_array_without_shell(self) -> None:
        calls: list[dict[str, object]] = []

        def runner(*args, **kwargs):
            calls.append({"args": args, **kwargs})
            return subprocess.CompletedProcess(
                args[0],
                0,
                json.dumps(
                    {
                        "ok": True,
                        "result": {
                            "sent": True,
                            "message_id": "<request@example.com>",
                            "refused": {},
                        },
                    }
                ),
                "",
            )

        gateway = ImapSmtpMailCliGateway(
            [sys.executable, "imap_smtp_mail_cli.py"], runner=runner
        )
        payload = {
            "account": "release-bot",
            "to": ["release@example.com"],
            "subject": "【发布申请】Task-module-time",
            "text": "body",
            "message_id": "<request@example.com>",
        }

        self.assertTrue(gateway.send_email(payload)["sent"])
        self.assertEqual(
            ([sys.executable, "imap_smtp_mail_cli.py"],),
            calls[0]["args"],
        )
        self.assertFalse(calls[0]["shell"])
        self.assertEqual(
            {
                "tool": "send_email",
                "arguments": payload,
            },
            json.loads(str(calls[0]["input"])),
        )

    def test_gateway_exposes_validated_search_and_authenticated_readback(self) -> None:
        calls: list[str] = []

        def runner(*args, **kwargs):
            request = json.loads(str(kwargs["input"]))
            calls.append(request["tool"])
            if request["tool"] == "search_messages":
                result = {"messages": [{"uid": "42", "message_id": "<report@example.com>"}]}
            elif request["tool"] == "test_connection":
                result = {"checks": {"imap": "ok", "smtp": "ok"}}
            else:
                result = {
                    "uid": "42",
                    "message_id": "<report@example.com>",
                    "evidence": {
                        "message_id": "<report@example.com>",
                        "raw_headers_sha256": "a" * 64,
                    },
                    "release_workflow_headers": {"event_id": "event-1"},
                }
            return subprocess.CompletedProcess(
                args[0],
                0,
                json.dumps({"ok": True, "result": result}),
                "",
            )

        gateway = ImapSmtpMailCliGateway(["mail"], runner=runner)
        connection = gateway.test_connection(
            {"account": "release-bot", "check_imap": True, "check_smtp": True}
        )
        search = gateway.search_messages({"account": "release-bot"})
        message = gateway.read_message(
            {"account": "release-bot", "mailbox": "INBOX", "uid": "42"}
        )

        self.assertEqual("ok", connection["checks"]["imap"])
        self.assertEqual("42", search["messages"][0]["uid"])
        self.assertEqual("<report@example.com>", message["message_id"])
        self.assertEqual(["test_connection", "search_messages", "read_message"], calls)

    def test_gateway_rejects_unsafe_command_or_timeout(self) -> None:
        cases = [
            ("python mail.py", 30),
            (["python", "mail.py\n--unsafe"], 30),
            (["python", "mail.py"], True),
            (["python", "mail.py"], 0),
            (["python", "mail.py"], 601),
        ]
        for command, timeout in cases:
            with self.subTest(command=command, timeout=timeout):
                with self.assertRaises(ApprovalMailError):
                    ImapSmtpMailCliGateway(command, timeout_seconds=timeout)

    def test_gateway_fails_closed_on_cli_errors(self) -> None:
        cases = [
            (
                subprocess.CompletedProcess(["mail"], 1, "", "SMTP failed"),
                "SMTP failed",
            ),
            (
                subprocess.CompletedProcess(["mail"], 0, "not-json", ""),
                "invalid JSON",
            ),
            (
                subprocess.CompletedProcess(
                    ["mail"],
                    0,
                    json.dumps({"ok": False, "error": "denied"}),
                    "",
                ),
                "denied",
            ),
            (
                subprocess.CompletedProcess(
                    ["mail"],
                    0,
                    json.dumps({"ok": True, "result": []}),
                    "",
                ),
                "result object",
            ),
        ]
        for completed, message in cases:
            with self.subTest(message=message):
                gateway = ImapSmtpMailCliGateway(
                    ["mail"], runner=lambda *args, **kwargs: completed
                )
                with self.assertRaisesRegex(ApprovalMailError, message):
                    gateway.send_email({"to": ["release@example.com"]})


class LockedApprovalMailTests(unittest.TestCase):
    def test_locked_gateway_executes_only_the_pinned_mail_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            lock, lock_digest, cli = _locked_mail_fixture(tmp_path)
            calls: list[list[str]] = []

            def runner(*args, **kwargs):
                calls.append(list(args[0]))
                return subprocess.CompletedProcess(
                    args[0],
                    0,
                    json.dumps(
                        {
                            "ok": True,
                            "result": {
                                "accounts": [
                                    {
                                        "name": "release-bot",
                                        "email": "bot@example.com",
                                    }
                                ]
                            },
                        }
                    ),
                    "",
                )

            gateway = LockedImapSmtpMailCliGateway(
                lock,
                dependency_lock_sha256=lock_digest,
                runner=runner,
            )

            self.assertEqual("release-bot", gateway.list_accounts()[0]["name"])
            self.assertEqual([[sys.executable, str(cli.resolve())]], calls)

    def test_locked_gateway_rejects_lock_or_entrypoint_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp_path = Path(temporary)
            lock, lock_digest, cli = _locked_mail_fixture(tmp_path)
            cli.write_text("print('tampered')\n", encoding="utf-8")

            with self.assertRaisesRegex(ApprovalMailError, "entrypoint drift"):
                LockedImapSmtpMailCliGateway(
                    lock,
                    dependency_lock_sha256=lock_digest,
                )

            lock.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ApprovalMailError, "lock drift"):
                LockedImapSmtpMailCliGateway(
                    lock,
                    dependency_lock_sha256=lock_digest,
                )


if __name__ == "__main__":
    unittest.main()
