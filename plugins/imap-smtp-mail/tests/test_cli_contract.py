from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


CLI_PATH = Path(__file__).parents[1] / "src" / "imap_smtp_mail_cli.py"
SRC_DIR = str(CLI_PATH.parent)
sys.path.insert(0, SRC_DIR)
CLI_SPEC = importlib.util.spec_from_file_location("imap_smtp_mail_cli_contract", CLI_PATH)
assert CLI_SPEC is not None and CLI_SPEC.loader is not None
CLI_MODULE = importlib.util.module_from_spec(CLI_SPEC)
CLI_SPEC.loader.exec_module(CLI_MODULE)
sys.path.remove(SRC_DIR)


def run_cli(payload: dict[str, object], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        [sys.executable, str(CLI_PATH)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=merged_env,
        check=False,
    )


def test_cli_runs_allowed_tool_and_returns_json_result() -> None:
    env = {
        "IMAP_SMTP_MAIL_ACCOUNTS_JSON": json.dumps(
            [
                {
                    "name": "work",
                    "provider": "custom",
                    "email": "approver@example.com",
                    "username": "approver@example.com",
                    "password": "secret",
                    "imap": {"host": "imap.example.com", "port": 993, "secure": True},
                    "smtp": {"host": "smtp.example.com", "port": 465, "secure": True},
                }
            ]
        )
    }

    completed = run_cli({"tool": "list_accounts", "arguments": {}}, env=env)

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["ok"] is True
    assert payload["result"]["accounts"][0]["name"] == "work"


@pytest.mark.parametrize("tool", ["create_draft", "send_email"])
def test_cli_allows_mail_write_tools_and_preserves_message_id(tool: str, monkeypatch, capsys) -> None:  # noqa: ANN001
    seen_arguments: dict[str, object] = {}

    mapped_tool = f"imap_smtp_mail_{tool}"
    monkeypatch.setitem(
        CLI_MODULE.server.TOOLS[mapped_tool],
        "handler",
        lambda arguments: seen_arguments.update(arguments)
        or CLI_MODULE.server.tool_result(
            {
                "message_id": str(arguments["message_id"]),
                "preview": {"message_id": str(arguments["message_id"])},
            }
        ),
    )
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "tool": tool,
                    "arguments": {
                        "to": ["requester@example.com"],
                        "subject": "Re: Release approval",
                        "text": "Approved.",
                        "message_id": "<approval-1@example.com>",
                    },
                }
            )
        ),
    )

    exit_code = CLI_MODULE.main()
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert seen_arguments["message_id"] == "<approval-1@example.com>"
    assert payload == {
        "ok": True,
        "result": {
            "message_id": "<approval-1@example.com>",
            "preview": {"message_id": "<approval-1@example.com>"},
        },
    }


def test_cli_read_message_preserves_shared_release_workflow_payload(monkeypatch, capsys) -> None:  # noqa: ANN001
    expected_headers = {
        "contract": "rd.release-approval.v1",
        "event_id": "event-1",
        "request_digest": "sha256:" + "4" * 64,
        "submitter_email": "submitter@example.com",
    }
    monkeypatch.setitem(
        CLI_MODULE.server.TOOLS["imap_smtp_mail_read_message"],
        "handler",
        lambda arguments: CLI_MODULE.server.tool_result(
            {
                "uid": str(arguments["uid"]),
                "release_workflow_headers": expected_headers,
            }
        ),
    )
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"tool": "read_message", "arguments": {"uid": "42"}})),
    )

    exit_code = CLI_MODULE.main()
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload == {
        "ok": True,
        "result": {"uid": "42", "release_workflow_headers": expected_headers},
    }
