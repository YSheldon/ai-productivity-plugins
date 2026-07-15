from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


CLI_PATH = Path(__file__).parents[1] / "src" / "imap_smtp_mail_cli.py"


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


def test_cli_rejects_unsupported_tool_with_clear_error() -> None:
    completed = run_cli({"tool": "create_draft", "arguments": {}})

    assert completed.returncode != 0
    assert "Unsupported tool" in completed.stderr
