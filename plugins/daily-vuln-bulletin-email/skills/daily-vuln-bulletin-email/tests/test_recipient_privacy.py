from __future__ import annotations

import json
import subprocess
import sys
from email.message import EmailMessage
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_recipient_privacy.py"


def write_message(
    path: Path,
    recipients: list[str],
    *,
    cc: list[str] | None = None,
    received: bool = True,
) -> None:
    message = EmailMessage()
    message["From"] = "assistant@example.com"
    message["To"] = ", ".join(recipients)
    if cc:
        message["Cc"] = ", ".join(cc)
    if received:
        message["Received"] = "from relay.example (8.8.8.8) by mx.example"
    message["Subject"] = "test"
    message.set_content("body")
    path.write_bytes(message.as_bytes())


def run(path: Path, *args: str) -> tuple[int, dict]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), str(path), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode, json.loads(completed.stdout)


def test_individual_message_passes_without_address_echo(tmp_path: Path) -> None:
    eml = tmp_path / "individual.eml"
    write_message(eml, ["one@example.com"])
    code, result = run(eml)
    assert code == 0
    assert result["verdict"] == "pass"
    assert result["visible_recipient_count"] == 1
    assert result["received_header_count"] == 1
    assert result["received_hostname_count"] == 1
    assert result["received_public_ipv4_count"] == 1
    assert "one@example.com" not in json.dumps(result)


def test_multiple_visible_to_is_blocked_in_individual_mode(tmp_path: Path) -> None:
    eml = tmp_path / "aggregate.eml"
    write_message(eml, ["one@example.com", "two@example.com"])
    code, result = run(eml)
    assert code == 2
    assert result["verdict"] == "block"
    assert "multiple_visible_recipients" in result["reasons"]
    assert "one@example.com" not in json.dumps(result)
    assert "two@example.com" not in json.dumps(result)


def test_visible_cc_is_blocked(tmp_path: Path) -> None:
    eml = tmp_path / "cc.eml"
    write_message(eml, ["one@example.com"], cc=["two@example.com"])
    code, result = run(eml)
    assert code == 2
    assert result["verdict"] == "block"
    assert "visible_cc" in result["reasons"]
