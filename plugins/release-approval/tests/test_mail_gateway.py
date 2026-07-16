from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_approval_mail import (
    MailCapabilityError,
    MailGateway,
    MailGatewayError,
)


def _write_locked_cli(tmp_path: Path, script_text: str) -> tuple[Path, Path]:
    plugin_root = tmp_path / "plugins" / "imap-smtp-mail"
    cli_path = plugin_root / "src" / "imap_smtp_mail_cli.py"
    cli_path.parent.mkdir(parents=True, exist_ok=True)
    cli_path.write_text(script_text, encoding="utf-8")
    lock_path = tmp_path / "dependency-lock.json"
    lock_payload = {
        "profile": "release-approval",
        "marketplace": {
            "name": "ai-productivity-plugins",
            "url": "https://github.com/YSheldon/ai-productivity-plugins.git",
            "commit": "85997dfb4ab07f12304af2b05e61c06554238680",
        },
        "plugins": [
            {
                "name": "imap-smtp-mail",
                "version": "0.2.0",
                "plugin_root": "plugins/imap-smtp-mail",
                "manifest_path": "plugins/imap-smtp-mail/.codex-plugin/plugin.json",
                "manifest_sha256": "0" * 64,
                "entrypoints": [
                    {
                        "kind": "cli_bridge",
                        "path": "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py",
                        "sha256": MailGateway.sha256_file(cli_path),
                    }
                ],
            }
        ],
    }
    lock_path.write_text(json.dumps(lock_payload, indent=2) + "\n", encoding="utf-8")
    return lock_path, cli_path


def test_send_email_uses_locked_cli_argument_list_and_verifies_sha256(tmp_path: Path) -> None:
    lock_path, cli_path = _write_locked_cli(
        tmp_path,
        "import json,sys; json.dump({'ok': True, 'result': {'sent': True, 'message_id': '<sent@example.com>', 'refused': {}}}, sys.stdout)",
    )
    seen: dict[str, object] = {}

    def fake_run(*, args, input, text, capture_output, shell, timeout, check):  # noqa: ANN001
        seen["args"] = args
        seen["input"] = input
        seen["text"] = text
        seen["capture_output"] = capture_output
        seen["shell"] = shell
        seen["timeout"] = timeout
        seen["check"] = check
        return subprocess.CompletedProcess(args, 0, stdout='{"ok": true, "result": {"sent": true, "message_id": "<sent@example.com>", "refused": {}}}', stderr="")

    gateway = MailGateway(lock_path, runner=fake_run, timeout_seconds=41)
    result = gateway.send_email({"tool": "send_email", "arguments": {"subject": "ignored"}})

    assert result.sent is True
    assert result.message_id == "<sent@example.com>"
    assert result.refused == {}
    assert seen["args"] == [sys.executable, str(cli_path)]
    assert json.loads(str(seen["input"]))["tool"] == "send_email"
    assert seen["text"] is True
    assert seen["capture_output"] is True
    assert seen["shell"] is False
    assert seen["timeout"] == 41
    assert seen["check"] is False


def test_send_email_rejects_drifted_locked_executable_before_runner_is_called(tmp_path: Path) -> None:
    lock_path, cli_path = _write_locked_cli(
        tmp_path,
        "print('original')\n",
    )
    cli_path.write_text("print('drifted')\n", encoding="utf-8")

    def unexpected_runner(**_kwargs):  # noqa: ANN001
        raise AssertionError("runner must not be called for drifted executables")

    gateway = MailGateway(lock_path, runner=unexpected_runner)

    with pytest.raises(MailGatewayError, match="drift"):
        gateway.send_email({"tool": "send_email", "arguments": {}})


def test_send_email_maps_timeout_nonzero_exit_and_malformed_json_to_hard_failures(tmp_path: Path) -> None:
    lock_path, _cli_path = _write_locked_cli(
        tmp_path,
        "print('unused')\n",
    )
    gateway = MailGateway(lock_path)

    def timeout_runner(**kwargs):  # noqa: ANN001
        raise subprocess.TimeoutExpired(kwargs["args"], kwargs["timeout"])

    gateway_timeout = MailGateway(lock_path, runner=timeout_runner, timeout_seconds=9)
    with pytest.raises(MailGatewayError, match="timed out"):
        gateway_timeout.send_email({"tool": "send_email", "arguments": {}})

    def nonzero_runner(**kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(kwargs["args"], 7, stdout="", stderr="boom")

    gateway_nonzero = MailGateway(lock_path, runner=nonzero_runner)
    with pytest.raises(MailGatewayError, match="exit code 7"):
        gateway_nonzero.send_email({"tool": "send_email", "arguments": {}})

    def malformed_runner(**kwargs):  # noqa: ANN001
        return subprocess.CompletedProcess(kwargs["args"], 0, stdout="{not-json", stderr="")

    gateway_malformed = MailGateway(lock_path, runner=malformed_runner)
    with pytest.raises(MailGatewayError, match="invalid JSON"):
        gateway_malformed.send_email({"tool": "send_email", "arguments": {}})


def test_send_email_captures_message_id_and_refused_map(tmp_path: Path) -> None:
    lock_path, _cli_path = _write_locked_cli(
        tmp_path,
        "print('unused')\n",
    )

    def fake_run(**kwargs):  # noqa: ANN001
        payload = {
            "ok": True,
            "result": {
                "sent": True,
                "message_id": "<smtp-message@example.com>",
                "refused": {"blocked@example.com": [550, "Rejected"]},
            },
        }
        return subprocess.CompletedProcess(kwargs["args"], 0, stdout=json.dumps(payload), stderr="")

    gateway = MailGateway(lock_path, runner=fake_run)
    result = gateway.send_email({"tool": "send_email", "arguments": {}})

    assert result.sent is True
    assert result.message_id == "<smtp-message@example.com>"
    assert result.refused == {"blocked@example.com": [550, "Rejected"]}


def test_capability_checks_fail_closed_when_thread_reply_or_raw_header_readback_is_missing(tmp_path: Path) -> None:
    lock_path, _cli_path = _write_locked_cli(
        tmp_path,
        "print('unused')\n",
    )
    gateway = MailGateway(lock_path)

    with pytest.raises(MailCapabilityError, match="CAPABILITY_BLOCKED"):
        gateway.require_thread_reply_capability(
            {
                "reply_subject": "",
                "original_message_id": "<request@example.com>",
                "references": ["<root@example.com>"],
            }
        )

    with pytest.raises(MailCapabilityError, match="CAPABILITY_BLOCKED"):
        gateway.require_authenticated_readback_capability(
            {
                "message_id": "<reply@example.com>",
                "evidence": {
                    "in_reply_to": "<request@example.com>",
                    "references": ["<root@example.com>", "<request@example.com>"],
                },
            }
        )
