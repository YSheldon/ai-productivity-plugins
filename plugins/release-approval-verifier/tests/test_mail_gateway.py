from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from verifier_mail import MailGateway, MailGatewayError  # noqa: E402


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    cli_path = (
        tmp_path
        / "plugins"
        / "imap-smtp-mail"
        / "src"
        / "imap_smtp_mail_cli.py"
    )
    cli_path.parent.mkdir(parents=True)
    cli_path.write_text("# locked CLI\n", encoding="utf-8")
    lock_path = tmp_path / "dependency-lock.json"
    lock_path.write_text(
        json.dumps(
            {
                "plugins": [
                    {
                        "name": "imap-smtp-mail",
                        "plugin_root": "plugins/imap-smtp-mail",
                        "entrypoints": [
                            {
                                "path": "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py",
                                "sha256": hashlib.sha256(
                                    cli_path.read_bytes()
                                ).hexdigest(),
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return lock_path, cli_path


def test_mail_gateway_uses_pinned_lock_and_cli(tmp_path: Path) -> None:
    lock_path, cli_path = _fixture(tmp_path)
    seen: dict[str, object] = {}

    def runner(**kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(
            kwargs["args"],
            0,
            stdout=json.dumps(
                {
                    "ok": True,
                    "result": {
                        "accounts": [
                            {"name": "work", "email": "verifier@example.com"}
                        ]
                    },
                }
            ),
            stderr="",
        )

    gateway = MailGateway(
        lock_path,
        dependency_lock_sha256=hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        runner=runner,
    )

    result = gateway.list_accounts()

    assert result["accounts"][0]["name"] == "work"
    assert seen["args"] == [sys.executable, str(cli_path)]
    assert seen["shell"] is False


def test_mail_gateway_rejects_rewritten_lock_and_cli_before_execution(
    tmp_path: Path,
) -> None:
    lock_path, cli_path = _fixture(tmp_path)
    expected_lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    cli_path.write_text("# attacker replacement\n", encoding="utf-8")
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    payload["plugins"][0]["entrypoints"][0]["sha256"] = hashlib.sha256(
        cli_path.read_bytes()
    ).hexdigest()
    lock_path.write_text(json.dumps(payload), encoding="utf-8")

    gateway = MailGateway(
        lock_path,
        dependency_lock_sha256=expected_lock_digest,
        runner=lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("runner must not execute after lock drift")
        ),
    )

    with pytest.raises(MailGatewayError, match="dependency lock drift"):
        gateway.list_accounts()
