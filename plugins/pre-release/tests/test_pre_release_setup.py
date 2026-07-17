from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from pre_release_setup import PreReleaseSetup


class FakeScheduler:
    def install(self, *, mode: str) -> dict:
        return {"status": "ready", "mode": mode, "installed": True}

    def status(self, *, mode: str) -> dict:
        return {"status": "ready", "mode": mode, "installed": True}


class FakeController:
    def preflight(self) -> dict:
        return {"status": "ready", "ready": True, "missing_capabilities": []}

    def run_once(self) -> dict:
        return {"status": "ready", "matched_events": 0}

    def doctor(self) -> dict:
        return {"status": "ready", "ready": True}


def test_setup_writes_locked_config_and_runs_once() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        repo_root = root / "repo"
        config_path = root / "managed" / "config.json"
        lock_path = repo_root / "dependency-lock.product-release-gate.json"
        (repo_root / "plugins" / "imap-smtp-mail" / "src").mkdir(parents=True)
        (repo_root / "plugins" / "product-release-gate" / "src").mkdir(parents=True)
        mail_cli = repo_root / "plugins" / "imap-smtp-mail" / "src" / "imap_smtp_mail_cli.py"
        product_cli = repo_root / "plugins" / "product-release-gate" / "src" / "release_gate_cli.py"
        mail_cli.write_text("print('mail')\n", encoding="utf-8")
        product_cli.write_text("print('gate')\n", encoding="utf-8")
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
                                    "sha256": hashlib.sha256(mail_cli.read_bytes()).hexdigest(),
                                }
                            ],
                        },
                        {
                            "name": "product-release-gate",
                            "plugin_root": "plugins/product-release-gate",
                            "entrypoints": [
                                {
                                    "path": "plugins/product-release-gate/src/release_gate_cli.py",
                                    "sha256": hashlib.sha256(product_cli.read_bytes()).hexdigest(),
                                }
                            ],
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        setup = PreReleaseSetup(
            config_path,
            repo_root=repo_root,
            bootstrap_runner=lambda **_kwargs: {"dependency_lock": str(lock_path)},
            controller_factory=lambda _config, _lock: FakeController(),
            scheduler_factory=lambda _config, _state, _minutes: FakeScheduler(),
        )
        result = setup.run(non_interactive=True, scheduler_mode="auto", provided={"mail_profile": "qa-owner"})
        assert result["status"] == "ready"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        assert config["mail_account"]["profile"] == "qa-owner"
        assert config["dependency_lock_sha256"] == hashlib.sha256(lock_path.read_bytes()).hexdigest()
        assert Path(config["shared_hmac_secret_path"]).exists()
