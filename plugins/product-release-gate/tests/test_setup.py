from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_setup import ReleaseGateSetup, SetupError


class FakeScheduler:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def install(self, *, mode: str) -> dict:
        self.calls.append(("install", mode))
        return {"status": "ready", "mode": "windows", "installed": True}

    def status(self, *, mode: str) -> dict:
        self.calls.append(("status", mode))
        return {"status": "ready", "mode": "windows", "installed": True}


class FakeRuntime:
    def __init__(self) -> None:
        self.calls = 0

    def run_once(self) -> dict:
        self.calls += 1
        return {"status": "ready", "processed": 0}


class FakeController:
    def __init__(self, path: Path) -> None:
        self.config = json.loads(path.read_text(encoding="utf-8"))
        self.storage_dir = Path(self.config["storage_dir"])

    def unified_approval_preflight(self) -> dict:
        workflow = self.config["production"]["approval_workflow"]
        ready = bool(
            workflow["dependency_lock"]
            and workflow["dependency_lock_sha256"]
            and workflow["verifier_config_path"]
            and workflow["verify_command"]
            and workflow["mail"]["command"]
        )
        return {
            "ready": ready,
            "status": "ready" if ready else "CAPABILITY_BLOCKED",
            "mode": workflow["mode"],
            "missing_capabilities": [] if ready else ["runtime binding"],
        }


class FakeMailGateway:
    def __init__(self, accounts: list[dict[str, str]]) -> None:
        self.accounts = accounts

    def list_accounts(self) -> list[dict[str, str]]:
        return list(self.accounts)


class SetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo_root = self.root / "repo"
        self.config_path = self.root / "managed" / "config.json"
        self.verifier_config = self.root / "verifier" / "config.json"
        self.prompts: list[str] = []
        self.scheduler = FakeScheduler()
        self.runtime = FakeRuntime()
        self.bootstrap_calls: list[tuple[str, Path]] = []
        self.accounts = [
            {"name": "mail-primary", "email": "verifier@example.com"}
        ]
        self.lock_path = self._build_lock()
        self.verifier_config.parent.mkdir(parents=True, exist_ok=True)
        self.verifier_config.write_text(
            json.dumps(
                {
                    "release_group": "release@example.com",
                    "verifier_mail_account": {
                        "profile": "mail-primary",
                        "email": "verifier@example.com",
                    },
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build_lock(self) -> Path:
        paths = {
            "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py": "print('mail')\n",
            "plugins/release-approval-verifier/src/verifier_product_gate_bridge.py": (
                "print('bridge')\n"
            ),
        }
        entries: dict[str, dict[str, str]] = {}
        for relative, content in paths.items():
            path = self.repo_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            entries[relative] = {
                "kind": "runtime_entrypoint",
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        lock = {
            "profile": "product-release-gate",
            "plugins": [
                {
                    "name": "imap-smtp-mail",
                    "plugin_root": "plugins/imap-smtp-mail",
                    "entrypoints": [
                        entries[
                            "plugins/imap-smtp-mail/src/imap_smtp_mail_cli.py"
                        ]
                    ],
                },
                {
                    "name": "release-approval-verifier",
                    "plugin_root": "plugins/release-approval-verifier",
                    "entrypoints": [
                        entries[
                            "plugins/release-approval-verifier/src/verifier_product_gate_bridge.py"
                        ]
                    ],
                },
            ],
        }
        path = self.repo_root / "dependency-lock.product-release-gate.json"
        path.write_text(json.dumps(lock, sort_keys=True), encoding="utf-8")
        return path

    def _bootstrap(self, profile: str, *, repo_root: Path) -> dict:
        self.bootstrap_calls.append((profile, Path(repo_root)))
        return {
            "dependency_lock": str(self.lock_path),
            "fresh_task_required": False,
            "profile": profile,
        }

    def _setup(self) -> ReleaseGateSetup:
        def prompt(message: str) -> str:
            self.prompts.append(message)
            raise AssertionError("production setup must not prompt")

        return ReleaseGateSetup(
            self.config_path,
            repo_root=self.repo_root,
            prompt=prompt,
            controller_factory=lambda path: FakeController(path),
            scheduler_factory=lambda _controller, _path: self.scheduler,
            runtime_factory=lambda _controller, _path: self.runtime,
            bootstrap_runner=self._bootstrap,
            mail_gateway_factory=lambda _lock, _digest: FakeMailGateway(
                self.accounts
            ),
        )

    def _provided(self) -> dict[str, str]:
        return {
            "verifier_config_path": str(self.verifier_config),
            "module": "kernel",
        }

    def test_non_interactive_setup_binds_locked_dependencies_and_runs_once(self) -> None:
        result = self._setup().run(
            non_interactive=True,
            scheduler_mode="auto",
            provided=self._provided(),
        )

        self.assertEqual("ready", result["status"])
        self.assertEqual(0, result["prompt_count"])
        self.assertEqual(1, self.runtime.calls)
        self.assertEqual(
            [("install", "auto"), ("status", "windows")],
            self.scheduler.calls,
        )
        self.assertEqual(
            [("product-release-gate", self.repo_root.resolve())],
            self.bootstrap_calls,
        )
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        workflow = config["production"]["approval_workflow"]
        self.assertEqual("unified_multi_role", workflow["mode"])
        self.assertEqual(
            str(self.lock_path.resolve()), workflow["dependency_lock"]
        )
        self.assertEqual(
            hashlib.sha256(self.lock_path.read_bytes()).hexdigest(),
            workflow["dependency_lock_sha256"],
        )
        self.assertEqual(
            str(
                self.repo_root.resolve()
                / "plugins/release-approval-verifier/src/verifier_product_gate_bridge.py"
            ),
            workflow["verify_command"][1],
        )
        self.assertEqual("mail-primary", workflow["mail"]["profile"])
        self.assertEqual("release@example.com", workflow["mail"]["release_group"])
        self.assertEqual("kernel", workflow["mail"]["module"])
        self.assertEqual(60, config["runtime"]["poll_minutes"])
        self.assertFalse(config["runtime"]["auto_deploy_authorized_releases"])
        self.assertFalse(config["runtime"]["auto_generate_production_report"])
        self.assertFalse(config["runtime"]["auto_deliver_production_report"])
        delivery = config["production"]["report_delivery"]
        self.assertFalse(delivery["enabled"])
        self.assertEqual("mail-primary", delivery["profile"])
        self.assertEqual("verifier@example.com", delivery["sender_email"])
        self.assertEqual(["release@example.com"], delivery["recipients"])
        lowered = self.config_path.read_text(encoding="utf-8").lower()
        self.assertNotIn("password", lowered)
        self.assertNotIn("token", lowered)

    def test_setup_rerun_refreshes_binding_without_prompts(self) -> None:
        setup = self._setup()
        setup.run(
            non_interactive=True,
            scheduler_mode="auto",
            provided=self._provided(),
        )
        self.prompts.clear()

        result = setup.run(
            non_interactive=False,
            scheduler_mode="auto",
            provided=self._provided(),
        )

        self.assertEqual("ready", result["status"])
        self.assertEqual([], self.prompts)
        self.assertEqual(2, self.runtime.calls)

    def test_setup_fails_closed_when_verifier_config_is_missing(self) -> None:
        self.verifier_config.unlink()

        with self.assertRaisesRegex(
            SetupError,
            "release-approval-verifier must be configured",
        ):
            self._setup().run(
                non_interactive=True,
                scheduler_mode="auto",
                provided=self._provided(),
            )

    def test_setup_fails_closed_when_mail_account_binding_differs(self) -> None:
        self.accounts = [
            {"name": "mail-primary", "email": "other@example.com"}
        ]

        with self.assertRaisesRegex(SetupError, "not found exactly once"):
            self._setup().run(
                non_interactive=True,
                scheduler_mode="auto",
                provided=self._provided(),
            )

    def test_setup_rejects_credentials(self) -> None:
        with self.assertRaisesRegex(SetupError, "does not accept credential"):
            self._setup().run(
                non_interactive=True,
                scheduler_mode="auto",
                provided={**self._provided(), "password": "forbidden"},
            )


if __name__ == "__main__":
    unittest.main()
