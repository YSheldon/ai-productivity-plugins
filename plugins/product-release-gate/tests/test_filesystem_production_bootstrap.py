from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from bootstrap_filesystem_production import (
    BootstrapError,
    bootstrap_filesystem_production,
    main,
)


class FilesystemProductionBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output_config = self.root / "runtime" / "config.json"
        self.adapter_dir = self.root / "runtime" / "immutable-adapter"
        self.targets = {
            "preproduction_target": self.root / "targets" / "preproduction",
            "canary_target": self.root / "targets" / "canary",
            "production_target": self.root / "targets" / "production",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _bootstrap(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "output_config": self.output_config,
            "adapter_dir": self.adapter_dir,
            **self.targets,
        }
        arguments.update(overrides)
        return bootstrap_filesystem_production(**arguments)

    def test_bootstrap_writes_locked_disabled_config_without_targets(self) -> None:
        previous_auth = os.environ.get("PRODUCT_RELEASE_GATE_AUTH_KEY")
        previous_audit = os.environ.get("PRODUCT_RELEASE_GATE_AUDIT_KEY")
        auth_secret = "authorization-secret-not-for-config-32-bytes"
        audit_secret = "audit-secret-not-for-config-at-least-32-bytes"
        try:
            os.environ["PRODUCT_RELEASE_GATE_AUTH_KEY"] = auth_secret
            os.environ["PRODUCT_RELEASE_GATE_AUDIT_KEY"] = audit_secret
            result = self._bootstrap()
        finally:
            if previous_auth is None:
                os.environ.pop("PRODUCT_RELEASE_GATE_AUTH_KEY", None)
            else:
                os.environ["PRODUCT_RELEASE_GATE_AUTH_KEY"] = previous_auth
            if previous_audit is None:
                os.environ.pop("PRODUCT_RELEASE_GATE_AUDIT_KEY", None)
            else:
                os.environ["PRODUCT_RELEASE_GATE_AUDIT_KEY"] = previous_audit

        self.assertEqual("PASS", result["result"])
        self.assertFalse(result["production_enabled"])
        self.assertFalse(result["automatic_actions_enabled"])
        self.assertFalse(result["secrets_written"])
        for target in self.targets.values():
            self.assertFalse(Path(target).exists())

        config_text = self.output_config.read_text(encoding="utf-8")
        self.assertNotIn(auth_secret, config_text)
        self.assertNotIn(audit_secret, config_text)
        config = json.loads(config_text)
        self.assertFalse(config["production"]["enabled"])
        runtime = config["runtime"]
        identity_binding = runtime["identity_binding"]
        self.assertTrue(identity_binding["required"])
        self.assertEqual("", identity_binding["principal_sha256"])
        for name in (
            "auto_authorize_verified_pre_release",
            "auto_deploy_authorized_releases",
            "auto_generate_production_report",
            "auto_deliver_production_report",
        ):
            self.assertFalse(runtime[name])
        self.assertFalse(config["production"]["report_delivery"]["enabled"])

        deployment = config["production"]["deployment"]
        deploy_command = deployment["deploy_command"]
        verify_command = deployment["verify_command"]
        svn_release_gate = config["production"]["svn_release_gate"]
        svn_receipt_verifier = Path(result["svn_receipt_verifier"]["path"])
        self.assertIn("--expected-digest", deploy_command)
        self.assertIn("{manifest_r_digest}", deploy_command)
        self.assertIn("--rollback-ref", verify_command)
        self.assertIn("{rollback_ref}", verify_command)
        self.assertFalse(svn_release_gate["required"])
        self.assertEqual(59, svn_release_gate["expected_project_id"])
        self.assertTrue(svn_receipt_verifier.is_file())
        self.assertEqual(
            (PLUGIN_ROOT / "scripts" / "verify_gitlab_svn_gate_receipt.py").read_bytes(),
            svn_receipt_verifier.read_bytes(),
        )
        self.assertEqual(
            self._sha256(svn_receipt_verifier),
            result["svn_receipt_verifier"]["sha256"],
        )
        self.assertEqual(
            str(self.targets["production_target"].resolve()),
            deployment["targets"]["production_full"],
        )

        lock_path = Path(deployment["dependency_lock"])
        self.assertEqual(
            self._sha256(lock_path),
            deployment["dependency_lock_sha256"],
        )
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "deploy",
                "verify",
                "rollback",
                "rollback_verify",
                "readback",
                "svn_release_gate_receipt",
            },
            set(lock["commands"]),
        )
        self.assertEqual(
            lock["commands"]["svn_release_gate_receipt"]["argv_template"],
            svn_release_gate["verify_command"],
        )
        self.assertEqual(
            str(svn_receipt_verifier),
            svn_release_gate["verify_command"][1],
        )
        for command in lock["commands"].values():
            self.assertEqual([0, 1], [
                entry["argv_index"] for entry in command["entrypoints"]
            ])

    def test_bootstrap_locks_required_svn_receipt_verifier(self) -> None:
        source_config = self.root / "required-svn-gate.json"
        source_config.write_text(
            json.dumps(
                {
                    "production": {
                        "svn_release_gate": {
                            "required": True,
                            "expected_project_id": 59,
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        result = self._bootstrap(source_config=source_config)
        config = json.loads(self.output_config.read_text(encoding="utf-8"))
        gate = config["production"]["svn_release_gate"]
        lock_path = Path(config["production"]["deployment"]["dependency_lock"])
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        verifier_entrypoints = lock["commands"]["svn_release_gate_receipt"][
            "entrypoints"
        ]

        self.assertTrue(gate["required"])
        self.assertEqual(
            str(result["svn_receipt_verifier"]["path"]),
            gate["verify_command"][1],
        )
        self.assertEqual(
            result["svn_receipt_verifier"]["sha256"],
            verifier_entrypoints[1]["sha256"],
        )
    def test_existing_outputs_require_explicit_idempotent_replace(self) -> None:
        first = self._bootstrap()
        adapter_path = Path(first["adapter"]["path"])
        lock_path = Path(first["dependency_lock"]["path"])
        adapter_digest = self._sha256(adapter_path)
        lock_digest = self._sha256(lock_path)

        with self.assertRaisesRegex(BootstrapError, "use --replace"):
            self._bootstrap()
        second = self._bootstrap(replace=True)

        self.assertEqual(adapter_digest, self._sha256(adapter_path))
        self.assertEqual(lock_digest, self._sha256(lock_path))
        self.assertEqual(first["adapter"]["sha256"], second["adapter"]["sha256"])
        self.assertEqual(
            first["dependency_lock"]["sha256"],
            second["dependency_lock"]["sha256"],
        )

    def test_overlapping_targets_fail_before_writing_outputs(self) -> None:
        parent = self.root / "targets" / "shared"
        with self.assertRaisesRegex(BootstrapError, "targets overlap"):
            self._bootstrap(
                preproduction_target=parent,
                canary_target=parent / "canary",
            )
        self.assertFalse(self.output_config.exists())
        self.assertFalse(self.adapter_dir.exists())
        self.assertFalse(parent.exists())

    def test_embedded_secret_in_source_config_is_rejected(self) -> None:
        source_config = self.root / "source-config.json"
        source_config.write_text(
            json.dumps(
                {
                    "production": {
                        "report_delivery": {
                            "smtp_password": "must-not-be-copied"
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(BootstrapError, "embeds secret values"):
            self._bootstrap(source_config=source_config)
        self.assertFalse(self.output_config.exists())
        self.assertFalse(self.adapter_dir.exists())

    def test_tampered_adapter_cannot_be_replaced_in_place(self) -> None:
        result = self._bootstrap()
        adapter_path = Path(result["adapter"]["path"])
        original_config = self.output_config.read_bytes()
        adapter_path.write_bytes(b"print('tampered')\n")

        with self.assertRaisesRegex(
            BootstrapError,
            "choose a new --adapter-dir",
        ):
            self._bootstrap(replace=True)

        self.assertEqual(b"print('tampered')\n", adapter_path.read_bytes())
        self.assertEqual(original_config, self.output_config.read_bytes())

    def test_failed_self_check_cleans_new_adapter_install(self) -> None:
        source_config = self.root / "bad-command-config.json"
        source_config.write_text(
            json.dumps(
                {
                    "production": {
                        "approval_workflow": {
                            "mode": "legacy_external",
                            "verify_command": [],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        # A path token named "tests" is rejected by the production lock policy.
        rejected_adapter_dir = self.root / "tests" / "immutable-adapter"
        with self.assertRaisesRegex(
            BootstrapError,
            "deployment.adapter_lock",
        ):
            self._bootstrap(
                source_config=source_config,
                adapter_dir=rejected_adapter_dir,
            )
        self.assertFalse(self.output_config.exists())
        self.assertFalse(rejected_adapter_dir.exists())

    def test_cli_failure_is_machine_readable(self) -> None:
        output = io.StringIO()
        shared = self.root / "shared-target"
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "--output-config",
                    str(self.output_config),
                    "--adapter-dir",
                    str(self.adapter_dir),
                    "--preproduction-target",
                    str(shared),
                    "--canary-target",
                    str(shared / "canary"),
                    "--production-target",
                    str(self.targets["production_target"]),
                ]
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(1, exit_code)
        self.assertEqual("FAIL", payload["result"])
        self.assertEqual(
            "FILESYSTEM_PRODUCTION_BOOTSTRAP_BLOCKED",
            payload["error_code"],
        )
        self.assertFalse(self.output_config.exists())

    def test_redirected_target_fails_before_any_bootstrap_write(self) -> None:
        redirect = self.root / "redirect-destination"
        redirect.mkdir()
        target = self.root / "target-link"
        junction_created = False
        try:
            target.symlink_to(redirect, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            if os.name != "nt":
                self.skipTest(f"directory symlink is unavailable: {exc}")
            result = subprocess.run(
                [
                    "cmd.exe",
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(target),
                    str(redirect),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(
                    "directory symlink and junction are unavailable: "
                    f"{result.stderr or result.stdout}"
                )
            junction_created = True

        try:
            with self.assertRaisesRegex(
                BootstrapError,
                "symlink or redirected",
            ):
                self._bootstrap(preproduction_target=target)
            self.assertFalse(self.output_config.exists())
            self.assertFalse(self.adapter_dir.exists())
            self.assertEqual([], list(redirect.iterdir()))
        finally:
            if junction_created and target.exists():
                os.rmdir(target)


if __name__ == "__main__":
    unittest.main()
