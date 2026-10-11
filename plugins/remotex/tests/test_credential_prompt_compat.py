from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import credential_store
import remotex_core as core


@unittest.skipUnless(os.name == "nt", "Windows credential prompt compatibility")
class CredentialPromptCompatibilityTests(unittest.TestCase):
    def test_malformed_receipt_enums_are_rejected_without_raw_values(self):
        digest = "a" * 64
        base = {"schema": "RemoteXCredentialSetupReceipt/v2", "status": "failed",
                "existingBefore": False, "referencePresent": False, "targetSha256": digest,
                "failureCode": "prompt-unavailable"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            for field in ("status", "schema", "failureCode"):
                for value in (["synthetic-secret-canary"], {"secret": "synthetic-secret-canary"}):
                    path.write_text(json.dumps({**base, field: value}))
                    with self.subTest(field=field, value=value):
                        with self.assertRaises(core.ToolError) as caught:
                            credential_store._decode_setup_receipt(path, digest)
                        self.assertNotIn("synthetic-secret-canary", str(caught.exception))

    def test_launcher_environment_resolves_builtin_cmdlet_despite_parent_module_path(self):
        self.assertTrue(callable(getattr(credential_store, "_setup_environment", None)))
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
            "PSModulePath": directory, "PSModuleAnalysisCachePath": directory,
            "PSExecutionPolicyPreference": "Bypass", "SECRET_CANARY": "synthetic-only",
        }):
            environment = credential_store._setup_environment()
            self.assertNotIn("SECRET_CANARY", environment)
            self.assertFalse(any(k.casefold() in {"psmoduleanalysiscachepath", "psexecutionpolicypreference"} for k in environment))
            result = subprocess.run([
                credential_store._powershell_path(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                "(Get-Command Get-Credential -ErrorAction Stop).Module.Path",
            ], env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("windowspowershell", result.stdout.casefold())

    def test_failed_receipt_exit_one_reports_failure_not_contract_mismatch(self):
        target = "RemoteX/test-prompt-" + uuid.uuid4().hex
        bundle = core.ConfigBundle({"version": 2, "credentials": {
            "fixture": {"source": "windows-credential-manager", "target": target}},
            "profiles": {}, "defaults": {}}, Path("unused.json"), "test", True)
        reference = credential_store.resolve_named_reference(bundle, "fixture")
        original_popen = subprocess.Popen

        def popen(arguments, **kwargs):
            if "-ReceiptPath" not in arguments:
                return original_popen(arguments, **kwargs)
            receipt = Path(arguments[arguments.index("-ReceiptPath") + 1])
            receipt.write_text(json.dumps({"schema": "RemoteXCredentialSetupReceipt/v1",
                "status": "failed", "existingBefore": False, "referencePresent": False,
                "targetSha256": hashlib.sha256(target.encode()).hexdigest()}))
            return mock.Mock(returncode=1)

        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"REMOTEX_CREDENTIAL_SETUP_DIR": directory}):
            with mock.patch.object(credential_store.subprocess, "Popen", side_effect=popen):
                with self.assertRaisesRegex(core.ToolError, r"setup failed"):
                    credential_store.launch_secure_setup(reference, timeout=30)

    def test_real_helper_failure_receipt_never_contains_exception_or_secret_text(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "manage_windows_credential.ps1"
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            target = "RemoteX/test-prompt-" + uuid.uuid4().hex
            command = "function Get-Credential { throw 'synthetic-secret-canary' }; & '" + str(script).replace("'", "''") + "' -Operation Store -Target '" + target + "' -ReceiptPath '" + str(receipt).replace("'", "''") + "'"
            environment = dict(os.environ)
            environment["PSModulePath"] = str(Path(credential_store._powershell_path()).parent / "Modules")
            result = subprocess.run([credential_store._powershell_path(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
            value = json.loads(receipt.read_text(encoding="utf-8-sig"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value.get("failureCode"), "prompt-unavailable")
        self.assertEqual(value["status"], "failed")
        self.assertNotIn("synthetic-secret-canary", json.dumps(value) + result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
