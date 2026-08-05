from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import remotex_core as core
import windows_guest


class PreflightReceiptIntegrityTests(unittest.TestCase):
    def test_operation_receipt_scrubs_allowlisted_output_and_paths(self) -> None:
        cfg = {
            "profile": "guest",
            "identity": {
                "id": "lab-windows",
                "vmwareUuid": "00112233445566778899aabbccddeeff",
                "guestMachineId": "lab-windows",
                "queueResource": "lab:windows",
            },
        }
        receipt = windows_guest._operation_receipt(
            "guest-copy-from",
            cfg,
            None,
            {
                "result": {"stdoutSha256": "a" * 64, "outputFields": {"password": "secret-value"}},
                "localPath": "C:\\Users\\operator\\secret.txt",
                "actualRemotePath": "C:\\RemoteX\\Staging\\secret.txt",
                "requestedRelativePath": "secret.txt",
            },
        )
        serialized = str(receipt)
        self.assertNotIn("secret-value", serialized)
        self.assertNotIn("C:\\Users\\operator\\secret.txt", serialized)
        self.assertNotIn("C:\\RemoteX\\Staging\\secret.txt", serialized)
        self.assertFalse(receipt["rawOutputExported"])
        self.assertFalse(receipt["payload"]["result"]["outputFieldsExported"])
        self.assertIn("localPathSha256", receipt["payload"])

    def test_receipt_content_is_rehashed_before_snapshot_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipts.json"
            identity = {
                "id": "lab-windows",
                "vmwareUuid": "00112233445566778899aabbccddeeff",
                "guestMachineId": "lab-windows",
                "queueResource": "lab:windows",
            }
            receipt = {
                "schema": windows_guest.RECEIPT_SCHEMA,
                "createdAtUtc": windows_guest._utc_now(),
                "runId": "run-1",
                "profile": "guest",
                "vmIdentity": dict(identity),
                "policy": {"maxReceiptAgeSeconds": 60},
                "evidence": {},
                "pass": True,
                "failureCodes": [],
                "rawOutputExported": False,
            }
            receipt["sha256"] = windows_guest._hash_receipt(receipt)
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_GUEST_RECEIPT_FILE": str(receipt_path)},
                clear=True,
            ):
                windows_guest._persist_preflight(receipt)
                approved = windows_guest.require_preflight_receipt(
                    identity,
                    receipt["sha256"],
                )
                self.assertTrue(approved["pass"])

                state = windows_guest._load_receipts()
                state["receipts"][receipt["sha256"]]["pass"] = False
                windows_guest._write_receipts(state)
                with self.assertRaisesRegex(core.ToolError, "preflight-receipt-invalid"):
                    windows_guest.require_preflight_receipt(identity, receipt["sha256"])


if __name__ == "__main__":
    unittest.main()
