from __future__ import annotations

import sys
import unittest
from pathlib import Path


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import audit_log


class AuditGuestPathTests(unittest.TestCase):
    def test_guest_relative_path_is_redacted_in_audit_summary(self) -> None:
        summary = audit_log.summarize_arguments(
            "remotex_windows_guest_copy_to",
            {
                "profile": "guest",
                "requester": "operator",
                "relative_path": "token=do-not-record.bin",
            },
        )
        self.assertNotIn("do-not-record", str(summary))
        self.assertIn("[REDACTED]", summary["relative_path"])


if __name__ == "__main__":
    unittest.main()
