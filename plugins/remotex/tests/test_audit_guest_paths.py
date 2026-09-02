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

    def test_profile_setup_audit_uses_reference_hashes_not_connection_values(self) -> None:
        summary = audit_log.summarize_arguments(
            "remotex_profile_setup",
            {
                "profile": "arm64",
                "kind": "ssh",
                "host": "arm64.example.internal",
                "user": "builder",
                "credential_ref": "arm64-key",
                "credential_source": "ssh-agent",
                "queue_resource": "lab:arm64",
                "confirm": False,
                "password": "do-not-record",
            },
        )
        self.assertIn("kind", summary)
        self.assertEqual(summary["kind"], "ssh")
        self.assertEqual(summary["credentialSource"], "ssh-agent")
        self.assertEqual(
            summary["credentialRefSha256"],
            "94fdb79e9eebb5cdbd0e41e495dad7d0ba81adb7c3e7ff8cbbc67254b2412138",
        )
        self.assertEqual(
            summary["queueResourceSha256"],
            "e2048f813377e04cc44055803dd813189638101785b85d296747594f53f7390e",
        )
        self.assertEqual(
            summary["endpointSha256"],
            "f7ac4bc2e5bd2b12ebcdadb7d8634e0770416cf61ec0dacabc1c6af2a190f134",
        )
        rendered = str(summary)
        for forbidden in (
            "arm64.example.internal",
            "builder",
            "arm64-key",
            "lab:arm64",
            "do-not-record",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_allowlisted_audit_strings_are_redacted_before_persistence(self) -> None:
        summary = audit_log.summarize_arguments(
            "remotex_profile_setup",
            {
                "profile": "password=do-not-record",
                "confirm": False,
            },
        )
        self.assertNotIn("do-not-record", str(summary))
        self.assertIn("[REDACTED]", summary["profile"])


if __name__ == "__main__":
    unittest.main()
