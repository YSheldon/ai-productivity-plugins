from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import remotex_core as core
import ssh_adapter


class SSHAgentStatusTests(unittest.TestCase):
    def test_agent_profile_is_not_ready_without_loaded_identity(self) -> None:
        outcome = {
            "returncode": 1,
            "timed_out": False,
            "stdout": "",
            "stderr": "The agent has no identities.",
        }
        profile = {
            "kind": "ssh",
            "host": "linux.example",
            "user": "root",
            "credential": {"source": "ssh-agent"},
        }
        with mock.patch.object(core, "executable_available", return_value=True):
            with mock.patch.object(core, "find_executable", return_value="ssh-add"):
                with mock.patch.object(core, "run_process", return_value=outcome):
                    status = ssh_adapter.profile_status("linux", profile)
        self.assertFalse(status["ready"])
        self.assertFalse(status["ssh_agent_has_identities"])
        self.assertIn("ssh-agent has no available identities", status["errors"])


if __name__ == "__main__":
    unittest.main()
