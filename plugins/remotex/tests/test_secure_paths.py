from __future__ import annotations

import base64
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(SRC))

import secure_paths


class SecurePathTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows PowerShell transport test")
    def test_windows_powershell_arguments_are_encoded_not_appended(self) -> None:
        marker = r"C:\path with spaces\state"
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="ok\n",
            stderr="",
        )
        with mock.patch.object(secure_paths.subprocess, "run", return_value=completed) as run:
            result = secure_paths._run_windows_powershell(
                "[Console]::Out.Write($args[0])",
                marker,
            )
        argv = run.call_args.args[0]
        self.assertEqual(result, "ok")
        self.assertIn("-EncodedCommand", argv)
        self.assertNotIn("-Command", argv)
        self.assertNotIn(marker, argv)
        encoded = argv[argv.index("-EncodedCommand") + 1]
        decoded = base64.b64decode(encoded).decode("utf-16-le")
        self.assertIn(base64.b64encode(marker.encode("utf-8")).decode("ascii"), decoded)

    @unittest.skipUnless(os.name == "nt", "Windows ACL inspection test")
    def test_windows_acl_inspection_does_not_depend_on_powershell_modules(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"Owner":"S-1-5-21-1","Sddl":"O:S-1-5-21-1D:P"}\n',
            stderr="",
        )
        with mock.patch.object(secure_paths.subprocess, "run", return_value=completed) as run:
            result = secure_paths._windows_acl(Path(r"C:\private"))
        encoded = run.call_args.args[0][-1]
        decoded = base64.b64decode(encoded).decode("utf-16-le")
        self.assertNotIn("Get-Acl", decoded)
        self.assertIn("GetAccessControl", decoded)
        self.assertEqual(result["owner"], "S-1-5-21-1")


if __name__ == "__main__":
    unittest.main()
