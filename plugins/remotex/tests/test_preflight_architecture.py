from __future__ import annotations

import sys
import unittest
from pathlib import Path


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import remotex_core as core
import windows_guest


class PreflightArchitectureTests(unittest.TestCase):
    def test_windows_osarchitecture_values_normalize_to_policy_architecture(self) -> None:
        self.assertEqual(windows_guest._architecture("64-bit"), "x64")
        self.assertEqual(windows_guest._architecture("AMD64"), "x64")
        self.assertEqual(windows_guest._architecture("32-bit"), "x86")
        with self.assertRaisesRegex(core.ToolError, "recognized x86 or x64"):
            windows_guest._architecture("arm64")


if __name__ == "__main__":
    unittest.main()
