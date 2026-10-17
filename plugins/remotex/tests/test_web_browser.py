from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "Edge web credentials are Windows-only")
class WebBrowserIntegrationTests(unittest.TestCase):
    def test_guarded_edge_fixture(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node.js is required for RemoteX browser tests")
        plugin = Path(__file__).resolve().parents[1]
        result = subprocess.run([node,"--test",str(plugin / "tests" / "web_login_worker.test.mjs"), str(plugin / "tests" / "web_tls.test.mjs"), str(plugin / "tests" / "web_control.test.mjs")],
            cwd=plugin,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=120)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__ == "__main__":
    unittest.main()
