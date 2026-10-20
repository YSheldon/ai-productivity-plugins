from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import web_approval as approval


@pytest.mark.skipif(os.name != 'nt', reason='Windows native notification adapter')
@pytest.mark.parametrize('scenario', ['privacy-one-shot', 'pending-click', 'expiry-click', 'closed-click', 'failure', 'creation-failure'])
def test_owned_notification_is_only_a_non_authorizing_window_hint(scenario):
    result = subprocess.run([approval.credential_store._powershell_path(), '-NoLogo', '-NoProfile',
        '-NonInteractive', '-STA', '-File', str(Path(__file__).with_name('Test-WebApprovalNotification.ps1')),
        '-Scenario', scenario], stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
        timeout=20, env=approval.credential_store._setup_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {'passed': True}
