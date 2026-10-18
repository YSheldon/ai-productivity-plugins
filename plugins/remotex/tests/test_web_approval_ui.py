from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import web_approval as approval


@pytest.mark.skipif(os.name!='nt',reason='Real Windows Forms controls')
@pytest.mark.parametrize('scenario',[
    'select-all','clear-selection','apply-bootstrap','checked-only',
    'mixed-refused','wrong-class-refused','unreviewed-refused',
    'unknown-kind-refused','no-checked-refused','scope-countdown',
    'known-effects','native-wiring',
])
def test_native_batch_controls_preserve_explicit_authority(scenario):
    script=Path(__file__).with_name('Test-WebApprovalUI.ps1')
    result=subprocess.run([approval.credential_store._powershell_path(),'-NoLogo','-NoProfile','-STA',
        '-File',str(script),'-Scenario',scenario],capture_output=True,text=True,encoding='utf-8',
        timeout=20,env=approval.credential_store._setup_environment(),
        creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode==0,result.stdout+result.stderr
    report=json.loads(result.stdout)
    assert report.get('implemented') is True,'Native batch selection/classification UI is not implemented'
    assert report['passed'] is True
