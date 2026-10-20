from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import web_approval as approval


def _run_harness(scenario):
    script=Path(__file__).with_name('Test-WebApprovalUI.ps1')
    try:
        return subprocess.run([approval.credential_store._powershell_path(),'-NoLogo','-NoProfile','-NonInteractive','-STA',
            '-File',str(script),'-Scenario',scenario],stdin=subprocess.DEVNULL,capture_output=True,text=True,encoding='utf-8',
            timeout=20,env=approval.credential_store._setup_environment(),
            creationflags=subprocess.CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired as error:
        details=error.stderr or b''
        if isinstance(details,bytes):details=details.decode('utf-8',errors='replace')
        raise AssertionError(f'Native UI harness timed out in {scenario}; diagnostic stages:\n{details[-4000:]}') from error


@pytest.mark.skipif(os.name!='nt',reason='Windows PowerShell host prerequisites')
def test_native_host_prerequisites():
    result=_run_harness('host-prerequisite')
    assert result.returncode==0,result.stdout+result.stderr
    assert json.loads(result.stdout)=={'prerequisite':True}
    assert 'host-stage: control-end;' in result.stderr


@pytest.mark.skipif(os.name!='nt',reason='Windows PowerShell console behavior')
def test_background_ui_harness_does_not_inherit_console_input():
    result=_run_harness('console-input-probe')
    assert result.returncode==0,result.stdout+result.stderr
    assert json.loads(result.stdout)=={'consoleInputObserved':False}


@pytest.mark.skipif(os.name!='nt',reason='Real Windows Forms controls')
@pytest.mark.parametrize('scenario',[
    'select-all','clear-selection','apply-bootstrap','checked-only',
    'mixed-refused','wrong-class-refused','unreviewed-refused',
    'unknown-kind-refused','no-checked-refused','scope-countdown',
    'known-effects','native-wiring','v3-awaiting-commit',
    'hint-selection','hint-row','hint-tooltips','hint-resize','hint-action-context',
    'apply-initialization-read','mixed-init-refused','init-hint',
    'replacement-scope','replacement-carried-required','replacement-lifetime',
    'recommend-mixed','recommend-unknown','recommend-fixed-read','recommend-fixed-action',
    'recommend-v3-proof','recommend-unchecked',
    'recommend-binding','recommend-display-tamper',
])
def test_native_batch_controls_preserve_explicit_authority(scenario):
    result=_run_harness(scenario)
    assert result.returncode==0,result.stdout+result.stderr
    report=json.loads(result.stdout)
    assert report.get('implemented') is True,'Native batch selection/classification UI is not implemented'
    assert report['passed'] is True


if __name__=='__main__':
    try:
        result=_run_harness('host-prerequisite')
        print(result.stderr,flush=True)
        print(result.stdout,flush=True)
        passed=result.returncode==0 and json.loads(result.stdout)=={'prerequisite':True}
    except (AssertionError,ValueError) as error:
        print(str(error),flush=True)
        passed=False
    raise SystemExit(0 if passed else 1)
