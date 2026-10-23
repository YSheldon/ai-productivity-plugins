import json
import os
import subprocess
import sys
import io
from types import SimpleNamespace
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN / 'src'))
import web_approval as approval
from web_authorization import ScopeError, canonical


def manifest():
    return {'ui_mode': 'recovery', 'request_id': 'a' * 32, 'nonce': 'b' * 64,
        'request_digest': 'c' * 64, 'wait_seconds': 180, 'mode': 'initialize',
        'target': 'Synthetic local recovery store', 'summary': {
            'scopeCount': 1, 'completedAttempts': 0, 'historicalBindings': 0,
            'historyPolicy': 'reconcile-v2',
            'reviewText': 'Recorded verified attempts: 0\nUnknown historical scope bindings: 0',
            'scopes': [{'profile': 'lab', 'origin': 'https://console.example', 'account': 'operator'}],
            'uncertainty': 'Synthetic test. Missing data cannot prove an empty history.'}}


def test_recovery_has_own_decision_schema_not_grant_choices():
    packet = manifest()
    frame = {k: packet[k] for k in ('request_id', 'nonce', 'request_digest')}
    frame.update(event='decision', owner_reviewed=True)
    assert approval.decode_frame(canonical(frame) + b'\n', packet)['owner_reviewed'] is True
    for update in ({'owner_reviewed': False}, {'choices': []}, {'ttl_seconds': 43200}, {'nonce': 'd' * 64}):
        with pytest.raises(ScopeError): approval.decode_frame(canonical({**frame, **update}) + b'\n', packet)


def test_recovery_complete_receipt_is_not_valid_in_site_mode():
    packet = manifest()
    frame = {k: packet[k] for k in ('request_id', 'nonce', 'request_digest')}
    frame.update(event='closed', reason='recovery-complete')
    assert approval.decode_ui_receipt(canonical(frame) + b'\n', packet)['reason'] == 'recovery-complete'
    with pytest.raises(ScopeError): approval.decode_ui_receipt(canonical(frame) + b'\n', {**packet, 'ui_mode': 'site'})


def test_recovery_acknowledgment_never_creates_a_grant_timer():
    packet = manifest()
    process = SimpleNamespace(stdin=io.BytesIO(), poll=lambda: None)
    job = SimpleNamespace(terminate=lambda: None, close=lambda: None)
    prompt = approval.RecoveryPrompt(process, job, packet, lambda frame: {'state': 'ready'},
        lambda: None, lambda: None)
    prompt._apply_decision({})
    value = json.loads(process.stdin.getvalue())
    assert value == {'event': 'recovery-result', 'request_id': 'a' * 32, 'nonce': 'b' * 64,
        'request_digest': 'c' * 64, 'state': 'ready'}
    assert prompt.timer is None and prompt.decided


def test_recovery_helper_launch_failure_cannot_recover(monkeypatch):
    monkeypatch.setattr(approval.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=1, stdout=b''))
    with pytest.raises(ScopeError, match='approval-ui-unavailable'):
        approval.RecoveryPrompt.start(manifest(), on_decision=lambda _: pytest.fail('decision'), on_revoke=lambda: None, on_cancel=lambda: None)


def test_old_recovery_helper_cannot_present_amended_history_review(monkeypatch):
    monkeypatch.setattr(approval.subprocess, 'run', lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=b'{"legacy_recovery":1,"review_seconds":180}'))
    monkeypatch.setattr(approval.subprocess, 'Popen', lambda *a, **k: pytest.fail('Old helper started without the amended summary'))
    with pytest.raises(ScopeError, match='approval-ui-unavailable'):
        approval.RecoveryPrompt.start(manifest(), on_decision=lambda _: pytest.fail('decision'),
            on_revoke=lambda: None, on_cancel=lambda: None)


@pytest.mark.skipif(os.name != 'nt' or os.environ.get('REMOTEX_TEST_NATIVE_APPROVAL') != '1', reason='Opt-in native form EOF test')
def test_native_stdin_eof_closes_without_decision():
    result = subprocess.run([approval.credential_store._powershell_path(), '-NoLogo', '-NoProfile', '-STA',
        '-File', str(PLUGIN / 'scripts/web_recovery_approval.ps1')], input=canonical(manifest()) + b'\n',
        capture_output=True, timeout=15, env=approval.credential_store._setup_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0 and not result.stdout
    receipts = [approval.decode_ui_receipt(line + b'\n', manifest()) for line in result.stderr.splitlines()]
    assert receipts[-1]['event'] == 'closed'


@pytest.mark.skipif(os.name != 'nt', reason='Windows native helper descriptor')
def test_actual_recovery_helper_descriptor():
    result = subprocess.run([approval.credential_store._powershell_path(), '-NoLogo', '-NoProfile', '-STA',
        '-File', str(PLUGIN / 'scripts/web_recovery_approval.ps1'), '-DescribeProtocol'],
        capture_output=True, timeout=15, env=approval.credential_store._setup_environment())
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert json.loads(result.stdout) == {'legacy_recovery': 2, 'review_seconds': 180}


@pytest.mark.skipif(os.name != 'nt' or os.environ.get('REMOTEX_TEST_NATIVE_APPROVAL') != '1', reason='Opt-in native expiry test, no decision')
def test_native_recovery_shows_then_expires_without_authority():
    packet = manifest()
    packet['wait_seconds'] = 2
    process = subprocess.Popen([approval.credential_store._powershell_path(), '-NoLogo', '-NoProfile', '-STA',
        '-File', str(PLUGIN / 'scripts/web_recovery_approval.ps1')], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=approval.credential_store._setup_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        process.stdin.write(canonical(packet) + b'\n'); process.stdin.flush()
        process.wait(timeout=15)
        assert process.returncode == 0 and process.stdout.read() == b''
        receipts = [approval.decode_ui_receipt(line + b'\n', packet) for line in process.stderr.read().splitlines()]
    finally:
        if process.poll() is None: process.terminate(); process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr): stream.close()
    assert any(r['event'] == 'shown' for r in receipts)
    assert receipts[-1]['reason'] == 'review-expired'
