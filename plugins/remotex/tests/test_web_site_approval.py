import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from web_approval import ApprovalPrompt,decode_ui_receipt
from web_authorization import canonical
import credential_store


@pytest.mark.skipif(os.name!='nt' or os.environ.get('REMOTEX_TEST_NATIVE_APPROVAL')!='1',
    reason='Explicit native-window smoke opt-in; no decision is automated')
@pytest.mark.parametrize('scope',['site','action'])
def test_real_site_helper_shows_then_expires_without_emitting_authority(scope):
    manifest={'ui_mode':'site','scope':scope,'request_id':'a'*32,'nonce':'b'*64,'request_digest':'c'*64,
        'binding':{'origin':'https://console.example','account':'operator'},'wait_seconds':1,'ttl_seconds':30,
        'items':[],'preview':{'control':'Delete synthetic record','action':'click','target':'Synthetic record only'}}
    script=Path(__file__).resolve().parents[1]/'scripts/web_site_approval.ps1'
    process=subprocess.Popen([credential_store._powershell_path(),'-NoLogo','-NoProfile','-STA','-File',str(script)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=credential_store._setup_environment(),
        creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        process.stdin.write(canonical(manifest)+b'\n');process.stdin.flush()
        process.wait(timeout=15)
        output,diagnostics=process.stdout.read(),process.stderr.read()
    finally:
        if process.poll() is None: process.terminate();process.wait(timeout=5)
        for stream in (process.stdin,process.stdout,process.stderr): stream.close()
    assert process.returncode==0,diagnostics.decode('utf-8',errors='replace')
    assert output==b'', 'Showing or expiring a native form must not approve anything'
    events=[decode_ui_receipt(line+b'\n',manifest) for line in diagnostics.splitlines()]
    assert any(row['event']=='shown' for row in events)
    assert events[-1]['event']=='closed' and events[-1]['reason']=='review-expired'


def test_site_prompt_needs_committed_ack_and_never_accepts_a_public_approval():
    from unittest.mock import Mock
    manifest={'ui_mode':'site','wait_seconds':180,'ttl_seconds':43200}
    prompt=ApprovalPrompt(Mock(poll=lambda:None),Mock(),manifest,Mock(),Mock(),Mock())
    assert prompt.acknowledged and not prompt.decided
    assert prompt.status()['review_remaining_seconds']<=180
