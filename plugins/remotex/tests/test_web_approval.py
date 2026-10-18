from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import web_authorization as auth
try:
    import web_approval as approval
except ModuleNotFoundError:
    approval=None


def manifest():
    return {'request_id':'a'*32,'nonce':'b'*64,'request_digest':'c'*64,
            'binding':{'origin':'https://console.example','account':'operator'},
            'items':[],'ttl_seconds':300,'wait_seconds':120}


def frame(**updates):
    return {'event':'decision','request_id':'a'*32,'nonce':'b'*64,'request_digest':'c'*64,
            'choices':[],'ttl_seconds':60,**updates}


def test_native_decision_transport_is_required():
    assert approval is not None,'The native approval transport has not been implemented'
    assert approval.decode_frame(json.dumps(frame()).encode()+b'\n',manifest())['event']=='decision'


@pytest.mark.skipif(os.name!='nt' or os.environ.get('REMOTEX_TEST_NATIVE_APPROVAL')!='1',
                    reason='Opt-in interactive Windows helper smoke test')
@pytest.mark.parametrize('item_count',[0,15])
def test_native_helper_emits_no_frame_before_human_decision(item_count):
    script=Path(__file__).resolve().parents[1]/'scripts'/'web_approval.ps1'
    process=subprocess.Popen([approval.credential_store._powershell_path(),'-NoLogo','-NoProfile','-STA',
        '-File',str(script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env=approval.credential_store._setup_environment(),creationflags=subprocess.CREATE_NO_WINDOW)
    observed=queue.Queue()
    diagnostics=queue.Queue()
    reader=threading.Thread(target=lambda:observed.put(process.stdout.readline(32769)),daemon=True)
    diagnostic_reader=threading.Thread(target=lambda:diagnostics.put(process.stderr.readline(2049)),daemon=True)
    packet=manifest()
    packet['items']=[{'item_id':f'asset.{index}','capability':'web.page_step',
        'fingerprint':'d'*64,'page':'#/','max_uses':2,'depends_on':[],'targets':[],
        'parameters':{'review_kind':'bootstrap'},'output':{'rows':0,'columns':0,'bytes':0},
        'display':{'label':f'Network: GET /assets/{index}.js','preview':'{}'},
        'effect':{'class':'task-bounded','fields':[],'digest':'e'*64}}
        for index in range(item_count)]
    try:
        process.stdin.write(auth.canonical(packet)+b'\n')
        process.stdin.flush()
        reader.start()
        diagnostic_reader.start()
        try:
            raw=observed.get(timeout=4)
        except queue.Empty:
            raw=None
        assert raw is None, f'Native helper emitted unsolicited protocol output: {raw!r}'
        assert process.poll() is None, 'Native helper exited before a human decision'
        try:
            diagnostic=diagnostics.get(timeout=4)
        except queue.Empty:
            diagnostic=None
        assert diagnostic is not None, 'Native helper has no Shown receipt'
        value=json.loads(diagnostic)
        assert value['event']=='shown' and value['reason']=='shown'
        assert value['nonce']==packet['nonce'] and value['request_digest']==packet['request_digest']
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)
        reader.join(timeout=2)
        diagnostic_reader.join(timeout=2)
        for stream in (process.stdin,process.stdout,process.stderr):
            stream.close()


@pytest.mark.skipif(os.name!='nt' or os.environ.get('REMOTEX_TEST_NATIVE_APPROVAL')!='1',
                    reason='Opt-in interactive Windows helper lifecycle test')
@pytest.mark.parametrize('scenario',['closed','startup-error'])
def test_native_closed_and_error_receipts_use_only_diagnostic_pipe(tmp_path,scenario):
    source=Path(__file__).resolve().parents[1]/'scripts'/'web_approval.ps1'
    script=source
    packet=manifest()
    packet['wait_seconds']=1
    if scenario=='startup-error':
        script=tmp_path/'web_approval.ps1'
        shutil.copyfile(source,script)  # Missing companion module is a real startup failure.
    result=subprocess.run([approval.credential_store._powershell_path(),'-NoLogo','-NoProfile','-STA',
        '-File',str(script)],input=auth.canonical(packet)+b'\n',capture_output=True,
        env=approval.credential_store._setup_environment(),creationflags=subprocess.CREATE_NO_WINDOW,timeout=12)
    assert result.stdout==b'','Native lifecycle must not emit authority'
    values=[approval.decode_ui_receipt(raw+b'\n',packet) for raw in result.stderr.splitlines()]
    if scenario=='closed':
        assert result.returncode==0
        assert [(value['event'],value['reason']) for value in values]==[('shown','shown'),('closed','review-expired')]
    else:
        assert result.returncode==1
        assert [(value['event'],value['reason']) for value in values]==[('error','helper-startup-failed')]


@pytest.mark.skipif(os.name!='nt' or os.environ.get('REMOTEX_TEST_NATIVE_APPROVAL')!='1',
                    reason='Opt-in real private-pipe lifecycle integration')
@pytest.mark.parametrize('scenario',['shown','startup-error'])
def test_real_prompt_wires_diagnostics_without_authority(tmp_path,monkeypatch,scenario):
    if scenario=='startup-error':
        scripts=tmp_path/'scripts';scripts.mkdir()
        shutil.copyfile(Path(__file__).resolve().parents[1]/'scripts'/'web_approval.ps1',scripts/'web_approval.ps1')
        monkeypatch.setattr(approval,'__file__',str(tmp_path/'src'/'web_approval.py'))
    calls=[];cancelled=threading.Event()
    def cancel():
        calls.append('cancel');cancelled.set()
    prompt=approval.ApprovalPrompt.start(manifest(),
        on_decision=lambda value:calls.append('decision') or {'grant_id':None},
        on_revoke=lambda:calls.append('revoke'),on_cancel=cancel)
    try:
        deadline=time.monotonic()+8
        expected='shown' if scenario=='shown' else 'error'
        while time.monotonic()<deadline and prompt.status()['state']!=expected:
            time.sleep(0.05)
        status=prompt.status()
        assert status['state']==expected,'Actual prompt did not consume its native stderr receipt'
        assert 'decision' not in calls and not prompt.decided
        if scenario=='shown':
            assert status['shown'] is True and 0<status['review_remaining_seconds']<=120
            assert calls==[]
        else:
            assert status['error_code']=='helper-startup-failed'
            assert status['exit_reason']=='helper-startup-failed'
            assert cancelled.wait(1)
    finally:
        prompt.stop();prompt.process.wait(timeout=5)
        for stream in (prompt.process.stdin,prompt.process.stdout,prompt.process.stderr):
            stream.close()


@pytest.mark.parametrize('update',[{'nonce':'wrong'},{'request_digest':'d'*64},
    {'request_id':'e'*32},{'approved':True},{'event':'approve'},{'ttl_seconds':True}])
def test_forged_malformed_or_widened_frames_cannot_grant(update):
    assert approval is not None
    with pytest.raises(auth.ScopeError,match='decision-invalid'):
        approval.decode_frame(json.dumps(frame(**update)).encode()+b'\n',manifest())


def test_oversized_duplicate_or_non_json_frames_are_fixed_errors():
    assert approval is not None
    for raw in (b'X'*32769,b'{"event":"decision","event":"revoke"}\n',b'not-json\n'):
        with pytest.raises(auth.ScopeError,match='decision-invalid'):
            approval.decode_frame(raw,manifest())


def test_revoke_is_not_an_approval_and_does_not_carry_choice_values():
    assert approval is not None
    value={k:v for k,v in frame(event='revoke').items() if k not in {'choices','ttl_seconds'}}
    result=approval.decode_frame(json.dumps(value).encode()+b'\n',manifest())
    assert result['event']=='revoke'
    with pytest.raises(auth.ScopeError):
        approval.decode_frame(json.dumps(frame(event='revoke')).encode()+b'\n',manifest())


def test_helper_launch_failure_never_reports_approval(monkeypatch):
    assert approval is not None
    def fail(*args,**kwargs):raise OSError('private-exception-canary')
    monkeypatch.setattr(approval.subprocess,'Popen',fail)
    with pytest.raises(auth.ScopeError,match='approval-ui-unavailable') as error:
        approval.ApprovalPrompt.start(manifest(),on_decision=lambda value:None,on_revoke=lambda:None,on_cancel=lambda:None)
    assert 'private-exception-canary' not in str(error.value)


def test_revoke_frame_is_processed_while_decision_persistence_is_blocked():
    assert approval is not None
    lines=queue.Queue();entered=threading.Event();release=threading.Event();revoked=threading.Event()
    def decide(value):
        entered.set();release.wait(3)
        return {'grant_id':'f'*32,'expires_in_seconds':60}
    process=SimpleNamespace(stdout=SimpleNamespace(readline=lambda limit:lines.get(timeout=3)))
    job=SimpleNamespace(terminate=lambda:None,close=lambda:None)
    prompt=approval.ApprovalPrompt(process,job,manifest(),decide,revoked.set,lambda:None)
    prompt.timer=threading.Timer(30,lambda:None)
    lines.put(json.dumps(frame()).encode()+b'\n')
    reader=threading.Thread(target=prompt._read,daemon=True);reader.start()
    assert entered.wait(1)
    revoke={k:v for k,v in frame(event='revoke').items() if k not in {'choices','ttl_seconds'}}
    lines.put(json.dumps(revoke).encode()+b'\n')
    try:
        assert revoked.wait(0.5),'Revocation waited for slow decision persistence'
    finally:
        release.set();lines.put(b'');reader.join(3);prompt.stop()
