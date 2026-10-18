from __future__ import annotations

import json
import queue
import sys
import threading
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
