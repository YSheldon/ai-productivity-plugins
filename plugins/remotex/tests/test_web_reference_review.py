"""Private protocol units. These do not stand in for native/human evidence."""
import io
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

PLUGIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PLUGIN/'src'))
sys.path.insert(0,str(PLUGIN/'tests'))
from remotex_v3_support import native_manifest,compare_frame
from web_approval import ApprovalPrompt,decode_frame

def packet(value):
    return json.dumps(value,separators=(',',':')).encode()+b'\n'

def ready(manifest):
    return {'event':'helper-ready',**{k:manifest[k] for k in ('request_id','nonce','request_digest')},
        'protocol_revision':3,'profiles':['json-utf8-v1','form-utf8-v1','form-json-name-view-v1']}

def test_native_compare_is_not_a_final_decision_and_old_manifests_reject_it():
    manifest=native_manifest();frame=compare_frame(manifest)
    value=decode_frame(packet(frame),manifest)
    assert value['event']=='reference-check' and 'choices' not in value and 'approved_semantics' not in value
    assert decode_frame(packet(ready(manifest)),manifest)['event']=='helper-ready'
    legacy={k:v for k,v in manifest.items() if k!='protocol_revision'}
    with pytest.raises(ValueError,match='decision-invalid'):decode_frame(packet(frame),legacy)

@pytest.mark.parametrize('update',[{'extra':True},{'nonce':'x'*64},{'item_id':'foreign'},
    {'edit_revision':True},{'edit_revision':0},{'check_id':'wrong'},{'native_input':[]}])
def test_reference_frames_reject_wrong_binding_shape_item_and_revision(update):
    manifest=native_manifest()
    with pytest.raises(ValueError,match='decision-invalid'):decode_frame(packet({**compare_frame(manifest),**update}),manifest)

def prompt_case(callback,*,clock=time.monotonic,decision=None):
    manifest=native_manifest();lines=queue.Queue();calls=[]
    process=SimpleNamespace(stdout=SimpleNamespace(readline=lambda limit:lines.get(timeout=3)),stdin=io.BytesIO(),poll=lambda:None)
    job=SimpleNamespace(terminate=lambda:calls.append('terminate'),close=lambda:calls.append('close'))
    prompt=ApprovalPrompt(process,job,manifest,decision or (lambda frame:calls.append('decision')),
        lambda:calls.append('revoke'),lambda:calls.append('cancel'),clock=clock,on_reference=callback)
    return prompt,manifest,lines,calls

def test_ready_and_private_compare_keep_original_timer_and_do_not_decide():
    entered=threading.Event()
    def callback(frame):
        entered.set()
        return {k:frame[k] for k in ('check_id','item_id','edit_revision')}|{'review_ref':'1'*32,'unit_count':5,'code':'ready'}
    prompt,manifest,lines,calls=prompt_case(callback)
    reader=threading.Thread(target=prompt._read,daemon=True);reader.start()
    try:
        deadline=prompt.review_deadline
        lines.put(packet(ready(manifest)));lines.put(packet(compare_frame(manifest)))
        assert entered.wait(1)
        until=time.monotonic()+1
        while not prompt.process.stdin.getvalue() and time.monotonic()<until:time.sleep(.01)
        reply=json.loads(prompt.process.stdin.getvalue())
        assert reply['event']=='reference-result' and reply['review_ref']=='1'*32
        assert not prompt.decided and prompt.review_deadline==deadline and 'decision' not in calls
        assert not {'native_input','reference','body_text'}&set(reply)
    finally:
        lines.put(b'');reader.join(2);prompt.stop()

def test_a_late_decision_ack_cannot_create_native_active_state():
    now=[1000.0]
    def decision(frame):
        now[0]=1121.0
        return {'grant_id':'2'*32,'expires_in_seconds':100,'effective_limits':{}}
    prompt,manifest,_,calls=prompt_case(lambda frame:None,clock=lambda:now[0],decision=decision)
    prompt.helper_ready=True;prompt.decision_pending=True
    frame={'event':'decision',**{k:manifest[k] for k in ('request_id','nonce','request_digest')},'choices':[],'ttl_seconds':60}
    prompt._apply_decision(frame)
    assert not prompt.decided and prompt.stopped and 'revoke' in calls
    frames=[json.loads(line) for line in prompt.process.stdin.getvalue().splitlines()]
    assert all(value.get('state')!='active' for value in frames)

@pytest.mark.skipif(os.name!='nt',reason='Native Windows reference state and bounded async reader')
@pytest.mark.parametrize('scenario',['state','foreign','typed','unit-boundaries','controls','queue','queue-limit','line-limit','reference-json'])
def test_native_reference_state_and_bounded_reader(scenario):
    import credential_store
    result=subprocess.run([credential_store._powershell_path(),'-NoLogo','-NoProfile','-STA','-File',
        str(PLUGIN/'tests/Test-WebReferenceReview.ps1'),'-Scenario',scenario],capture_output=True,text=True,
        encoding='utf-8',errors='replace',timeout=20)
    assert result.returncode==0,result.stdout+result.stderr
    assert result.stdout.strip()=='PASS'

@pytest.mark.skipif(os.name!='nt' or os.environ.get('REMOTEX_TEST_NATIVE_APPROVAL')!='1',
    reason='Opt-in actual v3 helper handshake, no human decision')
@pytest.mark.parametrize('unit_count',[5,32])
def test_actual_v3_helper_handshake_is_not_authority(unit_count):
    calls=[];manifest=native_manifest();manifest['wait_seconds']=10
    manifest['reference_items'][0]['locations']=[{'ref':format(i+1,'032x'),'position':i+1,'type':'string','sensitive':False} for i in range(unit_count)]
    prompt=ApprovalPrompt.start(manifest,on_decision=lambda frame:calls.append('decision'),
        on_revoke=lambda:calls.append('revoke'),on_cancel=lambda:calls.append('cancel'),
        on_reference=lambda frame:calls.append('reference'))
    try:
        until=time.monotonic()+6
        while time.monotonic()<until and not (prompt.helper_ready and prompt.status()['shown']):time.sleep(.05)
        assert prompt.helper_ready,'Actual helper never advertised the required private v3 protocol: '+json.dumps(prompt.status())
        assert prompt.status()['shown'] and not prompt.decided and calls==[]
        assert 0<prompt.status()['review_remaining_seconds']<=10
    finally:
        prompt.stop();prompt.process.wait(timeout=5)
        for stream in (prompt.process.stdin,prompt.process.stdout,prompt.process.stderr):stream.close()

@pytest.mark.skipif(os.name!='nt' or os.environ.get('REMOTEX_TEST_NATIVE_APPROVAL')!='1',
    reason='Opt-in actual v3 parent-pipe lifecycle, no human decision')
def test_actual_v3_helper_exits_when_its_original_parent_pipe_closes():
    calls=[];manifest=native_manifest();manifest['wait_seconds']=10
    prompt=ApprovalPrompt.start(manifest,on_decision=lambda frame:calls.append('decision'),
        on_revoke=lambda:calls.append('revoke'),on_cancel=lambda:calls.append('cancel'),
        on_reference=lambda frame:calls.append('reference'))
    try:
        until=time.monotonic()+5
        while time.monotonic()<until and not (prompt.helper_ready and prompt.status()['shown']):time.sleep(.05)
        assert prompt.helper_ready and prompt.status()['shown']
        prompt.process.stdin.close()
        until=time.monotonic()+2
        while time.monotonic()<until and not prompt.stopped:time.sleep(.05)
        assert prompt.stopped and 'cancel' in calls and 'decision' not in calls
    finally:
        prompt.stop();prompt.process.wait(timeout=5)
        for stream in (prompt.process.stdin,prompt.process.stdout,prompt.process.stderr):stream.close()
