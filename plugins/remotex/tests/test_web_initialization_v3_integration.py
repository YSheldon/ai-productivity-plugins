"""Real isolated Edge/Job/Channel/Service; fake Prompt is synthetic, not native evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import pytest

PLUGIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PLUGIN/'src'))
import execution
import secure_paths
import web_adapter
from web_authorization import ScopeError
from web_authorization_store import Journal
from web_channel import Channel
from web_task_service import Service

SECRET='synthetic-v3-password-only-canary'


def write_manual_public_review_packet(directory,reference):
    if not isinstance(reference,dict) or set(reference)!={'profile_id','target_text','content_type','body_text','public_headers'}:
        raise ValueError('Synthetic source must supply only the five public reference fields')
    source=PLUGIN/'tests/fixtures/web_initialization_v3_worker.mjs'
    packet={'schema':'RemoteXPublicReview/v1','reference':reference,'evidence':{
        'kind':'source-review','source_ref':'plugins/remotex/tests/fixtures/web_initialization_v3_worker.mjs',
        'revision_ref':'sha256:'+hashlib.sha256(source.read_bytes()).hexdigest(),
        'deployment_ref':'isolated-owned-loopback synthetic manual fixture',
        'basis':'Fixed fixture source defines public mode/userSession constants and initialization handlers that return '
            'ready=true without business writes or authentication. Public headers come from a separate offline browser, '
            'not intercepted requests. Review the source and original response predicate before confirming.'},
        'cookie_evidence':'The fixture source sets fixture_preauth on the root response; it is not used for authentication '
            'by the initialization or login handlers. Review only the original synthetic prelogin cookie context.'}
    raw=json.dumps(packet,ensure_ascii=False,allow_nan=False,indent=2).encode('utf-8',errors='strict')
    if len(raw)>24000:raise ValueError('Synthetic public review packet exceeds the 24000-byte import bound')
    path=directory/'public-review.json';path.write_bytes(raw)
    (directory/'public-reference.json').write_text(json.dumps(reference,ensure_ascii=False,allow_nan=False,indent=2),encoding='utf-8')
    return path


def test_manual_public_review_packet_is_source_bound_and_non_authorizing(tmp_path):
    reference={'profile_id':'form-json-name-view-v1','target_text':'/init/one',
        'content_type':'application/x-www-form-urlencoded',
        'body_text':'{"mode":"one","userSession":"PUBLIC_V3_MARKER"}',
        'public_headers':[{'name':'origin','value':'https://127.0.0.1:32100'}]}
    path=write_manual_public_review_packet(tmp_path,reference)
    raw=path.read_bytes();packet=json.loads(raw.decode('utf-8',errors='strict'))
    assert len(raw)<=24000 and not raw.startswith(b'\xef\xbb\xbf')
    assert set(packet)=={'schema','reference','evidence','cookie_evidence'}
    assert packet['schema']=='RemoteXPublicReview/v1' and packet['reference']==reference
    assert set(packet['evidence'])=={'kind','source_ref','revision_ref','deployment_ref','basis'}
    assert packet['evidence']['kind']=='source-review'
    source=PLUGIN/'tests/fixtures/web_initialization_v3_worker.mjs'
    assert packet['evidence']['source_ref']=='plugins/remotex/tests/fixtures/web_initialization_v3_worker.mjs'
    assert packet['evidence']['revision_ref']=='sha256:'+hashlib.sha256(source.read_bytes()).hexdigest()
    assert 'offline browser' in packet['evidence']['basis']
    assert 'not used for authentication' in packet['cookie_evidence']
    assert json.loads((tmp_path/'public-reference.json').read_text(encoding='utf-8'))==reference


@pytest.mark.parametrize('invalid',['oversized','invalid-utf8','authority-field'])
def test_manual_public_review_packet_rejects_invalid_source_before_writing(tmp_path,invalid):
    reference={'profile_id':'form-json-name-view-v1','target_text':'/init/one',
        'content_type':'application/x-www-form-urlencoded','body_text':'{}','public_headers':[]}
    if invalid=='oversized':reference['body_text']='\u20ac'*8000
    elif invalid=='invalid-utf8':reference['body_text']='\ud800'
    else:reference['approved']=True
    with pytest.raises(ValueError):write_manual_public_review_packet(tmp_path,reference)
    assert not (tmp_path/'public-review.json').exists()
    assert not (tmp_path/'public-reference.json').exists()


@contextmanager
def v3_runtime(tmp_path,mode,*,manual=False):
    node=shutil.which('node');assert node
    site=tmp_path/'site';site.mkdir()
    server=subprocess.Popen([node,str(PLUGIN/'tests/fixtures/web_initialization_v3_worker.mjs'),str(site),mode],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
    worker=job=channel=None
    old_audit=os.environ.get('REMOTEX_AUDIT_FILE');audit=tmp_path/'audit.jsonl'
    os.environ['REMOTEX_AUDIT_FILE']=str(audit)
    prior_threads=set(threading.enumerate())
    try:
        line=server.stdout.readline();assert line,server.stderr.read(4000)
        peer=json.loads(line);assert urlsplit(peer['origin']).hostname=='127.0.0.1'
        if manual:
            public_review_file=write_manual_public_review_packet(tmp_path,peer['references'][0])
        cfg={key:peer[key] for key in ('origin','certificate_sha256')}
        cfg.update(url=peer['origin']+'/#/',account='operator',username_selector='#user',
            password_selector='#pass',submit_selector='#login',success_selector='#main')
        directory=tmp_path/'worker';secure_paths.ensure_private_directory(directory)
        seconds=1800 if manual else 180
        deadline=int((time.time()+seconds)*1000)
        worker=subprocess.Popen([node,'--use-system-ca',str(PLUGIN/'scripts/web_login_worker.mjs'),str(directory),
            str(PLUGIN/'scripts/web-runtime/node_modules/playwright-core'),str(PLUGIN/'scripts/web-runtime/node_modules/jsonc-parser')],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=web_adapter._environment())
        job=execution._WindowsJob(worker,memory_limit_mb=None,cpu_time_seconds=None,max_processes=None)
        assert job.assigned
        channel=Channel(worker,job,profile='synthetic-v3',requester='synthetic-v3-owner',resource='web:'+'e'*64,
            deadline=deadline,config=cfg)
        binding={'origin':cfg['origin'],'account':'operator','profile':'synthetic-v3','session':uuid.uuid4().hex,
            'worker':'synthetic-original-v3','acquisition':uuid.uuid4().hex,
            'profile_digest':hashlib.sha256(json.dumps(cfg).encode()).hexdigest(),'deadline':time.monotonic()+seconds}
        prompts={}
        class SyntheticPrompt:
            def __init__(self,manifest,callbacks):self.manifest=manifest;self.callbacks=callbacks;self.stopped=False
            @classmethod
            def start(cls,manifest,**callbacks):
                assert urlsplit(manifest['binding']['origin']).hostname=='127.0.0.1'
                assert SECRET not in json.dumps(manifest)
                value=cls(manifest,callbacks);prompts[manifest['request_id']]=value;return value
            def stop(self,reason='stopped'):
                if not self.stopped:self.stopped=True;self.callbacks['on_revoke']()
            def status(self):return {'state':'shown','shown':True,'review_remaining_seconds':180,
                'exit_reason':None,'error_code':None,'helper_exit_code':None}
        from web_approval import ApprovalPrompt
        service=Service(channel,binding=binding,check=lambda:copy.deepcopy(binding),journal=Journal(tmp_path/'authorization'),
            prompt=ApprovalPrompt if manual else SyntheticPrompt)
        race={'emitted':0,'held':False,'released':False,'error':None}
        held=[]
        original_send=channel._send
        if mode=='response-cookie':
            def defer_last_receipt(packet):
                if packet.get('allowed') is True and packet.get('permit',{}).get('kind')=='initialization-permit-v3':
                    race['emitted']+=1
                    if race['emitted']==3:
                        held.append((copy.deepcopy(packet),time.monotonic()));race['held']=True
                        try:server_call('release-cookie')
                        except Exception:race['error']='synthetic-response-release-failed'
                        return
                return original_send(packet)
            channel._send=defer_last_receipt
        def release_late_receipt():
            assert race['emitted']==3 and race['held'] and race['error'] is None
            assert len(held)==1 and not race['released']
            packet,started=held.pop()
            assert time.monotonic()-started<5,'Fixture must exercise cancellation before the original ten-second check expiry'
            race['released']=True
            original_send(packet)
        worker.stdin.write((json.dumps({'config':cfg,'username':'operator','password':SECRET,'deadline':deadline})+'\n').encode())
        worker.stdin.flush();channel.start()
        sequence=0
        def server_call(operation):
            nonlocal sequence
            sequence+=1;server.stdin.write(json.dumps({'id':sequence,'operation':operation})+'\n');server.stdin.flush()
            result=json.loads(server.stdout.readline());assert result['id']==sequence;return result['result']
        def stats():return server_call('stats')
        def approve(request,*,partial=False):
            if manual:
                request_id=request['request_id']
                row=service.broker.requests[request_id]['items'][0]
                stage='public-reference' if (service.broker.requests[request_id].get('setup_context') or {}).get('revision')==3 else row['parameters'].get('review_kind','read')
                (tmp_path/'native-request.json').write_text(json.dumps({
                    'digest':request['request_digest'][:8],'stage':stage,'public_review_file':str(public_review_file),
                    'public_reference_file':str(tmp_path/'public-reference.json'),
                    'scope':'Synthetic loopback only; no real credentials, shared queue or business writes'},indent=2),encoding='utf-8')
                until=time.monotonic()+180
                while time.monotonic()<until:
                    result=service.status(request_id)
                    if result.get('grant_state')=='active':return result
                    if result.get('state')!='pending':raise AssertionError('Native request ended without an active grant')
                    time.sleep(.2)
                raise AssertionError('Native review did not complete within its original deadline')
            prompt=prompts[request['request_id']];choices=[];unused=list(peer['references'])
            for index,row in enumerate(prompt.manifest['items']):
                if partial and index==len(prompt.manifest['items'])-1:continue
                choice={'item_id':row['item_id'],'max_uses':row['max_uses'],'targets':row['targets']}
                review=row['parameters'].get('review_kind')
                if review:choice['semantic_classification']='read' if review=='unclassified' else review
                if prompt.manifest.get('protocol_revision')==3:
                    meta=next(part for part in prompt.manifest['reference_items'] if part['item_id']==row['item_id'])
                    for reference in unused:
                        native={'version':3,'reference':reference,'attestation':{'data_status':'public-invariant','role':'non-auth',
                            'effect':'initialization-read','sensitive_ack_refs':[loc['ref'] for loc in meta['locations'] if loc['sensitive']],
                            'evidence':{'kind':'source-review','source_ref':'synthetic-fixture-v3','revision_ref':'fixture-v1',
                                'deployment_ref':'isolated-owned-loopback','basis':'Reviewed fixed synthetic handler, public constants and ready response',
                                'independently_reviewed':True}},'cookie_review':{'context_ref':meta['cookie_context_ref'],
                            'role':'non-auth-prelogin' if meta['cookie_context_ref'] else 'none',
                            'evidence_ref':'Synthetic prelogin-only cookie' if meta['cookie_context_ref'] else None}}
                        proof=prompt.callbacks['on_reference']({'event':'reference-check',**{key:prompt.manifest[key] for key in
                            ('request_id','nonce','request_digest')},'item_id':row['item_id'],'check_id':uuid.uuid4().hex,
                            'edit_revision':1,'native_input':native})
                        if proof['code']=='ready':
                            unused.remove(reference);break
                    else:raise AssertionError('Independent source reference failed complete private comparison')
                    choice.update(review_ref=proof['review_ref'],edit_revision=1)
                choices.append(choice)
            assert stats()['initialization']==0 or review!='initialization-read'
            result=prompt.callbacks['on_decision']({'nonce':prompt.manifest['nonce'],'request_digest':prompt.manifest['request_digest'],
                'choices':choices,'ttl_seconds':min(300,prompt.manifest['ttl_seconds'])})
            assert result['grant_state']=='active';return result
        def request_setup(rows,key,revision=2):
            return service.request({'setup':{'revision':revision,'phase':service.status()['phase'],'requests':rows},
                'idempotency_key':key,'ttl_seconds':1800 if manual else 300})
        public=[]
        yield {'service':service,'channel':channel,'cfg':cfg,'stats':stats,'approve':approve,'request':request_setup,
            'directory':directory,'audit':audit,'public':public,'references':peer['references'],
            'race':race,'release_late_receipt':release_late_receipt}
    finally:
        if worker:
            try:worker.stdin.close();worker.wait(timeout=10)
            except (OSError,subprocess.TimeoutExpired):
                if job:job.terminate()
                elif worker.poll() is None:worker.terminate()
                worker.wait(timeout=10)
        if channel:channel.close()
        if job:job.close()
        server.stdin.close()
        try:server.wait(timeout=10)
        except subprocess.TimeoutExpired:server.terminate();server.wait(timeout=10)
        owned=[t for t in threading.enumerate() if t not in prior_threads and t is not threading.current_thread()]
        for thread in owned:thread.join(timeout=5)
        assert not any(thread.is_alive() for thread in owned),'Synthetic authority workers did not drain'
        if old_audit is None:os.environ.pop('REMOTEX_AUDIT_FILE',None)
        else:os.environ['REMOTEX_AUDIT_FILE']=old_audit


def run_flow(r,mode):
    service=r['service'];stats=r['stats'];approve=r['approve'];request=r['request']
    evidence=[{'kind':'source-review','reference':'Reviewed isolated synthetic fixture v3'}]
    root=next(row for row in service.status()['pending_network'] if row.get('path')=='/')
    approve(request([{'network_ref':root['ref'],'purpose':'bootstrap-resource','max_uses':10,'evidence':evidence}],'root'))
    assert stats()['requests']==0
    service._worker('resume-login',{})
    rows=service.status()['pending_network'];candidates=[row for row in rows if row.get('scope')=='private-initialization']
    if mode=='auth-field':
        assert not candidates and stats()['initialization']==0 and stats()['logins']==0
        return
    assert len(candidates)==(1 if mode=='manual' else 3)
    assert all(row['setup_revisions']==[3] and 'path' not in row for row in candidates)
    declarations=[]
    for row in candidates:
        rep=next(v for v in row['representations'] if v['profile_id']=='form-json-name-view-v1')
        declarations.append({'network_ref':row['ref'],'representation_ref':rep['representation_ref'],
            'literal_review_refs':rep['literal_review_refs'],'purpose':'initialization-read','max_uses':4,
            'response_checks':[{'pointer':'/ready','test':'equals-boolean','expected':True}],'evidence':evidence})
    # Full private captures, views and native metadata all count toward 32 KiB.
    # Two initialization grants plus the root leave the fourth slot for Login.
    for offset in range(0,len(declarations),2):
        proposal=request(declarations[offset:offset+2],'initialization-v3-'+str(offset),revision=3)
        assert stats()['initialization']==0 and stats()['logins']==0
        if mode=='late-reference':
            service.broker.requests[proposal['request_id']]['review_deadline']=time.monotonic()-1
            with pytest.raises(ScopeError):approve(proposal)
            assert not service.broker.status(proposal['request_id'])['grant_id']
            return
        approve(proposal,partial=mode=='partial' and offset==0)
    assert stats()['initialization']==0 and stats()['logins']==0
    if mode=='new-document':
        try:service._worker('resume-login',{})
        except ScopeError:pass
        until=time.monotonic()+5
        while r['channel'].available and time.monotonic()<until:time.sleep(.02)
        assert not r['channel'].available and stats()['logins']==0
        return
    service._worker('resume-login',{})
    if mode=='response-cookie':r['release_late_receipt']()
    status=service.status();r['public'].append(status)
    if mode in {'partial','wire-change','cookie-change','response-cookie'}:
        expected=2 if mode=='partial' else 0
        assert status['initialization']['ready']==expected
        assert stats()['logins']==0
        if mode in {'wire-change','cookie-change'}:assert stats()['initialization']==0
        return
    assert status['initialization']['ready']==len(candidates) and stats()['logins']==0
    login=next(row for row in status['pending_network'] if row.get('path')=='/login')
    grant=service.request({'setup':{'phase':'login-once','network_refs':[login['ref']],'evidence':evidence},'idempotency_key':'one-login'})
    approve(grant)
    result=service._worker('resume-login',{});r['public'].append(result)
    assert result['authenticationVerified'] is True and stats()['logins']==1
    view=service.components();region=next(row for row in view['components'] if row.get('id')=='main')
    read=service.request({'items':[{'item_id':'read','capability':'web.read_region','observation_id':view['observationId'],
        'component_ref':region['ref'],'limits':{'bytes':4096}}],'idempotency_key':'read'})
    read_grant=approve(read)
    # Human review can outlive a 30-second observation; the grant still binds the original fingerprint and route.
    view=service.components()
    current=[row for row in view['components'] if row.get('id')==region['id'] and
        row.get('kind')==region['kind'] and not row.get('ambiguous')]
    assert len(current)==1,'Approved read target is no longer uniquely observable'
    region=current[0]
    output=service.execute({'grant_id':read_grant['grant_id'],'item_id':'read','idempotency_key':'read-once',
        'observation_id':view['observationId'],'component_ref':region['ref']})
    assert 'Synthetic V3 Center' in output['result']['text'];r['public'].append(output)
    assert stats()['writes']==0 and not stats()['credentialOutsideLogin'] and not stats()['wrongLogin']


@pytest.mark.skipif(os.name!='nt',reason='Original Windows Job and real isolated Edge')
@pytest.mark.parametrize('mode',['complete','partial','auth-field','wire-change','cookie-change','late-reference','new-document','response-cookie'])
def test_original_v3_pipeline_synthetic_prompt(tmp_path,mode):
    with v3_runtime(tmp_path,mode) as r:
        run_flow(r,mode)
        if mode=='response-cookie':
            assert r['race']=={'emitted':3,'held':True,'released':True,'error':None}
        assert r['stats']()['writes']==0 and not r['stats']()['credentialOutsideLogin']
        active_state=(r['directory']/'state.json').read_text()
        for text in (json.dumps(r['public']),active_state):
            assert SECRET not in text and 'PUBLIC_V3_MARKER' not in text
    # Read final evidence only after the owned writers and revocation audits drain.
    audit=r['audit'].read_text()
    state=(r['directory']/'state.json').read_text()
    for text in (audit,state):
        assert SECRET not in text and 'PUBLIC_V3_MARKER' not in text


@pytest.mark.skipif(os.name!='nt' or os.environ.get('REMOTEX_TEST_MANUAL_V3')!='1',reason='Explicit human native review opt-in')
def test_manual_native_original_supervisor_v3(tmp_path):
    with v3_runtime(tmp_path,'manual',manual=True) as r:run_flow(r,'manual')


@pytest.mark.skipif(os.name!='nt',reason='Original Windows Job and real isolated Edge')
def test_synthetic_read_review_outlives_observation_without_renewing_authority(tmp_path):
    with v3_runtime(tmp_path,'complete') as r:
        original_approve=r['approve'];delayed=[]
        def approve_after_review(request,**kwargs):
            items=r['service'].broker.requests[request['request_id']]['items']
            if any(item['capability']=='web.read_region' for item in items):
                # Exercise real worker expiry, not a production test clock or a larger TTL.
                started=time.monotonic()
                time.sleep(31)
                delayed.append(time.monotonic()-started)
            return original_approve(request,**kwargs)
        r['approve']=approve_after_review
        run_flow(r,'complete')
        assert len(delayed)==1 and delayed[0]>=31
        assert r['stats']()['logins']==1 and r['stats']()['writes']==0
