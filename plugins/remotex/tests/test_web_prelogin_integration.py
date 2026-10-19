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
from pathlib import Path
from urllib.parse import urlsplit
import pytest

PLUGIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PLUGIN/'src'))
import audit_log
import execution
import secure_paths
import web_adapter
from web_channel import Channel
from web_task_service import Service
from web_authorization_store import Journal
from web_authorization import ScopeError

SECRET='synthetic-prelogin-only-canary'

@pytest.mark.skipif(os.name!='nt',reason='Original Windows job and real Edge integration')
@pytest.mark.parametrize('mode',['complete','partial','late-auth','late-revoke','replace-complete','replace-pending'],
    ids=['complete','partial-blocks-login','late-auth-no-replay','late-auth-revocation',
        'new-document-clears-ready','new-document-rejects-delayed-response'])
def test_original_supervisor_initialization_replacement_login_and_read(tmp_path,mode):
    partial=mode=='partial'
    node=shutil.which('node');assert node
    site=tmp_path/'site';site.mkdir()
    server=subprocess.Popen([node,str(PLUGIN/'tests/fixtures/web_initialization_worker.mjs'),str(site),
        'hold-login' if mode in {'late-auth','late-revoke'} else mode],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',errors='replace')
    worker=job=channel=None;old_audit=os.environ.get('REMOTEX_AUDIT_FILE')
    audit=tmp_path/'audit.jsonl';os.environ['REMOTEX_AUDIT_FILE']=str(audit)
    prior_threads=set(threading.enumerate());public=[]
    try:
        hello=server.stdout.readline()
        assert hello,server.stderr.read(4000)
        peer=json.loads(hello);assert urlsplit(peer['origin']).hostname=='127.0.0.1'
        cfg={**peer,'url':peer['origin']+'/#/','account':'operator','username_selector':'#user',
            'password_selector':'#pass','submit_selector':'#login','success_selector':'#main'}
        directory=tmp_path/'worker';secure_paths.ensure_private_directory(directory)
        deadline=int((time.time()+180)*1000)
        worker=subprocess.Popen([node,'--use-system-ca',str(PLUGIN/'scripts/web_login_worker.mjs'),str(directory),
            str(PLUGIN/'scripts/web-runtime/node_modules/playwright-core'),str(PLUGIN/'scripts/web-runtime/node_modules/jsonc-parser')],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=web_adapter._environment())
        job=execution._WindowsJob(worker,memory_limit_mb=None,cpu_time_seconds=None,max_processes=None)
        assert job.assigned,'The fixture worker must have the production process-lifetime boundary'
        channel=Channel(worker,job,profile='fixture',requester='fixture-owner',resource='web:'+'a'*64,deadline=deadline,config=cfg)
        binding={'origin':cfg['origin'],'account':'operator','profile':'fixture','session':'a'*32,
            'worker':'fixture-original','acquisition':'fixture-acquisition','profile_digest':hashlib.sha256(json.dumps(cfg).encode()).hexdigest(),
            'deadline':time.monotonic()+180}
        prompts={}
        class Prompt:
            def __init__(self,manifest,callbacks):self.manifest=manifest;self.callbacks=callbacks;self.stopped=False
            @classmethod
            def start(cls,manifest,**callbacks):
                assert urlsplit(manifest['binding']['origin']).hostname=='127.0.0.1','Never simulate native approval for a real site'
                assert SECRET not in json.dumps(manifest)
                value=cls(manifest,callbacks);prompts[manifest['request_id']]=value;return value
            def stop(self,reason='stopped'):
                if not self.stopped:self.stopped=True;self.callbacks['on_revoke']()
            def status(self):
                return {'state':'closed' if self.stopped else 'shown','shown':True,'review_remaining_seconds':0 if self.stopped else 120,
                    'exit_reason':None,'error_code':None,'helper_exit_code':None}
        service=Service(channel,binding=binding,check=lambda:copy.deepcopy(binding),journal=Journal(tmp_path/'authorization'),prompt=Prompt)
        worker.stdin.write((json.dumps({'config':cfg,'username':'operator','password':SECRET,'deadline':deadline})+'\n').encode());worker.stdin.flush()
        channel.start()
        sequence=0
        def server_call(operation='stats'):
            nonlocal sequence
            sequence+=1;server.stdin.write(json.dumps({'id':sequence,'operation':operation})+'\n');server.stdin.flush()
            value=json.loads(server.stdout.readline());assert value['id']==sequence;return value['result']
        stats=server_call
        def approve(request,exclude=None):
            prompt=prompts[request['request_id']];choices=[]
            for row in prompt.manifest['items']:
                contract=service.contexts[request['request_id']].get(row['item_id'],{})
                if exclude and exclude(contract):continue
                choice={'item_id':row['item_id'],'max_uses':row['max_uses'],'targets':row['targets']}
                review=row['parameters'].get('review_kind')
                if review:choice['semantic_classification']='read' if review=='unclassified' else review
                choices.append(choice)
            value=prompt.callbacks['on_decision']({'nonce':prompt.manifest['nonce'],'request_digest':prompt.manifest['request_digest'],
                'choices':choices,'ttl_seconds':prompt.manifest['ttl_seconds']})
            assert value['grant_state']=='active';public.append(value);return value
        def request(rows,key,sources=()):
            phase=service.status()['phase']
            return service.request({'setup':{'revision':2,'phase':phase,'requests':rows,'replace_grant_ids':list(sources)},
                'idempotency_key':key,'ttl_seconds':300})
        proof=[{'kind':'source-review','reference':'fixture:'+hashlib.sha256((PLUGIN/'tests/fixtures/web_initialization_worker.mjs').read_bytes()).hexdigest()}]
        static_proof=[{'kind':'operator-inspected','reference':'Fixture static resource'}]
        def static(row,uses=7):return {'network_ref':row['ref'],'purpose':'bootstrap-resource','max_uses':uses,'evidence':static_proof}
        status=service.status();root=next(r for r in status['pending_network'] if r['path']=='/')
        assert stats()['requests']==0
        first=approve(request([static(root,10)],'root'))
        assert stats()['requests']==0,'Approval alone cannot transmit a request'
        service._worker('resume-login',{})
        pending=service.status()['pending_network'];assets=[r for r in pending if r['path'].startswith('/assets/')]
        assert len(assets)==47;assert stats()['assets']==0
        group=assets[:24];first_paths={r['path'] for r in group}
        approve(request([static(r) for r in group],'carry-root',[first['grant_id']]))
        assert service.broker.status(first['request_id'])['grant_state']=='replaced'
        assert sum(g['state']=='active' for g in service.broker.grants.values())==1
        service._worker('resume-login',{})
        pending=service.status()['pending_network']
        rest=[r for r in pending if r['path'].startswith('/assets/') and r['path'] not in first_paths]
        assert len(rest)==23
        approve(request([static(r) for r in rest],'remaining'))
        service._worker('resume-login',{})
        pending=service.status()['pending_network']
        additional=[r for r in pending if r['path'].startswith(('/script/','/img/'))]
        initialization=[r for r in pending if r['path'].startswith('/init/')]
        assert len(additional)==3 and len(initialization)==3
        rows=[static(r) for r in additional]+[{'network_ref':r['ref'],'purpose':'initialization-read','evidence':proof,
            'response_checks':[{'pointer':'/ready','test':'equals-boolean','expected':True}]} for r in initialization]
        mixed=request(rows,'initialization')
        approve(mixed,exclude=(lambda c:c.get('descriptor',{}).get('path')=='/init/guid') if partial else None)
        assert stats()['initialization']==0
        if mode.startswith('replace-'):
            outcomes=[]
            def resume_replacement():
                try:outcomes.append(service._worker('resume-login',{}))
                except ScopeError as error:outcomes.append(type(error).__name__)
            attempt=threading.Thread(target=resume_replacement);attempt.start()
            until=time.monotonic()+10
            while attempt.is_alive() and time.monotonic()<until:
                if stats()['replacements']:break
                time.sleep(0.05)
            if mode=='replace-pending':assert server_call('release-initialization')['released']==2
            attempt.join(timeout=10);assert not attempt.is_alive()
            assert outcomes
            assert stats()['replacements']==0,'A second document must not inherit a startup permit or readiness'
            assert stats()['logins']==0 and stats()['writes']==0
            state=json.loads((directory/'state.json').read_text())
            assert state['loginSubmitted'] is False and state['authenticationVerified'] is False
            until=time.monotonic()+5
            while channel.available and time.monotonic()<until:time.sleep(0.02)
            assert channel.available is False
            assert service.startup.authentication_forwarded==0
            return
        service._worker('resume-login',{})
        status=service.status();public.append(status)
        assert status['initialization']['required']==3
        assert stats()['logins']==0
        if partial:
            assert status['initialization']['ready']==2
            assert json.loads((directory/'state.json').read_text())['loginSubmitted'] is False
        else:
            assert status['initialization']['ready']==3
            login=next(r for r in status['pending_network'] if r['path']=='/login')
            auth=service.request({'setup':{'phase':'login-once','network_refs':[login['ref']],'evidence':proof},'idempotency_key':'login'})
            approve(auth)
            assert sum(g['state']=='active' for g in service.broker.grants.values())==4
            result=service._worker('resume-login',{});public.append(result)
            if mode in {'late-auth','late-revoke'}:
                assert result['authenticationVerified'] is False
                sent=stats()['requests'];unknown=service._worker('resume-login',{})
                assert unknown['doNotResubmit'] is True and stats()['requests']==sent
                if mode=='late-revoke':
                    prompts[auth['request_id']].stop()
                    assert channel.available is False,'Revoking an outstanding Login response must fence only its owned session'
                    assert stats()['logins']==1 and stats()['writes']==0
                    return
                assert server_call('release-login')['released']==1
                until=time.monotonic()+5
                while time.monotonic()<until:
                    result=service._worker('resume-login',{})
                    if result.get('authenticationVerified'):break
                    assert result['doNotResubmit'] is True
                    time.sleep(0.05)
                public.append(result)
            assert result['authenticationVerified'] is True
            assert service.startup.authentication_forwarded==1
            assert stats()['logins']==1 and stats()['initialization']==6
            view=service.components();region=next(c for c in view['components'] if c.get('id')=='main')
            read=service.request({'items':[{'item_id':'read','capability':'web.read_region','observation_id':view['observationId'],
                'component_ref':region['ref'],'limits':{'bytes':4096}}],'idempotency_key':'read'})
            grant=approve(read)
            output=service.execute({'grant_id':grant['grant_id'],'item_id':'read','idempotency_key':'read-once',
                'observation_id':view['observationId'],'component_ref':region['ref']})
            public.append(output);assert 'Fixture Center' in output['result']['text']
        evidence=stats();assert evidence['writes']==0
        assert not evidence['credentialOutsideLogin'] and not evidence['invalidPreauthCookie'] and not evidence['wrongLogin']
        for text in [json.dumps(public),audit.read_text(),(directory/'state.json').read_text()]:
            assert SECRET not in text and 'fixture-private-guid' not in text
        with audit.open('rb') as handle:records=audit_log._records(handle)
        assert len(records)>20
        if not partial:
            assert sum(r.get('authorization',{}).get('event')=='authentication-verified' for r in records)==1
    finally:
        if worker:
            try:
                worker.stdin.close();worker.wait(timeout=10)
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
        if not any(thread.is_alive() for thread in owned):
            if old_audit is None:os.environ.pop('REMOTEX_AUDIT_FILE',None)
            else:os.environ['REMOTEX_AUDIT_FILE']=old_audit
        else:
            raise AssertionError('Fixture audit workers have not drained; keep this test process redirected to its private audit file')
