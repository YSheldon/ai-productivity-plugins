"""Owned loopback and fake credentials; simulated decision is not native approval evidence."""
import copy
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

PLUGIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PLUGIN/'src'))
from web_authorization_store import Journal, upgrade_protocol
from web_channel import Channel
from web_site_service import SiteService
import execution
import web_adapter


@pytest.mark.skipif(os.name!='nt',reason='Isolated Windows Edge and owned Windows Job')
def test_one_site_decision_runs_initialization_login_read_and_ordinary_write(tmp_path,monkeypatch):
    monkeypatch.setenv('REMOTEX_AUDIT_FILE',str(tmp_path/'audit.jsonl'))
    manual=os.environ.get('REMOTEX_TEST_MANUAL_SITE')=='1'
    node=shutil.which('node')
    if not node or not shutil.which('openssl') or not (PLUGIN/'scripts/web-runtime/node_modules/playwright-core').exists():
        pytest.skip('Node, OpenSSL and the pinned browser runtime are required')
    site=tmp_path/'site';site.mkdir()
    server=subprocess.Popen([node,str(PLUGIN/'tests/fixtures/web_site_fixture.mjs'),str(site)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    worker=channel=job=None
    try:
        peer=json.loads(server.stdout.readline())
        assert peer['origin'].startswith('https://127.0.0.1:')
        directory=tmp_path/'worker';directory.mkdir()
        cfg={**peer,'url':peer['origin']+'/','account':'operator','username_selector':'#user',
            'password_selector':'#pass','submit_selector':'#login','success_selector':'#main'}
        seconds=600 if manual else 120
        deadline=int((time.time()+seconds)*1000)
        worker=subprocess.Popen([node,'--use-system-ca',str(PLUGIN/'scripts/web_site_worker.mjs'),str(directory),
            str(PLUGIN/'scripts/web-runtime/node_modules/playwright-core')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,env=web_adapter._environment())
        job=execution._WindowsJob(worker,memory_limit_mb=None,cpu_time_seconds=None,max_processes=None)
        assert job.assigned
        channel=Channel(worker,job,profile='synthetic-site',requester='synthetic-site',resource='web:'+'1'*64,deadline=deadline,config=cfg)
        binding={'origin':cfg['origin'],'account':'operator','profile':'synthetic-site','session':uuid.uuid4().hex,
            'worker':uuid.uuid4().hex,'acquisition':uuid.uuid4().hex,'profile_digest':'a'*64,'deadline':time.monotonic()+seconds}
        prompts=[]
        class SyntheticPrompt:
            @staticmethod
            def start(manifest,**callbacks):
                assert 'synthetic-site-password-only' not in json.dumps(manifest)
                prompts.append((manifest,callbacks));return SyntheticPrompt()
            def stop(self,reason='stopped'): pass
            def status(self):return {'state':'shown','shown':True,'review_remaining_seconds':180}
        from web_approval import ApprovalPrompt
        assert upgrade_protocol(tmp_path/'audit',check_idle=lambda:True,confirm=True)['ready']
        service=SiteService(channel,binding=binding,check=lambda:copy.deepcopy(binding),
            journal=Journal(tmp_path/'audit'),prompt=ApprovalPrompt if manual else SyntheticPrompt)
        worker.stdin.write((json.dumps({'config':cfg,'username':'operator','password':'synthetic-site-password-only',
            'deadline':deadline,'authorization_mode':'site'})+'\n').encode());worker.stdin.flush();channel.start()
        service.begin()
        def stats():
            server.stdin.write(b'{"id":1,"operation":"stats"}\n');server.stdin.flush()
            return json.loads(server.stdout.readline())['result']
        assert stats()['logins']==0
        if manual:
            manifest=service.manifests[service.request_id]
            print('REMOTEX_SITE_REVIEW '+json.dumps({'digest':manifest['request_digest'][:8],
                'origin':cfg['origin'],'account':'operator','scope':'Synthetic loopback only; one Allow Automation click; fake login, read, fill and one save',
                **service.status().get('approval_ui',{})}),flush=True)
            until=time.monotonic()+180
            while time.monotonic()<until and service.status()['state']=='pending':time.sleep(.1)
            assert service.status()['state']=='active', 'Native site approval did not become active'
        else:
            manifest,callbacks=prompts[0]
            callbacks['on_decision']({'nonce':manifest['nonce'],'request_digest':manifest['request_digest'],
                'choices':[{'item_id':'site','max_uses':1,'targets':[]}],'ttl_seconds':100})
        until=time.monotonic()+55
        while time.monotonic()<until and not service.status()['login']['authenticationVerified']:time.sleep(.1)
        assert service.status()['login']['authenticationVerified'],service.status()
        assert len(service.manifests)==1
        def act(name,action,value=None):
            snapshot=service.components()
            candidates=[row for row in snapshot['components'] if row['id']==name]
            assert len(candidates)==1
            args={'observation_id':snapshot['observationId'],'component_ref':candidates[0]['ref'],
                'action':action,'risk':'ordinary','idempotency_key':uuid.uuid4().hex}
            if value is not None:args['value']=value
            return service.execute(args),args
        read,_=act('main','read')
        assert 'Synthetic Site Center' in read['result']['text']
        filled,_=act('group','fill','new-group');assert filled['state']=='completed'
        saved,args=act('save','click');assert saved['state']=='completed'
        assert service.execute(args)==saved
        until=time.monotonic()+5
        while time.monotonic()<until and stats()['writes']!=1:time.sleep(.1)
        actual=stats()
        assert actual=={'initialization':1,'logins':1,'writes':1,'credentialOutsideLogin':False,'wrongLogin':False}
        read,_=act('main','read');assert 'Saved new-group' in read['result']['text']
        assert len(service.manifests)==1
        service.revoke({'end_task':True});assert not channel.available
    finally:
        if channel:channel.close()
        if worker:
            try:worker.wait(timeout=10)
            except subprocess.TimeoutExpired:worker.kill();worker.wait(timeout=10)
        if job:job.close()
        server.stdin.write(b'{"operation":"stop"}\n');server.stdin.flush()
        try:server.wait(timeout=10)
        except subprocess.TimeoutExpired:server.kill();server.wait(timeout=10)
