from __future__ import annotations
import copy
import json
import subprocess
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).parent))
from test_web_task_service import prepared, approve
from web_authorization import ScopeError

def prepared_replacement():
    service,channel,prompts=prepared();calls=[];instances=[]
    script="""import {setupContracts} from './plugins/remotex/scripts/web_task_contracts.mjs';
      const proof=[{kind:'operator-inspected',reference:'Synthetic static resource only'}];
      const resolve=path=>setupContracts({revision:2,phase:'bootstrap',requests:[{network_ref:'b'.repeat(32),
        purpose:'bootstrap-resource',max_uses:4,evidence:proof}]},{phase:'bootstrap',preauthLifecycle:'a'.repeat(32),
        resolve:()=>({method:'GET',path,query:{},contentType:'',body:null,resourceType:path==='/'?'document':'script'})});
      console.log(JSON.stringify([resolve('/'),resolve('/app.js')]));"""
    values=json.loads(subprocess.run(['node','--input-type=module','-e',script],cwd=Path(__file__).resolve().parents[3],
        capture_output=True,text=True,timeout=10,check=True).stdout)
    class Prompt:
        def __init__(self,callbacks):self.callbacks=callbacks;self.reason=None
        @classmethod
        def start(cls,manifest,**callbacks):
            prompts.append((manifest,callbacks));value=cls(callbacks);instances.append(value);return value
        def stop(self,reason='stopped'):
            self.reason=reason;self.callbacks['on_revoke']()
        def status(self):
            return {'state':'shown','shown':True,'review_remaining_seconds':120,
                'exit_reason':self.reason,'error_code':None,'helper_exit_code':None}
    service.prompt=Prompt
    original=channel.request
    def worker(operation,args,**kwargs):
        calls.append(operation)
        if operation=='resolve-setup':
            value=copy.deepcopy(values[1 if args['setup'].get('replace_grant_ids') else 0])
            value['replace_grant_ids']=args['setup'].get('replace_grant_ids',[])
            return value
        if operation in {'hold-setup','release-setup'}:
            return {'ok':True,'held':operation=='hold-setup'}
        return original(operation,args,**kwargs)
    channel.request=worker
    service.request({'setup':{'revision':2},'idempotency_key':'root'})
    source=approve(service,prompts)
    return service,channel,prompts,instances,calls,source

def test_pending_replacement_blocks_resume_and_success_retires_old_helper_before_its_callback():
    service,channel,prompts,instances,calls,source=prepared_replacement()
    request=service.request({'setup':{'revision':2,'replace_grant_ids':[source['grant_id']]},'idempotency_key':'swap'})
    assert calls.count('hold-setup')==1
    with pytest.raises(ScopeError,match='replacement-pending'):service._worker('resume-login',{})
    result=approve(service,prompts)
    assert result['grant_state']=='active'
    assert instances[0].reason=='grant-replaced'
    assert service.broker.status(result['request_id'])['grant_state']=='active'
    assert calls[-1]=='release-setup'
    assert not service.broker.replacement_pending()

def test_omitting_carried_row_closes_only_failed_new_helper_and_keeps_source():
    service,channel,prompts,instances,calls,source=prepared_replacement()
    request=service.request({'setup':{'revision':2,'replace_grant_ids':[source['grant_id']]},'idempotency_key':'swap'})
    manifest,callbacks=prompts[-1]
    row=next(r for r in manifest['items'] if not r['item_id'].startswith('carry.'))
    result=callbacks['on_decision']({'nonce':manifest['nonce'],'request_digest':manifest['request_digest'],
        'choices':[{'item_id':row['item_id'],'max_uses':row['max_uses'],'targets':[],
            'semantic_classification':'bootstrap'}],'ttl_seconds':30})
    assert result['grant_id'] is None
    assert instances[0].reason is None
    assert service.broker.status(source['request_id'])['grant_state']=='active'
    assert result['failure_code']=='replacement-incomplete'
    assert calls[-1]=='release-setup'

def test_a_running_original_resume_is_not_interrupted_to_make_replacement_possible():
    service,channel,prompts,instances,calls,source=prepared_replacement()
    ticket=service.startup.begin(lifecycle='a'*32,session_deadline_ms=channel.deadline)
    before=list(calls)
    with pytest.raises(ScopeError,match='operation-in-progress'):
        service.request({'setup':{'revision':2,'replace_grant_ids':[source['grant_id']]},'idempotency_key':'swap'})
    assert calls==before
    assert instances[0].reason is None
    service.startup.end(ticket['resume_id'])
