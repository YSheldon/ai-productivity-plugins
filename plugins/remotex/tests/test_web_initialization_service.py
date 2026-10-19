from __future__ import annotations
import copy
import io
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).parent))
from test_web_task_service import prepared, approve
from web_authorization import ScopeError
import web_channel
import web_initialization

def resolved():
    script="""import {setupContracts} from './plugins/remotex/scripts/web_task_contracts.mjs';
const descriptor={method:'POST',path:'/init',query:{},contentType:'application/json',body:{cmd:'info'},resourceType:'xhr'};
console.log(JSON.stringify(setupContracts({revision:2,phase:'bootstrap',requests:[{network_ref:'b'.repeat(32),
purpose:'initialization-read',evidence:[{kind:'source-review',reference:'Synthetic reviewed handler'}],
response_checks:[{pointer:'/exist',test:'equals-boolean',expected:true}]}]},
{phase:'bootstrap',preauthLifecycle:'a'.repeat(32),resolve:()=>descriptor})));"""
    result=subprocess.run(['node','--input-type=module','-e',script],cwd=Path(__file__).resolve().parents[3],
        capture_output=True,text=True,check=True,timeout=10)
    return json.loads(result.stdout)

def setup_service(value):
    service,channel,prompts=prepared()
    original=channel.request
    channel.request=lambda operation,args,**kw:copy.deepcopy(value) if operation=='resolve-setup' else original(operation,args,**kw)
    return service,channel,prompts

def test_real_worker_normalization_is_independently_accepted_by_supervisor():
    value=resolved();context=web_initialization.validate_setup_context(value,{'origin':'https://console.example'})
    assert context['revision']==2
    assert context['prerequisites']==value['prerequisites']

def test_forged_setup_semantics_are_rejected_before_a_native_proposal():
    value=resolved();value['contracts']['setup.network.1']['semantics']='bootstrap'
    service,_,prompts=setup_service(value)
    with pytest.raises(ScopeError):service.request({'setup':{'revision':2},'idempotency_key':'forged'})
    assert prompts==[]

def test_native_init_grant_still_needs_original_resume_context_and_typed_pipe():
    value=resolved();service,channel,prompts=setup_service(value)
    service.request({'setup':{'revision':2},'idempotency_key':'init'})
    grant=approve(service,prompts)
    assert grant['grant_state']=='active'
    assert callable(getattr(channel,'authorize_network',None))
    contract=value['contracts']['setup.network.1']
    message={'kind':'network','phase':'bootstrap','attempt_id':None,'descriptor':contract['descriptor'],
             'digest':web_initialization.wire_digest(contract['descriptor'])}
    assert channel.authorize_network(message,'c'*32) is False
    ticket=service.startup.begin(lifecycle='a'*32,session_deadline_ms=2_000_000_000_000)
    base={'resume_id':ticket['resume_id'],'preauth_lifecycle':'a'*32,'document_id':'d'*32,
        'phase':'bootstrap','generation':0,'authentication_forwarded':0}
    service._startup_event({**base,'kind':'document-opening'})
    service._startup_event({**base,'kind':'document-committed'})
    message['startup']={key:base[key] for key in ['resume_id','preauth_lifecycle','document_id','generation']}
    reply=channel.authorize_network(message,'c'*32)
    assert reply['allowed'] is True
    assert reply['permit']['kind']=='initialization-read'
    assert service._authorize(message) is False
    assert service.broker.status(grant['request_id'])['remaining']['setup.network.1']==1

def test_private_channel_preserves_check_id_on_typed_network_reply():
    request={'kind':'network'}
    source=io.BytesIO((json.dumps({'event':'authorization-check','id':'a'*32,'request':request})+'\n').encode())
    process=mock.Mock(stdout=source,stdin=io.BytesIO(),poll=lambda:None)
    channel=web_channel.Channel(process,mock.Mock(),profile='p',requester='r',resource='q',deadline=1,config={})
    seen=[]
    def authorize(value,check_id):
        seen.append((value,check_id));return {'allowed':True,'permit':{'kind':'initialization-read'}}
    channel.authorize_network=authorize
    channel._read()
    frames=[json.loads(line) for line in process.stdin.getvalue().splitlines()]
    assert seen==[(request,'a'*32)]
    assert frames==[{'authorization_reply':'a'*32,'allowed':True,'permit':{'kind':'initialization-read'}}]
