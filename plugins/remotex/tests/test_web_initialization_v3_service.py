"""Synthetic original Service integration, not human/native acceptance."""
import copy
import base64
import json
from pathlib import Path
import subprocess
import sys

import pytest

PLUGIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PLUGIN/'src'))
sys.path.insert(0,str(PLUGIN/'tests'))
from remotex_v3_support import independent_native_input
from web_initialization_v3 import validate_setup_context_v3
from web_authorization import ScopeError
from test_web_task_service import prepared

def resolved_v3():
    script="""
import {setupContracts} from './scripts/web_task_contracts.mjs';
import {sampleCapture,parseTree} from './tests/fixtures/v3_test_support.mjs';
const refs=Array.from({length:5},(_,i)=>(i+1).toString(16).padStart(32,'0'));
const capture=sampleCapture({origin:'https://console.example'});
const setup={revision:3,phase:'bootstrap',requests:[{network_ref:'b'.repeat(32),representation_ref:'c'.repeat(32),
literal_review_refs:refs,purpose:'initialization-read',max_uses:2,evidence:[{kind:'verified-record',reference:'independent-fixture-source'}],
response_checks:[{pointer:'/ready',test:'equals-boolean',expected:true}]}]};
const network={phase:'bootstrap',preauthLifecycle:'a'.repeat(32),parseTree,
resolveV3:()=>({capture,profile_id:'json-utf8-v1',representation_ref:'c'.repeat(32),literal_review_refs:refs})};
process.stdout.write(JSON.stringify({resolved:setupContracts(setup,network),setup}));
"""
    result=subprocess.run(['node','--input-type=module','-e',script],cwd=PLUGIN,capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    value=json.loads(result.stdout)
    return value['resolved'],value['setup']

def test_real_worker_v3_context_has_independent_supervisor_validation_and_safe_scope():
    value,setup=resolved_v3()
    result=validate_setup_context_v3(value,{'origin':'https://console.example'},setup)
    assert result['context']['revision']==3
    assert result['context']['prerequisites']==value['prerequisites']
    assert result['captures']==value['private_initialization']
    assert 'body_b64' not in json.dumps(result['context'])
    assert result['locators']['setup.network.1']['intent_ref']=='c'*32

@pytest.mark.parametrize('field',['descriptor','public_invariant','native_input','headers'])
def test_private_worker_cannot_smuggle_capture_or_verdict_into_public_contract(field):
    value,setup=resolved_v3();value['contracts']['setup.network.1'][field]={'private':'canary'}
    with pytest.raises(ScopeError):validate_setup_context_v3(value,{'origin':'https://console.example'},setup)

def test_worker_resolution_cannot_substitute_requested_checks_refs_or_wire_origin():
    value,setup=resolved_v3()
    for change in ['checks','refs','origin','fingerprint','preview','duplicate-preview']:
        altered=copy.deepcopy(value)
        if change=='checks':altered['contracts']['setup.network.1']['response_checks'][0]['expected']=False
        if change=='refs':altered['contracts']['setup.network.1']['literal_review_refs'][0]='f'*32
        if change=='origin':altered['private_initialization']['setup.network.1']['origin']='https://foreign.example'
        if change=='fingerprint':altered['items'][0]['fingerprint']='0'*64
        if change=='preview':altered['items'][0]['display']['preview']='{"body":"private-canary"}'
        if change=='duplicate-preview':
            altered['items'][0]['display']['preview']=altered['items'][0]['display']['preview'].replace('"required":true','"required":"private-canary","required":true')
        with pytest.raises(ScopeError):validate_setup_context_v3(altered,{'origin':'https://console.example'},setup)

def service_case():
    value,setup=resolved_v3();service,channel,prompts=prepared();original=channel.request;calls=[]
    def request(operation,args,**options):
        calls.append(operation)
        if operation=='resolve-setup':return copy.deepcopy(value)
        if operation in {'hold-setup','release-setup'}:return {'ok':True,'held':operation=='hold-setup'}
        return original(operation,args,**options)
    channel.request=request
    result=service.request({'setup':setup,'idempotency_key':'v3-original-service'})
    return service,channel,prompts,value,result,calls

def compare_and_decide(service,prompts,*,decide=True):
    manifest,callbacks=prompts[-1]
    frame={'event':'reference-check','request_id':manifest['request_id'],'nonce':manifest['nonce'],
        'request_digest':manifest['request_digest'],'check_id':'f'*32,'item_id':'setup.network.1',
        'edit_revision':1,'native_input':independent_native_input()}
    proof=callbacks['on_reference'](frame)
    assert proof['code']=='ready'
    choice={'item_id':'setup.network.1','max_uses':2,'targets':[],'semantic_classification':'initialization-read',
        'review_ref':proof['review_ref'],'edit_revision':1}
    decision={'event':'decision','request_id':manifest['request_id'],'nonce':manifest['nonce'],
        'request_digest':manifest['request_digest'],'choices':[choice],'ttl_seconds':60}
    return callbacks['on_decision'](decision) if decide else decision

def test_original_service_keeps_native_comparison_approval_and_resume_separate():
    service,channel,prompts,value,result,calls=service_case()
    assert result['state']=='pending' and not service.broker.grants
    manifest,callbacks=prompts[-1]
    assert manifest['protocol_revision']==3 and len(manifest['reference_items'][0]['locations'])==5
    assert service.setup_hold and 'release-setup' not in calls
    forged={'nonce':manifest['nonce'],'request_digest':manifest['request_digest'],'ttl_seconds':60,
        'choices':[{'item_id':'setup.network.1','max_uses':2,'targets':[],'semantic_classification':'initialization-read'}]}
    with pytest.raises(ScopeError,match='decision-invalid'):callbacks['on_decision'](forged)
    decision=compare_and_decide(service,prompts,decide=False)
    assert not service.broker.grants and service.setup_hold
    with pytest.raises(ScopeError,match='replacement-pending'):service._worker('resume-login',{})
    grant=callbacks['on_decision'](decision)
    assert grant['grant_state']=='active' and not service.setup_hold and calls[-1]=='release-setup'
    assert 'body_b64' not in json.dumps({key:row['setup_context'] for key,row in service.broker.requests.items()})

    capture=value['private_initialization']['setup.network.1']
    message={'kind':'network','version':3,'phase':'bootstrap','attempt_id':None,'capture':capture,
        'startup':{'preauth_lifecycle':'a'*32,'resume_id':'b'*32,'document_id':'d'*32,'generation':0}}
    assert channel.authorize_network(message,'e'*32) is False
    ticket=service.startup.begin(lifecycle='a'*32,session_deadline_ms=2_000_000_000_000)
    base={'resume_id':ticket['resume_id'],'preauth_lifecycle':'a'*32,'document_id':'d'*32,
        'phase':'bootstrap','generation':0,'authentication_forwarded':0}
    assert service._startup_event({**base,'kind':'document-opening'})
    assert service._startup_event({**base,'kind':'document-committed'})
    message['startup']={k:base[k] for k in ('preauth_lifecycle','resume_id','document_id','generation')}
    altered=copy.deepcopy(message);altered['capture']['body_b64']=base64.b64encode(b'{"mode":"privat"}').decode()
    assert channel.authorize_network(altered,'c'*32) is False
    assert service.broker.status(grant['request_id'])['remaining']['setup.network.1']==2
    reply=channel.authorize_network(message,'e'*32)
    assert reply['allowed'] is True and reply['permit']['kind']=='initialization-permit-v3'
    assert service._authorize(message) is False
    assert service.broker.status(grant['request_id'])['remaining']['setup.network.1']==1
    assert service._startup_event({**base,'kind':'initialization-forwarded','check_id':'e'*32,
        'prerequisite_id':reply['permit']['prerequisite_id']})
    assert service._startup_event({**base,'kind':'prerequisite-response','check_id':'e'*32,
        'prerequisite_id':reply['permit']['prerequisite_id'],'ready':True})
    assert service.startup.status()['ready']==1
    assert 'body_b64' not in json.dumps(service.broker.journal.events)

def test_v3_durable_commit_cannot_publish_after_original_review_deadline():
    service,_,prompts,_,result,_=service_case()
    decision=compare_and_decide(service,prompts,decide=False)
    decision['ttl_seconds']=300
    now=[100.0]
    service.broker.clock=lambda:now[0];service.initialization_v3.clock=lambda:now[0]
    append=service.broker.journal.append
    def delayed(event):
        append(event)
        if event['event']=='grant-issued':now[0]=281.0
    service.broker.journal.append=delayed
    with pytest.raises(ScopeError):prompts[-1][1]['on_decision'](decision)
    assert not service.broker.grants and not service.initialization_v3.grants
    assert service.broker.status(result['request_id'])['grant_state'] is None


def issued_service():
    service,channel,prompts,value,request,calls=service_case()
    grant=compare_and_decide(service,prompts)
    ticket=service.startup.begin(lifecycle='a'*32,session_deadline_ms=2_000_000_000_000)
    base={'resume_id':ticket['resume_id'],'preauth_lifecycle':'a'*32,'document_id':'d'*32,
        'phase':'bootstrap','generation':0,'authentication_forwarded':0}
    assert service._startup_event({**base,'kind':'document-opening'})
    assert service._startup_event({**base,'kind':'document-committed'})
    message={'kind':'network','version':3,'phase':'bootstrap','attempt_id':None,
        'capture':value['private_initialization']['setup.network.1'],
        'startup':{k:base[k] for k in ('preauth_lifecycle','resume_id','document_id','generation')}}
    reply=channel.authorize_network(message,'e'*32)
    assert reply['allowed'] is True
    return service,channel,grant,base,reply['permit']


@pytest.mark.parametrize('partial',[False,True])
def test_api_revoke_fences_already_issued_initialization_not_in_execute(partial):
    service,channel,grant,base,permit=issued_service()
    assert not service.executing
    args={'grant_id':grant['grant_id']}
    if partial:args['items']=['setup.network.1']
    result=service.revoke(args)
    assert result['session_closed'] is True and channel.available is False
    assert not service._startup_event({**base,'kind':'initialization-forwarded','check_id':'e'*32,
        'prerequisite_id':permit['prerequisite_id']})
    assert service.startup.status()['ready']==0


def test_api_cancel_releases_private_pending_plan_and_owned_hold_immediately():
    service,_,prompts,_,request,calls=service_case()
    result=service.revoke({'request_id':request['request_id']})
    assert result['state']=='cancelled'
    assert request['request_id'] not in service.initialization_v3.plans
    assert not service.setup_hold and calls[-1]=='release-setup'


def test_expired_v3_grant_cannot_make_a_delayed_response_ready():
    service,channel,grant,base,permit=issued_service()
    assert service._startup_event({**base,'kind':'initialization-forwarded','check_id':'e'*32,
        'prerequisite_id':permit['prerequisite_id']})
    service.broker.clock=lambda:161.0
    assert not service._startup_event({**base,'kind':'prerequisite-response','check_id':'e'*32,
        'prerequisite_id':permit['prerequisite_id'],'ready':True})
    assert channel.available is False and service.startup.status()['ready']==0
