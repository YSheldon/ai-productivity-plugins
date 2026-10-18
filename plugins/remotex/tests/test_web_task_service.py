from __future__ import annotations

import copy
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_web_authorization import MemoryJournal, item


def prepared():
    import web_task_service
    binding = {'origin':'https://console.example', 'account':'operator', 'profile':'lab',
               'session':'a'*32, 'worker':'worker-1', 'acquisition':'b'*32,
               'profile_digest':'c'*64, 'deadline':1000.0}
    prompts = []
    class Channel:
        available = True
        deadline = int(time.time() * 1000) + 900000
        def close(self):
            self.available = False
        def request(self, operation, args, timeout=30):
            if operation == 'resolve-items':
                return {'ok':True, 'items':[item()], 'contracts':{}}
            if operation == 'execute':
                assert self.authorize({'kind':'action', 'attempt_id':args['attempt_id'], 'consume':False})
                return {'ok':True, 'state':'verified', 'summary':{'count':1}, 'result':{'rows':[['Linux']]}, 'forwarded':0}
            return {'ok':True, 'descriptors':[]}
    class Prompt:
        @staticmethod
        def start(manifest, **callbacks):
            prompts.append((manifest, callbacks))
            return Prompt()
        def stop(self):
            pass
        def status(self):
            return {'state':'starting','shown':False,'review_remaining_seconds':120,
                    'exit_reason':None,'error_code':None,'helper_exit_code':None}
    channel = Channel()
    service = web_task_service.Service(channel, binding=binding, check=lambda:copy.deepcopy(binding),
        journal=MemoryJournal(), prompt=Prompt, clock=lambda:100.0)
    return service, channel, prompts


def approve(service, prompts):
    manifest, callbacks = prompts[-1]
    choices=[]
    for row in manifest['items']:
        choice={'item_id':row['item_id'],'max_uses':row['max_uses'],'targets':row['targets']}
        review=row['parameters'].get('review_kind')
        if review:
            choice['semantic_classification']='read' if review=='unclassified' else review
        choices.append(choice)
    return callbacks['on_decision']({'nonce':manifest['nonce'], 'request_digest':manifest['request_digest'],
        'choices':choices,
        'ttl_seconds':60})


def test_only_resume_login_uses_the_reviewed_55_second_budget(monkeypatch):
    import web_task_service
    service,channel,_=prepared()
    monkeypatch.setattr(web_task_service.time,'time',lambda:1000.0)
    channel.deadline=1_100_000
    calls=[]
    def worker(operation,args,timeout=30):
        calls.append((operation,timeout))
        return {'ok':True,'authenticationVerified':False}
    channel.request=worker
    service._worker('resume-login',{})
    service._worker('components',{})
    assert calls==[('resume-login',55),('components',30)]


def test_resume_wait_is_capped_by_the_existing_session_deadline(monkeypatch):
    import web_task_service
    service,channel,_=prepared()
    monkeypatch.setattr(web_task_service.time,'time',lambda:1000.0)
    channel.deadline=1_002_000
    calls=[]
    channel.request=lambda operation,args,timeout=30:calls.append(timeout) or {'ok':True}
    service._worker('resume-login',{})
    assert calls==[2.0]


def test_expired_session_cannot_emit_a_new_resume_command(monkeypatch):
    import web_task_service
    service,channel,_=prepared()
    monkeypatch.setattr(web_task_service.time,'time',lambda:1000.0)
    channel.deadline=999_000
    calls=[]
    channel.request=lambda *args,**kwargs:calls.append(args) or {'ok':True}
    with pytest.raises(ValueError,match='session-unavailable'):
        service._worker('resume-login',{})
    assert calls==[]


def static_prepared():
    service,channel,prompts=prepared()
    descriptors=[{'method':'GET','path':f'/assets/{index}.js','query':{},'contentType':'',
        'body':None,'resourceType':'script'} for index in range(15)]
    rows=[{**item(f'static.{index}'),'capability':'web.page_step',
        'parameters':{'network_ref':f'static.{index}','review_kind':'bootstrap'},
        'output':{'rows':0,'columns':0,'bytes':0}} for index in range(15)]
    contracts={f'static.{index}':{'phase':'bootstrap','semantics':'bootstrap',
        'descriptor':descriptor,'targets':[]} for index,descriptor in enumerate(descriptors)}
    original=channel.request
    channel.request=lambda operation,args:({'ok':True,'items':rows,'contracts':contracts}
        if operation=='resolve-items' else original(operation,args))
    service.request({'items':[{}],'idempotency_key':'static-many'})
    grant=approve(service,prompts)
    return service,channel,descriptors,grant


def test_competing_startup_descriptors_do_not_spend_the_budget_rechecking_unmatched_grants():
    service,_,descriptors,_=static_prepared()
    now=[100.0]
    service.broker.clock=lambda:now[0]
    original=service.broker.check
    def binding_read():
        now[0]+=0.1
        return original()
    service.broker.check=binding_read
    def permit(descriptor):
        return service.channel.authorize({'kind':'network','phase':'bootstrap','attempt_id':None,
            'descriptor':descriptor,'digest':'e'*64})
    unknown=[{**descriptors[0],'path':f'/unapproved/{index}.js'} for index in range(32)]
    assert [permit(descriptor) for descriptor in unknown]==[False]*32
    results=[permit(descriptor) if now[0]-100<45 else False for descriptor in descriptors]
    assert results==[True]*15,'unmatched contracts must not consume the finite startup waiting budget'
    assert sum(row['event']=='execution-finished' for row in service.broker.journal.events)==15


@pytest.mark.parametrize('matching',[False,True])
def test_startup_descriptor_filter_still_checks_current_binding_before_any_decision(matching):
    service,channel,descriptors,_=static_prepared()
    original=service.broker.check
    service.broker.check=lambda:{**original(),'account':'changed-account'}
    descriptor=descriptors[0] if matching else {**descriptors[0],'path':'/unapproved.js'}
    assert channel.authorize({'kind':'network','phase':'bootstrap','attempt_id':None,
        'descriptor':descriptor,'digest':'e'*64}) is False
    assert channel.available is False


def test_no_approve_api_and_no_execution_before_native_decision():
    service, channel, prompts = prepared()
    request = service.request({'items':[{}], 'idempotency_key':'first'})
    assert request['state'] == 'pending'
    with pytest.raises(ValueError, match='approval-required'):
        service.execute({'grant_id':request['request_id'], 'item_id':'read', 'idempotency_key':'run',
            'observation_id':'d'*32, 'component_ref':'e'*32})
    grant = approve(service, prompts)
    result = service.execute({'grant_id':grant['grant_id'], 'item_id':'read', 'idempotency_key':'run',
        'observation_id':'d'*32, 'component_ref':'e'*32})
    assert result['result']['rows'] == [['Linux']]
    assert result['state'] == 'verified'
    assert not hasattr(service, 'approve')


def test_closing_native_grant_window_revokes_only_its_grant_when_idle():
    service, channel, prompts = prepared()
    service.request({'items':[{}], 'idempotency_key':'first'})
    grant=approve(service, prompts)
    prompts[-1][1]['on_revoke']()
    assert not service.broker.fenced.is_set()
    assert channel.available
    with pytest.raises(ValueError,match='grant-revoked'):
        service.broker.reserve(grant['grant_id'],'read','revoked',{})


def test_unknown_network_and_old_attempt_cannot_forward():
    service, channel, prompts = prepared()
    assert channel.authorize({'kind':'network', 'phase':'grant-active', 'attempt_id':'a'*32,
        'descriptor':{'method':'POST', 'path':'/tasks'}, 'digest':'b'*64}) is False
    service.request({'items':[{}], 'idempotency_key':'first'})
    grant = approve(service, prompts)
    run = service.execute({'grant_id':grant['grant_id'], 'item_id':'read', 'idempotency_key':'run',
        'observation_id':'d'*32, 'component_ref':'e'*32})
    assert not channel.authorize({'kind':'action', 'attempt_id':run['attempt_id'], 'consume':False})


def test_duplicate_execute_returns_receipt_without_replaying_worker():
    service, channel, prompts = prepared()
    service.request({'items':[{}], 'idempotency_key':'first'})
    grant = approve(service, prompts)
    args = {'grant_id':grant['grant_id'], 'item_id':'read', 'idempotency_key':'run',
        'observation_id':'d'*32, 'component_ref':'e'*32}
    first = service.execute(args)
    def no_replay(*_):
        raise AssertionError('A completed attempt was replayed')
    channel.request = no_replay
    assert service.execute(args)['attempt_id'] == first['attempt_id']


def test_network_subitem_requires_own_approval_exact_payload_and_active_parent():
    service, channel, prompts = prepared()
    descriptor={'method':'POST','path':'/query','body':{'cmd':'inventory'},'query':{},'contentType':'application/json'}
    net={**item('read.network.1'),'capability':'web.page_step','parameters':{'network_ref':'read.network.1','review_kind':'unclassified'}}
    original=channel.request
    seen=[]
    def worker(operation,args):
        if operation=='resolve-items':
            return {'ok':True,'items':[item(),net], 'contracts':{'read.network.1':{
                'parent_id':'read','phase':'grant-active','semantics':'unclassified','descriptor':descriptor,'targets':[]}}}
        if operation=='execute':
            request={'kind':'network','phase':'grant-active','attempt_id':args['attempt_id'],
                'descriptor':descriptor,'digest':'e'*64}
            seen.append(channel.authorize({**request,'descriptor':{**descriptor,'path':'/mutate'}}))
            seen.append(channel.authorize(request))
            seen.append(channel.authorize(request))
            seen.append(channel.authorize(request))
        return original(operation,args)
    channel.request=worker
    service.request({'items':[{}],'idempotency_key':'batch'})
    grant=approve(service,prompts)
    assert not channel.authorize({'kind':'network','phase':'grant-active','attempt_id':None,
        'descriptor':descriptor,'digest':'e'*64})
    service.execute({'grant_id':grant['grant_id'],'item_id':'read','idempotency_key':'run',
        'observation_id':'d'*32,'component_ref':'e'*32})
    assert seen==[False,True,True,False]


def test_partial_targets_narrow_the_real_request_and_block_unapproved_objects():
    service,channel,prompts=prepared()
    write=item('move',write=True,targets=['host-one','host-two'])
    net={**item('move.network.1'),'capability':'web.page_step','parameters':{'network_ref':'move.network.1','review_kind':'write'}}
    descriptor={'method':'POST','path':'/dispatch','query':{},'contentType':'application/json',
        'body':{'cmd':'move','ids':['host-one','host-two'],'group':'New Group'}}
    seen=[]
    def worker(operation,args):
        if operation=='resolve-items':
            return {'ok':True,'items':[write,net],'contracts':{'move.network.1':{'parent_id':'move',
                'phase':'grant-active','semantics':'write','targets':['host-one','host-two'],
                'descriptor':descriptor,'target_path':['body','ids'],'change_paths':{'group':['body','group']}}}}
        if operation=='execute':
            message={'kind':'network','phase':'grant-active','attempt_id':args['attempt_id'],'descriptor':descriptor,'digest':'e'*64}
            seen.append(channel.authorize(message))
            seen.append(channel.authorize({**message,'descriptor':{**descriptor,'body':{**descriptor['body'],'ids':['host-one']}}}))
            seen.append(channel.authorize({**message,'descriptor':{**descriptor,'body':{**descriptor['body'],'ids':['host-two']}}}))
            return {'ok':True,'state':'partial','summary':{'target_count':1},'result':{},'forwarded':1}
        return {'ok':True,'descriptors':[]}
    channel.request=worker
    service.request({'items':[{}],'idempotency_key':'partial'})
    manifest,callbacks=prompts[-1]
    grant=callbacks['on_decision']({'nonce':manifest['nonce'],'request_digest':manifest['request_digest'],
        'choices':[{'item_id':'move','max_uses':1,'targets':['host-one']},
                   {'item_id':'move.network.1','max_uses':1,'targets':[],'semantic_classification':'write'}],'ttl_seconds':60})
    service.execute({'grant_id':grant['grant_id'],'item_id':'move','idempotency_key':'move-once',
        'observation_id':'d'*32,'component_ref':'e'*32})
    assert seen==[False,True,False]
    assert service.broker.journal.pending


def test_unknown_write_is_resolved_only_by_owned_worker_readback_not_a_model_claim():
    service,channel,prompts=prepared()
    write=item('move',write=True,targets=['host-one'])
    def worker(operation,args):
        if operation=='resolve-items':
            return {'ok':True,'items':[write],'contracts':{}}
        if operation=='execute':
            service.dispatched.add(args['attempt_id'])
            return {'ok':True,'state':'partial','summary':{},'result':{},'forwarded':1}
        if operation=='reconcile':
            assert args['read_receipts']==['f'*32]
            assert args['scope']==write
            return {'ok':True,'state':'verified','summary':{'count':1},
                'targets':[{'identity':'host-one','state':'verified'}]}
    channel.request=worker
    service.request({'items':[{}],'idempotency_key':'recovery'})
    grant=approve(service,prompts)
    attempt=service.execute({'grant_id':grant['grant_id'],'item_id':'move','idempotency_key':'once',
        'observation_id':'d'*32,'component_ref':'e'*32})
    assert service.broker.journal.pending
    with pytest.raises(ValueError,match='request-invalid'):
        service.execution_status({'attempt_id':attempt['attempt_id'],'success':True})
    result=service.execution_status({'attempt_id':attempt['attempt_id'],'read_receipts':['f'*32]})
    assert result['state']=='verified'
    assert not service.broker.journal.pending
