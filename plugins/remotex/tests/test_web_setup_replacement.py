from __future__ import annotations
import copy
import sys
import threading
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).parent))
from test_web_authorization import prepared, item
from web_authorization import ScopeError

def resource(name='root',uses=4):
    return {**item(name),'capability':'web.page_step','max_uses':uses,
        'parameters':{'network_ref':name,'review_kind':'bootstrap'},'output':{'rows':0,'columns':0,'bytes':0}}

def context(rows):
    return {'revision':2,'preauth_lifecycle':'a'*32,'phase_applicability':['bootstrap','login-once'],
        'prerequisites':[],'contracts':{row['item_id']:{'revision':2,'purpose':'bootstrap-resource',
          'semantics':'bootstrap','phase':'bootstrap','phase_applicability':['bootstrap','login-once'],
          'preauth_lifecycle':'a'*32,'parent_id':None,'targets':[],'required':False,
          'response_checks':[],'prerequisite_id':None,'descriptor':{'method':'GET',
          'path':'/' if row['item_id']=='root' else '/'+row['item_id']+'.js','query':{},'contentType':'',
          'body':None,'resourceType':'document' if row['item_id']=='root' else 'script'}} for row in rows}}

def decide(broker,request,*,choose=None,ttl=None):
    manifest=broker.approval_manifest(request['request_id'])
    rows=manifest['items'] if choose is None else [row for row in manifest['items'] if choose(row)]
    return broker.accept_decision(request['request_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],
        choices=[{'item_id':r['item_id'],'max_uses':r['max_uses'],'targets':[],
                  'semantic_classification':'bootstrap'} for r in rows],
        ttl_seconds=ttl or min(300,manifest['ttl_seconds']))

def original(broker,rows=None,key='source',ttl=300):
    rows=rows or [resource()]
    return decide(broker,broker.request(rows,idempotency_key=key,ttl_seconds=ttl,setup_context=context(rows)),ttl=ttl)

def replace(broker,ids,rows=None,key='replace'):
    rows=rows or [resource('new')]
    return broker.request(rows,idempotency_key=key,ttl_seconds=43200,
        setup_context=context(rows),replacement_source_ids=ids)

def test_replacement_carries_remaining_uses_and_earliest_source_deadline(prepared):
    broker,clock,*_=prepared;source=original(broker)
    approved=broker.grants[source['grant_id']]['items']['root']
    broker.consume_static_network(source['grant_id'],'root',approved['parameters'])
    request=replace(broker,[source['grant_id']]);manifest=broker.approval_manifest(request['request_id'])
    carried=next(r for r in manifest['items'] if r['item_id'].startswith('carry.'))
    assert carried['max_uses']==3
    assert manifest['replacement']['source_grant_ids']==[source['grant_id']]
    assert manifest['ttl_seconds']<=300
    result=decide(broker,request)
    assert result['remaining'][carried['item_id']]==3
    assert result['expires_in_seconds']<=300
    assert broker.grants[source['grant_id']]['state']=='replaced'
    assert broker.grants[result['grant_id']]['deadline']==400.0

def test_four_slots_can_replace_two_but_never_create_a_fifth_active_grant(prepared):
    broker,_,journal,*_=prepared
    sources=[original(broker,[resource('r'+str(n))],key='s'+str(n)) for n in range(4)]
    observed=[];append=journal.append
    journal.append=lambda event:(observed.append(sum(g['state']=='active' for g in broker.grants.values())),append(event))[-1]
    request=replace(broker,[s['grant_id'] for s in sources[:2]])
    assert sum(g['state']=='active' for g in broker.grants.values())==4
    with pytest.raises(ScopeError,match='replacement-pending'):
        row=broker.grants[sources[0]['grant_id']]['items']['r0']
        broker.reserve(sources[0]['grant_id'],'r0','overlap',row['parameters'])
    result=decide(broker,request)
    assert result['grant_state']=='active'
    assert sum(g['state']=='active' for g in broker.grants.values())==3
    assert max(observed)<=4

def test_missing_carried_row_grants_nothing_and_preserves_valid_source(prepared):
    broker,*_=prepared;source=original(broker)
    request=replace(broker,[source['grant_id']])
    result=decide(broker,request,choose=lambda row:not row['item_id'].startswith('carry.'))
    assert result['grant_id'] is None
    assert result['state']=='replacement-blocked'
    assert result['failure_code']=='replacement-incomplete'
    assert broker.status(source['request_id'])['grant_state']=='active'

def test_new_rows_can_be_rejected_without_dropping_any_carried_scope(prepared):
    broker,*_=prepared;source=original(broker)
    request=replace(broker,[source['grant_id']])
    result=decide(broker,request,choose=lambda row:row['item_id'].startswith('carry.'),ttl=30)
    assert result['grant_state']=='active'
    assert len(result['allowed_items'])==1
    assert result['expires_in_seconds']==30

def test_operator_can_narrow_carried_uses_without_renewing_the_source(prepared):
    broker,*_=prepared;source=original(broker);request=replace(broker,[source['grant_id']])
    manifest=broker.approval_manifest(request['request_id'])
    result=broker.accept_decision(request['request_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],ttl_seconds=60,
        choices=[{'item_id':r['item_id'],'max_uses':2 if r['item_id'].startswith('carry.') else r['max_uses'],
                  'targets':[],'semantic_classification':'bootstrap'} for r in manifest['items']])
    assert result['state']=='partially-approved'
    assert result['remaining']['carry.1.1']==2

@pytest.mark.parametrize('change',[
    'legacy','mixed','wrong-life','revoked','expired','zero','item-revoked','scope-changed'])
def test_ineligible_sources_cannot_be_converted_or_renewed(prepared,change):
    broker,clock,*_=prepared;source=original(broker);grant=broker.grants[source['grant_id']]
    if change=='legacy':grant['setup_context']['revision']=1
    elif change=='mixed':grant['setup_context']['contracts']['root']['purpose']='initialization-read'
    elif change=='wrong-life':grant['setup_context']['preauth_lifecycle']='f'*32
    elif change=='revoked':grant['state']='revoked'
    elif change=='expired':grant['deadline']=clock.now
    elif change=='zero':grant['remaining']['root']=0
    elif change=='item-revoked':grant['revoked_items'].add('root')
    elif change=='scope-changed':grant['items']['root']['parameters']['approved_semantics']='login'
    with pytest.raises(ScopeError):replace(broker,[source['grant_id']])

def test_source_counter_change_between_review_and_decision_blocks_new_authority(prepared):
    broker,*_=prepared;source=original(broker);request=replace(broker,[source['grant_id']])
    broker.grants[source['grant_id']]['remaining']['root']-=1
    result=decide(broker,request)
    assert result['grant_id'] is None
    assert broker.status(source['request_id'])['grant_state']=='active'

def test_source_expiry_during_native_review_cannot_become_a_fresh_grant(prepared):
    broker,clock,*_=prepared;source=original(broker,ttl=60);request=replace(broker,[source['grant_id']])
    clock.now+=61
    result=decide(broker,request)
    assert result['grant_id'] is None
    assert result['failure_code']=='replacement-source-changed'
    assert broker.status(source['request_id'])['grant_state']=='expired'

def test_source_fence_remains_immediate_while_commit_is_durably_recorded(prepared):
    broker,_,journal,*_=prepared;source=original(broker);request=replace(broker,[source['grant_id']]);append=journal.append
    fenced=threading.Event()
    def record(event):
        if event['event']=='replacement-committed':
            thread=threading.Thread(target=lambda:(broker.revoke_request(source['request_id']),fenced.set()))
            thread.start();assert fenced.wait(2),'Revocation must not wait behind commit journal I/O';thread.join(timeout=2)
        append(event)
    journal.append=record
    result=decide(broker,request)
    assert result['grant_id'] is None
    assert broker.status(source['request_id'])['grant_state']=='revoked'

def test_two_source_deadlines_and_operator_narrowing_share_one_effective_end(prepared):
    broker,*_=prepared;one=original(broker);two=original(broker,[resource('two')],key='two',ttl=100)
    request=replace(broker,[one['grant_id'],two['grant_id']]);result=decide(broker,request,ttl=80)
    assert result['expires_in_seconds']==80
    assert broker.grants[result['grant_id']]['deadline']==180.0
    assert broker.grants[one['grant_id']]['deadline']==400.0
    assert broker.grants[two['grant_id']]['deadline']==200.0

def test_duplicate_or_more_than_two_sources_are_not_a_consolidation_api(prepared):
    broker,*_=prepared;source=original(broker)
    for ids in [[source['grant_id']]*2,[source['grant_id'],'a'*32,'b'*32],source['grant_id']]:
        with pytest.raises(ScopeError,match='request-invalid'):replace(broker,ids)

def test_source_revoke_during_commit_keeps_an_unrelated_source_active(prepared):
    broker,_,journal,*_=prepared;first=original(broker);second=original(broker,[resource('second')],key='second')
    request=replace(broker,[first['grant_id']]);append=journal.append
    def record(event):
        if event['event']=='replacement-committed':broker.revoke(first['grant_id'])
        append(event)
    journal.append=record
    result=decide(broker,request)
    assert result['grant_id'] is None
    assert broker.status(second['request_id'])['grant_state']=='active'

def test_retired_source_callbacks_cannot_revoke_or_resurrect_replacement(prepared):
    broker,*_=prepared;source=original(broker);result=decide(broker,replace(broker,[source['grant_id']]))
    broker.revoke_request(source['request_id'])
    broker.revoke(source['grant_id'])
    assert broker.status(result['request_id'])['grant_state']=='active'
    assert broker.status(source['request_id'])['grant_state']=='replaced'

def test_durability_failure_never_leaves_new_forwarding_authority(prepared):
    broker,_,journal,closed,*_=prepared;source=original(broker);request=replace(broker,[source['grant_id']]);append=journal.append
    def record(event):
        if event['event']=='replacement-committed':raise OSError('synthetic durability failure')
        append(event)
    journal.append=record
    with pytest.raises(ScopeError):decide(broker,request)
    assert broker.fenced.is_set();assert closed
    assert not any(g['state']=='active' and not broker.fenced.is_set() for g in broker.grants.values())

def test_same_key_does_not_refresh_source_or_review_lifetimes(prepared):
    broker,clock,*_=prepared;source=original(broker);request=replace(broker,[source['grant_id']])
    deadline=broker.requests[request['request_id']]['review_deadline'];clock.now+=20
    repeated=replace(broker,[source['grant_id']])
    assert repeated['request_id']==request['request_id']
    assert broker.requests[request['request_id']]['review_deadline']==deadline
    result=decide(broker,request);assert result['expires_in_seconds']<=280

@pytest.mark.parametrize('kind',['items','bytes','uses'])
def test_combined_source_and_new_rows_keep_hard_proposal_bounds(prepared,kind):
    broker,*_=prepared
    if kind=='items':old=[resource('r'+str(n),1) for n in range(31)];new=[resource('n0',1),resource('n1',1)]
    elif kind=='bytes':
        old=[resource('r'+str(n),1) for n in range(7)];new=[resource('n0',1),resource('n1',1)]
        for row in old+new:row['display']['preview']='x'*3500
    else:old=[resource('r'+str(n),10) for n in range(12)];new=[resource('n'+str(n),10) for n in range(10)]
    source=original(broker,old)
    with pytest.raises(ScopeError,match='setup-plan-capacity-required'):replace(broker,[source['grant_id']],new)
    assert broker.status(source['request_id'])['grant_state']=='active'
