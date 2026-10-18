from __future__ import annotations

import copy
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
try:
    import web_authorization as auth
except ModuleNotFoundError:
    auth = None


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class MemoryJournal:
    def __init__(self):
        self.events = []
        self.pending = {}

    def append(self, event):
        self.events.append(copy.deepcopy(event))

    def reserve(self, attempt, conflicts):
        if any(set(conflicts) & set(row) for row in self.pending.values()):
            raise auth.ScopeError('unresolved-prior-write')
        self.pending[attempt] = list(conflicts)

    def resolve(self, attempt):
        self.pending.pop(attempt, None)


@pytest.fixture
def prepared():
    assert auth is not None, 'The task authorization broker has not been implemented'
    clock, journal, closed = Clock(), MemoryJournal(), []
    binding = {'origin':'https://console.example:6868', 'account':'operator',
               'profile':'web-lab', 'session':'a'*32, 'worker':'worker-1',
               'acquisition':'lease-1', 'profile_digest':'b'*64, 'deadline':1000.0}
    current = copy.deepcopy(binding)
    broker = auth.Broker(binding, journal=journal, check=lambda:current,
                         close=lambda:closed.append(True), clock=clock)
    return broker, clock, journal, closed, current


def item(name='read', *, depends=(), write=False, targets=()):
    return {'item_id':name, 'capability':'web.business_action' if write else 'web.read_table',
            'fingerprint':'c'*64, 'page':'#/assets', 'max_uses':1 if write else 2, 'depends_on':list(depends),
            'targets':list(targets), 'parameters':{}, 'output':{'rows':100,'columns':30,'bytes':98304},
            'display':{'label':'Terminal inventory'},
            'effect':{'class':'action-bound' if write else 'task-bounded',
                      'fields':['group'] if write else [], 'digest':'d'*64}}


def approve(broker, rows, *, uses=2, targets=None, key='request-1', ttl=300):
    request = broker.request(rows, idempotency_key=key, ttl_seconds=ttl)
    manifest = broker.approval_manifest(request['request_id'])
    choices = [{'item_id':row['item_id'],'max_uses':min(uses,row['max_uses']),
                'targets':list(row['targets'] if targets is None else targets)} for row in rows]
    return broker.accept_decision(request['request_id'], nonce=manifest['nonce'],
                                  digest=manifest['request_digest'], choices=choices,
                                  ttl_seconds=ttl)


def test_request_cannot_self_approve_or_execute(prepared):
    broker, *_ = prepared
    request = broker.request([item()], idempotency_key='first', ttl_seconds=300)
    assert request['state'] == 'pending'
    assert 'nonce' not in request
    assert request['allowed_items'] == []
    with pytest.raises(auth.ScopeError, match='approval-required'):
        broker.reserve(request['request_id'], 'read', 'attempt-1', {})


def test_human_output_narrowing_cannot_be_widened_or_ignored(prepared):
    broker,*_=prepared
    request=broker.request([item()],idempotency_key='output-limits')
    manifest=broker.approval_manifest(request['request_id'])
    result=broker.accept_decision(request['request_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],
        choices=[{'item_id':'read','max_uses':1,'targets':[],
                  'output':{'rows':2,'columns':1,'bytes':1024}}],ttl_seconds=60)
    attempt=broker.reserve(result['grant_id'],'read','read-once',{})
    assert attempt['scope']['output']=={'rows':2,'columns':1,'bytes':1024}
    assert result['state']=='partially-approved'


def test_decision_is_bound_to_nonce_digest_and_consumed_once(prepared):
    broker, *_ = prepared
    request = broker.request([item()], idempotency_key='first', ttl_seconds=300)
    manifest = broker.approval_manifest(request['request_id'])
    for nonce,digest in [('wrong',manifest['request_digest']),(manifest['nonce'],'wrong')]:
        with pytest.raises(auth.ScopeError, match='decision-invalid'):
            broker.accept_decision(request['request_id'],nonce=nonce,digest=digest,choices=[],ttl_seconds=60)
    result = broker.accept_decision(request['request_id'],nonce=manifest['nonce'],
        digest=manifest['request_digest'],choices=[],ttl_seconds=60)
    assert result['state'] == 'rejected'
    with pytest.raises(auth.ScopeError, match='decision-consumed'):
        broker.accept_decision(request['request_id'],nonce=manifest['nonce'],
            digest=manifest['request_digest'],choices=[],ttl_seconds=60)


def test_partial_approval_narrows_targets_and_blocks_dependencies(prepared):
    broker, *_ = prepared
    rows = [item('write',write=True,targets=['host-1','host-2']),item('verify',depends=['write'])]
    request = broker.request(rows,idempotency_key='batch',ttl_seconds=300)
    manifest = broker.approval_manifest(request['request_id'])
    grant = broker.accept_decision(request['request_id'],nonce=manifest['nonce'],
        digest=manifest['request_digest'],choices=[{'item_id':'write','targets':['host-1'],'max_uses':1}],ttl_seconds=60)
    assert grant['state'] == 'partially-approved'
    assert grant['allowed_items'] == ['write']
    attempt = broker.reserve(grant['grant_id'],'write','one',{})
    assert attempt['scope']['targets'] == ['host-1']
    with pytest.raises(auth.ScopeError):
        broker.reserve(grant['grant_id'],'verify','two',{})


def test_rejected_prerequisite_never_grants_selected_dependent(prepared):
    broker, *_ = prepared
    rows=[item('navigate'),item('read',depends=['navigate'])]
    req=broker.request(rows,idempotency_key='deps',ttl_seconds=300)
    manifest=broker.approval_manifest(req['request_id'])
    grant=broker.accept_decision(req['request_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],
        choices=[{'item_id':'read','max_uses':1,'targets':[]}],ttl_seconds=60)
    assert grant['allowed_items'] == []
    assert grant['item_states']['read'] == 'dependency-blocked'


def test_cycles_unknown_fields_and_oversized_batches_are_rejected(prepared):
    broker, *_ = prepared
    for rows in ([item('a',depends=['b']),item('b',depends=['a'])],
                 [{**item(),'script':'anything'}], [item(str(i)) for i in range(33)]):
        with pytest.raises(auth.ScopeError, match='request-invalid|request-too-large'):
            broker.request(rows,idempotency_key='invalid',ttl_seconds=300)


def test_idempotency_returns_same_request_and_rejects_changed_scope(prepared):
    broker, clock, *_ = prepared
    first=broker.request([item()],idempotency_key='same',ttl_seconds=300)
    clock.now += 31
    assert broker.request([item()],idempotency_key='same',ttl_seconds=300)['request_id'] == first['request_id']
    with pytest.raises(auth.ScopeError, match='request-conflict'):
        broker.request([item('other')],idempotency_key='same',ttl_seconds=300)


def test_human_cannot_widen_limits_or_target_set(prepared):
    broker, *_=prepared
    req=broker.request([item('write',write=True,targets=['host-1'])],idempotency_key='bounds',ttl_seconds=60)
    manifest=broker.approval_manifest(req['request_id'])
    for targets,uses,ttl in [(['host-2'],1,60),(['host-1'],3,60),(['host-1'],1,61)]:
        with pytest.raises(auth.ScopeError,match='decision-invalid'):
            broker.accept_decision(req['request_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],
                choices=[{'item_id':'write','targets':targets,'max_uses':uses}],ttl_seconds=ttl)


def test_budget_expiry_binding_and_parameter_checks(prepared):
    broker, clock, _, _, current=prepared
    grant=approve(broker,[item()],uses=1,ttl=60)
    attempt=broker.reserve(grant['grant_id'],'read','a',{})
    assert broker.reserve(grant['grant_id'],'read','a',{})['attempt_id'] == attempt['attempt_id']
    with pytest.raises(auth.ScopeError,match='budget-exhausted'):
        broker.reserve(grant['grant_id'],'read','b',{})
    clock.now += 60
    with pytest.raises(auth.ScopeError,match='grant-expired'):
        broker.reserve(grant['grant_id'],'read','c',{})
    current['acquisition']='another-lease'
    with pytest.raises(auth.ScopeError,match='scope-mismatch'):
        broker.request([item()],idempotency_key='new',ttl_seconds=300)


def test_dependencies_require_verified_outcome_and_revoke_prevents_new_dispatch(prepared):
    broker,*_=prepared
    grant=approve(broker,[item('a'),item('b',depends=['a'])])
    with pytest.raises(auth.ScopeError,match='dependency-blocked'):
        broker.reserve(grant['grant_id'],'b','b',{})
    attempt=broker.reserve(grant['grant_id'],'a','a',{})
    broker.finish(attempt['attempt_id'],state='verified',summary={'count':1})
    assert broker.reserve(grant['grant_id'],'b','b',{})['state'] == 'reserved'
    broker.revoke(grant['grant_id'])
    with pytest.raises(auth.ScopeError,match='grant-revoked'):
        broker.release_output(attempt['attempt_id'], {'rows':[['private']]})


def test_unknown_write_blocks_new_key_grant_session_and_changed_value(prepared):
    broker, clock, journal, _, binding=prepared
    row=item('write',write=True,targets=['host-1'])
    grant=approve(broker,[row],uses=1)
    attempt=broker.reserve(grant['grant_id'],'write','first',{})
    broker.finish(attempt['attempt_id'],state='outcome-unknown',summary={})
    other=auth.Broker(copy.deepcopy(binding),journal=journal,check=lambda:binding,close=lambda:None,clock=clock)
    changed={**row,'parameters':{'group':'new-value'}}
    other_grant=approve(other,[changed],uses=1,key='other')
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'):
        other.reserve(other_grant['grant_id'],'write','new-key',{'group':'new-value'})


def test_revocation_during_slow_audit_prevents_late_dispatch_and_output(prepared):
    broker, _, journal, closed, _=prepared
    grant=approve(broker,[item()])
    entered,release=threading.Event(),threading.Event()
    original=journal.append
    def slow(event):
        if event['event']=='execution-reserved':
            entered.set();release.wait(3)
        original(event)
    journal.append=slow
    errors=[]
    def run():
        try:broker.reserve(grant['grant_id'],'read','slow',{})
        except auth.ScopeError as exc:errors.append(exc.code)
    thread=threading.Thread(target=run);thread.start()
    assert entered.wait(1)
    try:
        broker.emergency_revoke()
        assert closed == [True]
    finally:
        release.set();thread.join(3)
    assert errors == ['grant-revoked']


def test_audit_contains_hashes_and_codes_not_scope_values(prepared):
    broker, _, journal, *_=prepared
    row=item();row['display']['label']='private-display-canary'
    row['parameters']={'filter':'private-parameter-canary'}
    grant=approve(broker,[row])
    attempt=broker.reserve(grant['grant_id'],'read','private-key-canary',row['parameters'])
    broker.finish(attempt['attempt_id'],state='verified',summary={'count':2})
    serialized=str(journal.events)
    assert 'private-display-canary' not in serialized
    assert 'private-parameter-canary' not in serialized
    assert 'private-key-canary' not in serialized


def test_malformed_dependency_and_target_types_fail_with_fixed_code(prepared):
    broker,*_=prepared
    for bad in ({**item(),'targets':[{}]}, {**item(),'depends_on':[[]]},
                {**item(),'fingerprint':None}):
        with pytest.raises(auth.ScopeError,match='request-invalid'):
            broker.request([bad],idempotency_key='bad-types',ttl_seconds=300)


def test_binding_change_at_output_commit_does_not_deadlock_or_release_content(prepared):
    broker,_,journal,closed,current=prepared
    grant=approve(broker,[item()])
    attempt=broker.reserve(grant['grant_id'],'read','output',{})
    broker.finish(attempt['attempt_id'],state='verified',summary={})
    original=journal.append
    def change(event):
        original(event)
        if event['event']=='output-ready':current['worker']='changed'
    journal.append=change
    errors=[]
    def run():
        try:broker.release_output(attempt['attempt_id'],{'rows':[['private']]})
        except auth.ScopeError as exc:errors.append(exc.code)
    thread=threading.Thread(target=run,daemon=True);thread.start();thread.join(1)
    assert not thread.is_alive(), 'Output invalidation deadlocked with its emergency fence'
    assert errors==['scope-mismatch']
    assert closed==[True]


def test_action_time_approval_is_exact_one_use_and_not_task_preapproval(prepared):
    broker,clock,*_=prepared
    row=item('delete',write=True,targets=['host-1']);row['effect']['class']='action-time'
    grant=approve(broker,[row],uses=1)
    attempt=broker.reserve(grant['grant_id'],'delete','delete-once',{})
    assert attempt['state']=='awaiting-action-confirmation'
    with pytest.raises(auth.ScopeError,match='action-confirmation-required'):
        broker.authorize_attempt(attempt['attempt_id'],consume=True)
    manifest=broker.confirmation_manifest(attempt['attempt_id'])
    result=broker.accept_action_decision(attempt['attempt_id'],nonce=manifest['nonce'],
        digest=manifest['request_digest'],choices=[{'item_id':'delete','targets':['host-1'],'max_uses':1}],ttl_seconds=30)
    assert result['state']=='reserved'
    assert broker.authorize_attempt(attempt['attempt_id'],consume=True) is True
    with pytest.raises(auth.ScopeError,match='action-confirmation-required'):
        broker.authorize_attempt(attempt['attempt_id'],consume=True)
    clock.now+=30
    with pytest.raises(auth.ScopeError,match='action-confirmation-required'):
        broker.authorize_attempt(attempt['attempt_id'])


def test_action_time_target_change_or_late_decision_cannot_be_accepted(prepared):
    broker,clock,*_=prepared
    row=item('write',write=True,targets=['host-1']);row['effect']['class']='action-time'
    grant=approve(broker,[row],uses=1)
    attempt=broker.reserve(grant['grant_id'],'write','one',{})
    manifest=broker.confirmation_manifest(attempt['attempt_id'])
    with pytest.raises(auth.ScopeError,match='decision-invalid'):
        broker.accept_action_decision(attempt['attempt_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],
            choices=[{'item_id':'write','targets':['host-2'],'max_uses':1}],ttl_seconds=30)
    clock.now+=121
    with pytest.raises(auth.ScopeError,match='request-expired'):
        broker.accept_action_decision(attempt['attempt_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],
            choices=[{'item_id':'write','targets':['host-1'],'max_uses':1}],ttl_seconds=30)
