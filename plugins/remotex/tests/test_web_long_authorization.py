from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import web_authorization as auth
import web_adapter
from test_web_authorization import Clock, MemoryJournal, item, approve
from test_web_task_service import prepared


def long_broker(lifetime=46800):
    clock, closed = Clock(), []
    binding = {'origin': 'https://console.example', 'account': 'operator', 'profile': 'long-lab',
        'session': 'a' * 32, 'worker': 'worker', 'acquisition': 'lease',
        'profile_digest': 'b' * 64, 'deadline': 100.0 + lifetime}
    current = copy.deepcopy(binding)
    broker = auth.Broker(binding, journal=MemoryJournal(), check=lambda: copy.deepcopy(current),
        close=lambda: closed.append(True), clock=clock)
    return broker, clock, current, closed


@pytest.mark.parametrize('write', [False, True])
def test_exact_read_or_write_scope_can_last_twelve_hours_then_expires(write):
    broker, clock, _, _ = long_broker()
    row = item('operation', write=write, targets=['host-one'] if write else [])
    grant = approve(broker, [row], ttl=43200)
    assert grant['expires_in_seconds'] == 43200
    clock.now += 43199
    assert broker.status(grant['request_id'])['expires_in_seconds'] == 1
    assert broker._grant(grant['grant_id'], 'operation')[1]['targets'] == row['targets']
    clock.now += 1
    with pytest.raises(auth.ScopeError, match='grant-expired'):
        broker._grant(grant['grant_id'], 'operation')


def test_default_long_request_is_still_pending_until_a_bound_human_decision():
    broker, _, _, _ = long_broker()
    result = broker.request([item()], idempotency_key='long-default')
    manifest = broker.approval_manifest(result['request_id'])
    assert manifest['ttl_seconds'] == 43200
    assert manifest['wait_seconds'] == 180
    assert result['state'] == 'pending' and result['grant_id'] is None
    with pytest.raises(auth.ScopeError, match='approval-required'):
        broker.reserve(result['request_id'], 'read', 'not-approved', {})


def test_long_task_service_default_reaches_the_native_manifest():
    service, _, prompts = prepared()
    service.broker.binding['deadline'] = 46900.0
    service.broker.binding_digest = auth.digest(service.broker.binding)
    service.broker.check = lambda: copy.deepcopy(service.broker.binding)
    result = service.request({'items': [{}], 'idempotency_key': 'long-service'})
    manifest, callbacks = prompts[-1]
    assert manifest['ttl_seconds'] == 43200
    assert manifest['wait_seconds'] == 180
    assert result['state'] == 'pending' and result['approval_ui']['review_remaining_seconds'] == 120
    decision = callbacks['on_decision']({'nonce': manifest['nonce'], 'request_digest': manifest['request_digest'],
        'choices': [{'item_id': 'read', 'max_uses': 2, 'targets': []}], 'ttl_seconds': 43200})
    assert decision['expires_in_seconds'] == 43200


def test_twelve_hour_request_does_not_extend_the_review_deadline():
    broker, clock, _, _ = long_broker()
    request = broker.request([item()], idempotency_key='review-still-short', ttl_seconds=43200)
    manifest = broker.approval_manifest(request['request_id'])
    clock.now += 179
    assert broker.status(request['request_id'])['state']=='pending'
    clock.now += 1
    with pytest.raises(auth.ScopeError, match='request-expired'):
        broker.accept_decision(request['request_id'], nonce=manifest['nonce'], digest=manifest['request_digest'],
            choices=[], ttl_seconds=43200)


def test_operator_can_still_reduce_the_long_requested_lifetime():
    broker, _, _, _ = long_broker()
    request = broker.request([item()], idempotency_key='shorter-choice', ttl_seconds=43200)
    manifest = broker.approval_manifest(request['request_id'])
    grant = broker.accept_decision(request['request_id'], nonce=manifest['nonce'], digest=manifest['request_digest'],
        choices=[{'item_id': 'read', 'max_uses': 1, 'targets': []}], ttl_seconds=600)
    assert grant['expires_in_seconds'] == 600
    assert grant['remaining'] == {'read': 1}


def test_long_request_is_capped_by_existing_session_not_extended_implicitly():
    broker, _, _, _ = long_broker(lifetime=1800)
    grant = approve(broker, [item()], ttl=43200)
    assert grant['expires_in_seconds'] == 1800


def test_new_long_request_never_extends_an_older_short_grant():
    broker, clock, _, _ = long_broker()
    short = approve(broker, [item()], key='old', ttl=900)
    clock.now += 100
    approve(broker, [item('other')], key='new', ttl=43200)
    assert broker.status(short['request_id'])['expires_in_seconds'] == 800


def test_long_write_does_not_remove_action_time_confirmation_or_its_thirty_second_ticket():
    broker, clock, _, _ = long_broker()
    row = item('remove', write=True, targets=['host-one'])
    row['effect']['class'] = 'action-time'
    grant = approve(broker, [row], ttl=43200)
    attempt = broker.reserve(grant['grant_id'], 'remove', 'write-once', {})
    with pytest.raises(auth.ScopeError, match='action-confirmation-required'):
        broker.authorize_attempt(attempt['attempt_id'])
    manifest = broker.confirmation_manifest(attempt['attempt_id'])
    assert manifest['ttl_seconds'] == 30 and manifest['wait_seconds'] == 180
    broker.accept_action_decision(attempt['attempt_id'], nonce=manifest['nonce'], digest=manifest['request_digest'],
        choices=[{'item_id': 'remove', 'targets': ['host-one'], 'max_uses': 1}], ttl_seconds=30)
    clock.now += 30
    with pytest.raises(auth.ScopeError, match='action-confirmation-required'):
        broker.authorize_attempt(attempt['attempt_id'])


def test_long_grants_still_honor_scope_change_revocation_and_use_budget():
    broker, _, current, _ = long_broker()
    grant = approve(broker, [item()], uses=1, ttl=43200)
    broker.reserve(grant['grant_id'], 'read', 'once', {})
    with pytest.raises(auth.ScopeError, match='budget-exhausted'):
        broker.reserve(grant['grant_id'], 'read', 'second', {})
    current['acquisition'] = 'another-acquisition'
    with pytest.raises(auth.ScopeError, match='scope-mismatch'):
        broker._grant(grant['grant_id'], 'read')


def test_public_contracts_allow_twelve_hour_grants_and_thirteen_hour_sessions():
    grants = web_adapter.TOOLS['remotex_web_authorization_request']['inputSchema']['properties']['ttl_seconds']
    sessions = web_adapter.TOOLS['remotex_web_login']['inputSchema']['properties']['session_seconds']
    assert grants['minimum'] <= 43200 <= grants['maximum']
    assert sessions['minimum'] <= 46800 <= sessions['maximum']
    assert grants.get('default') == 43200 and sessions.get('default') == 46800
    broker, _, _, _ = long_broker()
    with pytest.raises(auth.ScopeError, match='request-invalid'):
        broker.request([item()], idempotency_key='too-long', ttl_seconds=43201)
