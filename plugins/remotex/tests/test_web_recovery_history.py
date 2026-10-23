import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from web_authorization import ScopeError, digest
try:
    from web_recovery_history import observe
except ModuleNotFoundError:
    observe = None

SCOPE = [{'profile': 'console', 'origin': 'https://console.example', 'account': 'operator'}]
START = datetime(2026, 10, 20, tzinfo=timezone.utc)
NOW = START + timedelta(days=1)


def history(*, action='click', result='completed', revoked=True, ttl=900):
    values = [
        {'event': 'site-requested', 'request_id': '1' * 32},
        {'event': 'site-granted', 'request_id': '1' * 32, 'grant_id': '2' * 32, 'ttl_seconds': ttl},
        {'event': 'site-login-result', 'summary': {'authentication_verified': True}},
        {'event': 'site-action-requested', 'attempt_id': '3' * 32, 'scope_digest': 'c' * 64,
         'summary': {'action': action, 'sensitive': False}},
        {'event': 'site-action-dispatch', 'attempt_id': '3' * 32, 'scope_digest': 'c' * 64},
        {'event': 'site-action-result', 'attempt_id': '3' * 32, 'state': result}]
    if revoked:
        values.append({'event': 'site-revoked', 'count': 1})
    return [row(value, i) for i, value in enumerate(values)]


def row(value, second=0, *, session='process-one', binding='b' * 64):
    return {'event': 'web-authorization', 'sessionId': session,
        'timestamp': (START + timedelta(seconds=second)).isoformat(),
        'authorization': {'binding_digest': binding, **value}}


def inspect(records, *, now=NOW):
    assert observe is not None, 'Owner-reconciled legacy history is not implemented'
    return observe(records, SCOPE, now=now)


@pytest.mark.parametrize('action,reads,effects', [('read', 1, 0), ('read-table', 1, 0), ('fill', 0, 1), ('click', 0, 1)])
def test_closed_completed_actions_need_owner_reconciliation_not_business_verification(action, reads, effects):
    records = history(action=action)
    before = copy.deepcopy(records)
    summary, inventory = inspect(records)
    assert summary['completedAttempts'] == 1
    assert summary['verifiedAttempts'] == 0
    assert summary['technicalReadAttempts'] == reads
    assert summary['technicalEffectAttempts'] == effects
    assert summary['unknownScopeBindings'] == 1
    assert summary['inventoryDigest'] == digest(inventory)
    assert inventory[0]['historicalOrigin'] == inventory[0]['historicalAccount'] == 'unknown'
    assert inventory[0]['attempts'][0]['state'] == 'completed'
    assert records == before


def test_expired_unrevoked_grant_is_reviewable_but_active_grant_is_not():
    records = history(revoked=False)
    summary, inventory = inspect(records)
    assert summary['technicalEffectAttempts'] == 1
    assert inventory[0]['grants'][0]['closure'] == 'expired'
    with pytest.raises(ScopeError, match='recovery-busy'):
        inspect(records, now=START + timedelta(seconds=10))


@pytest.mark.parametrize('state', ['outcome-unknown', 'partially-verified', 'executing', 'failed', None])
def test_unknown_result_cannot_be_overridden_by_revocation_or_expiry(state):
    with pytest.raises(ScopeError, match='recovery-unresolved-write'):
        inspect(history(result=state))


@pytest.mark.parametrize('index', [0, 1, 2, 3, 4, 5])
def test_missing_request_grant_dispatch_or_terminal_record_blocks(index):
    records = history()
    del records[index]
    with pytest.raises(ScopeError):
        inspect(records)


@pytest.mark.parametrize('index', [0, 1, 2, 3, 4, 5, 6])
def test_duplicate_lifecycle_or_result_is_not_balanced_by_counts(index):
    records = history()
    records.insert(index + 1, copy.deepcopy(records[index]))
    with pytest.raises(ScopeError):
        inspect(records)


@pytest.mark.parametrize('field', ['sessionId', 'binding_digest', 'attempt_id', 'scope_digest'])
def test_other_identity_cannot_close_an_attempt(field):
    records = history()
    if field == 'sessionId':
        records[5][field] = 'another-process'
    elif field == 'scope_digest':
        records[4]['authorization'][field] = 'd' * 64
    else:
        records[5]['authorization'][field] = 'd' * (64 if field == 'binding_digest' else 32)
    with pytest.raises(ScopeError):
        inspect(records)


@pytest.mark.parametrize('bad', [0, -1, 43201, True, None, '900'])
def test_invalid_grant_ttl_blocks_even_after_revocation(bad):
    with pytest.raises(ScopeError):
        inspect(history(ttl=bad))


@pytest.mark.parametrize('timestamp', ['not-a-time', '2026-10-20T00:00:00', '2030-01-01T00:00:00Z'])
def test_bad_or_future_timestamp_is_not_expiry_evidence(timestamp):
    records = history()
    records[1]['timestamp'] = timestamp
    with pytest.raises(ScopeError):
        inspect(records)


def test_result_after_revocation_cannot_be_used_as_reconciliation():
    records = history()
    records[5], records[6] = records[6], records[5]
    for i, value in enumerate(records):
        value['timestamp'] = (START + timedelta(seconds=i)).isoformat()
    with pytest.raises(ScopeError):
        inspect(records)


def test_unknown_action_or_event_semantics_and_missing_binding_block():
    for records in (history(action='execute-javascript'),
            [row({'event': 'unknown-event'})],
            [row({'event': 'site-requested', 'request_id': '1' * 32}, binding=None)]):
        with pytest.raises(ScopeError):
            inspect(records)


def test_ungranted_request_is_visible_without_becoming_write_or_scope_proof():
    records = [row({'event': 'site-requested', 'request_id': '1' * 32})]
    summary, inventory = inspect(records)
    assert summary['ungrantedRequests'] == 1 and summary['completedAttempts'] == 0
    assert summary['unknownScopeBindings'] == 1
    assert inventory[0]['requests'][0]['granted'] is False
    with pytest.raises(ScopeError, match='recovery-busy'):
        inspect(records, now=START + timedelta(seconds=10))


def granular_history(state='verified'):
    values = [
        {'event': 'request-created', 'request_id': '1' * 32, 'count': 1},
        {'event': 'decision-recorded', 'request_id': '1' * 32, 'ttl_seconds': 900,
         'approved_scope_digest': 'c' * 64, 'approved_items': ['read']},
        {'event': 'grant-issued', 'request_id': '1' * 32, 'grant_id': '2' * 32, 'approved_scope_digest': 'c' * 64},
        {'event': 'execution-reserved', 'attempt_id': '3' * 32, 'grant_id': '2' * 32,
         'capability': 'web.page_step', 'item_id': 'read'},
        {'event': 'execution-finished', 'attempt_id': '3' * 32, 'state': state},
        {'event': 'request-revoked', 'request_id': '1' * 32}]
    return [row(value, i) for i, value in enumerate(values)]


def test_paired_verified_granular_history_retains_unknown_scope_for_owner_review():
    summary, inventory = inspect(granular_history())
    assert summary['verifiedAttempts'] == 1 and summary['unknownScopeBindings'] == 1
    assert summary['technicalEffectAttempts'] == 0
    assert inventory[0]['attempts'][0]['state'] == 'verified'


def test_granular_completed_is_not_silently_promoted_to_verified():
    with pytest.raises(ScopeError, match='recovery-unresolved-write'):
        inspect(granular_history('completed'))


def test_mcp_write_without_verified_result_remains_non_overridable():
    base = {'sessionId': 'mcp-one', 'tool': 'remotex_web_execute', 'operationId': 'op-one',
        'timestamp': START.isoformat(), 'request': {}}
    records = [{**base, 'event': 'operation-start'},
        {**base, 'event': 'operation-finish', 'result': {'state': 'completed'}}]
    with pytest.raises(ScopeError, match='recovery-unresolved-write'):
        inspect(records)


@pytest.mark.parametrize('value', [
    {'event': 'output-ready', 'attempt_id': '3' * 32},
    {'event': 'action-confirmed', 'attempt_id': '3' * 32},
    {'event': 'site-action-confirmed', 'attempt_id': '3' * 32},
    {'event': 'site-login-result', 'summary': {'authentication_verified': True}},
    {'event': 'replacement-committed', 'request_id': '1' * 32}])
def test_orphan_passive_lifecycle_event_is_not_scope_reconciliation(value):
    with pytest.raises(ScopeError):
        inspect([row(value)])


def test_verified_mcp_operation_keeps_full_private_identity_and_unknown_scope():
    base = {'sessionId': 'mcp-one', 'tool': 'remotex_web_execute', 'operationId': 'op-one',
        'timestamp': START.isoformat()}
    records = [{**base, 'event': 'operation-start', 'request': {'profileSha256': 'f' * 64}},
        {**base, 'event': 'operation-finish', 'result': {'state': 'verified'}}]
    summary, inventory = inspect(records)
    assert summary['mcpWriteOperations'] == 1 and summary['historicalProfileHashes'] == 1
    assert inventory[0]['operationId'] == 'op-one' and inventory[0]['profileHash'] == 'f' * 64
    assert inventory[0]['historicalOrigin'] == 'unknown'


@pytest.mark.parametrize('forwarded', ['authentication-forwarded', 'initialization-forwarded'])
def test_forwarded_work_without_unique_terminal_proof_survives_revoke_and_cleanup(forwarded):
    records = granular_history()[:-1]
    for value in [
        {'event': 'document-opening', 'generation': 0},
        {'event': 'document-committed', 'generation': 0},
        {'event': forwarded, 'generation': 0, 'count': 1},
        {'event': 'resume-ended', 'generation': 0},
        {'event': 'request-revoked', 'request_id': '1' * 32}]:
        records.append(row(value, len(records)))
    with pytest.raises(ScopeError, match='recovery-unresolved-write'):
        inspect(records)


@pytest.mark.parametrize('generations', [(0, 12, 77), (None, 0, 0), (0, None, 0), (0, 0, None), (True, True, True), (-1, -1, -1)])
def test_mismatched_or_missing_document_generation_cannot_close_lifecycle(generations):
    records = granular_history()[:-1]
    for event, generation in zip(['document-opening', 'document-committed', 'resume-ended'], generations):
        value = {'event': event}
        if generation is not None:
            value['generation'] = generation
        records.append(row(value, len(records)))
    records.append(row({'event': 'request-revoked', 'request_id': '1' * 32}, len(records)))
    with pytest.raises(ScopeError):
        inspect(records)


@pytest.mark.parametrize('ready_generation', [0, 1])
def test_controls_ready_can_preserve_or_advance_generation_once(ready_generation):
    records = granular_history()[:-1]
    for value in [
        {'event': 'document-opening', 'generation': 0},
        {'event': 'document-committed', 'generation': 0},
        {'event': 'controls-ready', 'generation': ready_generation},
        {'event': 'resume-ended', 'generation': ready_generation},
        {'event': 'request-revoked', 'request_id': '1' * 32}]:
        records.append(row(value, len(records)))
    assert inspect(records)[0]['verifiedAttempts'] == 1


def test_native_summary_has_exact_observed_history_time_range():
    summary, _ = inspect(history())
    assert summary['historyFirstObserved'] == '2026-10-20T00:00:00+00:00'
    assert summary['historyLastObserved'] == '2026-10-20T00:00:06+00:00'
