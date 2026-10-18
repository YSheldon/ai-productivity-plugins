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

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_log
import remotex_core as core
from test_audit_event_pairs import ledger, records, recorded_service
from test_web_authorization import item
from test_web_task_service import approve


def batch_service(tmp_path, monkeypatch, count=16):
    service, channel, prompts = recorded_service(tmp_path, monkeypatch)
    descriptors = [{'method': 'GET', 'path': f'/assets/{n}.js', 'query': {},
        'contentType': '', 'body': None, 'resourceType': 'script'} for n in range(count)]
    rows = [{**item(f'static.{n}'), 'capability': 'web.page_step', 'max_uses': 2,
        'parameters': {'network_ref': f'static.{n}', 'review_kind': 'bootstrap'},
        'output': {'rows': 0, 'columns': 0, 'bytes': 0}} for n in range(count)]
    contracts = {row['item_id']: {'phase': 'bootstrap', 'semantics': 'bootstrap',
        'descriptor': descriptor, 'targets': []} for row, descriptor in zip(rows, descriptors)}
    base = channel.request
    channel.request = lambda operation, args, **options: (
        {'ok': True, 'items': rows, 'contracts': contracts} if operation == 'resolve-items'
        else base(operation, args, **options))
    service.request({'items': [{}], 'idempotency_key': 'static-batch'})
    grant = approve(service, prompts)
    messages = [{'kind': 'network', 'phase': 'bootstrap', 'attempt_id': None,
        'descriptor': descriptor, 'digest': 'e' * 64} for descriptor in descriptors]
    return service, channel, grant, messages


def authorize(channel, messages):
    callback = getattr(channel, 'authorize_batch', None)
    assert callable(callback), 'Supervisor startup batch authorization is missing'
    return callback(messages)


def additional_grant(service, channel, descriptor):
    row = {**item('alternative'), 'capability': 'web.page_step', 'max_uses': 2,
        'parameters': {'network_ref': 'alternative', 'review_kind': 'bootstrap'},
        'output': {'rows': 0, 'columns': 0, 'bytes': 0}}
    base = channel.request
    channel.request = lambda operation, args, **options: ({'ok': True, 'items': [row],
        'contracts': {'alternative': {'phase': 'bootstrap', 'semantics': 'bootstrap',
            'descriptor': descriptor, 'targets': []}}} if operation == 'resolve-items'
        else base(operation, args, **options))
    pending = service.request({'items': [{}], 'idempotency_key': 'additional-grant'})
    manifest = service.broker.approval_manifest(pending['request_id'])
    return service._decision(pending['request_id'], {'nonce': manifest['nonce'],
        'request_digest': manifest['request_digest'], 'ttl_seconds': 60,
        'choices': [{'item_id': 'alternative', 'max_uses': 2, 'targets': [], 'semantic_classification': 'bootstrap'}]})


def test_sixteen_static_permits_keep_individual_records_with_one_full_prefix_check(tmp_path, monkeypatch, ledger):
    service, channel, grant, messages = batch_service(tmp_path, monkeypatch)
    before = len(records(ledger))
    original = audit_log._verify_records
    checked = []
    def verify(rows):
        checked.append(len(rows))
        return original(rows)
    monkeypatch.setattr(audit_log, '_verify_records', verify)
    assert authorize(channel, messages) == [True] * 16
    assert checked == [before]
    tail = records(ledger)[before:]
    assert [row['authorization']['event'] for row in tail] == ['execution-reserved', 'execution-finished'] * 16
    assert len({row['authorization']['attempt_id'] for row in tail}) == 16
    assert list(service.broker.status(grant['request_id'])['remaining'].values()) == [1] * 16


def test_unknown_and_exhausted_items_do_not_borrow_sibling_authority(tmp_path, monkeypatch, ledger):
    service, channel, grant, messages = batch_service(tmp_path, monkeypatch, 3)
    unknown = copy.deepcopy(messages[0]); unknown['descriptor']['path'] = '/unapproved.js'
    assert authorize(channel, [messages[0], unknown, messages[1]]) == [True, False, True]
    assert authorize(channel, [messages[0], messages[0], messages[2]]) == [True, False, True]
    assert service.broker.status(grant['request_id'])['remaining'] == {'static.0': 0, 'static.1': 1, 'static.2': 1}


@pytest.mark.parametrize('update', [
    {'phase': 'grant-active'}, {'attempt_id': 'a' * 32},
    {'descriptor': {'method': 'POST', 'path': '/assets/0.js', 'query': {}, 'body': None, 'resourceType': 'script'}},
    {'descriptor': {'method': 'GET', 'path': '/assets/0.js', 'query': {'x': '1'}, 'body': None, 'resourceType': 'script'}},
    {'descriptor': {'method': 'GET', 'path': '/image.png', 'query': {}, 'body': None, 'resourceType': 'image'}},
])
def test_nonstatic_messages_remain_denied_in_a_startup_batch(tmp_path, monkeypatch, ledger, update):
    _, channel, _, messages = batch_service(tmp_path, monkeypatch, 2)
    changed = {**copy.deepcopy(messages[0]), **update}
    assert authorize(channel, [changed, messages[1]]) == [False, True]


def test_no_batch_permission_leaves_before_fsync_completes(tmp_path, monkeypatch, ledger):
    _, channel, _, messages = batch_service(tmp_path, monkeypatch, 2)
    assert callable(getattr(channel, 'authorize_batch', None))
    entered, release = threading.Event(), threading.Event()
    original = audit_log.os.fsync
    def held(fd):
        entered.set(); assert release.wait(5)
        return original(fd)
    monkeypatch.setattr(audit_log.os, 'fsync', held)
    output = []
    thread = threading.Thread(target=lambda: output.extend(authorize(channel, messages)))
    thread.start()
    try:
        assert entered.wait(2)
        assert output == []
    finally:
        release.set(); thread.join(5)
    assert output == [True, True]


def test_batch_fsync_failure_fences_every_permission(tmp_path, monkeypatch, ledger):
    service, channel, _, messages = batch_service(tmp_path, monkeypatch, 2)
    def failed(fd):
        raise OSError('fixture-fsync-failed')
    monkeypatch.setattr(audit_log.os, 'fsync', failed)
    assert authorize(channel, messages) == [False, False]
    assert service.broker.fenced.is_set()


def test_revocation_during_batch_fsync_cannot_return_true(tmp_path, monkeypatch, ledger):
    service, channel, grant, messages = batch_service(tmp_path, monkeypatch, 2)
    original = audit_log.os.fsync
    def revoke(fd):
        service.broker.requests[grant['request_id']]['fence'].set()
        return original(fd)
    monkeypatch.setattr(audit_log.os, 'fsync', revoke)
    assert authorize(channel, messages) == [False, False]


def test_normal_pair_bound_is_not_widened_by_the_internal_startup_path(ledger):
    with pytest.raises(core.ToolError):
        audit_log.append_many([{'event': 'fixture'}] * 3)


def test_oversized_batch_is_denied_without_spending_any_quota(tmp_path, monkeypatch, ledger):
    service, channel, grant, messages = batch_service(tmp_path, monkeypatch)
    assert authorize(channel, messages + [messages[0]]) == [False] * 17
    assert list(service.broker.status(grant['request_id'])['remaining'].values()) == [2] * 16


def test_global_fence_during_reservation_still_persists_buffered_failure_evidence(tmp_path, monkeypatch, ledger):
    service, channel, _, messages = batch_service(tmp_path, monkeypatch, 2)
    before = len(records(ledger))
    original = service.broker.finish
    def revoke(*args, **kwargs):
        service.broker.emergency_revoke()
        return original(*args, **kwargs)
    monkeypatch.setattr(service.broker, 'finish', revoke)
    assert authorize(channel, messages) == [False, False]
    tail = records(ledger)[before:]
    assert [row['authorization']['event'] for row in tail] == ['execution-reserved', 'execution-finished']


def test_corrupt_prefix_is_never_repaired_or_allowed(tmp_path, monkeypatch, ledger):
    service, channel, _, messages = batch_service(tmp_path, monkeypatch, 2)
    ledger.write_bytes(b'corrupt-fixture\n')
    assert authorize(channel, messages) == [False, False]
    assert service.broker.fenced.is_set()
    assert ledger.read_bytes() == b'corrupt-fixture\n'


def test_overlapping_live_grants_can_cover_exhaustion_within_one_batch(tmp_path, monkeypatch, ledger):
    service, channel, grant, messages = batch_service(tmp_path, monkeypatch, 1)
    assert authorize(channel, messages) == [True]
    alternative = additional_grant(service, channel, messages[0]['descriptor'])
    assert authorize(channel, messages * 3) == [True, True, True]
    assert service.broker.status(grant['request_id'])['remaining']['static.0'] == 0
    assert service.broker.status(alternative['request_id'])['remaining']['alternative'] == 0


def test_revoking_one_grant_during_fsync_keeps_an_independent_sibling_valid(tmp_path, monkeypatch, ledger):
    service, channel, grant, messages = batch_service(tmp_path, monkeypatch, 1)
    other = copy.deepcopy(messages[0]); other['descriptor']['path'] = '/other.js'
    additional_grant(service, channel, other['descriptor'])
    original = audit_log.os.fsync
    def revoke(fd):
        service.broker.requests[grant['request_id']]['fence'].set()
        return original(fd)
    monkeypatch.setattr(audit_log.os, 'fsync', revoke)
    assert authorize(channel, [messages[0], other]) == [False, True]


def test_binding_change_during_fsync_fences_the_entire_batch(tmp_path, monkeypatch, ledger):
    service, channel, _, messages = batch_service(tmp_path, monkeypatch, 2)
    original = audit_log.os.fsync
    def change(fd):
        service.broker.check = lambda: {**service.broker.binding, 'worker': 'changed'}
        return original(fd)
    monkeypatch.setattr(audit_log.os, 'fsync', change)
    assert authorize(channel, messages) == [False, False]
    assert service.broker.fenced.is_set()


def test_mixed51_startup_uses_real_private_transport_and_durable_grants(tmp_path, monkeypatch, ledger):
    from web_channel import Channel
    with ledger.open('wb') as handle:
        previous = None
        for _ in range(97000):
            row = {'schema': 'RemoteXAudit/v1', 'timestamp': '2026-10-18T00:00:00Z',
                'sessionId': 'fixture-history', 'event': 'fixture', 'padding': 'x' * 314,
                'previousHash': previous}
            row['entryHash'] = hashlib.sha256(json.dumps(row, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest()
            previous = row['entryHash']
            handle.write(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n')
    service, fixture_channel, prompts = recorded_service(tmp_path, monkeypatch)
    static = [{'method': 'GET', 'path': f'/assets/{n}.js', 'query': {}, 'contentType': '',
        'body': None, 'resourceType': 'script'} for n in range(48)]
    ordinary = [{'method': 'GET', 'path': path, 'query': {}, 'contentType': '', 'body': None,
        'resourceType': resource} for path, resource in [('/', 'document'), ('/one.png', 'image'), ('/two.png', 'image')]]
    # Four separately approved scopes mirror root +32 +15 +index/two PNGs.
    base = fixture_channel.request
    for group, descriptors in enumerate(([ordinary[0]], static[:32], static[32:47], [static[47], *ordinary[1:]])):
        rows = [{**item(f'g{group}.{n}'), 'capability': 'web.page_step', 'max_uses': 1,
            'parameters': {'network_ref': f'g{group}.{n}', 'review_kind': 'bootstrap'},
            'output': {'rows': 0, 'columns': 0, 'bytes': 0}} for n in range(len(descriptors))]
        contracts = {row['item_id']: {'phase': 'bootstrap', 'semantics': 'bootstrap',
            'descriptor': descriptor, 'targets': []} for row, descriptor in zip(rows, descriptors)}
        fixture_channel.request = lambda operation, args, rows=rows, contracts=contracts, **options: (
            {'ok': True, 'items': rows, 'contracts': contracts} if operation == 'resolve-items'
            else base(operation, args, **options))
        service.request({'items': [{}], 'idempotency_key': f'mixed-{group}'})
        approve(service, prompts)
    node = shutil.which('node')
    assert node, 'Node is required for the private transport integration test'
    process = subprocess.Popen([node, str(Path(__file__).parent / 'fixtures' / 'web_static_batch_worker.mjs')],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    class Job:
        def terminate(self):
            process.terminate()
    channel = Channel(process, Job(), profile='fixture', requester='fixture', resource='fixture',
        deadline=int((time.time() + 60) * 1000), config={})
    channel.authorize, channel.authorize_batch = service._authorize, service._authorize_batch
    service.channel = channel
    channel.on_close = service.broker.emergency_revoke
    checked = []
    original = audit_log._verify_records
    def verify(rows):
        checked.append(len(rows)); return original(rows)
    monkeypatch.setattr(audit_log, '_verify_records', verify)
    channel.start()
    started = time.monotonic()
    try:
        result = channel.request('exercise', {}, timeout=55)
        elapsed = time.monotonic() - started
    finally:
        channel.close(); process.wait(timeout=5)
        process.stdin.close(); process.stdout.close(); process.stderr.close()
    assert result['allowed'] == [True] * 51 + [False]
    assert 4 <= result['batchCount'] <= 5
    assert len(checked) <= 12, 'Startup batches must amortize full-prefix checks, not omit verification'
    assert len(records(ledger)) == 97000 + 12 + 102
    print('MIXED_STARTUP_PERFORMANCE ' + json.dumps({'history_records': 97000,
        'requests': 51, 'audit_events': 102, 'prefix_checks': len(checked) - 1,
        'elapsed_seconds': round(elapsed, 3), 'budget_seconds': 45}))
    if os.environ.get('REMOTEX_ASSERT_STARTUP_BUDGET') == '1':
        assert elapsed < 45, 'The representative mixed startup exceeded the unchanged budget'
