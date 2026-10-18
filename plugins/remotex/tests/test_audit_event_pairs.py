from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_log
import remotex_core as core
import web_authorization_store as storage
from test_web_authorization import item
from test_web_task_service import prepared, approve


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    path = tmp_path / 'audit.jsonl'
    monkeypatch.setenv('REMOTEX_AUDIT_FILE', str(path))
    return path


def records(path):
    with path.open('rb') as handle:
        rows = audit_log._records(handle)
    audit_log._verify_records(rows)
    return rows


def require_batch():
    assert callable(getattr(audit_log, 'append_many', None)), 'Durable bounded audit batch is missing'


def recorded_service(tmp_path, monkeypatch):
    # ACL enforcement has separate real-Windows tests; all files here are disposable.
    monkeypatch.setattr(storage.secure_paths, 'ensure_private_directory', lambda p: p.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(storage.secure_paths, 'ensure_private_file', lambda p: None)
    service, channel, prompts = prepared()
    service.broker.journal = storage.Journal(tmp_path / 'authorization')
    return service, channel, prompts


def static_service(tmp_path, monkeypatch, *, descriptor=None, phase='bootstrap'):
    service, channel, prompts = recorded_service(tmp_path, monkeypatch)
    descriptor = descriptor or {'method': 'GET', 'path': '/assets/login.js', 'query': {},
        'contentType': '', 'body': None, 'resourceType': 'script'}
    semantics = 'bootstrap' if phase == 'bootstrap' else 'login'
    row = {**item('static.1'), 'capability': 'web.page_step',
        'parameters': {'network_ref': 'static.1', 'review_kind': semantics},
        'output': {'rows': 0, 'columns': 0, 'bytes': 0}}
    original = channel.request
    channel.request = lambda operation, args, **options: ({'ok': True, 'items': [row],
        'contracts': {'static.1': {'phase': phase, 'semantics': semantics,
            'descriptor': copy.deepcopy(descriptor), 'targets': []}}}
        if operation == 'resolve-items' else original(operation, args, **options))
    service.request({'items': [{}], 'idempotency_key': 'static-pair'})
    grant = approve(service, prompts)
    message = {'kind': 'network', 'phase': phase, 'attempt_id': None,
        'descriptor': descriptor, 'digest': 'e' * 64}
    return service, channel, grant, message


def test_pair_retains_consecutive_hash_linked_records_with_one_prefix_check(ledger, monkeypatch):
    require_batch()
    audit_log.append({'event': 'prefix'})
    checked = []
    original = audit_log._verify_records
    def verify(rows):
        checked.append(len(rows))
        return original(rows)
    monkeypatch.setattr(audit_log, '_verify_records', verify)
    result = audit_log.append_many([{'event': 'reserved', 'number': 1}, {'event': 'finished', 'number': 2}])
    assert checked == [1]
    assert [row['event'] for row in result] == ['reserved', 'finished']
    assert result[1]['previousHash'] == result[0]['entryHash']
    assert [row['event'] for row in records(ledger)] == ['prefix', 'reserved', 'finished']


def test_caller_cannot_grow_a_bounded_pair_while_it_waits_for_the_lock(ledger, monkeypatch):
    require_batch()
    reached, output, errors = threading.Event(), [], []
    original = audit_log.audit_path
    def path():
        reached.set(); return original()
    monkeypatch.setattr(audit_log, 'audit_path', path)
    events = [{'event': 'one'}, {'event': 'two'}]
    def append():
        try:
            output.extend(audit_log.append_many(events))
        except Exception as error:
            errors.append(error)
    audit_log._PROCESS_LOCK.acquire()
    thread = threading.Thread(target=append)
    thread.start()
    try:
        assert reached.wait(3)
        events.append({'event': 'not-in-the-original-pair'})
    finally:
        audit_log._PROCESS_LOCK.release(); thread.join(5)
    assert not thread.is_alive() and errors == []
    assert [row['event'] for row in output] == ['one', 'two']
    assert len(records(ledger)) == 2


@pytest.mark.parametrize('events', [[], [{'event': 'a'}] * 3, [None], 'not-a-batch'])
def test_batch_rejects_unbounded_or_malformed_input_without_creating_ledger(ledger, events):
    require_batch()
    with pytest.raises(core.ToolError):
        audit_log.append_many(events)
    assert not ledger.exists()


@pytest.mark.parametrize('damage', ['tamper', 'truncate', 'previous-hash'])
def test_pair_never_appends_to_an_invalid_prefix(ledger, damage):
    require_batch()
    audit_log.append({'event': 'prefix'})
    raw = ledger.read_bytes()
    if damage == 'truncate':
        ledger.write_bytes(raw + b'{"incomplete":')
    else:
        row = json.loads(raw)
        row['event' if damage == 'tamper' else 'previousHash'] = 'changed'
        ledger.write_bytes(json.dumps(row).encode() + b'\n')
    before = ledger.read_bytes()
    with pytest.raises(core.ToolError):
        audit_log.append_many([{'event': 'one'}, {'event': 'two'}])
    assert ledger.read_bytes() == before


def test_static_permit_keeps_both_events_but_checks_prefix_only_once(tmp_path, ledger, monkeypatch):
    service, channel, grant, message = static_service(tmp_path, monkeypatch)
    before = len(records(ledger))
    calls = []
    original = audit_log._verify_records
    def verify(rows):
        calls.append(len(rows))
        return original(rows)
    monkeypatch.setattr(audit_log, '_verify_records', verify)
    assert channel.authorize(message) is True
    assert calls == [before], 'A static permit must not reverify the same prefix for its finish event'
    events = [row['authorization'] for row in records(ledger)[before:]]
    assert [event['event'] for event in events] == ['execution-reserved', 'execution-finished']
    assert events[0]['attempt_id'] == events[1]['attempt_id']
    assert events[1]['state'] == 'verified' and events[1]['summary'] == {'count': 1}
    assert service.broker.grants[grant['grant_id']]['remaining']['static.1'] == 1


def test_static_permission_cannot_escape_before_fsync_finishes(tmp_path, ledger, monkeypatch):
    service, channel, _, message = static_service(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = audit_log.os.fsync
    def hold(descriptor):
        entered.set()
        if not release.wait(5):
            raise TimeoutError('Test did not release durable write')
        return original(descriptor)
    monkeypatch.setattr(audit_log.os, 'fsync', hold)
    result = []
    thread = threading.Thread(target=lambda: result.append(channel.authorize(message)))
    thread.start()
    try:
        assert entered.wait(3)
        assert result == [], 'Worker received permission before durable audit completion'
    finally:
        release.set(); thread.join(5)
    assert not thread.is_alive() and result == [True]
    assert not service.broker.fenced.is_set()


def test_static_fsync_failure_fences_authority_without_allowing_forwarding(tmp_path, ledger, monkeypatch):
    service, channel, _, message = static_service(tmp_path, monkeypatch)
    def fail(_):
        raise OSError('synthetic durability failure')
    monkeypatch.setattr(audit_log.os, 'fsync', fail)
    assert channel.authorize(message) is False
    assert service.broker.fenced.is_set() and not channel.available


def test_revocation_during_pair_commit_still_denies_the_static_request(tmp_path, ledger, monkeypatch):
    service, channel, grant, message = static_service(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = audit_log.os.fsync
    def hold(descriptor):
        entered.set()
        if not release.wait(5):
            raise TimeoutError('Test did not release durable write')
        return original(descriptor)
    monkeypatch.setattr(audit_log.os, 'fsync', hold)
    result = []
    thread = threading.Thread(target=lambda: result.append(channel.authorize(message)))
    thread.start()
    try:
        assert entered.wait(3)
        assert service.broker.revoke(grant['grant_id'])['state'] == 'revoked'
    finally:
        release.set(); thread.join(5)
    deadline = time.monotonic() + 5
    while service.broker.grants[grant['grant_id']].get('revocation_pending') and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not service.broker.grants[grant['grant_id']].get('revocation_pending')
    assert not thread.is_alive() and result == [False]
    assert channel.available, 'An idle scoped revocation must not close unrelated task authority'


def test_separate_process_pairs_cannot_interleave(ledger):
    require_batch()
    code = ("import audit_log,sys;sys.stdin.readline();"
        "audit_log.append_many([{'event':'pair','group':sys.argv[1],'part':1},"
        "{'event':'pair','group':sys.argv[1],'part':2}])")
    env = {**os.environ, 'PYTHONPATH': str(SRC), 'REMOTEX_AUDIT_FILE': str(ledger)}
    children = [subprocess.Popen([sys.executable, '-c', code, group], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) for group in ('alpha', 'beta')]
    try:
        for child in children:
            child.stdin.write(b'go\n'); child.stdin.flush()
        for child in children:
            out, err = child.communicate(timeout=15)
            assert child.returncode == 0, (out, err)
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
    rows = records(ledger)
    assert len(rows) == 4
    assert rows[0]['group'] == rows[1]['group']
    assert rows[2]['group'] == rows[3]['group'] != rows[0]['group']
    assert [row['part'] for row in rows] == [1, 2, 1, 2]


@pytest.mark.parametrize('phase,method,path,resource', [('bootstrap', 'GET', '/a.JS', 'script'),
    ('bootstrap', 'HEAD', '/a.css', 'stylesheet'), ('login-once', 'GET', '/a.js', 'script')])
def test_only_exact_startup_static_permissions_use_the_pair_path(tmp_path, ledger, monkeypatch, phase, method, path, resource):
    descriptor = {'method': method, 'path': path, 'query': {}, 'contentType': '',
        'body': None, 'resourceType': resource}
    _, channel, _, message = static_service(tmp_path, monkeypatch, descriptor=descriptor, phase=phase)
    calls = []
    original = audit_log._verify_records
    def verify(rows):
        calls.append(len(rows)); return original(rows)
    monkeypatch.setattr(audit_log, '_verify_records', verify)
    assert channel.authorize(message) is True
    assert len(calls) == 1


@pytest.mark.parametrize('updates', [{'method': 'POST', 'body': {'cmd': 'init'}},
    {'resourceType': 'xhr'}, {'query': {'version': '1'}}, {'path': '/login'}])
def test_login_exchange_or_nonstatic_requests_keep_the_original_audit_path(tmp_path, ledger, monkeypatch, updates):
    descriptor = {'method': 'GET', 'path': '/a.js', 'query': {}, 'contentType': '',
        'body': None, 'resourceType': 'script', **updates}
    _, channel, _, message = static_service(tmp_path, monkeypatch, descriptor=descriptor, phase='login-once')
    calls = []
    original = audit_log._verify_records
    def verify(rows):
        calls.append(len(rows)); return original(rows)
    monkeypatch.setattr(audit_log, '_verify_records', verify)
    assert channel.authorize(message) is True
    assert len(calls) == 2


def test_other_thread_audit_event_is_not_absorbed_into_the_static_pair(tmp_path, ledger, monkeypatch):
    service, channel, _, message = static_service(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = audit_log.os.fsync
    def hold(descriptor):
        entered.set()
        if not release.wait(5):
            raise TimeoutError('Test did not release durable write')
        return original(descriptor)
    monkeypatch.setattr(audit_log.os, 'fsync', hold)
    result = []
    thread = threading.Thread(target=lambda: result.append(channel.authorize(message)))
    other = threading.Thread(target=lambda: service.broker._event('concurrent-test', count=1))
    thread.start()
    try:
        assert entered.wait(3)
        other.start()
    finally:
        release.set(); thread.join(5)
        if other.ident is not None:
            other.join(5)
    assert not thread.is_alive() and not other.is_alive() and result == [True]
    assert [row['authorization']['event'] for row in records(ledger)[-3:]] == [
        'execution-reserved', 'execution-finished', 'concurrent-test']


def test_partial_pair_write_remains_corrupt_and_never_allows_forwarding(tmp_path, ledger, monkeypatch):
    from contextlib import contextmanager
    service, channel, _, message = static_service(tmp_path, monkeypatch)
    original = audit_log._locked_file
    class PartialWriter:
        def __init__(self, handle):
            self.handle = handle
        def __getattr__(self, name):
            return getattr(self.handle, name)
        def write(self, value):
            self.handle.write(value[:len(value)//2])
            self.handle.flush()
            raise OSError('synthetic partial write')
    @contextmanager
    def partial(path):
        with original(path) as handle:
            yield PartialWriter(handle)
    monkeypatch.setattr(audit_log, '_locked_file', partial)
    assert channel.authorize(message) is False
    assert service.broker.fenced.is_set() and not channel.available
    with ledger.open('rb') as handle, pytest.raises(core.ToolError):
        audit_log._records(handle)


def test_large_audit_static_path_amortizes_verification_without_losing_events(tmp_path, ledger, monkeypatch):
    # Generate inert history directly; using append would make fixture creation quadratic.
    previous = None
    with ledger.open('wb') as handle:
        for _ in range(97000):
            row = {'schema': 'RemoteXAudit/v1', 'timestamp': '2026-10-18T00:00:00Z',
                'sessionId': 'fixture-history', 'event': 'fixture', 'padding': 'x' * 314,
                'previousHash': previous}
            encoded = json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
            row['entryHash'] = hashlib.sha256(encoded).hexdigest()
            previous = row['entryHash']
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode() + b'\n')
    service, channel, prompts = recorded_service(tmp_path, monkeypatch)
    base = channel.request
    descriptors = [{'method': 'GET', 'path': f'/assets/{index}.js', 'query': {},
        'contentType': '', 'body': None, 'resourceType': 'script'} for index in range(49)]
    for offset in (0, 32):
        part = descriptors[offset:offset+32]
        rows = [{**item(f'static.{offset+index}'), 'capability': 'web.page_step', 'max_uses': 1,
            'parameters': {'network_ref': f'static.{offset+index}', 'review_kind': 'bootstrap'},
            'output': {'rows': 0, 'columns': 0, 'bytes': 0}} for index, _ in enumerate(part)]
        contracts = {row['item_id']: {'phase': 'bootstrap', 'semantics': 'bootstrap',
            'descriptor': descriptor, 'targets': []} for row, descriptor in zip(rows, part)}
        channel.request = lambda operation, args, rows=rows, contracts=contracts, **options: (
            {'ok': True, 'items': rows, 'contracts': contracts} if operation == 'resolve-items'
            else base(operation, args, **options))
        service.request({'items': [{}], 'idempotency_key': f'large-{offset}'})
        approve(service, prompts)
    verifications = []
    original = audit_log._verify_records
    def verify(rows):
        verifications.append(len(rows)); return original(rows)
    monkeypatch.setattr(audit_log, '_verify_records', verify)
    started = time.monotonic()
    allowed = [channel.authorize({'kind': 'network', 'phase': 'bootstrap', 'attempt_id': None,
        'descriptor': descriptor, 'digest': 'e' * 64}) for descriptor in descriptors]
    elapsed = time.monotonic() - started
    assert allowed == [True] * 49
    assert len(verifications) == 49
    assert len(records(ledger)) == 97000 + 6 + 98
    print('AUDIT_STARTUP_PERFORMANCE ' + json.dumps({'history_records': 97000,
        'ledger_bytes': ledger.stat().st_size, 'static_permits': 49, 'audit_events': 98,
        'elapsed_seconds': round(elapsed, 3), 'budget_seconds': 45}))
    if os.environ.get('REMOTEX_ASSERT_STARTUP_BUDGET') == '1':
        assert elapsed < 45, 'Representative authorized startup exceeded the unchanged local 45-second budget'
