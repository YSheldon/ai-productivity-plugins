import importlib.util
import json
import os
import sys
import threading
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN / 'src'))
import audit_log
import web_authorization_store as storage
from web_authorization import ScopeError
try:
    import web_recovery as recovery
except ModuleNotFoundError:
    recovery = None

WEB_SCOPE = [{'profile': 'console', 'origin': 'https://console.example', 'account': 'operator'}]


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setattr(storage.secure_paths, 'ensure_private_directory', lambda p: p.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(storage.secure_paths, 'ensure_private_file', lambda p: None)
    ledger = tmp_path / 'audit.jsonl'
    ledger.write_bytes(b'')
    monkeypatch.setenv('REMOTEX_AUDIT_FILE', str(ledger))
    monkeypatch.setenv('REMOTEX_WEB_STATE_DIR', str(tmp_path))
    spec = importlib.util.spec_from_file_location('recovery_legacy_069', PLUGIN / 'tests/fixtures/web_authorization_store_069.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    old = module.Journal(tmp_path / 'authorization')
    return old, ledger


def inspect(case, **overrides):
    assert recovery is not None, 'Legacy owner-review recovery is not implemented'
    old, ledger = case
    return recovery.inspect_legacy_state(old.root, audit_path=ledger, scope=WEB_SCOPE,
        check_idle=overrides.pop('check_idle', lambda: True), **overrides)


def snapshot(root):
    return {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns) for p in root.iterdir() if p.is_file()}


def event(name, **fields):
    audit_log.append({'event': 'operation-start', 'tool': 'remotex_web_login',
        'operationId': 'synthetic-scope', 'request': {'profileSha256': __import__('hashlib').sha256(b'console').hexdigest()}})
    return audit_log.append({'event': 'web-authorization', 'authorization': {
        'event': name, 'binding_digest': 'b' * 64, 'attempt_id': 'a' * 32, **fields}})


def test_key_only_preview_is_not_proof_of_empty_history(case, monkeypatch):
    before = snapshot(case[0].root)
    monkeypatch.setattr(storage.secure_paths, 'ensure_private_directory', lambda p: pytest.fail('preview changed directory'))
    monkeypatch.setattr(storage.secure_paths, 'ensure_private_file', lambda p: pytest.fail('preview changed file'))
    value = recovery.public_summary(inspect(case)) if recovery else inspect(case)
    assert value['historyBasis'] == 'owner-review-required'
    assert value['classification'] == 'key-only-ambiguous'
    assert value['scopeCount'] == 1
    assert snapshot(case[0].root) == before
    assert not case[0].state_path.exists()
    assert 'ledger_checkpoint' not in json.dumps(value)


@pytest.mark.parametrize('layout', ['missing-key', 'short-key', 'v1', 'v2', 'corrupt-state'])
def test_unsupported_layouts_never_reset(case, layout):
    old, _ = case
    if layout == 'missing-key': old.key_path.unlink()
    elif layout == 'short-key': old.key_path.write_bytes(b'x')
    else:
        old._write({'version': 1, 'pending': {}})
        if layout == 'v2':
            current = storage.Journal.existing(old.root)
            current._write({'version': 2, 'pending': {}})
        if layout == 'corrupt-state': old.state_path.write_bytes(b'{}')
    before = snapshot(old.root)
    with pytest.raises(ScopeError): inspect(case)
    assert snapshot(old.root) == before


@pytest.mark.parametrize('raw', [b'{', b'{}\n', b'\x00{', b'{"entryHash":"wrong"}\n'])
def test_corrupt_or_incomplete_audit_refuses_preview(case, raw):
    case[1].write_bytes(raw)
    with pytest.raises(ScopeError, match='recovery-evidence-invalid'): inspect(case)


@pytest.mark.parametrize('state', [None, 'outcome-unknown', 'partially-verified'])
def test_unfinished_or_unknown_attempt_blocks_even_with_balanced_counts(case, state):
    event('execution-reserved', capability='web.business_action')
    if state: event('execution-finished', state=state)
    with pytest.raises(ScopeError, match='recovery-unresolved-write'): inspect(case)


def test_result_for_different_identity_does_not_reconcile_write(case):
    event('execution-reserved', capability='web.business_action')
    event('execution-finished', attempt_id='c' * 32, state='verified')
    with pytest.raises(ScopeError, match='recovery-unresolved-write'): inspect(case)


def test_paired_attempts_still_require_historical_scope_proof(case):
    event('execution-reserved', capability='web.page_step')
    event('execution-finished', state='verified')
    with pytest.raises(ScopeError, match='recovery-scope-unknown'): inspect(case)


def test_unknown_historical_profile_cannot_be_omitted(case):
    audit_log.append({'event': 'operation-start', 'operationId': 'op', 'tool': 'remotex_web_execute',
        'request': {'profileSha256': 'f' * 64}})
    with pytest.raises(ScopeError, match='recovery-scope-unknown'): inspect(case)


def test_unexplained_historical_binding_blocks_owner_override(case):
    audit_log.append({'event': 'web-authorization', 'authorization': {
        'event': 'task-requested', 'binding_digest': 'f' * 64}})
    with pytest.raises(ScopeError, match='recovery-scope-unknown'): inspect(case)


def test_known_profile_in_same_mcp_does_not_prove_historical_origin_or_account(case):
    event('task-requested')
    with pytest.raises(ScopeError, match='recovery-scope-unknown'): inspect(case)


def test_missing_historical_binding_is_not_treated_as_no_scope(case):
    audit_log.append({'event': 'web-authorization', 'authorization': {'event': 'task-requested'}})
    with pytest.raises(ScopeError, match='recovery-scope-unknown'): inspect(case)


def test_malformed_authorization_record_returns_fixed_error(case):
    audit_log.append({'event': 'web-authorization', 'authorization': []})
    with pytest.raises(ScopeError, match='recovery-evidence-invalid'): inspect(case)


@pytest.mark.parametrize('idle', [False, None])
def test_busy_or_unknown_lifecycle_blocks_without_mutation(case, idle):
    before = snapshot(case[0].root)
    with pytest.raises(ScopeError, match='recovery-busy'): inspect(case, check_idle=lambda: idle)
    assert snapshot(case[0].root) == before


def test_preview_rejects_reparse_paths(case, monkeypatch):
    monkeypatch.setattr(storage.secure_paths, '_reparse_point', lambda p: p == case[0].key_path)
    with pytest.raises(ScopeError, match='recovery-evidence-invalid'): inspect(case)


def test_unrelated_append_is_tolerated_but_web_activity_is_stale(case):
    evidence = inspect(case)
    audit_log.append({'event': 'operation-start', 'tool': 'remotex_ssh_exec', 'operationId': 'ssh'})
    recovery.recheck_legacy_evidence(evidence, audit_path=case[1], scope=WEB_SCOPE, check_idle=lambda: True)
    audit_log.append({'event': 'operation-start', 'tool': 'remotex_web_login', 'operationId': 'web'})
    with pytest.raises(ScopeError, match='recovery-stale'):
        recovery.recheck_legacy_evidence(evidence, audit_path=case[1], scope=WEB_SCOPE, check_idle=lambda: True)


@pytest.mark.parametrize('change', ['key', 'scope', 'ledger', 'destination'])
def test_changed_review_inputs_require_new_preview(case, change):
    audit_log.append({'event': 'synthetic-evidence'})
    evidence = inspect(case)
    scope = WEB_SCOPE
    if change == 'key': case[0].key_path.write_bytes(b'x' * 32)
    elif change == 'scope': scope = []
    elif change == 'ledger': case[1].write_bytes(b'')
    else: case[0].state_path.write_bytes(b'new-owner')
    with pytest.raises(ScopeError):
        recovery.recheck_legacy_evidence(evidence, audit_path=case[1], scope=scope, check_idle=lambda: True)


def commit(case, **overrides):
    evidence = inspect(case)
    return recovery.recover_key_only_v2(evidence, recovery_id='d' * 32,
        before_publish=overrides.pop('before_publish', lambda: None),
        backup_root=case[0].root.parent / 'backups', **overrides)


def test_owner_reviewed_commit_preserves_key_and_publishes_standard_v2(case):
    key = case[0].key_path.read_bytes()
    result = commit(case)
    assert result['state'] == 'ready' and result['committed']
    assert case[0].key_path.read_bytes() == key
    assert storage.Journal.existing(case[0].root)._load() == {'version': 2, 'pending': {}}
    backup = case[0].root.parent / 'backups' / ('d' * 32)
    assert (backup / 'integrity.key').read_bytes() == key
    receipt = json.loads((case[0].root / ('recovery-' + 'd' * 32 + '.json')).read_text())
    assert receipt['receipt']['kind'] == 'legacy-key-only-recovery-receipt-v1'
    assert receipt['receipt']['phase'] == 'finalization-intent'
    assert 'nonce' not in json.dumps(receipt)
    with pytest.raises(ScopeError, match='audit-incomplete'):
        type(case[0])(case[0].root)


@pytest.mark.parametrize('point', ['publish', 'receipt', 'audit', 'resolve'])
def test_faults_never_reset_or_downgrade_state(case, monkeypatch, point):
    key = case[0].key_path.read_bytes()
    if point == 'publish':
        original_publish = storage._publish_no_replace
        def publish(source, destination):
            if destination == case[0].state_path: raise OSError('state publication')
            return original_publish(source, destination)
        monkeypatch.setattr(storage, '_publish_no_replace', publish)
    elif point == 'receipt':
        original = recovery._save_receipt
        def save(journal, value):
            if value['phase'] == 'finalization-intent': raise OSError('disk')
            return original(journal, value)
        monkeypatch.setattr(recovery, '_save_receipt', save)
    elif point == 'audit':
        monkeypatch.setattr(storage.Journal, 'append', lambda *a: (_ for _ in ()).throw(OSError('audit')))
    else:
        original = storage.Journal._write
        def write(journal, state, **kwargs):
            if not state['pending']: raise OSError('resolve')
            return original(journal, state, **kwargs)
        monkeypatch.setattr(storage.Journal, '_write', write)
    if point == 'publish':
        with pytest.raises(ScopeError): commit(case)
        assert not case[0].state_path.exists()
    else:
        result = commit(case)
        assert result['state'] == 'committed-unverified'
        current = storage.Journal.existing(case[0].root)
        assert current._load()['version'] == 2
        with pytest.raises(ScopeError, match='unresolved-prior-write'):
            current.reserve_site('b' * 32, 'https://other.example')
    assert case[0].key_path.read_bytes() == key


def test_destination_appearing_immediately_before_publish_is_never_overwritten(case, monkeypatch):
    original = storage._publish_no_replace
    def racing(source, destination):
        if destination == case[0].state_path: destination.write_bytes(b'competing-state')
        return original(source, destination)
    monkeypatch.setattr(storage, '_publish_no_replace', racing)
    with pytest.raises(ScopeError): commit(case)
    assert case[0].state_path.read_bytes() == b'competing-state'


@pytest.mark.parametrize('cancel_at', [1, 2, 3])
def test_cancel_or_expiry_at_commit_boundaries_never_grants_or_clears(case, cancel_at):
    count = [0]
    def live():
        count[0] += 1
        if count[0] >= cancel_at: raise ScopeError('review-expired')
    try:
        result = commit(case, before_publish=live)
        assert result['state'] == 'committed-unverified'
        assert storage.Journal.existing(case[0].root)._load()['pending']
    except ScopeError:
        assert not case[0].state_path.exists()


def test_interrupted_finalize_needs_new_native_callback_and_keeps_later_writes(case, monkeypatch):
    original = storage.Journal.append
    monkeypatch.setattr(storage.Journal, 'append', lambda *a: (_ for _ in ()).throw(OSError('audit')))
    assert commit(case)['state'] == 'committed-unverified'
    monkeypatch.setattr(storage.Journal, 'append', original)
    evidence = recovery.inspect_interrupted_recovery(case[0].root, 'd' * 32,
        audit_path=case[1], scope=WEB_SCOPE, check_idle=lambda: True)
    before = snapshot(case[0].root)
    assert recovery.read_recovery_status(case[0].root, 'd' * 32)['state'] == 'committed-unverified'
    assert snapshot(case[0].root) == before
    result = recovery.finalize_recovery_v2(evidence, recovery_id='d' * 32, before_publish=lambda: None)
    assert result['state'] == 'ready'
    journal = storage.Journal.existing(case[0].root)
    journal.reserve_site('e' * 32, 'https://console.example')
    before = journal.state_path.read_bytes()
    assert recovery.read_recovery_status(case[0].root, 'd' * 32)['state'] == 'ready'
    assert journal.state_path.read_bytes() == before


def test_receipt_missing_or_other_pending_entry_cannot_be_finalized(case, monkeypatch):
    monkeypatch.setattr(storage.Journal, 'append', lambda *a: (_ for _ in ()).throw(OSError('audit')))
    commit(case)
    journal = storage.Journal.existing(case[0].root)
    state = journal._load()
    state['pending']['e' * 32] = [journal._mac(storage.SITE_SESSION_CONFLICT)]
    journal._write(state)
    with pytest.raises(ScopeError, match='recovery-unresolved-write'):
        recovery.inspect_interrupted_recovery(case[0].root, 'd' * 32,
            audit_path=case[1], scope=WEB_SCOPE, check_idle=lambda: True)
    (case[0].root / ('recovery-' + 'd' * 32 + '.json')).unlink()
    with pytest.raises(ScopeError): recovery.read_recovery_status(case[0].root, 'd' * 32)


def test_expiry_during_final_state_fsync_keeps_technical_fence(case, monkeypatch):
    expired = [False]
    original = os.fsync
    def fsync(descriptor):
        original(descriptor)
        for path in case[0].root.glob('state-*.tmp'):
            if b'"pending":{}' in path.read_bytes(): expired[0] = True
    monkeypatch.setattr(os, 'fsync', fsync)
    def live():
        if expired[0]: raise ScopeError('review-expired')
    result = commit(case, before_publish=live)
    assert result['state'] == 'committed-unverified'
    assert result['fenceVerified'] is True
    assert storage.Journal.existing(case[0].root)._load()['pending']


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows no-replacement primitive')
def test_real_windows_publish_does_not_replace_existing_destination(tmp_path):
    source, destination = tmp_path / 'source', tmp_path / 'destination'
    source.write_bytes(b'candidate')
    destination.write_bytes(b'winner')
    with pytest.raises(OSError): storage._publish_no_replace(source, destination)
    assert source.read_bytes() == b'candidate' and destination.read_bytes() == b'winner'
    destination.unlink()
    storage._publish_no_replace(source, destination)
    assert not source.exists() and destination.read_bytes() == b'candidate'


def service_case(case):
    now, prompts = [100.0], []
    class Prompt:
        @classmethod
        def start(cls, manifest, **callbacks):
            prompts.append((manifest, callbacks))
            return cls()
        def stop(self, reason='stopped'): pass
        def status(self): return {'state': 'shown', 'shown': True}
    service = recovery.RecoveryService(case[0].root, audit_path=case[1], scope=lambda: WEB_SCOPE,
        check_idle=lambda: True, prompt=Prompt, clock=lambda: now[0])
    return service, prompts, now


def native_decision(prompts, **updates):
    manifest, callbacks = prompts[-1]
    frame = {k: manifest[k] for k in ('request_id', 'nonce', 'request_digest')}
    frame.update(event='decision', owner_reviewed=True)
    frame.update(updates)
    return callbacks['on_decision'](frame)


def test_confirm_argument_only_opens_one_native_review(case):
    service, prompts, now = service_case(case)
    preview = service.preview()
    identity = preview['recovery_id']
    first = service.open(identity)
    now[0] += 10
    second = service.open(identity)
    assert first['state'] == second['state'] == 'pending'
    assert second['review_remaining_seconds'] == first['review_remaining_seconds'] - 10
    assert len(prompts) == 1 and not case[0].state_path.exists()
    assert service.preview()['recovery_id'] == identity


@pytest.mark.parametrize('change', ['nonce', 'request_digest', 'request_id', 'owner_reviewed', 'public_field'])
def test_private_decision_binding_cannot_be_forged(case, change):
    service, prompts, _ = service_case(case)
    service.open(service.preview()['recovery_id'])
    update = {change: False if change == 'owner_reviewed' else 'forged'}
    with pytest.raises(ScopeError): native_decision(prompts, **update)
    assert not case[0].state_path.exists()


def test_private_owner_decision_commits_no_site_authority_and_cannot_be_reused(case):
    service, prompts, _ = service_case(case)
    identity = service.preview()['recovery_id']
    service.open(identity)
    result = native_decision(prompts)
    assert result['state'] == 'ready' and 'grant_id' not in result
    assert service.status(identity)['state'] == 'ready'
    before = snapshot(case[0].root)
    prompts[-1][1]['on_revoke']()
    with pytest.raises(ScopeError): native_decision(prompts)
    assert snapshot(case[0].root) == before


@pytest.mark.parametrize('stop', ['cancel', 'expiry', 'changed-scope'])
def test_pending_review_cannot_outlive_original_authority(case, stop):
    service, prompts, now = service_case(case)
    identity = service.preview()['recovery_id']
    service.open(identity)
    if stop == 'cancel': service.cancel()
    elif stop == 'expiry': now[0] += 181
    else: service.scope = lambda: []
    with pytest.raises(ScopeError): native_decision(prompts)
    assert not case[0].state_path.exists()


def test_unknown_recovery_id_does_not_reconstruct_approval(case):
    service, prompts, _ = service_case(case)
    with pytest.raises(ScopeError): service.open('f' * 32)
    assert not prompts


def test_mcp_recovery_preview_audits_invocation_without_mutating_store(case, monkeypatch):
    import remotex_mcp
    import web_adapter
    from types import SimpleNamespace
    monkeypatch.setattr(web_adapter, 'state_root', lambda: case[0].root.parent)
    monkeypatch.setattr(web_adapter, '_RECOVERY_SERVICE', None, raising=False)
    monkeypatch.setattr(web_adapter.core, 'load_config', lambda: SimpleNamespace(data={'profiles': {
        'console': {'kind': 'web', 'origin': 'https://console.example', 'account': 'operator'}}}))
    before = snapshot(case[0].root)
    response = remotex_mcp.handle_request({'jsonrpc': '2.0', 'id': 22, 'method': 'tools/call',
        'params': {'name': 'remotex_web_authorization_recovery', 'arguments': {'confirm': False}}})
    value = response['result']
    assert not value.get('isError'), value
    payload = json.loads(value['content'][0]['text'])
    assert payload['classification'] == 'key-only-ambiguous'
    assert snapshot(case[0].root) == before
    assert case[1].stat().st_size > 0


def test_cancel_during_fsync_is_observed_without_waiting_for_service_lock(case, monkeypatch):
    service, prompts, _ = service_case(case)
    service.open(service.preview()['recovery_id'])
    original = os.fsync
    def cancel(descriptor):
        original(descriptor)
        if any(b'"pending":{}' in p.read_bytes() for p in case[0].root.glob('state-*.tmp')):
            service.cancel()
    monkeypatch.setattr(os, 'fsync', cancel)
    result = native_decision(prompts)
    assert result['state'] == 'committed-unverified' and result['fenceVerified']


def test_restarted_service_reconstructs_evidence_not_approval(case, monkeypatch):
    original = storage.Journal.append
    monkeypatch.setattr(storage.Journal, 'append', lambda *a: (_ for _ in ()).throw(OSError('audit')))
    assert commit(case)['state'] == 'committed-unverified'
    monkeypatch.setattr(storage.Journal, 'append', original)
    service, prompts, _ = service_case(case)
    preview = service.preview()
    assert preview['classification'] == 'interrupted-owner-reviewed-recovery'
    assert not prompts
    before = snapshot(case[0].root)
    service.open(preview['recovery_id'])
    assert snapshot(case[0].root) == before
    assert native_decision(prompts)['state'] == 'ready'


def test_status_does_not_hold_service_lock_while_reading_native_status(case):
    service, prompts, _ = service_case(case)
    identity = service.preview()['recovery_id']
    service.open(identity)
    entered, release, cancelled = threading.Event(), threading.Event(), threading.Event()
    def status():
        entered.set(); release.wait(3)
        return {'state': 'shown'}
    service.prompt.status = status
    reader = threading.Thread(target=lambda: service.status(identity))
    reader.start()
    assert entered.wait(1)
    canceller = threading.Thread(target=lambda: (service.cancel(), cancelled.set()))
    canceller.start()
    try:
        assert cancelled.wait(0.5), 'Native status blocked service cancellation'
    finally:
        release.set(); reader.join(3); canceller.join(3)


def test_stale_unopened_preview_can_be_replaced_without_process_restart(case):
    service, prompts, _ = service_case(case)
    first = service.preview()
    audit_log.append({'event': 'operation-start', 'tool': 'remotex_web_login', 'operationId': 'new-web-observation',
        'request': {'profileSha256': __import__('hashlib').sha256(b'console').hexdigest()}})
    with pytest.raises(ScopeError, match='recovery-stale'): service.open(first['recovery_id'])
    second = service.preview()
    assert second['recovery_id'] != first['recovery_id']
    assert not prompts and not case[0].state_path.exists()


def test_late_callback_from_old_helper_cannot_cancel_fresh_finalize_review(case, monkeypatch):
    service, prompts, _ = service_case(case)
    identity = service.preview()['recovery_id']
    service.open(identity)
    old_cancel = prompts[-1][1]['on_cancel']
    original = storage.Journal.append
    monkeypatch.setattr(storage.Journal, 'append', lambda *a: (_ for _ in ()).throw(OSError('audit')))
    assert native_decision(prompts)['state'] == 'committed-unverified'
    monkeypatch.setattr(storage.Journal, 'append', original)
    service.preview()
    service.open(identity)
    old_cancel()
    assert service.status(identity)['state'] == 'pending'
    assert not service.cancelled.is_set()


def test_terminal_status_authenticates_disk_instead_of_reusing_cached_ready(case):
    service, prompts, _ = service_case(case)
    identity = service.preview()['recovery_id']
    service.open(identity)
    assert native_decision(prompts)['state'] == 'ready'
    case[0].state_path.write_bytes(b'corrupt')
    with pytest.raises(ScopeError): service.status(identity)


def test_restart_rejects_replaced_ledger_even_when_new_chain_is_valid(case, monkeypatch):
    audit_log.append({'event': 'synthetic-original-checkpoint'})
    monkeypatch.setattr(storage.Journal, 'append', lambda *a: (_ for _ in ()).throw(OSError('audit')))
    assert commit(case)['state'] == 'committed-unverified'
    case[1].write_bytes(b'')
    with pytest.raises(ScopeError, match='recovery-stale'):
        recovery.inspect_interrupted_recovery(case[0].root, 'd' * 32,
            audit_path=case[1], scope=WEB_SCOPE, check_idle=lambda: True)


@pytest.mark.parametrize('args', [{'approved': True}, {'owner_reviewed': True}, {'force': True}, {'root': 'other'}, {'confirm': True}, {'recovery_id': '../key'}])
def test_public_recovery_arguments_never_supply_authority(case, args):
    import web_adapter
    with pytest.raises(Exception): web_adapter.authorization_recovery(args)
    assert not case[0].state_path.exists()
