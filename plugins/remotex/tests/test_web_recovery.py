import importlib.util
import json
import os
import sys
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


def test_paired_synthetic_attempts_are_observations_not_empty_history_proof(case):
    event('execution-reserved', capability='web.page_step')
    event('execution-finished', state='verified')
    value = recovery.public_summary(inspect(case)) if recovery else inspect(case)
    assert value['completedAttempts'] == 1
    assert value['historyBasis'] == 'owner-review-required'


def test_unknown_historical_profile_cannot_be_omitted(case):
    audit_log.append({'event': 'operation-start', 'operationId': 'op', 'tool': 'remotex_web_execute',
        'request': {'profileSha256': 'f' * 64}})
    with pytest.raises(ScopeError, match='recovery-scope-unknown'): inspect(case)


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
