from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import web_authorization as auth
try:
    import web_authorization_store as storage
except ModuleNotFoundError:
    storage=None


@pytest.fixture
def journal(tmp_path,monkeypatch):
    assert storage is not None,'The protected authorization journal is not implemented'
    # Windows ACL behavior has its own real-path suite; this suite exercises storage.
    monkeypatch.setattr(storage.secure_paths,'ensure_private_directory',lambda p:p.mkdir(parents=True,exist_ok=True))
    monkeypatch.setattr(storage.secure_paths,'ensure_private_file',lambda p:None)
    monkeypatch.setattr(storage.audit_log,'append',lambda event:event)
    return storage.Journal(tmp_path/'authorization')


def test_pending_writes_survive_restart_and_block_overlapping_scope(journal):
    journal.reserve('a'*32,['scope-one'])
    another=storage.Journal(journal.root)
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'):
        another.reserve('b'*32,['scope-one'])
    another.reserve('c'*32,['different-scope'])
    journal.resolve('a'*32)
    another.reserve('d'*32,['scope-one'])


def test_state_contains_no_original_conflict_values_or_authority(journal):
    journal.reserve('a'*32,['private-host-group-canary'])
    raw=journal.state_path.read_text()
    assert 'private-host-group-canary' not in raw
    assert not any(key in raw for key in ['grant_id','nonce','cookie','password'])
    assert len(json.loads(raw)['mac'])==64


def test_tampered_truncated_or_unreadable_state_blocks_writes(journal):
    journal.reserve('a'*32,['scope'])
    content=json.loads(journal.state_path.read_text())
    content['state']['pending']={}
    journal.state_path.write_text(json.dumps(content))
    with pytest.raises(auth.ScopeError,match='audit-incomplete'):
        journal.reserve('b'*32,['scope'])


def test_journal_refuses_unknown_or_sensitive_event_fields(journal):
    with pytest.raises(auth.ScopeError,match='audit-incomplete'):
        journal.append({'event':'execution-finished','text':'private'})


def test_missing_integrity_key_cannot_reinitialize_existing_pending_state(journal):
    journal.reserve('a'*32,['scope'])
    journal.key_path.unlink()
    with pytest.raises(auth.ScopeError,match='audit-incomplete'):
        storage.Journal(journal.root)
