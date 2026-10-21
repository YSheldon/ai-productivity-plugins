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


def test_site_reservation_preserves_legacy_uncertainty_and_blocks_new_granular_writes(journal):
    journal.reserve('a'*32,[auth.digest(['https://console.example','record-1'])])
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'):
        journal.reserve_site('b'*32,'https://console.example')
    journal.resolve('a'*32)
    journal.reserve_site('b'*32,'https://console.example')
    restarted=storage.Journal(journal.root)
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'):
        restarted.reserve('c'*32,[auth.digest(['https://console.example','record-2'])])
    restarted.resolve('b'*32)
    restarted.reserve('d'*32,['ordinary-legacy-scope'])


@pytest.mark.parametrize('first,second',[('site','granular'),('granular','site'),('site','site')])
def test_typed_site_reservations_do_not_block_another_origin(journal,first,second):
    def reserve(kind,identity,origin,target):
        if kind=='site': journal.reserve_site(identity,origin)
        else: journal.reserve_origin(identity,[auth.digest([origin,target])],origin)
    reserve(first,'a'*32,'https://first.example','record-1')
    reserve(second,'b'*32,'https://second.example','record-1')
    assert len(journal._load()['pending'])==2


@pytest.mark.parametrize('first,second',[('site','granular'),('granular','site'),('site','site')])
def test_typed_broad_scope_conflicts_with_same_origin(journal,first,second):
    def reserve(kind,identity,target):
        if kind=='site': journal.reserve_site(identity,'https://console.example')
        else: journal.reserve_origin(identity,[auth.digest(['https://console.example',target])],'https://console.example')
    reserve(first,'a'*32,'record-1')
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'): reserve(second,'b'*32,'record-2')


def test_typed_granular_preserves_object_scope_and_opaque_legacy_protection(journal):
    origin='https://console.example'
    journal.reserve('a'*32,[auth.digest([origin,'record-1'])])
    journal.reserve_origin('b'*32,[auth.digest([origin,'record-2'])],origin)
    journal.reserve_origin('e'*32,[auth.digest([origin,'record-3'])],origin)
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'):
        journal.reserve_origin('c'*32,[auth.digest([origin,'record-1'])],origin)
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'):
        journal.reserve_site('d'*32,'https://other.example')


@pytest.mark.parametrize('kind,tail',[
    ('site-origin-reservation-v1',[]),('site-origin-reservation-v1',['a'*64,'b'*64]),
    ('object-origin-reservation-v1',['a'*64]),('site-session-reservation-v1',['a'*64]),
])
def test_malformed_typed_recovery_records_fail_closed(journal,kind,tail):
    row=[journal._mac({'kind':kind}),*tail]
    journal._write({'version':1,'pending':{'a'*32:row}})
    with pytest.raises(auth.ScopeError,match='audit-incomplete'):
        journal.reserve_origin('b'*32,['new-object'],'https://console.example')


def test_earlier_unscoped_site_marker_remains_fenced_until_resolved(journal):
    row=[journal._mac(storage.SITE_SESSION_CONFLICT)]
    journal._write({'version':1,'pending':{'a'*32:row}})
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'):
        journal.reserve_origin('b'*32,['object'],'https://console.example')
    journal.resolve('a'*32)
    journal.reserve_origin('b'*32,['object'],'https://console.example')


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
