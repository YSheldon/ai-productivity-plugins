import importlib.util
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

PLUGIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PLUGIN/'src'))
import web_authorization_store as storage
import web_adapter
from web_authorization import ScopeError


@pytest.fixture
def root(tmp_path,monkeypatch):
    monkeypatch.setattr(storage.secure_paths,'ensure_private_directory',lambda p:p.mkdir(parents=True,exist_ok=True))
    monkeypatch.setattr(storage.secure_paths,'ensure_private_file',lambda p:None)
    monkeypatch.setattr(storage.audit_log,'append',lambda event:event)
    return tmp_path/'authorization'


def legacy_type():
    spec=importlib.util.spec_from_file_location('legacy_recovery_069',PLUGIN/'tests/fixtures/web_authorization_store_069.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.Journal


def test_preview_new_store_does_not_create_anything(root):
    result=storage.upgrade_protocol(root,check_idle=lambda:True,confirm=False)
    assert result['canUpgrade'] and result['protocolVersion']==0
    assert not root.exists()


def test_preview_existing_store_does_not_adjust_permissions_or_mutate(root):
    journal=storage.Journal(root)
    before={p.name:p.read_bytes() for p in root.iterdir()}
    with mock.patch.object(storage.secure_paths,'ensure_private_directory',side_effect=AssertionError('preview wrote')), \
         mock.patch.object(storage.secure_paths,'ensure_private_file',side_effect=AssertionError('preview wrote')):
        result=storage.upgrade_protocol(root,check_idle=lambda:True,confirm=False)
    assert result['canUpgrade'] and result['protocolVersion']==1
    assert before=={p.name:p.read_bytes() for p in root.iterdir()}
    with pytest.raises(ScopeError,match='recovery-upgrade-required'):journal.require_site_protocol()
    with pytest.raises(ScopeError,match='recovery-upgrade-required'):journal.reserve_site('a'*32,'https://console.example')


@pytest.mark.parametrize('unknown',[False,True])
def test_busy_or_unknown_web_lifecycle_refuses_upgrade_without_change(root,unknown):
    journal=storage.Journal(root);before=journal.state_path.read_bytes()
    def idle():
        if unknown:raise OSError('unknown lifecycle')
        return False
    result=storage.upgrade_protocol(root,check_idle=idle,confirm=True)
    assert result['state']=='blocked' and not result['ready']
    assert journal.state_path.read_bytes()==before


def test_pending_old_writer_prevents_protocol_upgrade(root):
    journal=storage.Journal(root);journal.reserve('a'*32,['object'])
    before=journal.state_path.read_bytes()
    result=storage.upgrade_protocol(root,check_idle=lambda:True,confirm=True)
    assert result['state']=='blocked' and result['reason']=='unresolved-prior-write'
    assert journal.state_path.read_bytes()==before


def test_explicit_upgrade_blocks_actual_cached_and_fresh_069_writers(root):
    current=storage.Journal(root);old=legacy_type()(root);key=current.key_path.read_bytes()
    assert storage.upgrade_protocol(root,check_idle=lambda:True,confirm=True)['ready']
    assert current.key_path.read_bytes()==key
    current.reserve_site('a'*32,'https://console.example')
    with pytest.raises(ScopeError,match='audit-incomplete'):old.reserve('b'*32,['same-origin-record'])
    with pytest.raises(ScopeError,match='audit-incomplete'):legacy_type()(root)
    current.resolve('a'*32)
    assert current._load()['version']==2
    with pytest.raises(ScopeError,match='audit-incomplete'):old.reserve('c'*32,['later-old-session'])


def test_explicit_pristine_store_initializes_directly_as_v2(root):
    assert storage.upgrade_protocol(root,check_idle=lambda:True,confirm=True)['ready']
    assert storage.Journal(root)._load()=={'version':2,'pending':{}}


def test_precommit_replace_failure_preserves_v1_and_key(root,monkeypatch):
    journal=storage.Journal(root);state=journal.state_path.read_bytes();key=journal.key_path.read_bytes()
    monkeypatch.setattr(storage.os,'replace',mock.Mock(side_effect=OSError('replace failed')))
    with pytest.raises(ScopeError,match='audit-incomplete'):
        storage.upgrade_protocol(root,check_idle=lambda:True,confirm=True)
    assert journal.state_path.read_bytes()==state and journal.key_path.read_bytes()==key


def test_postcommit_audit_failure_never_restores_v1(root,monkeypatch):
    journal=storage.Journal(root)
    monkeypatch.setattr(storage.audit_log,'append',mock.Mock(side_effect=OSError('audit unavailable')))
    result=storage.upgrade_protocol(root,check_idle=lambda:True,confirm=True)
    assert result['state']=='committed-unverified' and result['committed'] and not result['ready']
    assert journal._load()['version']==2


@pytest.mark.parametrize('remove',['key','state'])
def test_missing_existing_material_is_not_recreated(root,remove):
    journal=storage.Journal(root)
    (journal.key_path if remove=='key' else journal.state_path).unlink()
    before={p.name:p.read_bytes() for p in root.iterdir()}
    with pytest.raises(ScopeError,match='audit-incomplete'):
        storage.upgrade_protocol(root,check_idle=lambda:True,confirm=True)
    assert before=={p.name:p.read_bytes() for p in root.iterdir()}


def test_corrupt_state_cannot_downgrade_or_upgrade(root):
    journal=storage.Journal(root);journal.state_path.write_text('{}')
    with pytest.raises(ScopeError,match='audit-incomplete'):
        storage.upgrade_protocol(root,check_idle=lambda:True,confirm=True)
    assert json.loads(journal.state_path.read_text())=={}


def test_actual_069_key_only_layout_requires_separate_recovery_and_is_not_reset(root):
    legacy=legacy_type()(root)
    assert legacy.key_path.exists() and not legacy.state_path.exists()
    before={p.name:p.read_bytes() for p in root.iterdir()}
    for confirm in (False,True):
        with pytest.raises(ScopeError,match='audit-incomplete'):
            storage.upgrade_protocol(root,check_idle=lambda:True,confirm=confirm)
        assert before=={p.name:p.read_bytes() for p in root.iterdir()}


def test_legacy_writer_racing_inside_commit_recheck_blocks_upgrade(root):
    current=storage.Journal(root);old=legacy_type()(root);calls=[]
    def idle():
        calls.append(1)
        return True
    original=storage.vm_queue._exclusive_lock
    competing=[False]
    from contextlib import contextmanager
    @contextmanager
    def lock(path,label):
        if not calls:raise AssertionError('preview must precede commit')
        if not competing[0]:
            competing[0]=True
            old.reserve('a'*32,['racing-write'])
        with original(path,label):yield
    with mock.patch.object(storage.vm_queue,'_exclusive_lock',lock):
        result=storage.upgrade_protocol(root,check_idle=idle,confirm=True)
    assert result['state']=='blocked' and current._load()['version']==1


def test_read_only_lifecycle_scan_never_cleans_markers_or_takes_queue_locks(root,monkeypatch):
    state=root.parent/'web';active=state/'active';active.mkdir(parents=True)
    marker={'webSessionId':'a'*32,'processId':123,'supervisorId':456}
    path=active/('b'*64+'.json');path.write_text(json.dumps(marker))
    monkeypatch.setenv('REMOTEX_WEB_STATE_DIR',str(state))
    monkeypatch.setattr(web_adapter,'_running_or_unknown',lambda pid:True)
    with mock.patch.object(web_adapter.queue_leases,'_locked',side_effect=AssertionError('reverse lock')), \
         mock.patch.object(web_adapter.vm_queue,'_locked_state',side_effect=AssertionError('reverse lock')):
        assert not web_adapter._upgrade_web_idle()
        directory=state/'sessions'/marker['webSessionId'];directory.mkdir(parents=True)
        (directory/'closed.json').write_text(json.dumps(marker))
        assert web_adapter._upgrade_web_idle()
    assert json.loads(path.read_text())==marker


@pytest.mark.parametrize('contents',['{}','not-json'])
def test_unknown_lifecycle_blocks_without_cleanup(root,monkeypatch,contents):
    state=root.parent/'web';active=state/'active';active.mkdir(parents=True)
    path=active/('b'*64+'.json');path.write_text(contents)
    monkeypatch.setenv('REMOTEX_WEB_STATE_DIR',str(state))
    result=web_adapter.authorization_upgrade({'confirm':True})
    value=json.loads(result['content'][0]['text'])
    assert value['state']=='blocked' and path.read_text()==contents
    assert not (state/'authorization').exists()
