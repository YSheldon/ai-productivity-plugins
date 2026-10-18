import io
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_web_authorization import prepared, approve, item
from test_web_task_service import prepared as service_prepared, approve as service_approve
import web_authorization as auth


def test_network_effect_needs_an_independent_native_classification(prepared):
    broker,*_=prepared
    row=item('network');row['parameters']={'network_ref':'network','review_kind':'unclassified'}
    request=broker.request([row],idempotency_key='unclassified')
    manifest=broker.approval_manifest(request['request_id'])
    base={'item_id':'network','max_uses':1,'targets':[]}
    for choice in (base,{**base,'semantic_classification':'write'}):
        with pytest.raises(auth.ScopeError,match='decision-invalid'):
            broker.accept_decision(request['request_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],
                choices=[choice],ttl_seconds=60)
    approved=broker.accept_decision(request['request_id'],nonce=manifest['nonce'],digest=manifest['request_digest'],
        choices=[{**base,'semantic_classification':'read'}],ttl_seconds=60)
    _,scope=broker._grant(approved['grant_id'],'network')
    assert scope['parameters']['approved_semantics']=='read'


def test_field_alias_cannot_bypass_an_unresolved_write(prepared):
    broker,*_=prepared
    first=item('write',write=True,targets=['host-one'])
    first['effect']['fields']=['group']
    grant=approve(broker,[first],key='first')
    attempt=broker.reserve(grant['grant_id'],'write','write-once',{})
    broker.finish(attempt['attempt_id'],state='outcome-unknown',summary={})
    renamed=item('write',write=True,targets=['host-one'])
    renamed['effect']['fields']=['different_label']
    second=approve(broker,[renamed],key='second')
    with pytest.raises(auth.ScopeError,match='unresolved-prior-write'):
        broker.reserve(second['grant_id'],'write','another-key',{})


def test_revoked_prerequisites_block_reservation_and_already_reserved_dispatch(prepared):
    broker,*_=prepared
    grant=approve(broker,[item('read'),item('next',depends=['read'])])
    first=broker.reserve(grant['grant_id'],'read','read-once',{})
    broker.finish(first['attempt_id'],state='verified',summary={})
    second=broker.reserve(grant['grant_id'],'next','next-once',{})
    broker.revoke(grant['grant_id'],['read'])
    with pytest.raises(auth.ScopeError,match='dependency-blocked|grant-revoked'):
        broker.authorize_attempt(second['attempt_id'])
    with pytest.raises(auth.ScopeError,match='dependency-blocked|grant-revoked'):
        broker.reserve(grant['grant_id'],'next','next-again',{})


def test_rejection_and_expiry_do_not_close_an_independent_grant():
    service,channel,prompts=service_prepared()
    service.request({'items':[{}],'idempotency_key':'first'})
    first=service_approve(service,prompts)
    service.request({'items':[{}],'idempotency_key':'second'})
    manifest,callbacks=prompts[-1]
    callbacks['on_decision']({'nonce':manifest['nonce'],'request_digest':manifest['request_digest'],
        'choices':[],'ttl_seconds':1})
    callbacks['on_revoke']()  # The rejected helper closes after emitting its decision.
    assert channel.available
    assert service.broker.authorize_attempt(service.broker.reserve(first['grant_id'],'read','still-valid',{})['attempt_id'])
    service.request({'items':[{}],'idempotency_key':'third'})
    third=service_approve(service,prompts)
    prompts[-1][1]['on_revoke']()  # Normal grant window expiry must stay grant-scoped.
    assert channel.available
    with pytest.raises(auth.ScopeError,match='grant-revoked'):
        service.broker.reserve(third['grant_id'],'read','expired',{})
    service.broker.reserve(first['grant_id'],'read','independent',{})


def test_helper_loss_during_slow_decision_fences_only_its_pending_request():
    service,channel,prompts=service_prepared()
    service.request({'items':[{}],'idempotency_key':'first'})
    first=service_approve(service,prompts)
    request=service.request({'items':[{}],'idempotency_key':'slow'})
    entered,release=threading.Event(),threading.Event()
    append=service.broker.journal.append
    def slow(event):
        if event['event']=='decision-recorded' and event['request_id']==request['request_id']:
            entered.set();release.wait(timeout=3)
        append(event)
    service.broker.journal.append=slow
    errors=[]
    def decide():
        try:service_approve(service,prompts)
        except auth.ScopeError as exc:errors.append(exc.code)
    decision=threading.Thread(target=decide)
    decision.start();assert entered.wait(timeout=1)
    try:
        prompts[-1][1]['on_revoke']()
        assert channel.available
    finally:
        release.set();decision.join(timeout=3)
    assert not decision.is_alive()
    pending=service.broker.status(request['request_id'])
    assert pending['grant_id'] is None or pending['grant_state']=='revoked'
    service.broker.reserve(first['grant_id'],'read','independent',{})


def test_idle_grant_revocation_is_scoped_even_while_an_unrelated_audit_holds_the_lock():
    service,channel,prompts=service_prepared()
    service.request({'items':[{}],'idempotency_key':'first'});first=service_approve(service,prompts)
    service.request({'items':[{}],'idempotency_key':'second'});second=service_approve(service,prompts)
    entered,release=threading.Event(),threading.Event()
    append=service.broker.journal.append
    def slow(event):
        if event['event']=='execution-reserved':entered.set();release.wait(timeout=3)
        append(event)
    service.broker.journal.append=slow
    failures=[]
    def reserve():
        try:service.broker.reserve(first['grant_id'],'read','slow',{})
        except auth.ScopeError as exc:failures.append(exc.code)
    worker=threading.Thread(target=reserve);worker.start();assert entered.wait(timeout=1)
    try:
        service.revoke({'grant_id':second['grant_id']})
        assert channel.available
        assert not service.broker.fenced.is_set()
    finally:release.set();worker.join(timeout=3)
    assert not failures
    with pytest.raises(auth.ScopeError,match='grant-revoked'):
        service.broker.reserve(second['grant_id'],'read','revoked',{})


def test_verified_login_retires_only_startup_grants_before_task_requests():
    service,channel,prompts=service_prepared()
    row=item('startup');row['parameters']={'network_ref':'startup','review_kind':'bootstrap'}
    original=channel.request
    def worker(operation,args,timeout=30):
        if operation=='resolve-setup':
            return {'ok':True,'items':[row],'contracts':{'startup':{'phase':'bootstrap'}}}
        if operation=='resume-login':
            return {'ok':True,'authenticationVerified':True}
        return original(operation,args,timeout=timeout)
    channel.request=worker
    service.request({'setup':{},'idempotency_key':'startup'})
    grant=service_approve(service,prompts)
    service._worker('resume-login',{})
    assert channel.available
    assert service.broker.status(grant['request_id'])['grant_state']=='revoked'


def mcp_fixture(monkeypatch):
    import remotex_mcp
    import web_adapter
    service,channel,prompts=service_prepared();channel.authorization=service
    service.request({'items':[{}],'idempotency_key':'read'})
    grant=service_approve(service,prompts)
    monkeypatch.setattr(web_adapter,'_owned_channel',lambda *_:channel)
    monkeypatch.setattr(remotex_mcp.audit_log,'begin',lambda *_:'test-operation')
    monkeypatch.setattr(remotex_mcp.audit_log,'finish',lambda *_:None)
    args={'session_id':'a'*32,'requester':'owner','grant_id':grant['grant_id'],'item_id':'read',
          'idempotency_key':'once','observation_id':'d'*32,'component_ref':'e'*32}
    return remotex_mcp,service,args


def test_outer_mcp_audit_cannot_release_revoked_content(monkeypatch):
    mcp,service,args=mcp_fixture(monkeypatch)
    monkeypatch.setattr(mcp.audit_log,'finish',lambda *_:service.broker.emergency_revoke())
    result=mcp._call_tool('remotex_web_execute',args)
    assert result.get('isError') is True
    assert 'Linux' not in json.dumps(result)


def test_final_transport_checks_authority_after_serialization(monkeypatch):
    mcp,service,args=mcp_fixture(monkeypatch)
    result=mcp._call_tool('remotex_web_execute',args)
    stream=io.StringIO();monkeypatch.setattr(mcp.sys,'stdout',stream)
    dumps=mcp.json.dumps
    def serialize(value,*args,**kwargs):
        encoded=dumps(value,*args,**kwargs)
        if isinstance(value,dict) and value.get('jsonrpc')=='2.0':
            service.broker.emergency_revoke()
        return encoded
    monkeypatch.setattr(mcp.json,'dumps',serialize)
    mcp.send_message(mcp.response(1,result))
    assert 'Linux' not in stream.getvalue()
    assert json.loads(stream.getvalue())['result']['isError'] is True
