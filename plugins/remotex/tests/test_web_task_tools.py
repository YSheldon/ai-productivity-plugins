import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import web_adapter


def test_typed_task_tools_exist_without_an_approve_or_raw_browser_interface():
    expected={'remotex_web_components','remotex_web_action_prepare','remotex_web_authorization_request',
        'remotex_web_authorization_status','remotex_web_execute','remotex_web_execution_status',
        'remotex_web_authorization_revoke'}
    assert expected <= set(web_adapter.TOOLS)
    assert not any('approve' in name for name in web_adapter.TOOLS)
    for name in expected:
        schema=web_adapter.TOOLS[name]['inputSchema']
        assert schema['additionalProperties'] is False
        assert not set(schema['properties']) & {'password','url','selector','script','headers','body','cookies','nonce','decision'}

def test_public_setup_schema_exposes_mutually_exclusive_exact_v2_contracts():
    setup=web_adapter.TOOLS['remotex_web_authorization_request']['inputSchema']['properties']['setup']
    variants=setup.get('oneOf',[])
    assert len(variants)==2,'Clients cannot discover strict legacy and revision2 shapes'
    modern=next(v for v in variants if v['properties'].get('revision',{}).get('const')==2)
    assert modern['additionalProperties'] is False
    assert set(modern['properties'])=={'revision','phase','requests','replace_grant_ids'}
    assert set(modern['required'])=={'revision','phase','requests'}
    assert modern['properties']['replace_grant_ids']['maxItems']==2
    kinds=modern['properties']['requests']['items']['oneOf']
    assert {v['properties']['purpose']['const'] for v in kinds}=={'bootstrap-resource','initialization-read'}
    for row in kinds:
        assert row['additionalProperties'] is False
        assert not {'url','body','headers','approved_semantics','phase_applicability'}&set(row['properties'])
    initialization=next(v for v in kinds if v['properties']['purpose']['const']=='initialization-read')
    assert 'response_checks' in initialization['required']
    assert initialization['properties']['response_checks']['maxItems']==8

def test_read_only_capabilities_do_not_export_private_startup_context():
    from test_web_task_service import prepared
    service,_,_=prepared()
    result=service.status()
    assert result['setup_purposes']==['bootstrap-resource','initialization-read']
    assert result['limits']['active_grants']==4 and result['limits']['pending_requests']==1
    assert result['initialization']['state']=='not-required'
    assert not {'resume_id','document_id','check_id','permit','response_checks'}&set(result['initialization'])


def test_unknown_or_secret_tool_fields_are_rejected_before_channel_access(monkeypatch):
    def unexpected(*_):
        raise AssertionError('Accessed a browser before validating input')
    monkeypatch.setattr(web_adapter,'_owned_channel',unexpected)
    for tool in ('remotex_web_components','remotex_web_execute','remotex_web_authorization_request'):
        result=web_adapter.TOOLS[tool]['handler']({'session_id':'a'*32,'requester':'owner','password':'DO-NOT-LOG'})
        assert result.get('isError') is True
        assert 'DO-NOT-LOG' not in json.dumps(result)


def test_web_audit_does_not_store_nonsecret_form_or_target_values():
    import audit_log
    result=audit_log.summarize_arguments('remotex_web_action_prepare',{
        'session_id':'a'*32,'requester':'private-requester','idempotency_key':'private-key',
        'changes':[{'value':'private-group'}],'target_refs':['b'*32]})
    text=json.dumps(result)
    assert 'private-group' not in text
    assert 'private-key' not in text
    assert 'private-requester' not in text


def test_emergency_revocation_is_not_blocked_by_generic_audit_begin(monkeypatch):
    import remotex_mcp
    called=[]
    monkeypatch.setitem(remotex_mcp.TOOLS,'remotex_web_authorization_revoke',{
        'handler':lambda args:called.append(args) or {'ok':True}})
    monkeypatch.setattr(remotex_mcp.audit_log,'begin',lambda *_:(_ for _ in ()).throw(AssertionError('audit unavailable')))
    assert remotex_mcp._call_tool('remotex_web_authorization_revoke',{'end_task':True})=={'ok':True}
    assert called==[{'end_task':True}]


def test_duplicate_json_fields_do_not_choose_an_ambiguous_authorization_scope():
    import remotex_mcp
    with pytest.raises(ValueError):
        remotex_mcp._parse_message('{"params":{"arguments":{"grant_id":"first","grant_id":"second"}}}')


def test_private_web_profile_hash_still_supports_credential_usage_reporting():
    import audit_log
    import usage_report
    from datetime import datetime,timezone
    request=audit_log.summarize_arguments('remotex_web_login',{'profile':'web-lab'})
    records=[{'timestamp':'2026-10-17T00:00:00Z','operationId':'op','event':'operation-start',
        'tool':'remotex_web_login','request':request}]
    operations=usage_report._operations(records,datetime(2026,10,18,tzinfo=timezone.utc),{},profile_names=['web-lab'])
    assert operations[0]['profile']=='web-lab'
    assert 'web-lab' not in json.dumps(request)


def test_session_tool_audit_joins_only_the_bound_profile_hash(monkeypatch):
    import audit_log
    import hashlib
    from types import SimpleNamespace
    monkeypatch.setitem(web_adapter._CHANNELS,'a'*32,SimpleNamespace(profile='web-lab'))
    request=audit_log.summarize_arguments('remotex_web_execute',{'session_id':'a'*32,
        'changes':[{'value':'private-value'}]})
    assert request['profileSha256']==hashlib.sha256(b'web-lab').hexdigest()
    assert 'private-value' not in json.dumps(request)
