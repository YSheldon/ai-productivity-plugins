import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
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
