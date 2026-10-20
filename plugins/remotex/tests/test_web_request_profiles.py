from pathlib import Path
import json
import shutil
import subprocess
import sys
import pytest

PLUGIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PLUGIN/'src'))
sys.path.insert(0,str(PLUGIN/'tests'))
from remotex_v3_support import VECTORS,sample_capture,public_reference,header
from web_request_profiles import validate_v3_capture,validate_public_reference,safe_v3_observation

@pytest.mark.parametrize('row',VECTORS,ids=lambda r:r['id'])
def test_shared_strict_profiles(row):
    capture=sample_capture(body_text=row['body'],content_type=row['content_type'])
    if 'error' in row:
        with pytest.raises(ValueError,match=row['error']):validate_v3_capture(capture,row['profile'])
        return
    view=validate_v3_capture(capture,row['profile'])
    assert view['unit_count']==row['units']
    assert validate_public_reference(capture,view,public_reference(row['id']))=={
        'matched':True,'complete':True,'unit_count':row['units']}

@pytest.mark.parametrize('change',[{'body_text':'{ "mode":"public"}'},
    {'body_text':'{"mode":"publ\\u0069c"}'},{'target':'/bootstrap?mode=p%75blic'},
    {'content_type':'application/json; charset=utf-8'}])
def test_equivalent_wire_is_not_the_approved_reference(change):
    capture=sample_capture(**change);view=validate_v3_capture(capture,'json-utf8-v1')
    assert not validate_public_reference(capture,view,public_reference())['matched']


@pytest.mark.parametrize('name',['{"token":"PRIVATE_SESSION_CANARY"}',' {"userSession":"PUBLIC_MARKER"}',
    '\ufeff{"token":"PRIVATE_SESSION_CANARY"}'])
def test_structured_query_names_cannot_hide_authentication_slots(name):
    from urllib.parse import quote
    capture=sample_capture(target='/bootstrap?'+quote(name,safe='')+'=')
    with pytest.raises(ValueError,match='request-contract-unavailable'):
        validate_v3_capture(capture,'json-utf8-v1')

@pytest.mark.parametrize('capture',[
    sample_capture(extra=True),sample_capture(body_b64='e30'),sample_capture(protection_refs=['1'*32]),
    sample_capture(headers=[('Authorization','public')]),sample_capture(headers=[('X-Api-Key','public')]),
    sample_capture(headers=[('Cookie','pre=one')]),sample_capture(effective_headers=[]),
    sample_capture(original_headers=[header('content-type','application/json'),header('Content-Type','application/json')]),
    sample_capture(target='/bootstrap?x=%ZZ'),sample_capture(body_b64='/w==')])
def test_capture_integrity_and_protection(capture):
    with pytest.raises(ValueError):validate_v3_capture(capture,'json-utf8-v1')

def test_safe_projection_never_exports_unknown_path_header_or_key():
    refs={'network_ref':'1'*32,'representation_ref':'2'*32,'literal_review_refs':['3'*32]}
    value=safe_v3_observation(refs,{'origin':'https://fixture.example','account':'operator'})
    assert value['network_ref']=='1'*32
    assert not {'path','body','headers','digest','fingerprint'} & set(value)

def test_json_strings_are_not_recursively_interpreted():
    a=validate_v3_capture(sample_capture(body_text='{"x":"{\\"a\\":1}"}'),'json-utf8-v1')
    b=validate_v3_capture(sample_capture(body_text='{"x":{"a":1}}'),'json-utf8-v1')
    assert a['ordered_tree']!=b['ordered_tree']

@pytest.mark.parametrize('body',['{"a":1.0}','{"a":1e0}','{"a":-0}'])
def test_safe_integer_values_preserve_separate_wire_spelling(body):
    assert validate_v3_capture(sample_capture(body_text=body),'json-utf8-v1')

def test_exact_parser_ceilings():
    validate_v3_capture(sample_capture(body_text='{}'+' '*16382),'json-utf8-v1')
    with pytest.raises(ValueError):validate_v3_capture(sample_capture(body_text='{}'+' '*16383),'json-utf8-v1')
    validate_v3_capture(sample_capture(body_text='{"'+'k'*128+'":true}'),'json-utf8-v1')
    with pytest.raises(ValueError):validate_v3_capture(sample_capture(body_text='{"'+'k'*129+'":true}'),'json-utf8-v1')
    validate_v3_capture(sample_capture(body_text=json.dumps({'x':[True]*31}),target='/'),'json-utf8-v1')
    with pytest.raises(ValueError,match='setup-plan-capacity-required'):
        validate_v3_capture(sample_capture(body_text=json.dumps({'x':[True]*32}),target='/'),'json-utf8-v1')

def test_remaining_profile_ceilings_and_private_literal_rejection():
    def parse(body,**overrides):
        return validate_v3_capture(sample_capture(body_text=body,**overrides),'json-utf8-v1')
    parse(json.dumps({'x':'\u00e9'*128}))
    with pytest.raises(ValueError,match='setup-plan-capacity-required'):parse(json.dumps({'x':'\u00e9'*129}))
    parse(json.dumps({'\u00e9'*64:True}))
    with pytest.raises(ValueError,match='request-contract-unavailable'):parse(json.dumps({'\u00e9'*65:True}))
    value=True
    for _ in range(7):value=[value]
    parse(json.dumps({'x':value}))
    with pytest.raises(ValueError,match='request-contract-unavailable'):parse(json.dumps({'x':[value]}))
    with pytest.raises(ValueError,match='setup-plan-capacity-required'):parse(json.dumps({'x':[True]*100}))
    with pytest.raises(ValueError,match='request-contract-unavailable'):parse(json.dumps({'x':[True]*101}))
    with pytest.raises(ValueError,match='setup-plan-capacity-required'):parse('{}',target='/bootstrap?x='+'a'*8190)
    with pytest.raises(ValueError,match='request-contract-unavailable'):parse('{}',target='/bootstrap?x='+'a'*8191)
    for value in ['-----BEGIN PRIVATE KEY-----','ghp_synthetic','glpat-synthetic','sk-proj-synthetic']:
        with pytest.raises(ValueError,match='request-contract-unavailable'):parse(json.dumps({'x':value}))

def test_shared_vectors_have_identical_js_python_private_views():
    node=shutil.which('node')
    assert node
    script="""
import {parseV3Profile} from './scripts/web_request_profiles.mjs';
import {vectors,sampleCapture,parseTree} from './tests/fixtures/v3_test_support.mjs';
const result=vectors.map(r=>{try{return parseV3Profile(sampleCapture({bodyText:r.body,contentType:r.content_type}),r.profile,parseTree);}
catch(e){return {code:e.message};}});
process.stdout.write(JSON.stringify(result));
"""
    result=subprocess.run([node,'--input-type=module','-e',script],cwd=PLUGIN,capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
    expected=[]
    for row in VECTORS:
        try:expected.append(validate_v3_capture(sample_capture(body_text=row['body'],content_type=row['content_type']),row['profile']))
        except ValueError as exc:expected.append({'code':str(exc)})
    assert json.loads(result.stdout)==expected
