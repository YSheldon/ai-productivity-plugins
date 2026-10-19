from pathlib import Path
import copy
import json
import sys
import pytest

PLUGIN=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PLUGIN/'src'))
sys.path.insert(0,str(PLUGIN/'tests'))
from remotex_v3_support import sample_capture,public_reference
from web_initialization_v3 import V3Authority

REQUEST='1'*32
ITEM='setup.network.1'
GRANT='2'*32
LIFECYCLE='3'*32

def authority_case(capture_override=None,key_byte=b'K'):
    now=[1000.0]
    binding={'origin':'https://fixture.example','account':'operator','session':'a'*32,'worker':'fixture-worker',
             'acquisition':'fixture-acquisition','profile_digest':'b'*64,'deadline':10000.125}
    authority=V3Authority(binding,clock=lambda:now[0],wall_clock=lambda:now[0],key_factory=lambda n:key_byte*n)
    capture=sample_capture() if capture_override is None else capture_override
    meta={ITEM:{'profile_id':'json-utf8-v1','response_checks':[{'pointer':'/ready','test':'equals-boolean','expected':True}],
        'evidence':[{'kind':'verified-record','reference':'independent-fixture-source'}],'preauth_lifecycle':LIFECYCLE,
        'representation_ref':'4'*32,'literal_review_refs':[format(i,'032x') for i in range(5,10)]}}
    authority.register_plan(REQUEST,{ITEM:capture},meta,review_deadline=1120.0)
    native={'version':3,'reference':public_reference(),'attestation':{'data_status':'public-invariant','role':'non-auth',
        'effect':'initialization-read','sensitive_ack_refs':[],'evidence':{'kind':'verified-record',
            'source_ref':'synthetic-public-reference','revision_ref':'fixture-v1','deployment_ref':'owned-loopback-fixture',
            'basis':'Reviewed independent fixture handler and public response contract','independently_reviewed':True}},
        'cookie_review':{'context_ref':None,'role':'none','evidence_ref':None}}
    return authority,now,capture,meta,native

def compare(authority,native,revision=1,check='5'*32):
    return authority.check_reference(REQUEST,check,revision,native,item_id=ITEM)

def commit(authority,proof,revision=1):
    authority.bind_grant(REQUEST,GRANT,[{'item_id':ITEM,'review_ref':proof['review_ref'],
        'edit_revision':revision,'max_uses':2,'deadline':2000.0}])

def execution(**overrides):
    return {'preauth_lifecycle':LIFECYCLE,'resume_id':'6'*32,'document_id':'7'*32,'generation':1,
            'check_id':'8'*32,'expires_at_ms':1009000,**overrides}

def test_comparison_never_grants_or_issues_and_memory_key_is_not_journal_key(tmp_path):
    authority,now,capture,_,native=authority_case()
    proof=compare(authority,native)
    assert proof['code']=='ready' and proof['review_ref']
    assert not authority.grants
    with pytest.raises(ValueError):authority.issue(GRANT,ITEM,capture,execution())
    commit(authority,proof)
    receipt=authority.issue(GRANT,ITEM,capture,execution())
    assert receipt['kind']=='initialization-permit-v3' and receipt['document_id']=='7'*32
    assert receipt['grant_id']==GRANT and receipt['item_id']==ITEM
    assert receipt['receipt_id'] and receipt['intent_ref']
    assert receipt['expires_at_ms']<=1009000
    with pytest.raises(ValueError):authority.issue(GRANT,ITEM,capture,execution())
    assert list(tmp_path.iterdir())==[]
    authority.close()
    with pytest.raises(ValueError):authority.issue(GRANT,ITEM,capture,execution(check_id='9'*32))


def test_partial_private_revocation_preserves_an_independent_unrevoked_item():
    authority,_,capture,meta,native=authority_case()
    authority.cancel_plan(REQUEST)
    second='setup.network.2'
    other=copy.deepcopy(meta[ITEM]);other['representation_ref']='f'*32
    other['literal_review_refs']=[format(i,'032x') for i in range(20,25)]
    authority.register_plan(REQUEST,{ITEM:capture,second:capture},{**meta,second:other})
    one=authority.check_reference(REQUEST,'5'*32,1,native,item_id=ITEM)
    two=authority.check_reference(REQUEST,'6'*32,1,native,item_id=second)
    authority.bind_grant(REQUEST,GRANT,[{'item_id':item_id,'review_ref':proof['review_ref'],'edit_revision':1,
        'max_uses':2,'deadline':2000.0} for item_id,proof in [(ITEM,one),(second,two)]])
    authority.revoke(GRANT,[ITEM])
    assert not authority.matches(GRANT,ITEM,capture)
    assert authority.matches(GRANT,second,capture)
    assert authority.issue(GRANT,second,capture,execution())['item_id']==second
    assert ITEM not in authority.plans[REQUEST]['rows']

@pytest.mark.parametrize('section,field,value',[
    ('attestation','data_status','unknown'),('attestation','role','auth'),('attestation','effect','write'),
    ('reference','body_text','{}'),('reference','target_text','/other')])
def test_reference_data_role_and_effect_are_independent_required_conditions(section,field,value):
    authority,_,_,_,native=authority_case();native[section][field]=value
    proof=compare(authority,native)
    assert proof['code']!='ready' and proof['review_ref'] is None
    assert not authority.grants

def test_edits_expiry_revocation_and_wire_changes_cannot_inherit_proof():
    authority,now,capture,_,native=authority_case();old=compare(authority,native)
    newer=compare(authority,native,revision=2,check='a'*32)
    with pytest.raises(ValueError,match='decision-invalid'):authority.require_review(REQUEST,ITEM,old['review_ref'],1)
    commit(authority,newer,revision=2)
    for changed in [sample_capture(body_text='{ "mode":"public"}'),sample_capture(target='/bootstrap?mode=p%75blic')]:
        with pytest.raises(ValueError):authority.issue(GRANT,ITEM,changed,execution())
    receipt=authority.issue(GRANT,ITEM,capture,execution())
    second=authority.issue(GRANT,ITEM,capture,execution(check_id='b'*32,document_id='c'*32,resume_id='d'*32,generation=2))
    assert receipt['intent_ref']==second['intent_ref'] and receipt['receipt_id']!=second['receipt_id']
    assert receipt['document_id']!=second['document_id']
    authority.revoke(GRANT)
    with pytest.raises(ValueError):authority.issue(GRANT,ITEM,capture,execution(check_id='e'*32))
    other,clock,_,_,native=authority_case();proof=compare(other,native);clock[0]=1120
    with pytest.raises(ValueError,match='decision-invalid'):commit(other,proof)

def test_native_comparison_budget_and_hard_markers_are_fail_closed():
    authority,_,_,_,native=authority_case()
    for index in range(8):assert compare(authority,native,revision=index+1,check=format(index+20,'032x'))['code']=='ready'
    with pytest.raises(ValueError):compare(authority,native,revision=9,check='f'*32)
    for capture in [sample_capture(protection_refs=['a'*32]),sample_capture(body_text='{"token":"public"}')]:
        with pytest.raises(ValueError):authority_case(capture)

def test_forged_native_fields_do_not_become_provenance_or_match_oracle():
    authority,_,_,_,native=authority_case()
    for field in ['source_ref','revision_ref','deployment_ref','basis']:
        invalid=copy.deepcopy(native);invalid['attestation']['evidence'][field]=''
        proof=compare(authority,invalid,revision=len(field),check=format(len(field),'032x'))
        assert proof['review_ref'] is None
    invalid=copy.deepcopy(native);invalid['attestation']['evidence']['independently_reviewed']=False
    assert compare(authority,invalid,revision=99,check='c'*32)['review_ref'] is None
    assert not authority.grants

def test_staged_reference_bytes_are_rechecked_at_final_decision():
    authority,_,_,_,native=authority_case();proof=compare(authority,native)
    authority.plans[REQUEST]['rows'][ITEM]['native']['reference']['body_text']='{}'
    with pytest.raises(ValueError,match='decision-invalid'):commit(authority,proof)

def test_commitment_canonicalization_has_explicit_domains_and_safe_numbers():
    from web_initialization_v3 import _canonical
    assert _canonical({'z':[1,True,None],'a':'value'})==b'{"a":"value","z":[1,true,null]}'
    for value in [1.0,9007199254740992,'\u00e9',float('nan')]:
        with pytest.raises(ValueError):_canonical({'x':value})
    a,_,capture,_,native=authority_case();proof=compare(a,native);commit(a,proof)
    first=a.issue(GRANT,ITEM,capture,execution())
    b,_,_,_,native=authority_case(key_byte=b'J');proof=compare(b,native);commit(b,proof)
    second=b.issue(GRANT,ITEM,capture,execution())
    assert first['intent_commitment']!=second['intent_commitment']
    assert first['permit_commitment']!=first['intent_commitment']

def test_owned_safe_ids_and_manifest_budget_are_bound_before_native_review():
    old,now,capture,meta,native=authority_case()
    binding=old.binding
    meta[ITEM].update(intent_ref='4'*32,prerequisite_id='f'*64)
    authority=V3Authority(binding,clock=lambda:now[0],wall_clock=lambda:now[0])
    value=authority.register_plan(REQUEST,{ITEM:capture},meta,review_deadline=1120,external_bytes=1000)
    assert value['items'][ITEM]['intent_ref']=='4'*32 and value['items'][ITEM]['prerequisite_id']=='f'*64
    proof=compare(authority,native);commit(authority,proof)
    assert authority.issue(GRANT,ITEM,capture,execution())['prerequisite_id']=='f'*64
    other=V3Authority(binding,clock=lambda:now[0])
    with pytest.raises(ValueError,match='setup-plan-capacity-required'):
        other.register_plan(REQUEST,{ITEM:capture},meta,external_bytes=32768)

def test_canceling_a_pending_plan_drops_its_private_proof_and_one_pending_slot():
    authority,_,capture,meta,native=authority_case();proof=compare(authority,native)
    authority.cancel_plan(REQUEST)
    with pytest.raises(ValueError):commit(authority,proof)
    authority.register_plan('f'*32,{ITEM:capture},meta)
    assert list(authority.plans)==['f'*32]

def test_proposal_reference_units_accept_96_and_reject_97_without_increasing_byte_budget():
    old,now,_,_,_=authority_case()
    captures,meta={},{}
    for index in range(3):
        identity=f'setup.network.{index+1}'
        captures[identity]=sample_capture(body_text=json.dumps({'x':[True]*31}),target='/')
        meta[identity]={'profile_id':'json-utf8-v1','response_checks':[{'pointer':'/ready','test':'type','expected':'boolean'}],
            'evidence':[{'kind':'verified-record','reference':'independent-synthetic-source'}],
            'preauth_lifecycle':LIFECYCLE,'representation_ref':format(index+1000,'032x'),
            'literal_review_refs':[format(100+index*40+offset,'032x') for offset in range(32)]}
    authority=V3Authority(old.binding,clock=lambda:now[0])
    authority.register_plan(REQUEST,captures,meta)
    assert authority.plans[REQUEST]['units']==96 and authority.plans[REQUEST]['budget']<=32768
    captures['setup.network.4']=sample_capture(body_text='{}',target='/')
    meta['setup.network.4']={**copy.deepcopy(meta['setup.network.1']),'representation_ref':'f'*32,'literal_review_refs':['e'*32]}
    other=V3Authority(old.binding,clock=lambda:now[0])
    with pytest.raises(ValueError,match='setup-plan-capacity-required'):other.register_plan(REQUEST,captures,meta)
