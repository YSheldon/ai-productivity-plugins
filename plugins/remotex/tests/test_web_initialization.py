from __future__ import annotations
import copy
import sys
from pathlib import Path
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from web_authorization import ScopeError
try:
    import web_initialization as init
except ModuleNotFoundError:
    init=None

LIFE='a'*32
DESCRIPTOR={'method':'POST','path':'/init','query':{},'contentType':'application/json',
            'body':{'cmd':'database_info'},'resourceType':'xhr'}
CHECKS=[{'pointer':'/exist','test':'equals-boolean','expected':True}]
PID='b'*64

def authority():
    assert init is not None, 'Original-supervisor initialization authority is missing'
    clock=[100.0]
    value=init.StartupAuthority({'origin':'https://console.example','deadline':1000.0},
        clock=lambda:clock[0],wall_clock=lambda:1000.0+(clock[0]-100))
    value.register({'revision':2,'preauth_lifecycle':LIFE,'contracts':{'init':{
        'purpose':'initialization-read','descriptor':copy.deepcopy(DESCRIPTOR),
        'response_checks':copy.deepcopy(CHECKS),'prerequisite_id':PID}}})
    return value,clock

def event(ticket,kind,**extra):
    return {'kind':kind,'resume_id':ticket['resume_id'],'preauth_lifecycle':LIFE,
        'document_id':'d'*32,'phase':'bootstrap','generation':0,
        'authentication_forwarded':0,**extra}

def opened(value):
    ticket=value.begin(lifecycle=LIFE,session_deadline_ms=1_900_000)
    value.event(event(ticket,'document-opening'))
    value.event(event(ticket,'document-committed'))
    return ticket

def message(ticket):
    return {'kind':'network','phase':'bootstrap','attempt_id':None,
        'descriptor':copy.deepcopy(DESCRIPTOR),'digest':init.wire_digest(DESCRIPTOR),
        'startup':{'resume_id':ticket['resume_id'],'preauth_lifecycle':LIFE,
            'document_id':'d'*32,'generation':0}}

def contract():
    return {'descriptor':copy.deepcopy(DESCRIPTOR),'prerequisite_id':PID,
        'response_checks':copy.deepcopy(CHECKS),'purpose':'initialization-read'}

def test_native_scope_cannot_issue_an_init_permit_without_original_resume():
    value,_=authority()
    with pytest.raises(ScopeError):
        value.issue(check_id='c'*32,message=message({'resume_id':'e'*32}),contract=contract())

def test_typed_permit_is_exact_fresh_and_bound_to_one_check():
    value,clock=authority();ticket=opened(value)
    permit=value.issue(check_id='c'*32,message=message(ticket),contract=contract())
    assert permit['kind']=='initialization-read'
    assert permit['expires_at_ms']==1_010_000
    assert permit['descriptor_digest']==init.wire_digest(DESCRIPTOR)
    for changed in [message(ticket)|{'digest':'0'*64},
        message(ticket)|{'startup':message(ticket)['startup']|{'generation':1}},
        message(ticket)|{'descriptor':DESCRIPTOR|{'path':'/write'}}]:
        with pytest.raises(ScopeError):value.issue(check_id='f'*32,message=changed,contract=contract())
    with pytest.raises(ScopeError):value.issue(check_id='c'*32,message=message(ticket),contract=contract())
    clock[0]+=46
    with pytest.raises(ScopeError):value.issue(check_id='f'*32,message=message(ticket),contract=contract())

def test_readiness_requires_own_forwarded_response_and_cannot_remove_a_requirement():
    value,_=authority();ticket=opened(value)
    value.register({'revision':2,'preauth_lifecycle':LIFE,'contracts':{}})
    assert value.status()['required']==1
    with pytest.raises(ScopeError):value.event(event(ticket,'credentials-armed'))
    value.issue(check_id='c'*32,message=message(ticket),contract=contract())
    with pytest.raises(ScopeError):value.event(event(ticket,'prerequisite-response',
        check_id='c'*32,prerequisite_id=PID,ready=True))
    value.event(event(ticket,'initialization-forwarded',check_id='c'*32,prerequisite_id=PID))
    value.event(event(ticket,'prerequisite-response',check_id='c'*32,prerequisite_id=PID,ready=True))
    assert value.status()['ready']==1
    value.event(event(ticket,'controls-ready'))
    value.event(event(ticket,'credentials-armed'))
    with pytest.raises(ScopeError):value.issue(check_id='f'*32,message=message(ticket),contract=contract())

def test_cancelled_or_replaced_document_never_satisfies_new_readiness():
    value,_=authority();old=opened(value)
    value.issue(check_id='c'*32,message=message(old),contract=contract())
    value.end(old['resume_id']);new=opened(value)
    assert new['resume_id']!=old['resume_id']
    assert value.status()['ready']==0
    with pytest.raises(ScopeError):value.event(event(old,'initialization-forwarded',check_id='c'*32,prerequisite_id=PID))

def test_possible_authentication_is_monotonic_and_never_reopens_init():
    value,_=authority();ticket=opened(value)
    value.event(event(ticket,'authentication-forwarded',authentication_forwarded=1))
    value.end(ticket['resume_id'])
    with pytest.raises(ScopeError):value.begin(lifecycle=LIFE,session_deadline_ms=1_900_000)
    assert value.authentication_forwarded==1
