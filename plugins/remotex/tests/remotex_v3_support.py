"""Synthetic v3 fixtures; no real profile, credential or queue access."""
import base64
import copy
import json
from pathlib import Path

VECTORS=json.loads((Path(__file__).parent/'fixtures/v3_profile_vectors.json').read_text(encoding='utf-8'))

def b64(value):
    return base64.b64encode(value.encode('utf-8')).decode('ascii')

def header(name,value):
    return {'name_b64':b64(name),'value_b64':b64(value)}

def sample_capture(*,body_text='{"mode":"public"}',content_type='application/json',
                   target='/bootstrap?mode=public',headers=(),**overrides):
    original=[header('content-type',content_type),*(header(n,v) for n,v in headers)]
    effective=sorted([*original,header('host','fixture.example'),header('accept-encoding','identity'),
                      header('content-length',str(len(body_text.encode('utf-8'))))],
                     key=lambda h:base64.b64decode(h['name_b64']))
    return {'version':3,'method':'POST','origin':'https://fixture.example','resource_type':'xhr',
            'target_b64':b64(target),'body_b64':b64(body_text),'content_type_b64':b64(content_type),
            'original_headers':original,'effective_headers':effective,'transport_policy':'fixed-egress-v1',
            'cookie_context':None,'protection_refs':[],**overrides}

def public_reference(case_id='json-public'):
    # Fixed source fixture records, not an observation-to-expected conversion.
    row=next(r for r in VECTORS if r['id']==case_id and 'error' not in r)
    return copy.deepcopy({'profile_id':row['profile'],'target_text':'/bootstrap?mode=public',
                          'content_type':row['content_type'],'body_text':row['body'],'public_headers':[]})

def independent_native_input():
    return {'version':3,'reference':public_reference(),'attestation':{'data_status':'public-invariant','role':'non-auth',
        'effect':'initialization-read','sensitive_ack_refs':[],'evidence':{'kind':'verified-record',
            'source_ref':'synthetic-public-reference','revision_ref':'fixture-v1','deployment_ref':'owned-loopback-fixture',
            'basis':'Reviewed independent fixture handler and public response contract','independently_reviewed':True}},
        'cookie_review':{'context_ref':None,'role':'none','evidence_ref':None}}

def native_manifest():
    return {'protocol_revision':3,'request_id':'a'*32,'nonce':'b'*64,'request_digest':'c'*64,
        'binding':{'origin':'https://fixture.example','account':'operator'},'ttl_seconds':300,'wait_seconds':120,
        'items':[{'item_id':'setup.network.1','capability':'web.page_step','fingerprint':'d'*64,'page':'#/',
            'max_uses':2,'depends_on':[],'targets':[],'parameters':{'review_kind':'initialization-read'},
            'output':{'rows':0,'columns':0,'bytes':0},'display':{'label':'Private initialization request','preview':'{}'},
            'effect':{'class':'task-bounded','fields':[],'digest':'e'*64}}],
        'reference_items':[{'item_id':'setup.network.1','profile_id':'json-utf8-v1','cookie_context_ref':None,
            'response_checks':[{'pointer':'/ready','test':'equals-boolean','expected':True}],
            'locations':[{'ref':format(i+1,'032x'),'position':i+1,'type':'string','sensitive':False} for i in range(5)]}]}

def compare_frame(packet,edit_revision=1,check_id='f'*32):
    return {'event':'reference-check',**{k:packet[k] for k in ('request_id','nonce','request_digest')},
        'check_id':check_id,'item_id':'setup.network.1','edit_revision':edit_revision,'native_input':independent_native_input()}
