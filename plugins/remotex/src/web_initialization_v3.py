"""Original-supervisor, RAM-only v3 reference and dispatch authority."""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
import secrets
import threading
import time

from web_authorization import ScopeError, canonical, digest, validate_items, MAX_NATIVE_REVIEW_SECONDS
from web_initialization import validate_checks
from web_request_profiles import validate_v3_capture, validate_public_reference, MAX_PROPOSAL_UNITS

_KINDS={'source-review','api-document','verified-record','operator-inspected'}
_META={'profile_id','response_checks','evidence','preauth_lifecycle','representation_ref','literal_review_refs'}
_CONTRACT={'revision','phase','parent_id','semantics','targets','purpose','phase_applicability','preauth_lifecycle',
           'required','response_checks','prerequisite_id','intent_ref','profile_id','network_ref','representation_ref',
           'literal_review_refs','evidence'}


def _hex(value,length=32):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{'+str(length)+'}',value) is not None


def _safe_int(value,minimum=0,maximum=9007199254740991):
    return type(value) is int and minimum<=value<=maximum


def _text(value,limit=512):
    return isinstance(value,str) and 1<=len(value.encode('utf-8'))<=limit and not re.search(r'[\x00-\x1f\x7f]',value)


def _canonical(value):
    def check(part):
        if part is None or type(part) is bool:
            return
        if type(part) is int and abs(part)<=9007199254740991:
            return
        if isinstance(part,str) and part.isascii():
            return
        if isinstance(part,list):
            for item in part:
                check(item)
            return
        if isinstance(part,dict) and all(isinstance(k,str) and k.isascii() for k in part):
            for item in part.values():
                check(item)
            return
        raise ScopeError('request-contract-unavailable')
    check(value)
    return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')


def _encoded(value):
    # Typed private Unicode/reference data becomes an explicit binary commitment field.
    return base64.b64encode(canonical(value)).decode('ascii')


def validate_setup_context_v3(resolved,binding,declaration):
    """Validate the original worker result; return private data separately from public scope."""
    try:
        expected={'ok','items','contracts','setup_revision','preauth_lifecycle','phase_applicability','prerequisites','private_initialization'}
        if (not isinstance(resolved,dict) or set(resolved)!=expected or resolved['ok'] is not True or
                type(resolved['setup_revision']) is not int or resolved['setup_revision']!=3 or
                not _hex(resolved['preauth_lifecycle']) or resolved['phase_applicability']!=['bootstrap','login-once'] or
                not isinstance(declaration,dict) or set(declaration)!={'revision','phase','requests'} or
                type(declaration['revision']) is not int or declaration['revision']!=3 or
                declaration['phase'] not in {'bootstrap','login-once'} or not isinstance(declaration['requests'],list)):
            raise ScopeError('request-invalid')
        items=validate_items(resolved['items'])
        contracts=resolved['contracts']
        captures=resolved['private_initialization']
        if (not isinstance(contracts,dict) or not isinstance(captures,dict) or len(items)!=len(declaration['requests']) or
                set(contracts)!={row['item_id'] for row in items} or set(captures)!=set(contracts)):
            raise ScopeError('request-invalid')
        locators,views,prerequisites={},{},[]
        all_refs=set()
        for index,(item,requested) in enumerate(zip(items,declaration['requests'])):
            identity=f'setup.network.{index+1}'
            contract=contracts.get(identity)
            if (item['item_id']!=identity or not isinstance(contract,dict) or set(contract)!=_CONTRACT or
                    type(contract['revision']) is not int or contract['revision']!=3 or contract['phase']!=declaration['phase'] or
                    contract['parent_id'] is not None or contract['semantics']!='initialization-read' or contract['targets']!=[] or
                    contract['purpose']!='initialization-read' or contract['required'] is not True or
                    contract['preauth_lifecycle']!=resolved['preauth_lifecycle'] or
                    contract['phase_applicability']!=['bootstrap','login-once']):
                raise ScopeError('request-invalid')
            if (not isinstance(requested,dict) or set(requested)-{'network_ref','purpose','representation_ref','literal_review_refs',
                    'max_uses','response_checks','evidence'} or requested.get('purpose')!='initialization-read' or
                    any(canonical(contract[k])!=canonical(requested.get(k)) for k in
                        ('network_ref','representation_ref','literal_review_refs','response_checks','evidence'))):
                raise ScopeError('scope-mismatch')
            view=validate_v3_capture(captures[identity],contract['profile_id'])
            if captures[identity]['origin']!=binding['origin']:
                raise ScopeError('scope-mismatch')
            refs=contract['literal_review_refs']
            if (not isinstance(refs,list) or len(refs)!=view['unit_count'] or
                    contract['intent_ref']!=contract['representation_ref']):
                raise ScopeError('scope-mismatch')
            current=[contract['network_ref'],contract['representation_ref'],*refs]
            if any(not _hex(ref) for ref in current) or len(set(current))!=len(current) or all_refs.intersection(current):
                raise ScopeError('scope-mismatch')
            all_refs.update(current)
            validate_checks(contract['response_checks'])
            evidence=contract['evidence']
            if (not isinstance(evidence,list) or not 1<=len(evidence)<=8 or any(not isinstance(e,dict) or
                    set(e)!={'kind','reference'} or e['kind'] not in _KINDS or not _text(e['reference']) for e in evidence)):
                raise ScopeError('request-invalid')
            prerequisite=digest({key:contract[key] for key in ('preauth_lifecycle','network_ref','representation_ref',
                'literal_review_refs','response_checks')})
            if contract['prerequisite_id']!=prerequisite:
                raise ScopeError('scope-mismatch')
            uses=requested.get('max_uses',2)
            if not _safe_int(uses,1,10):
                raise ScopeError('request-invalid')
            expected_item={'item_id':identity,'capability':'web.page_step','fingerprint':digest(contract),'page':'#/',
                'max_uses':uses,'depends_on':[],'targets':[],'parameters':{'network_ref':identity,'review_kind':'initialization-read'},
                'output':{'rows':0,'columns':0,'bytes':0},'effect':{'class':'task-bounded','fields':[],
                    'digest':digest({'scope':contract,'semantics':'initialization-read','targets':[]})}}
            actual={key:value for key,value in item.items() if key!='display'}
            if canonical(actual)!=canonical(expected_item) or item['display']['label']!='Initialization POST (private scope)':
                raise ScopeError('scope-mismatch')
            if item['display']['preview']!=json.dumps(contract,ensure_ascii=False,separators=(',',':'),allow_nan=False):
                raise ScopeError('scope-mismatch')
            views[identity]=view
            locators[identity]={key:copy.deepcopy(contract[key]) for key in _META|{'intent_ref','prerequisite_id'}}
            prerequisites.append(prerequisite)
        if resolved['prerequisites']!=prerequisites:
            raise ScopeError('scope-mismatch')
        if (sum(view['unit_count'] for view in views.values())>MAX_PROPOSAL_UNITS or sum(item['max_uses'] for item in items)>200 or
                len(canonical(resolved))+len(canonical(views))>32768):
            raise ScopeError('setup-plan-capacity-required')
        context={'revision':3,'preauth_lifecycle':resolved['preauth_lifecycle'],'phase_applicability':['bootstrap','login-once'],
            'contracts':copy.deepcopy(contracts),'prerequisites':prerequisites}
        native_items=[]
        for identity,view in views.items():
            meta=locators[identity]
            native_items.append({'item_id':identity,'profile_id':meta['profile_id'],
                'locations':[{'ref':ref,'position':index+1,'type':location['type'],'sensitive':location['sensitive']}
                    for index,(ref,location) in enumerate(zip(meta['literal_review_refs'],view['locations']))],
                'cookie_context_ref':captures[identity]['cookie_context']['epoch_ref'] if captures[identity]['cookie_context'] else None,
                'response_checks':copy.deepcopy(meta['response_checks'])})
        return {'context':context,'captures':copy.deepcopy(captures),'locators':locators,'native_items':native_items}
    except ScopeError:
        raise
    except Exception:
        raise ScopeError('request-invalid') from None


class V3Authority:
    def __init__(self,binding,clock=time.monotonic,key_factory=secrets.token_bytes,*,wall_clock=time.time):
        self.clock,self.wall_clock=clock,wall_clock
        self.binding=copy.deepcopy(binding)
        self.binding_digest=digest(binding)
        key=key_factory(32)
        if not isinstance(key,bytes) or len(key)!=32:
            raise ScopeError('request-contract-unavailable')
        self._key=bytearray(key)
        self._closed=False
        self.lock=threading.RLock()
        self.plans,self.grants={},{}

    def _valid(self):
        if self._closed or self.clock()>=self.binding['deadline']:
            raise ScopeError('decision-invalid')

    def _commit(self,domain,value):
        return hmac.new(self._key,domain.encode('ascii')+b'\0'+_canonical(value),hashlib.sha256).hexdigest()

    def _prune(self):
        now=self.clock()
        for identity,grant in list(self.grants.items()):
            if grant['deadline']<=now:
                self.grants.pop(identity)
        linked={grant['request_id'] for grant in self.grants.values()}
        for identity,plan in list(self.plans.items()):
            if identity not in linked and plan['review_deadline']<=now:
                self.plans.pop(identity)

    def register_plan(self,request_id,captures,evidence_locators,*,review_deadline=None,external_bytes=0):
        with self.lock:
            self._valid()
            self._prune()
            if (not _hex(request_id) or not isinstance(captures,dict) or not 1<=len(captures)<=32 or
                    not isinstance(evidence_locators,dict) or set(captures)!=set(evidence_locators) or
                    not _safe_int(external_bytes,0,32768)):
                raise ScopeError('request-contract-unavailable')
            rows={}
            units=0
            for item_id,capture in captures.items():
                meta=evidence_locators[item_id]
                if (not _text(item_id,128) or not isinstance(meta,dict) or set(meta) not in (_META,_META|{'intent_ref','prerequisite_id'}) or
                        not _hex(meta['preauth_lifecycle']) or not _hex(meta['representation_ref'])):
                    raise ScopeError('request-contract-unavailable')
                if 'intent_ref' in meta and (meta['intent_ref']!=meta['representation_ref'] or not _hex(meta['prerequisite_id'],64)):
                    raise ScopeError('request-contract-unavailable')
                view=validate_v3_capture(capture,meta['profile_id'])
                refs=meta['literal_review_refs']
                if (not isinstance(refs,list) or len(refs)!=view['unit_count'] or len(set(refs))!=len(refs) or
                        any(not _hex(ref) for ref in refs)):
                    raise ScopeError('request-contract-unavailable')
                validate_checks(meta['response_checks'])
                evidence=meta['evidence']
                if (not isinstance(evidence,list) or not 1<=len(evidence)<=8 or any(not isinstance(e,dict) or
                        set(e)!={'kind','reference'} or e['kind'] not in _KINDS or not _text(e['reference']) for e in evidence)):
                    raise ScopeError('request-contract-unavailable')
                if capture['origin']!=self.binding['origin']:
                    raise ScopeError('request-contract-unavailable')
                units+=view['unit_count']
                rows[item_id]={'capture':copy.deepcopy(capture),'view':view,'meta':copy.deepcopy(meta),
                    'intent_ref':meta.get('intent_ref',secrets.token_hex(16)),
                    'prerequisite_id':meta.get('prerequisite_id',secrets.token_hex(32)),'revision':0,
                    'proof':None,'native':None}
            budget=len(canonical(rows))+external_bytes
            if units>MAX_PROPOSAL_UNITS or budget>32768:
                raise ScopeError('setup-plan-capacity-required')
            if request_id in self.plans or len(self.grants)>=4 or any(
                    p['state']=='pending' and self.clock()<p['review_deadline'] for p in self.plans.values()):
                raise ScopeError('decision-invalid')
            deadline=min(self.clock()+MAX_NATIVE_REVIEW_SECONDS,self.binding['deadline'],
                review_deadline if review_deadline is not None else self.clock()+MAX_NATIVE_REVIEW_SECONDS)
            if deadline<=self.clock():
                raise ScopeError('decision-invalid')
            self.plans[request_id]={'rows':rows,'budget':budget,'units':units,'review_deadline':deadline,
                'attempts':0,'seen_checks':set(),'state':'pending'}
            return {'items':{identity:{'intent_ref':row['intent_ref'],'prerequisite_id':row['prerequisite_id'],
                'unit_count':row['view']['unit_count']} for identity,row in rows.items()}}

    def _pending(self,request_id):
        self._valid()
        plan=self.plans.get(request_id)
        if not plan or plan['state']!='pending' or self.clock()>=plan['review_deadline']:
            raise ScopeError('decision-invalid')
        return plan

    def _attested(self,row,native):
        if (not isinstance(native,dict) or set(native)!={'version','reference','attestation','cookie_review'} or
                type(native['version']) is not int or native['version']!=3):
            return False
        a=native['attestation']
        if (not isinstance(a,dict) or set(a)!={'data_status','role','effect','sensitive_ack_refs','evidence'} or
                a['data_status']!='public-invariant' or a['role']!='non-auth' or a['effect']!='initialization-read'):
            return False
        evidence=a['evidence']
        if (not isinstance(evidence,dict) or set(evidence)!={'kind','source_ref','revision_ref','deployment_ref','basis','independently_reviewed'} or
                evidence['kind'] not in _KINDS or evidence['independently_reviewed'] is not True or
                any(not _text(evidence[k]) for k in ('source_ref','revision_ref','deployment_ref','basis'))):
            return False
        sensitive=[ref for ref,location in zip(row['meta']['literal_review_refs'],row['view']['locations']) if location['sensitive']]
        if (not isinstance(a['sensitive_ack_refs'],list) or a['sensitive_ack_refs']!=sensitive):
            return False
        cookie=native['cookie_review']
        if not isinstance(cookie,dict) or set(cookie)!={'context_ref','role','evidence_ref'}:
            return False
        context=row['capture']['cookie_context']
        if context is None:
            return cookie=={'context_ref':None,'role':'none','evidence_ref':None}
        return (cookie['context_ref']==context['epoch_ref'] and cookie['role']=='non-auth-prelogin' and _text(cookie['evidence_ref']))

    def check_reference(self,request_id,check_id,edit_revision,native_input,*,item_id=None):
        with self.lock:
            plan=self._pending(request_id)
            if item_id is None and len(plan['rows'])==1:
                item_id=next(iter(plan['rows']))
            if (item_id not in plan['rows'] or not _hex(check_id) or check_id in plan['seen_checks'] or
                    not _safe_int(edit_revision,1) or plan['attempts']>=8):
                raise ScopeError('decision-invalid')
            plan['attempts']+=1
            plan['seen_checks'].add(check_id)
            row=plan['rows'][item_id]
            result={'check_id':check_id,'item_id':item_id,'edit_revision':edit_revision,'review_ref':None,
                'unit_count':row['view']['unit_count'],'code':'ineligible'}
            if edit_revision<row['revision']:
                return {**result,'code':'stale-edit'}
            row.update(revision=edit_revision,proof=None,native=None)
            if not self._attested(row,native_input):
                return result
            comparison=validate_public_reference(row['capture'],row['view'],native_input['reference'])
            if not comparison['matched'] or not comparison['complete']:
                return {**result,'code':'reference-mismatch'}
            other_native=sum(len(canonical(r['native'])) for r in plan['rows'].values() if r['native'] is not None)
            if plan['budget']+other_native+len(canonical(native_input))>32768:
                raise ScopeError('setup-plan-capacity-required')
            intent=self._commit('remotex/v3/grant-intent',{'binding_digest':self.binding_digest,
                'capture':row['capture'],'metadata_b64':_encoded(row['meta'])})
            proof={'review_ref':secrets.token_hex(16),'edit_revision':edit_revision,'intent':intent,
                'commitment':self._commit('remotex/v3/reference-proof',{'request_id':request_id,'item_id':item_id,
                    'edit_revision':edit_revision,'intent':intent,'native_input_b64':_encoded(native_input)})}
            row['native']=copy.deepcopy(native_input)
            row['proof']=proof
            return {**result,'review_ref':proof['review_ref'],'code':'ready'}

    def require_review(self,request_id,item_id,review_ref,edit_revision):
        with self.lock:
            plan=self._pending(request_id)
            row=plan['rows'].get(item_id)
            proof=row and row['proof']
            if (not proof or proof['review_ref']!=review_ref or proof['edit_revision']!=edit_revision or
                    row['revision']!=edit_revision or not self._attested(row,row['native'])):
                raise ScopeError('decision-invalid')
            current=self._commit('remotex/v3/reference-proof',{'request_id':request_id,'item_id':item_id,
                'edit_revision':edit_revision,'intent':proof['intent'],'native_input_b64':_encoded(row['native'])})
            comparison=validate_public_reference(row['capture'],row['view'],row['native']['reference'])
            if not hmac.compare_digest(current,proof['commitment']) or not comparison['complete'] or not comparison['matched']:
                raise ScopeError('decision-invalid')
            return copy.deepcopy({'intent_ref':row['intent_ref'],'prerequisite_id':row['prerequisite_id'],
                'profile_id':row['meta']['profile_id'],'proof_commitment':proof['commitment']})

    def review_audit(self,request_id,item_id,review_ref,edit_revision):
        with self.lock:
            self.require_review(request_id,item_id,review_ref,edit_revision)
            row=self.plans[request_id]['rows'][item_id]
            return {'event':'initialization-reference-approved','request_id':request_id,'item_id':item_id,
                'contract_digest':row['prerequisite_id'],'item_ids':list(row['meta']['literal_review_refs']),
                'count':row['view']['unit_count'],'reason':row['meta']['profile_id'],
                'state':'public-non-auth-initialization-read'}

    def bind_grant(self,request_id,grant_id,approved_items):
        with self.lock:
            plan=self._pending(request_id)
            if (not _hex(grant_id) or grant_id in self.grants or len(self.grants)>=4 or
                    not isinstance(approved_items,list) or not 1<=len(approved_items)<=32):
                raise ScopeError('decision-invalid')
            selected={}
            for item in approved_items:
                if (not isinstance(item,dict) or set(item)!={'item_id','review_ref','edit_revision','max_uses','deadline'} or
                        not _safe_int(item['max_uses'],1,10) or type(item['deadline']) not in {int,float} or
                        not self.clock()<item['deadline']<=min(self.binding['deadline'],self.clock()+43200) or
                        item['item_id'] in selected):
                    raise ScopeError('decision-invalid')
                self.require_review(request_id,item['item_id'],item['review_ref'],item['edit_revision'])
                row=copy.deepcopy(plan['rows'][item['item_id']])
                row['grant_intent']=self._commit('remotex/v3/grant-intent',{'scope_intent':row['proof']['intent'],
                    'reference_proof':row['proof']['commitment'],'grant_id':grant_id,'item_id':item['item_id'],
                    'max_uses':item['max_uses'],'deadline_ms':int(item['deadline']*1000)})
                selected[item['item_id']]={**row,'remaining':item['max_uses'],'deadline':item['deadline']}
            if sum(row['remaining'] for row in selected.values())>200:
                raise ScopeError('setup-plan-capacity-required')
            self._pending(request_id)
            self.grants[grant_id]={'request_id':request_id,'rows':selected,'deadline':min(r['deadline'] for r in selected.values()),'seen':set()}
            plan['state']='bound'

    def issue(self,grant_id,item_id,capture,execution):
        with self.lock:
            self._valid()
            grant=self.grants.get(grant_id)
            row=grant and grant['rows'].get(item_id)
            if not row or self.clock()>=row['deadline'] or row['remaining']<=0:
                raise ScopeError('decision-invalid')
            validate_v3_capture(capture,row['meta']['profile_id'])
            intent=self._commit('remotex/v3/grant-intent',{'binding_digest':self.binding_digest,
                'capture':capture,'metadata_b64':_encoded(row['meta'])})
            if not hmac.compare_digest(intent,row['proof']['intent']):
                raise ScopeError('decision-invalid')
            if (not isinstance(execution,dict) or set(execution)!={'preauth_lifecycle','resume_id','document_id','generation','check_id','expires_at_ms'} or
                    execution['preauth_lifecycle']!=row['meta']['preauth_lifecycle'] or
                    any(not _hex(execution[k]) for k in ('resume_id','document_id','check_id')) or
                    not _safe_int(execution['generation']) or not _safe_int(execution['expires_at_ms'],1) or
                    execution['check_id'] in grant['seen']):
                raise ScopeError('decision-invalid')
            remaining=min(10,row['deadline']-self.clock())
            expiry=min(execution['expires_at_ms'],int((self.wall_clock()+remaining)*1000))
            if expiry<=self.wall_clock()*1000:
                raise ScopeError('decision-invalid')
            receipt={'kind':'initialization-permit-v3','version':3,'binding_digest':self.binding_digest,
                'grant_id':grant_id,'item_id':item_id,
                'intent_ref':row['intent_ref'],'intent_commitment':row['grant_intent'],'prerequisite_id':row['prerequisite_id'],
                'receipt_id':secrets.token_hex(16),**execution,'expires_at_ms':expiry,
                'response_checks':copy.deepcopy(row['meta']['response_checks'])}
            receipt['permit_commitment']=self._commit('remotex/v3/dispatch-permit',receipt)
            row['remaining']-=1
            grant['seen'].add(execution['check_id'])
            return receipt

    def matches(self,grant_id,item_id,capture):
        with self.lock:
            self._valid()
            grant=self.grants.get(grant_id)
            row=grant and grant['rows'].get(item_id)
            if not row or self.clock()>=row['deadline'] or row['remaining']<=0:
                return False
            try:
                validate_v3_capture(capture,row['meta']['profile_id'])
                current=self._commit('remotex/v3/grant-intent',{'binding_digest':self.binding_digest,
                    'capture':capture,'metadata_b64':_encoded(row['meta'])})
                return hmac.compare_digest(current,row['proof']['intent'])
            except ScopeError:
                return False

    def revoke(self,grant_id,items=None):
        with self.lock:
            grant=self.grants.get(grant_id)
            if not grant:
                return
            if items is not None:
                for item_id in items:
                    grant['rows'].pop(item_id,None)
                    self.plans.get(grant['request_id'],{}).get('rows',{}).pop(item_id,None)
            if items is None or not grant['rows']:
                self.grants.pop(grant_id,None)
                self.plans.pop(grant['request_id'],None)

    def cancel_plan(self,request_id):
        with self.lock:
            plan=self.plans.get(request_id)
            if plan and plan['state']=='pending':
                self.plans.pop(request_id)

    def close(self):
        with self.lock:
            self._closed=True
            self.plans.clear()
            self.grants.clear()
            self._key[:]=b'\0'*len(self._key)
