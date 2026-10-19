from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import threading
import time

from web_authorization import ScopeError, canonical, digest, validate_items

PHASES=['bootstrap','login-once']
PRIVATE_FIELD=re.compile(r'password|passwd|credential|private.?key|cookie|authorization|token|session|csrf|nonce|signature|ticket|challenge|username|account|(?:^|[_-])auth(?:$|[_-])',re.I)

def wire_digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')).hexdigest()

def _hex(value,length):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{'+str(length)+'}',value) is not None

def validate_checks(value):
    if not isinstance(value,list) or not 1<=len(value)<=8:
        raise ScopeError('request-contract-unavailable')
    for row in value:
        if not isinstance(row,dict) or not isinstance(row.get('pointer'),str):
            raise ScopeError('request-contract-unavailable')
        pointer=row['pointer']
        if not pointer.startswith('/') or len(pointer)>512 or re.search(r'~(?![01])',pointer):
            raise ScopeError('request-contract-unavailable')
        parts=[p.replace('~1','/').replace('~0','~') for p in pointer[1:].split('/')]
        if len(parts)>8 or any(not p or PRIVATE_FIELD.search(p) or p in {'__proto__','constructor','prototype'} or
                any(ord(c)<32 for c in p) for p in parts):
            raise ScopeError('request-contract-unavailable')
        test=row.get('test')
        expected=row.get('expected')
        if test=='nonempty-string':
            valid=set(row)=={'pointer','test'}
        elif set(row)!={'pointer','test','expected'}:
            valid=False
        elif test=='type':
            valid=isinstance(expected,str) and expected in {'object','array','string','boolean','integer','null'}
        elif test=='equals-boolean':
            valid=type(expected) is bool
        elif test=='equals-integer':
            valid=type(expected) is int and abs(expected)<=9007199254740991
        else:
            valid=False
        if not valid:
            raise ScopeError('request-contract-unavailable')
    if len({canonical(row) for row in value})!=len(value):
        raise ScopeError('request-contract-unavailable')
    return copy.deepcopy(value)

def _literals(value,depth=0):
    if depth>8:
        raise ScopeError('request-contract-unavailable')
    if value is None or type(value) is bool or (type(value) is int and abs(value)<=9007199254740991):
        return
    if isinstance(value,str) and len(value)<=16384 and not any(ord(c)<32 for c in value):
        if '-----BEGIN ' not in value and not re.search(r'\b(?:ghp_|glpat-|sk-proj-)',value):
            return
    if isinstance(value,list) and len(value)<=100:
        for part in value:
            _literals(part,depth+1)
        return
    if isinstance(value,dict) and len(value)<=100:
        for key,part in value.items():
            if not isinstance(key,str) or len(key)>128 or PRIVATE_FIELD.search(key) or key in {'internalAuth','__proto__','constructor','prototype'}:
                raise ScopeError('request-contract-unavailable')
            _literals(part,depth+1)
        return
    raise ScopeError('request-contract-unavailable')

def validate_descriptor(value):
    if (not isinstance(value,dict) or set(value)!={'method','path','query','contentType','body','resourceType'} or
        value['method']!='POST' or not isinstance(value['path'],str) or not re.fullmatch(r'/[A-Za-z0-9/_.~-]{0,511}',value['path']) or
        value['resourceType'] not in {'xhr','fetch'} or value['contentType'] not in {'application/json','application/x-www-form-urlencoded'} or
        not isinstance(value['query'],dict) or not isinstance(value['body'],dict) or len(canonical(value))>32768):
        raise ScopeError('request-contract-unavailable')
    _literals(value['body']);_literals(value['query'])

def validate_setup_context(resolved,binding):
    expected={'ok','items','contracts','setup_revision','preauth_lifecycle','phase_applicability','prerequisites','replace_grant_ids'}
    if (not isinstance(resolved,dict) or set(resolved)!=expected or resolved['setup_revision']!=2 or resolved['ok'] is not True or
            not _hex(resolved['preauth_lifecycle'],32) or resolved['phase_applicability']!=PHASES):
        raise ScopeError('request-invalid')
    rows=validate_items(resolved['items']);contracts=resolved['contracts'];prerequisites=[]
    if not isinstance(contracts,dict) or set(contracts)!={r['item_id'] for r in rows} or len(canonical(contracts))>65536:
        raise ScopeError('request-invalid')
    sources=resolved['replace_grant_ids']
    if not isinstance(sources,list) or len(sources)>2 or len(set(sources))!=len(sources) or any(not _hex(s,32) for s in sources):
        raise ScopeError('request-invalid')
    for row in rows:
        c=contracts[row['item_id']]
        keys={'phase','parent_id','semantics','descriptor','targets','revision','purpose','phase_applicability',
              'preauth_lifecycle','required','response_checks','prerequisite_id'}
        if (not isinstance(c,dict) or set(c)!=keys or c['revision']!=2 or c['phase'] not in PHASES or c['parent_id'] is not None or
            c['targets']!=[] or c['phase_applicability']!=PHASES or c['preauth_lifecycle']!=resolved['preauth_lifecycle'] or
            row['capability']!='web.page_step' or row['targets'] or row['depends_on'] or row['max_uses']>10 or
            row['output']!={'rows':0,'columns':0,'bytes':0} or row['effect']['class']!='task-bounded' or row['effect']['fields']):
            raise ScopeError('request-invalid')
        init=c['purpose']=='initialization-read'
        semantics='initialization-read' if init else 'bootstrap'
        if (c['purpose'] not in {'initialization-read','bootstrap-resource'} or c['semantics']!=semantics or c['required'] is not init or
                row['parameters']!={'network_ref':row['item_id'],'review_kind':semantics}):
            raise ScopeError('request-invalid')
        if init:
            validate_descriptor(c['descriptor']);validate_checks(c['response_checks'])
            want=wire_digest({'lifecycle':c['preauth_lifecycle'],'descriptor':c['descriptor'],'checks':c['response_checks']})
            if c['prerequisite_id']!=want:
                raise ScopeError('scope-mismatch')
            prerequisites.append(want)
        elif (c['response_checks']!=[] or c['prerequisite_id'] is not None or c['descriptor'].get('method') not in {'GET','HEAD'} or
              c['descriptor'].get('body') is not None or c['descriptor'].get('resourceType') not in {'document','script','stylesheet','image','font'}):
            raise ScopeError('request-contract-unavailable')
        if not init:
            _literals(c['descriptor'].get('query'))
        try:
            preview=json.loads(row['display']['preview'])
        except (ValueError,KeyError,TypeError):
            raise ScopeError('request-invalid') from None
        expected_preview={**c}
        expected_preview.pop('parent_id')
        proof=preview.get('evidence')
        expected_preview['evidence']=proof
        if (canonical(preview)!=canonical(expected_preview) or not isinstance(proof,list) or not 1<=len(proof)<=8 or
            any(not isinstance(p,dict) or set(p)!={'kind','reference'} or p['kind'] not in
                {'source-review','api-document','verified-record','operator-inspected'} or not isinstance(p['reference'],str) or
                not 1<=len(p['reference'])<=512 for p in proof)):
            raise ScopeError('scope-mismatch')
    if resolved['prerequisites']!=prerequisites:
        raise ScopeError('scope-mismatch')
    return {'revision':2,'preauth_lifecycle':resolved['preauth_lifecycle'],'phase_applicability':PHASES[:],
            'contracts':copy.deepcopy(contracts),'prerequisites':prerequisites}

class StartupAuthority:
    """Original-process startup state; no public state setter or credential API."""

    def __init__(self,binding,*,clock=time.monotonic,wall_clock=time.time):
        self.binding=copy.deepcopy(binding);self.binding_digest=digest(binding)
        self.clock,self.wall_clock=clock,wall_clock
        self.lock=threading.RLock();self.lifecycle=None;self.active=None
        self.required={};self.authentication_forwarded=0
        self.authentication_verified=False;self.authentication_grants=set()
        self.issued={};self.seen=set();self.ready=set();self.blocked=set();self.used_grants=set()

    def register(self,context):
        with self.lock:
            lifecycle=context['preauth_lifecycle']
            if not _hex(lifecycle,32) or self.lifecycle not in {None,lifecycle} or self.authentication_forwarded:
                raise ScopeError('scope-mismatch')
            staged=copy.deepcopy(self.required)
            for c in context['contracts'].values():
                if c.get('purpose')!='initialization-read':
                    continue
                if c.get('revision')==3:
                    if (context.get('revision')!=3 or not _hex(c.get('prerequisite_id'),64) or not _hex(c.get('intent_ref'),32) or
                            c.get('preauth_lifecycle')!=lifecycle or c.get('required') is not True or
                            any(old.get('revision')!=3 for old in staged.values())):
                        raise ScopeError('scope-mismatch')
                    validate_checks(c['response_checks'])
                    for old in staged.values():
                        if old.get('intent_ref')==c['intent_ref'] and (old['prerequisite_id']!=c['prerequisite_id'] or
                                canonical(old['response_checks'])!=canonical(c['response_checks'])):
                            raise ScopeError('scope-mismatch')
                    staged[c['prerequisite_id']]=copy.deepcopy(c)
                    continue
                if any(old.get('revision')==3 for old in staged.values()):
                    raise ScopeError('scope-mismatch')
                for old in staged.values():
                    if canonical(old['descriptor'])==canonical(c['descriptor']) and canonical(old)!=canonical(c):
                        # Item IDs/phase are proposal-local; the prerequisite is not.
                        if old['prerequisite_id']!=c['prerequisite_id'] or canonical(old['response_checks'])!=canonical(c['response_checks']):
                            raise ScopeError('scope-mismatch')
                staged[c['prerequisite_id']]=copy.deepcopy(c)
            self.lifecycle=lifecycle;self.required=staged

    def begin(self,*,lifecycle,session_deadline_ms):
        with self.lock:
            if self.active is not None or lifecycle!=self.lifecycle or self.authentication_forwarded:
                raise ScopeError('outcome-unknown' if self.authentication_forwarded else 'operation-in-progress')
            now=self.clock();remaining=min(45,self.binding['deadline']-now,session_deadline_ms/1000-self.wall_clock())
            if remaining<=0:
                raise ScopeError('session-unavailable')
            ticket={'resume_id':secrets.token_hex(16),'preauth_lifecycle':lifecycle,
                'binding_digest':self.binding_digest,'deadline_ms':int((self.wall_clock()+remaining)*1000)}
            self.active={**ticket,'deadline':now+remaining,'stage':'resuming','document_id':None,
                'phase':None,'generation':None,'armed':False,'controls':False}
            self.ready.clear();self.blocked.clear();self.issued.clear();self.seen.clear();self.used_grants.clear()
            return ticket

    def _current(self,allow_expired=False):
        a=self.active
        if not a or self.clock()>=self.binding['deadline'] or (not allow_expired and
                (self.clock()>=a['deadline'] or self.wall_clock()*1000>=a['deadline_ms'])):
            raise ScopeError('session-unavailable')
        return a

    def matches(self,message):
        with self.lock:
            a=self._current();s=message.get('startup')
            if (self.authentication_forwarded or a['armed'] or not isinstance(s,dict) or
                set(s)!={'resume_id','preauth_lifecycle','document_id','generation'} or
                any(s.get(k)!=a.get(k) for k in s) or message.get('phase')!=a['phase']):
                raise ScopeError('scope-mismatch')
            return a

    def issue(self,*,check_id,message,contract):
        with self.lock:
            a=self.matches(message)
            if (a['stage']!='committed' or not _hex(check_id,32) or check_id in self.seen or
                contract.get('purpose')!='initialization-read' or contract.get('prerequisite_id') not in self.required or
                canonical(contract['descriptor'])!=canonical(message.get('descriptor')) or
                message.get('digest')!=wire_digest(message['descriptor'])):
                raise ScopeError('scope-mismatch')
            self.seen.add(check_id)
            permit={'kind':'initialization-read','check_id':check_id,'descriptor_digest':message['digest'],
                'binding_digest':self.binding_digest,'preauth_lifecycle':self.lifecycle,'resume_id':a['resume_id'],
                'document_id':a['document_id'],'generation':a['generation'],
                'expires_at_ms':min(a['deadline_ms'],int((self.wall_clock()+10)*1000)),
                'prerequisite_id':contract['prerequisite_id'],'response_checks':copy.deepcopy(contract['response_checks'])}
            self.issued[check_id]={'permit':permit,'forwarded':False}
            return copy.deepcopy(permit)

    def issue_v3(self,*,authority,grant_id,item_id,check_id,message,contract,check_deadline):
        with self.lock:
            a=self.matches(message)
            if (a['stage']!='committed' or not _hex(check_id,32) or check_id in self.seen or
                    contract.get('revision')!=3 or contract.get('purpose')!='initialization-read' or
                    contract.get('prerequisite_id') not in self.required or self.clock()>=check_deadline):
                raise ScopeError('scope-mismatch')
            remaining=min(10,check_deadline-self.clock())
            execution={'check_id':check_id,'preauth_lifecycle':self.lifecycle,'resume_id':a['resume_id'],
                'document_id':a['document_id'],'generation':a['generation'],
                'expires_at_ms':min(a['deadline_ms'],int((self.wall_clock()+remaining)*1000))}
            permit=authority.issue(grant_id,item_id,message['capture'],execution)
            if (permit['prerequisite_id']!=contract['prerequisite_id'] or permit['intent_ref']!=contract['intent_ref'] or
                    canonical(permit['response_checks'])!=canonical(contract['response_checks'])):
                raise ScopeError('scope-mismatch')
            self.seen.add(check_id)
            self.issued[check_id]={'permit':permit,'forwarded':False}
            return copy.deepcopy(permit)

    def event(self,frame):
        with self.lock:
            a=self._current(allow_expired=frame.get('kind')=='resume-ended')
            base={'kind','resume_id','preauth_lifecycle','document_id','phase','generation','authentication_forwarded'}
            kind=frame.get('kind')
            extra={'check_id','prerequisite_id','ready'} if kind=='prerequisite-response' else (
                {'check_id','prerequisite_id'} if kind=='initialization-forwarded' else set())
            if (set(frame)!=base|extra or frame['resume_id']!=a['resume_id'] or frame['preauth_lifecycle']!=self.lifecycle or
                not _hex(frame['document_id'],32) or frame['phase'] not in PHASES or type(frame['generation']) is not int or frame['generation']<0 or
                type(frame['authentication_forwarded']) is not int):
                raise ScopeError('scope-mismatch')
            if kind=='document-opening' and a['stage']=='resuming':
                a.update(document_id=frame['document_id'],phase=frame['phase'],generation=frame['generation'],stage='opening')
            if frame['document_id']!=a['document_id']:
                raise ScopeError('scope-mismatch')
            if (frame['phase'],frame['generation'])!=(a['phase'],a['generation']):
                if kind=='controls-ready' and a['phase'] in PHASES and frame['phase']=='login-once' and frame['generation']==a['generation']+1:
                    a.update(phase=frame['phase'],generation=frame['generation'])
                else:
                    raise ScopeError('scope-mismatch')
            count=frame['authentication_forwarded']
            if kind=='authentication-forwarded':
                if count!=self.authentication_forwarded+1:
                    raise ScopeError('scope-mismatch')
                self.authentication_forwarded=count;a['armed']=True
            elif count!=self.authentication_forwarded:
                raise ScopeError('scope-mismatch')
            if kind=='document-opening':
                pass
            elif kind=='document-committed' and a['stage']=='opening':
                a['stage']='committed'
            elif kind in {'initialization-forwarded','prerequisite-response'}:
                row=self.issued.get(frame['check_id'])
                if not row or row['permit']['prerequisite_id']!=frame['prerequisite_id'] or a['armed']:
                    raise ScopeError('scope-mismatch')
                if kind=='initialization-forwarded':
                    if row['forwarded'] or self.wall_clock()*1000>=row['permit']['expires_at_ms']:
                        raise ScopeError('scope-mismatch')
                    row['forwarded']=True
                else:
                    if not row['forwarded'] or type(frame['ready']) is not bool:
                        raise ScopeError('scope-mismatch')
                    self.issued.pop(frame['check_id'])
                    (self.ready if frame['ready'] else self.blocked).add(frame['prerequisite_id'])
            elif kind=='controls-ready':
                if len(self.ready-self.blocked)!=len(self.required) or self.issued or a['stage']!='committed':
                    raise ScopeError('initialization-required')
                a['controls']=True
            elif kind=='credentials-armed':
                if not a['controls'] or a['armed']:
                    raise ScopeError('initialization-required')
                a['armed']=True
            elif kind in {'authentication-forwarded','authentication-verified'}:
                if kind=='authentication-verified' and not self.authentication_forwarded:
                    raise ScopeError('scope-mismatch')
                if kind=='authentication-verified':
                    self.authentication_verified=True
            elif kind=='resume-ended':
                self.end(a['resume_id'])
            else:
                raise ScopeError('scope-mismatch')
            return {'event':kind,'generation':frame['generation'],'count':1,
                **({'contract_digest':frame['prerequisite_id']} if extra else {})}

    def end(self,resume_id):
        with self.lock:
            if self.active and self.active['resume_id']==resume_id:
                self.active=None;self.issued.clear();self.used_grants.clear()

    def status(self):
        with self.lock:
            ready=len(self.ready-self.blocked)
            return {'required':len(self.required),'ready':ready,'pending':len(self.issued),'blocked':len(self.blocked),
                'controls_ready':bool(self.active and self.active['controls']),
                'state':'not-required' if self.lifecycle is None else 'sealed' if self.authentication_forwarded or (self.active and self.active['armed']) else
                    'ready' if self.active and ready==len(self.required) and not self.issued and not self.blocked else 'pending'}
