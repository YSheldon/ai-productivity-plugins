from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import threading
import time
from typing import Any, Callable


CAPABILITIES = frozenset({'web.navigate', 'web.read_region', 'web.read_table',
    'web.query_input', 'web.page_step', 'web.read_result', 'web.inspect_action',
    'web.business_action'})
CLASSES = frozenset({'task-bounded', 'action-bound', 'action-time'})
ITEM_FIELDS = frozenset({'item_id','capability','fingerprint','page','max_uses',
    'depends_on','targets','parameters','output','display','effect'})
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
SECRET_FIELD = re.compile(r'password|passwd|credential|private.key|cookie|authorization|access.token|refresh.token', re.I)


class ScopeError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class GuardedResult(dict):
    """Transport-only authority context; the callback is never JSON content."""

    def __init__(self, value, check):
        super().__init__(value)
        self.check_authority=check


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True,
                          separators=(',', ':'), allow_nan=False).encode('ascii')
    except (TypeError, ValueError, OverflowError) as exc:
        raise ScopeError('request-invalid') from exc


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ScopeError('request-invalid')
    return value


def integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ScopeError('request-invalid')
    return value


def data_only(value: Any, depth: int = 0) -> None:
    if depth > 12:
        raise ScopeError('request-invalid')
    if isinstance(value, dict):
        for key, part in value.items():
            if not isinstance(key, str) or len(key) > 128 or SECRET_FIELD.search(key):
                raise ScopeError('request-invalid')
            data_only(part, depth + 1)
    elif isinstance(value, list):
        if len(value) > 200:
            raise ScopeError('request-too-large')
        for part in value:
            data_only(part, depth + 1)
    elif isinstance(value, str):
        if len(value.encode('utf-8')) > 4096 or any(ord(c) < 32 for c in value):
            raise ScopeError('request-invalid')
        if '-----BEGIN ' in value or re.search(r'\b(?:ghp_|glpat-|sk-proj-)[A-Za-z0-9_-]{12,}', value):
            raise ScopeError('request-invalid')
    elif value is not None and type(value) not in (int, bool):
        raise ScopeError('request-invalid')


def validate_items(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list) or not 1 <= len(items) <= 32:
        raise ScopeError('request-too-large')
    if len(canonical(items)) > 32768:
        raise ScopeError('request-too-large')
    names = set()
    for row in items:
        if not isinstance(row, dict) or set(row) != ITEM_FIELDS:
            raise ScopeError('request-invalid')
        data_only(row)
        name = identifier(row['item_id'])
        if name in names or row['capability'] not in CAPABILITIES:
            raise ScopeError('request-invalid')
        names.add(name)
        integer(row['max_uses'], 1, 50)
        if not isinstance(row['fingerprint'], str) or not re.fullmatch('[a-f0-9]{64}', row['fingerprint']):
            raise ScopeError('request-invalid')
        if not isinstance(row['page'], str) or not re.fullmatch(r'#/[A-Za-z0-9/_-]{0,511}', row['page']):
            raise ScopeError('request-invalid')
        for key in ('parameters','display','output','effect'):
            if not isinstance(row[key], dict):
                raise ScopeError('request-invalid')
        effect = row['effect']
        if set(effect) != {'class','fields','digest'} or effect['class'] not in CLASSES:
            raise ScopeError('request-invalid')
        if not isinstance(effect['digest'], str) or not re.fullmatch('[a-f0-9]{64}', effect['digest']):
            raise ScopeError('request-invalid')
        for key in ('targets','depends_on'):
            values = row[key]
            if not isinstance(values, list) or len(values) > 100 or any(not isinstance(v,str) for v in values) or len(set(values)) != len(values):
                raise ScopeError('request-invalid')
            for value in values:
                identifier(value)
        if not isinstance(effect['fields'], list) or not all(isinstance(v, str) and IDENTIFIER.fullmatch(v) for v in effect['fields']):
            raise ScopeError('request-invalid')
        if row['capability'] == 'web.business_action' and (not row['targets'] or not effect['fields']):
            raise ScopeError('request-invalid')
        if set(row['output']) != {'rows','columns','bytes'}:
            raise ScopeError('request-invalid')
        for key, maximum in (('rows',100),('columns',30),('bytes',98304)):
            integer(row['output'][key], 0, maximum)
    rows = {row['item_id']: row for row in items}
    visiting, visited = set(), set()
    def visit(name):
        if name not in rows or name in visiting:
            raise ScopeError('request-invalid')
        if name in visited:
            return
        visiting.add(name)
        for parent in rows[name]['depends_on']:
            visit(parent)
        visiting.remove(name)
        visited.add(name)
    for name in names:
        visit(name)
    if sum(row['max_uses'] for row in items) > 200 or len(set(t for row in items for t in row['targets'])) > 100:
        raise ScopeError('request-too-large')
    return copy.deepcopy(items)


class Broker:
    """Supervisor-owned authority. IDs are local lookups, never bearer tokens."""

    def __init__(self, binding: dict, *, journal, check: Callable, close: Callable,
                 clock: Callable = time.monotonic):
        self.binding = copy.deepcopy(binding)
        self.binding_digest = digest(binding)
        self.journal, self.check, self.close, self.clock = journal, check, close, clock
        self.lock = threading.RLock()
        self.output_lock = threading.RLock()
        self.fenced = threading.Event()
        self._close_once=threading.Lock()
        self.requests, self.request_keys, self.grants = {}, {}, {}
        self.attempts, self.attempt_keys = {}, {}

    def _valid(self):
        if self.fenced.is_set():
            raise ScopeError('grant-revoked')
        if digest(self.check()) != self.binding_digest:
            self.emergency_revoke()
            raise ScopeError('scope-mismatch')
        if self.clock() >= self.binding['deadline']:
            self.emergency_revoke()
            raise ScopeError('grant-expired')

    def _event(self, event, **fields):
        try:
            self.journal.append({'event':event, 'binding_digest':self.binding_digest, **fields})
        except Exception as exc:
            self.emergency_revoke()
            raise ScopeError('audit-incomplete') from exc
        if self.fenced.is_set():
            raise ScopeError('grant-revoked')

    def request(self, items, *, idempotency_key, ttl_seconds=300):
        key = identifier(idempotency_key)
        integer(ttl_seconds, 60, 900)
        rows = validate_items(items)
        submitted = digest({'items':rows,'ttl':ttl_seconds})
        with self.lock:
            self._valid()
            if key in self.request_keys:
                previous = self.requests[self.request_keys[key]]
                if previous['submitted'] != submitted:
                    raise ScopeError('request-conflict')
                return self.status(previous['id'])
            if any(r['state']=='pending' and not r['fence'].is_set() and r['review_deadline']>self.clock() for r in self.requests.values()):
                raise ScopeError('approval-already-pending')
            if sum(g['state']=='active' and not self.requests[g['request_id']]['fence'].is_set() and g['deadline']>self.clock() for g in self.grants.values()) >= 4:
                raise ScopeError('grant-limit-exceeded')
            if self.binding['deadline'] - self.clock() < 60:
                raise ScopeError('lifetime-insufficient')
            identifier_value = secrets.token_hex(16)
            request = {'id':identifier_value,'nonce':secrets.token_hex(32),
                'submitted':submitted,'digest':digest({'binding':self.binding,'scope':rows,'ttl':ttl_seconds}),
                'items':rows,'ttl':ttl_seconds,'state':'pending','created':self.clock(),
                'review_deadline':min(self.clock()+120,self.binding['deadline']),
                'grant_id':None,'fence':threading.Event(),'item_states':{row['item_id']:'pending' for row in rows}}
            self._event('request-created',request_id=identifier_value,request_digest=request['digest'],count=len(rows))
            self.requests[identifier_value] = request
            self.request_keys[key] = identifier_value
            return self.status(identifier_value)

    def approval_manifest(self, request_id):
        with self.lock:
            self._valid()
            request = self.requests.get(request_id)
            if not request or request['state'] != 'pending' or request['fence'].is_set():
                raise ScopeError('decision-consumed')
            return {'request_id':request_id,'nonce':request['nonce'],'request_digest':request['digest'],
                'binding':copy.deepcopy(self.binding),'items':copy.deepcopy(request['items']),
                'ttl_seconds':request['ttl'],'wait_seconds':max(0,int(request['review_deadline']-self.clock()))}

    def accept_decision(self, request_id, *, nonce, digest, choices, ttl_seconds):
        with self.lock:
            self._valid()
            request = self.requests.get(request_id)
            if not request or request['state'] != 'pending' or request['fence'].is_set():
                raise ScopeError('decision-consumed')
            if self.clock() >= request['review_deadline']:
                request['state']='expired'
                raise ScopeError('request-expired')
            if not secrets.compare_digest(str(nonce),request['nonce']) or not secrets.compare_digest(str(digest),request['digest']):
                raise ScopeError('decision-invalid')
            try:
                integer(ttl_seconds,1,request['ttl'])
                if not isinstance(choices,list) or len(choices)>len(request['items']):
                    raise ScopeError('decision-invalid')
                originals = {row['item_id']:row for row in request['items']}
                selected = {}
                for choice in choices:
                    if not isinstance(choice,dict) or not {'item_id','max_uses','targets'}<=set(choice) or set(choice)-{'item_id','max_uses','targets','output','semantic_classification'}:
                        raise ScopeError('decision-invalid')
                    name = choice['item_id']
                    if name not in originals or name in selected:
                        raise ScopeError('decision-invalid')
                    original = originals[name]
                    uses = integer(choice['max_uses'],1,original['max_uses'])
                    targets = choice['targets']
                    if not isinstance(targets,list) or any(not isinstance(v,str) for v in targets) or len(set(targets)) != len(targets) or not set(targets) <= set(original['targets']):
                        raise ScopeError('decision-invalid')
                    if original['targets'] and not targets:
                        continue
                    if original['effect']['class'] in {'action-bound','action-time'} and uses != 1:
                        raise ScopeError('decision-invalid')
                    output=choice.get('output',original['output'])
                    if not isinstance(output,dict) or set(output)!=set(original['output']):
                        raise ScopeError('decision-invalid')
                    for key,maximum in original['output'].items():
                        integer(output[key],0,maximum)
                    selected[name] = {**copy.deepcopy(original),'max_uses':uses,'targets':list(targets),'output':copy.deepcopy(output)}
                    review=original['parameters'].get('review_kind')
                    if review is not None:
                        expected='read' if review=='unclassified' else review
                        if expected not in {'read','write','bootstrap','login'} or choice.get('semantic_classification')!=expected:
                            raise ScopeError('decision-invalid')
                        selected[name]['parameters']['approved_semantics']=expected
                    elif 'semantic_classification' in choice:
                        raise ScopeError('decision-invalid')
            except (ScopeError,TypeError,KeyError) as exc:
                raise ScopeError('decision-invalid') from exc
            states = {name:('approved' if name in selected else 'rejected') for name in originals}
            while True:
                blocked = [name for name,row in selected.items() if any(p not in selected for p in row['depends_on'])]
                if not blocked:
                    break
                for name in blocked:
                    selected.pop(name)
                    states[name]='dependency-blocked'
            deadline = min(self.clock()+ttl_seconds,self.binding['deadline'])
            scope_digest = globals()['digest']({'items':selected,'deadline':deadline,'request':request['digest']})
            self._event('decision-recorded',request_id=request_id,approved_scope_digest=scope_digest,
                        approved_items=list(selected),ttl_seconds=ttl_seconds)
            if request['fence'].is_set():
                raise ScopeError('grant-revoked')
            request['nonce']=''
            request['item_states']=states
            def unchanged(name):
                original=copy.deepcopy(originals[name])
                if 'approved_semantics' in selected[name]['parameters']:
                    original['parameters']['approved_semantics']=selected[name]['parameters']['approved_semantics']
                return selected[name]==original
            full = len(selected)==len(originals) and all(unchanged(n) for n in selected)
            request['state']='approved' if full else 'partially-approved' if selected else 'rejected'
            if selected:
                grant_id=secrets.token_hex(16)
                self._event('grant-issued',grant_id=grant_id,request_id=request_id,approved_scope_digest=scope_digest)
                if request['fence'].is_set():
                    raise ScopeError('grant-revoked')
                self.grants[grant_id]={'state':'active','items':selected,'deadline':deadline,'scope_digest':scope_digest,
                    'remaining':{n:r['max_uses'] for n,r in selected.items()},'verified':set(),'revoked_items':set(),'write_reservations':0,'request_id':request_id}
                request['grant_id']=grant_id
            return self.status(request_id)

    def status(self, request_id):
        with self.lock:
            request=self.requests.get(request_id)
            if not request:
                raise ScopeError('request-invalid')
            if request['state']=='pending' and self.clock()>=request['review_deadline']:
                request['state']='expired'
            if request['state']=='pending' and request['fence'].is_set():
                request['state']='cancelled'
            grant=self.grants.get(request['grant_id'])
            grant_state=('revoked' if self.fenced.is_set() or request['fence'].is_set() else
                'expired' if grant and self.clock()>=grant['deadline'] else grant['state']) if grant else None
            allowed=[n for n in grant['items'] if not self._dependency_revoked(grant,n)] if grant_state=='active' else []
            return {'request_id':request_id,'state':request['state'],'request_digest':request['digest'],
                'grant_id':request['grant_id'],'allowed_items':allowed,
                'item_states':copy.deepcopy(request['item_states']),
                'grant_state':grant_state,
                'remaining':copy.deepcopy(grant['remaining']) if grant else {},
                'effective_limits':{n:{'max_uses':r['max_uses'],'targets':copy.deepcopy(r['targets']),
                    'output':copy.deepcopy(r['output'])} for n,r in grant['items'].items() if n in allowed} if grant else {},
                'expires_in_seconds':max(0,int(grant['deadline']-self.clock())) if grant else 0,
                'approved_scope_digest':grant['scope_digest'] if grant else None}

    def cancel(self, request_id):
        request=self.requests.get(request_id)
        if request and request['state']=='pending':
            request['fence'].set()
        with self.lock:
            request=self.requests.get(request_id)
            if not request or request['state']!='pending':
                raise ScopeError('decision-consumed')
            request['nonce']=''
            request['state']='cancelled'
            self._event('request-cancelled',request_id=request_id)
            return self.status(request_id)

    def revoke_request(self, request_id):
        request=self.requests.get(request_id)
        if not request:
            raise ScopeError('request-invalid')
        # Set before any audit/authorization lock; a late decision cannot revive it.
        if request['fence'].is_set():
            return
        request['fence'].set()
        def record():
            try:
                with self.lock:
                    request['nonce']=''
                    if not request.get('grant_id') and request['state'] not in {'rejected','expired'}:
                        request['state']='cancelled'
                    grant=self.grants.get(request.get('grant_id'))
                    if grant:
                        grant['state']='revoked'
                    self._event('request-revoked',request_id=request_id)
            except ScopeError:
                pass
        threading.Thread(target=record,daemon=True).start()

    def _dependency_revoked(self, grant, item_id):
        if item_id in grant['revoked_items']:
            return True
        return any(self._dependency_revoked(grant,parent) for parent in grant['items'][item_id]['depends_on'])

    def _grant(self, grant_id, item_id):
        self._valid()
        grant=self.grants.get(grant_id)
        if not grant:
            raise ScopeError('approval-required')
        if grant['state']!='active' or self.requests[grant['request_id']]['fence'].is_set() or item_id in grant['revoked_items']:
            raise ScopeError('grant-revoked')
        if self.clock()>=grant['deadline']:
            raise ScopeError('grant-expired')
        if item_id not in grant['items']:
            raise ScopeError('scope-mismatch')
        if self._dependency_revoked(grant,item_id):
            raise ScopeError('dependency-blocked')
        return grant,grant['items'][item_id]

    def reserve(self, grant_id, item_id, idempotency_key, parameters):
        identifier(idempotency_key)
        with self.lock:
            grant,row=self._grant(grant_id,item_id)
            submitted=digest({'grant':grant_id,'item':item_id,'parameters':parameters})
            key=digest([grant_id,idempotency_key])
            if key in self.attempt_keys:
                attempt=self.attempts[self.attempt_keys[key]]
                if attempt['submitted']!=submitted:
                    raise ScopeError('request-conflict')
                return self._attempt_result(attempt)
            if parameters != row['parameters']:
                raise ScopeError('parameter-denied')
            if any(parent not in grant['verified'] for parent in row['depends_on']):
                raise ScopeError('dependency-blocked')
            if grant['remaining'][item_id]<=0:
                raise ScopeError('budget-exhausted')
            confirmation=row['effect']['class']=='action-time'
            identifier_value=secrets.token_hex(16)
            write=row['capability']=='web.business_action'
            if write:
                if grant['write_reservations']+len(row['targets'])>200:
                    raise ScopeError('impact-limit-exceeded')
                # Model-provided field labels are not resource identities. Until
                # a canonical server mapping exists, fence the entire object.
                conflicts=[digest([self.binding['origin'],target]) for target in row['targets']]
                self.journal.reserve(identifier_value,conflicts)
                grant['write_reservations']+=len(row['targets'])
            grant['remaining'][item_id]-=1
            attempt={'id':identifier_value,'grant_id':grant_id,'item_id':item_id,'submitted':submitted,
                'scope':copy.deepcopy(row),'state':'awaiting-action-confirmation' if confirmation else 'reserved',
                'write':write,'summary':{},'ticket_used':False,'fence':threading.Event()}
            if confirmation:
                attempt.update({'nonce':secrets.token_hex(32),
                    'confirmation_digest':digest({'attempt':identifier_value,'scope':row,'binding':self.binding}),
                    'review_deadline':min(self.clock()+120,grant['deadline'])})
            self.attempts[identifier_value]=attempt
            self.attempt_keys[key]=identifier_value
            self._event('execution-reserved',attempt_id=identifier_value,grant_id=grant_id,item_id=item_id,
                        capability=row['capability'],scope_digest=digest(row),targets=len(row['targets']))
            self._valid()
            return self._attempt_result(attempt)

    def confirmation_manifest(self, attempt_id):
        with self.lock:
            attempt=self.attempts.get(attempt_id)
            if not attempt or attempt['state']!='awaiting-action-confirmation' or attempt['fence'].is_set():
                raise ScopeError('decision-consumed')
            grant,_=self._grant(attempt['grant_id'],attempt['item_id'])
            return {'request_id':attempt_id,'nonce':attempt['nonce'],
                'request_digest':attempt['confirmation_digest'],'binding':copy.deepcopy(self.binding),
                'items':[{**copy.deepcopy(attempt['scope']),'max_uses':1}],
                'ttl_seconds':min(30,max(1,int(grant['deadline']-self.clock()))),
                'wait_seconds':max(0,int(attempt['review_deadline']-self.clock()))}

    def accept_action_decision(self, attempt_id, *, nonce, digest, choices, ttl_seconds):
        with self.lock:
            attempt=self.attempts.get(attempt_id)
            if not attempt or attempt['state']!='awaiting-action-confirmation' or attempt['fence'].is_set():
                raise ScopeError('decision-consumed')
            grant,row=self._grant(attempt['grant_id'],attempt['item_id'])
            if self.clock()>=attempt['review_deadline']:
                raise ScopeError('request-expired')
            expected=[{'item_id':attempt['item_id'],'targets':row['targets'],'max_uses':1}]
            if isinstance(choices,list) and len(choices)==1 and isinstance(choices[0],dict) and 'output' in choices[0]:
                expected[0]['output']=row['output']
            if not secrets.compare_digest(str(nonce),attempt['nonce']) or not secrets.compare_digest(str(digest),attempt['confirmation_digest']):
                raise ScopeError('decision-invalid')
            if choices==[]:
                self.finish(attempt_id,state='failed-before-dispatch',summary={})
                return self.execution_status(attempt_id)
            if choices!=expected or type(ttl_seconds) is not int or not 1<=ttl_seconds<=30:
                raise ScopeError('decision-invalid')
            self._event('action-confirmed',attempt_id=attempt_id,scope_digest=attempt['confirmation_digest'])
            attempt['nonce']=''
            attempt['state']='reserved'
            attempt['ticket_deadline']=min(self.clock()+ttl_seconds,grant['deadline'])
            return {**self._attempt_result(attempt),'grant_id':attempt['grant_id'],
                    'expires_in_seconds':max(0,int(attempt['ticket_deadline']-self.clock()))}

    def authorize_attempt(self, attempt_id, *, consume=False):
        with self.lock:
            attempt=self.attempts.get(attempt_id)
            if not attempt:
                raise ScopeError('request-invalid')
            if attempt['fence'].is_set():
                raise ScopeError('grant-revoked')
            self._grant(attempt['grant_id'],attempt['item_id'])
            if attempt['state']!='reserved':
                raise ScopeError('action-confirmation-required' if attempt['state']=='awaiting-action-confirmation' else 'outcome-unknown')
            if attempt['scope']['effect']['class']=='action-time':
                if self.clock()>=attempt.get('ticket_deadline',0) or (consume and attempt['ticket_used']):
                    raise ScopeError('action-confirmation-required')
                if consume:
                    attempt['ticket_used']=True
            return True

    def _attempt_result(self, attempt):
        return {'attempt_id':attempt['id'],'state':attempt['state'],'scope':copy.deepcopy(attempt['scope']),
                'summary':copy.deepcopy(attempt['summary'])}

    def finish(self, attempt_id, *, state, summary, targets=None):
        if state not in {'verified','failed-before-dispatch','failed','outcome-unknown','accepted','running','partial'}:
            raise ScopeError('result-invalid')
        if not isinstance(summary,dict) or set(summary)-{'count','code','success','target_count'} or any(type(v) not in (int,bool) for v in summary.values()):
            raise ScopeError('result-invalid')
        with self.lock:
            attempt=self.attempts.get(attempt_id)
            if not attempt:
                raise ScopeError('request-invalid')
            if targets is not None:
                if not isinstance(targets,list) or any(not isinstance(row,dict) or set(row)!={'identity','state'} or
                    row.get('state') not in {'verified','outcome-unknown','partial','accepted','running'} for row in targets):
                    raise ScopeError('result-invalid')
                identities=[row['identity'] for row in targets]
                if sorted(identities)!=sorted(attempt['scope']['targets']) or len(set(identities))!=len(identities) or (
                    state=='verified' and any(row['state']!='verified' for row in targets)):
                    raise ScopeError('result-invalid')
                attempt['targets']=copy.deepcopy(targets)
            self._event('execution-finished',attempt_id=attempt_id,state=state,summary=summary)
            attempt['state'],attempt['summary']=state,copy.deepcopy(summary)
            if state=='verified':
                self.grants[attempt['grant_id']]['verified'].add(attempt['item_id'])
            if attempt['write'] and state in {'verified','failed-before-dispatch'}:
                self.journal.resolve(attempt_id)
            return self.execution_status(attempt_id)

    def execution_status(self, attempt_id):
        with self.lock:
            attempt=self.attempts.get(attempt_id)
            if not attempt:
                raise ScopeError('request-invalid')
            return {'attempt_id':attempt_id,'state':attempt['state'],'summary':copy.deepcopy(attempt['summary']),
                'targets':copy.deepcopy(attempt.get('targets',[{'identity':target,'state':attempt['state']} for target in attempt['scope']['targets']]))}

    def release_output(self, attempt_id, content):
        with self.lock:
            attempt=self.attempts[attempt_id]
            self._grant(attempt['grant_id'],attempt['item_id'])
            if len(canonical(content))>attempt['scope']['output']['bytes']:
                raise ScopeError('response-too-large')
            self._event('output-ready',attempt_id=attempt_id)
            with self.output_lock:
                self._grant(attempt['grant_id'],attempt['item_id'])
                return content

    def revoke(self, grant_id, items=None):
        grant=self.grants.get(grant_id)
        if not grant:
            raise ScopeError('request-invalid')
        if items is not None and (not isinstance(items,list) or any(not isinstance(n,str) for n in items)
                or not set(items)<=set(grant['items'])):
            raise ScopeError('request-invalid')
        already=grant['state']=='revoked' or (items is not None and set(items)<=grant['revoked_items'])
        if items is None:
            grant['state']='revoked'
        else:
            grant['revoked_items'].update(items)
        if already:
            return {'state':'revoked','session_closed':self.fenced.is_set(),'auditPending':grant.get('revocation_pending',False)}
        # Authority is fenced first; unrelated slow audit work must not turn
        # a scoped revocation into a whole-session termination.
        completed=threading.Event();grant['revocation_pending']=True
        def record():
            try:
                with self.lock:
                    self._event('grant-revoked',grant_id=grant_id,item_ids=items or [])
            except ScopeError:
                pass
            finally:
                grant['revocation_pending']=False;completed.set()
        threading.Thread(target=record,daemon=True).start()
        completed.wait(timeout=0.01)
        return {'state':'revoked','session_closed':self.fenced.is_set(),'auditPending':not completed.is_set()}

    def emergency_revoke(self):
        self.fenced.set()
        if self._close_once.acquire(blocking=False):
            self.close()
