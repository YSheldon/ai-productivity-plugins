"""Site-wide task authority, committed only by the private native decision pipe."""
from __future__ import annotations

import copy
import re
import secrets
import threading
import time

from web_authorization import ScopeError, digest, identifier, integer, MAX_GRANT_SECONDS, MAX_NATIVE_REVIEW_SECONDS
from web_approval import ApprovalPrompt


class SiteService:
    def __init__(self, channel, *, binding, check, journal, prompt=ApprovalPrompt, clock=time.monotonic):
        self.channel, self.binding, self.check = channel, copy.deepcopy(binding), check
        self.journal, self.prompt, self.clock = journal, prompt, clock
        self.lock, self.operation_lock = threading.RLock(), threading.Lock()
        self.state, self.request_id, self.grant_id = 'new', None, None
        self.deadline = binding['deadline']
        self.manifests, self.prompts, self.attempts, self.keys = {}, {}, {}, {}
        self.login_result = {'state':'waiting-for-authorization','authenticationVerified':False}
        self.pending_action = None
        self.network_count = 0
        self.network_requests = {}
        self.recovery_uncertain = False
        self.reservation_id = secrets.token_hex(16)
        self.reserved = False
        self.cleanup_started = False
        channel.authorize = self._authorize
        channel.on_startup = self._network_event
        channel.on_close = self._closed

    def _closed(self):
        with self.lock:
            uncertain=self.recovery_uncertain or any(not row['complete'] for row in self.network_requests.values()) or any(
                row['state'] in {'executing','outcome-unknown'} for row in self.attempts.values())
            self.state = 'revoked'
            for attempt in self.attempts.values():
                if attempt['state']=='awaiting-action-confirmation': attempt['state']='cancelled'
            if self.reserved and not uncertain:
                try:
                    self.journal.resolve(self.reservation_id)
                    self.reserved=False
                except Exception:
                    pass  # Cancellation is immediate; failed recovery writes keep the fence.
            if self.cleanup_started: return
            self.cleanup_started=True
        # Native acknowledgment/revoke can hold the prompt lock. Never take it
        # synchronously while the caller may still own this service's lock.
        def cleanup():
            for prompt in list(self.prompts.values()): prompt.stop('session-closed')
        try:
            threading.Thread(target=cleanup,daemon=True).start()
        except RuntimeError:
            with self.lock:
                self.cleanup_started=False

    def _reserve(self):
        if not self.reserved:
            self.journal.reserve_site(self.reservation_id,self.binding['origin'])
            self.reserved=True

    def _review_current(self, manifest):
        self._valid(False)
        if self.clock()>=manifest['review_deadline']:
            self.state='revoked';self.channel.close()
            raise ScopeError('decision-invalid')

    def _event(self, event, **fields):
        try:
            self.journal.append({'event':event,'binding_digest':digest(self.binding),**fields})
        except Exception:
            self.recovery_uncertain=True
            self.state='revoked'
            self.channel.close()
            raise ScopeError('audit-unavailable') from None

    def _valid(self, active=True):
        try:
            if (self.state=='revoked' or not self.channel.available or self.clock()>=self.deadline or
                    self.check()!=self.binding):
                raise ScopeError('session-unavailable')
        except Exception as exc:
            self.state='revoked'; self.channel.close()
            raise ScopeError('session-unavailable') from exc
        if active and self.state!='active': raise ScopeError('approval-required')

    def _manifest(self, identity, *, action=None):
        seconds = max(1,min(MAX_GRANT_SECONDS,int(self.deadline-self.clock())))
        row = {'request_id':identity,'nonce':secrets.token_hex(32),'ui_mode':'site',
            'scope':'action' if action else 'site','binding':copy.deepcopy(self.binding),
            'ttl_seconds':min(30,seconds) if action else seconds,
            'wait_seconds':min(MAX_NATIVE_REVIEW_SECONDS,seconds),'items':[],
            'preview':copy.deepcopy(action or {})}
        row['request_digest']=digest(row)
        row['review_deadline']=self.clock()+row['wait_seconds']
        self.manifests[identity]=row
        return copy.deepcopy(row)

    def begin(self):
        with self.lock:
            self._valid(False)
            if self.state not in {'new','pending'}:
                raise ScopeError('decision-consumed')
            if self.state=='new':
                self.request_id=secrets.token_hex(16)
                manifest=self._manifest(self.request_id)
                self._event('site-requested',request_id=self.request_id)
                self.state='pending'
                try:
                    self.prompts[self.request_id]=self.prompt.start(manifest,
                        on_decision=lambda frame:self._decision(self.request_id,frame),
                        on_revoke=lambda:self.revoke({'end_task':True}),
                        on_cancel=lambda:self.revoke({'end_task':True}))
                except Exception:
                    self.revoke({'end_task':True})
                    raise ScopeError('approval-ui-unavailable') from None
        return self.status()

    def _decision(self, identity, frame):
        with self.lock:
            self._valid(False)
            manifest=self.manifests[identity]
            if (self.clock()>=manifest['review_deadline'] or
                    not isinstance(frame,dict) or
                    frame.get('nonce')!=manifest['nonce'] or frame.get('request_digest')!=manifest['request_digest'] or
                    frame.get('choices')!=[{'item_id':'site','max_uses':1,'targets':[]}]):
                raise ScopeError('decision-invalid')
            ttl=integer(frame.get('ttl_seconds'),1,manifest['ttl_seconds'])
            if identity==self.request_id:
                if self.state!='pending': raise ScopeError('decision-consumed')
                deadline=min(self.deadline,self.clock()+ttl)
                grant=secrets.token_hex(16)
                self._event('site-granted',request_id=identity,grant_id=grant,ttl_seconds=int(deadline-self.clock()))
                self._review_current(manifest)
                self.deadline=deadline; self.grant_id=grant; self.state='active'
                threading.Thread(target=self._login,daemon=True).start()
                return {'grant_id':grant,'expires_in_seconds':max(1,int(self.deadline-self.clock()))}
            attempt=self.attempts.get(identity)
            if not attempt or attempt['state']!='awaiting-action-confirmation': raise ScopeError('decision-consumed')
            self._valid()
            attempt['ticket_deadline']=min(self.deadline,self.clock()+min(ttl,30))
            self._event('site-action-confirmed',attempt_id=identity,scope_digest=attempt['scope_digest'])
            self._review_current(manifest)
            attempt['state']='confirmed'
            threading.Thread(target=self._run,args=(identity,),daemon=True).start()
            return {'grant_id':self.grant_id,'expires_in_seconds':max(1,int(attempt['ticket_deadline']-self.clock()))}

    def _login(self):
        try:
            result=self._worker('resume-login',{},timeout=55)
            with self.lock:
                self.login_result={'state':'verified' if result.get('authenticationVerified') else 'needs-user-check',
                    'authenticationVerified':result.get('authenticationVerified') is True,
                    'doNotResubmit':result.get('doNotResubmit',False)}
                self._event('site-login-result',summary={'authentication_verified':self.login_result['authenticationVerified']})
        except Exception:
            with self.lock:
                self.login_result={'state':'needs-user-check','authenticationVerified':False,'doNotResubmit':True}

    def _worker(self, operation, args, timeout=30):
        with self.lock: self._valid()
        result=self.channel.request(operation,args,timeout=timeout)
        if not isinstance(result,dict) or result.get('ok') is not True:
            code=result.get('failureCode','control-failed') if isinstance(result,dict) else 'control-failed'
            raise ScopeError(code if isinstance(code,str) and len(code)<=64 else 'control-failed')
        with self.lock: self._valid()
        return result

    def _authorize(self, message):
        try:
            with self.lock:
                self._valid()
                if not isinstance(message,dict): return False
                if message=={'kind':'site-login'}: return True
                if set(message)=={'kind','origin','method','request_id'} and message['kind']=='site-network':
                    if message['origin']!=self.binding['origin'] or message['method'] not in {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'}:
                        return False
                    identity=message['request_id']
                    if not isinstance(identity,str) or re.fullmatch('[a-f0-9]{32}',identity) is None: return False
                    previous=self.network_requests.get(identity)
                    if previous and (previous['method']!=message['method'] or previous['complete']): return False
                    if message['method'] not in {'GET','HEAD','OPTIONS'}: self._reserve()
                    if not previous:
                        if len(self.network_requests)>=16384: return False
                        self.network_requests[identity]={'method':message['method'],'complete':False}
                    self.network_count+=1
                    return True
                if set(message)=={'kind','attempt_id'} and message['kind']=='site-action':
                    attempt=self.attempts.get(message['attempt_id'])
                    return bool(attempt and attempt['state']=='executing' and self.clock()<attempt['ticket_deadline'])
                return False
        except Exception:
            return False

    def _network_event(self, frame):
        with self.lock:
            if (not isinstance(frame,dict) or set(frame)!={'kind','request_id','known'} or
                    frame['kind']!='site-network-complete' or type(frame['known']) is not bool or
                    not isinstance(frame['request_id'],str) or re.fullmatch('[a-f0-9]{32}',frame['request_id']) is None): return False
            row=self.network_requests.get(frame['request_id'])
            if not row or row['complete']: return False
            row['complete']=True
            if not frame['known']:
                self.recovery_uncertain=True
                self.state='revoked';self.channel.close()
            return True

    def components(self):
        if self.pending_action: raise ScopeError('operation-in-progress')
        return self._worker('components',{})

    def _ui(self, identity):
        prompt=self.prompts.get(identity)
        if prompt is None: return {}
        ui=prompt.status()
        manifest=self.manifests[identity]
        pending=(self.state=='pending' if identity==self.request_id else
            self.attempts[identity]['state']=='awaiting-action-confirmation')
        ui['review_remaining_seconds']=min(ui['review_remaining_seconds'],
            max(0,int(manifest['review_deadline']-self.clock())) if pending else 0)
        return {'approval_ui':ui}

    def status(self, request_id=None):
        with self.lock:
            if self.state!='revoked': self._valid(False)
            if request_id and request_id!=self.request_id: raise ScopeError('request-invalid')
            result={'authorization_mode':'site','state':self.state,'request_id':self.request_id,'grant_id':self.grant_id,
                'origin':self.binding['origin'],'account':self.binding['account'],
                'expires_in_seconds':max(0,int(self.deadline-self.clock())) if self.state=='active' else 0,
                'login':copy.deepcopy(self.login_result),'network_checks':self.network_count}
        return {**result,**self._ui(self.request_id)}

    def execute(self, args):
        if not isinstance(args,dict) or set(args)-{'observation_id','component_ref','action','value','risk','idempotency_key'}:
            raise ScopeError('request-invalid')
        key=identifier(args.get('idempotency_key'))
        scope=digest(args)
        with self.operation_lock:
            with self.lock:
                if key in self.keys:
                    identity=self.keys[key]
                    if self.attempts[identity]['scope_digest']!=scope: raise ScopeError('idempotency-conflict')
                    return self._result(identity)
                self._valid()
                if self.pending_action: raise ScopeError('operation-in-progress')
                if len(self.attempts)>=4096: raise ScopeError('request-too-large')
            payload={k:v for k,v in args.items() if k!='idempotency_key'}
            preview=self._worker('site-preview',payload)
            with self.lock:
                identity=secrets.token_hex(16)
                sensitive=preview.get('sensitive') is True or args.get('risk')=='sensitive'
                attempt={'state':'awaiting-action-confirmation' if sensitive else 'confirmed','scope_digest':scope,
                    'action_ref':preview['action_ref'],'ticket_deadline':min(self.deadline,self.clock()+30),
                    'mutating':args.get('action') not in {'read','read-table'}}
                self._event('site-action-requested',attempt_id=identity,scope_digest=scope,
                    summary={'action':args.get('action'),'sensitive':sensitive})
                self.attempts[identity]=attempt; self.keys[key]=identity
                if sensitive:
                    self.pending_action=identity
                    manifest=self._manifest(identity,action=preview['preview'])
                    try:
                        self.prompts[identity]=self.prompt.start(manifest,
                            on_decision=lambda frame:self._decision(identity,frame),
                            on_revoke=lambda:self._cancel_action(identity),on_cancel=lambda:self._cancel_action(identity))
                    except Exception:
                        self._cancel_action(identity)
                        raise ScopeError('approval-ui-unavailable') from None
                    return self._result(identity)
            return self._run(identity)

    def _run(self, identity):
        with self.lock:
            attempt=self.attempts[identity]
            try:
                self._valid()
                if attempt['state']!='confirmed' or self.clock()>=attempt['ticket_deadline']: raise ScopeError('approval-required')
                if attempt['mutating']:
                    self._reserve()
                self._event('site-action-dispatch',attempt_id=identity,scope_digest=attempt['scope_digest'])
                attempt['state']='executing'
            except Exception:
                attempt['state']='cancelled'; self.pending_action=None
                return self._result(identity)
        try:
            result=self.channel.request('site-execute',{'action_ref':attempt['action_ref'],'attempt_id':identity})
            with self.lock:
                self._valid()
                if result.get('ok') is not True:
                    if attempt['mutating'] and result.get('dispatched') is not False: raise ScopeError('outcome-unknown')
                    attempt['state']='failed-before-dispatch'; attempt['failureCode']=result.get('failureCode','control-failed')
                else:
                    attempt['state']='completed'; attempt['result']=result
                self._event('site-action-result',attempt_id=identity,state=attempt['state'])
        except Exception:
            with self.lock:
                attempt['state']='outcome-unknown' if attempt['mutating'] else 'failed'
                self.state='revoked'; self.channel.close()
        finally:
            with self.lock:
                if self.pending_action==identity: self.pending_action=None
        return self._result(identity)

    def _result(self, identity):
        attempt=self.attempts[identity]
        return {'attempt_id':identity,**copy.deepcopy({k:v for k,v in attempt.items()
            if k in {'state','result','failureCode'}})}

    def execution_status(self, args):
        identity=args.get('attempt_id')
        with self.lock:
            if identity not in self.attempts: raise ScopeError('request-invalid')
            result=self._result(identity)
            if self.state=='revoked': result.pop('result',None)
            else: self._valid()
        return {**result,**self._ui(identity)}

    def _cancel_action(self, identity):
        with self.lock:
            attempt=self.attempts[identity]
            if attempt['state']=='executing': return self.revoke({'end_task':True})
            if attempt['state'] in {'awaiting-action-confirmation','confirmed'}:
                attempt['state']='cancelled'
            if self.pending_action==identity: self.pending_action=None

    def revoke(self, args):
        if not isinstance(args,dict) or args!={'end_task':True}: raise ScopeError('request-invalid')
        with self.lock:
            if self.state!='revoked':
                self.state='revoked'
                try: self._event('site-revoked',count=self.network_count)
                finally: self.channel.close()
            return {'state':'revoked','session_closed':True}

    def guard_output(self, operation, args, result):
        if operation=='components' or operation in {'site-execute','execution-status'} and 'result' in result:
            return self._valid
        return None
