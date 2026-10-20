from __future__ import annotations

import copy
import re
import secrets
import threading
import time

from web_authorization import Broker, ScopeError, MAX_GRANT_SECONDS, canonical, digest
from web_approval import ApprovalPrompt
from web_initialization import StartupAuthority, validate_setup_context
from web_initialization_v3 import V3Authority, validate_setup_context_v3
from web_component_protocol import V3_WORKER_PROTOCOL


class Service:
    """Authority belongs to the original supervisor, never the tool caller."""

    def __init__(self, channel, *, binding, check, journal, prompt=ApprovalPrompt,
                 clock=time.monotonic):
        self.channel, self.prompt, self.clock = channel, prompt, clock
        self.broker = Broker(binding, journal=journal, check=check, close=self._close, clock=clock)
        self.contexts, self.grant_contexts, self.prompts = {}, {}, {}
        self.executing, self.dispatched = set(), set()
        self.retired=set()
        self.receipt_authorities={}
        self.initialization_ready={}
        self.execute_lock = threading.RLock()
        self.startup=StartupAuthority(binding,clock=clock)
        self.initialization_v3=V3Authority(binding,clock=clock)
        self.broker.initialization_v3=self.initialization_v3
        self.setup_hold=False
        self.channel.authorize = self._authorize
        self.channel.authorize_network = self._authorize_network
        self.channel.authorize_batch = self._authorize_batch
        self.channel.on_startup = self._startup_event
        self.channel.on_close = self.broker.emergency_revoke

    def _close(self):
        self.initialization_v3.close()
        self.channel.close()
        for prompt in list(self.prompts.values()):
            prompt.stop()

    def _fence(self):
        self.broker.emergency_revoke()
        def record():
            try:
                self.broker.journal.append({'event':'task-revoked','binding_digest':self.broker.binding_digest})
            except Exception:
                pass  # Authority is already fenced; an unavailable ledger cannot restore it.
        threading.Thread(target=record,daemon=True).start()
        return {'state':'revoked','session_closed':True,'auditPending':True}

    def _worker(self, operation, args):
        with self.execute_lock:
            return self._worker_locked(operation,args)

    def _worker_locked(self, operation, args):
        self.broker._valid()
        if (self.broker.replacement_pending() or self._v3_pending()) and operation not in {'network-status','resolve-setup','register-initialization','release-setup'}:
            raise ScopeError('replacement-pending')
        options={}
        ticket=None
        if operation=='resume-login':
            remaining=self.channel.deadline/1000-time.time()
            if remaining<=0:
                self.channel.close()
                raise ScopeError('session-unavailable')
            options['timeout']=min(55,remaining)
            if self.startup.lifecycle and not self.startup.authentication_forwarded:
                ticket=self.startup.begin(lifecycle=self.startup.lifecycle,session_deadline_ms=self.channel.deadline)
                self.initialization_ready.clear()
                args={'startup':ticket}
        try:
            result = self.channel.request(operation, args, **options)
        finally:
            if ticket:
                self.startup.end(ticket['resume_id'])
        if result.get('ok') is not True:
            code = result.get('failureCode', 'control-failed')
            if not isinstance(code, str) or len(code)>64:
                code = 'control-failed'
            raise ScopeError(code)
        if operation=='resume-login' and result.get('authenticationVerified') is True:
            self.broker._valid()
            if not self.startup.authentication_verified:
                self.broker._event('authentication-verified',count=1)
                self.startup.authentication_verified=True
            self._retire_startup()
        return result

    def components(self):
        return self._worker('components', {})

    def prepare(self, args):
        self._check_receipts(args)
        return self._worker('prepare-action', args)

    def _ui_result(self, result, identity):
        prompt=self.prompts.get(identity)
        if prompt is None:
            return result
        ui=prompt.status()
        review=self.broker.requests.get(identity) or self.broker.attempts.get(identity)
        remaining=max(0,int(review['review_deadline']-self.broker.clock())) if review else 0
        if not review or review['state'] not in {'pending','awaiting-action-confirmation'}:
            remaining=0
        ui['review_remaining_seconds']=min(ui['review_remaining_seconds'],remaining)
        return {**result,'approval_ui':ui}

    def request(self, args):
        replacement=isinstance(args,dict) and isinstance(args.get('setup'),dict) and bool(args['setup'].get('replace_grant_ids'))
        v3=isinstance(args,dict) and isinstance(args.get('setup'),dict) and args['setup'].get('revision')==3
        if not replacement and not v3:
            return self._request(args)
        if not self.execute_lock.acquire(blocking=False):
            raise ScopeError('operation-in-progress')
        try:
            if self.startup.active is not None or self.executing:
                raise ScopeError('operation-in-progress')
            if not self.setup_hold:
                result=self._worker('hold-setup',{'revision':3} if v3 else {})
                if result.get('held') is not True:
                    self.broker.emergency_revoke()
                    raise ScopeError('control-failed')
                self.setup_hold=True
            try:
                return self._request(args)
            finally:
                self._sync_setup_hold()
        finally:
            self.execute_lock.release()

    def _sync_setup_hold(self):
        if not self.setup_hold or self.broker.replacement_pending() or self._v3_pending():
            return
        if self.broker.fenced.is_set():
            self.setup_hold=False
            return
        try:
            result=self._worker('release-setup',{})
            if result.get('held') is not False:
                raise ScopeError('control-failed')
            self.setup_hold=False
        except Exception:
            self.broker.emergency_revoke()
            raise

    def _v3_pending(self):
        return any(request.get('setup_context',{}).get('revision')==3 and request['state']=='pending' and
            not request['fence'].is_set() and self.broker.clock()<request['review_deadline']
            for request in self.broker.requests.values() if request.get('setup_context'))

    def _request(self, args):
        if not isinstance(args, dict) or set(args)-{'items','setup','idempotency_key','ttl_seconds'}:
            raise ScopeError('request-invalid')
        if ('items' in args) == ('setup' in args):
            raise ScopeError('request-invalid')
        resolved = self._worker('resolve-setup' if 'setup' in args else 'resolve-items',
            {'setup':args['setup']} if 'setup' in args else {'items':args['items']})
        setup_context=None;v3_context=None
        if resolved.get('setup_revision') is not None:
            if resolved['setup_revision']==3:
                v3_context=validate_setup_context_v3(resolved,self.broker.binding,args.get('setup'))
                setup_context=v3_context['context']
            else:
                setup_context=validate_setup_context(resolved,self.broker.binding)
            if resolved.get('replace_grant_ids',[])!=args.get('setup',{}).get('replace_grant_ids',[]) or (
                resolved.get('replace_grant_ids') and not self.setup_hold):
                raise ScopeError('scope-mismatch')
        elif any(isinstance(c,dict) and (c.get('revision')==2 or c.get('semantics')=='initialization-read')
                 for c in resolved.get('contracts',{}).values()):
            raise ScopeError('request-invalid')
        result = self.broker.request(resolved.get('items'), idempotency_key=args.get('idempotency_key'),
            ttl_seconds=args.get('ttl_seconds',MAX_GRANT_SECONDS),setup_context=setup_context,
            replacement_source_ids=resolved.get('replace_grant_ids',[]))
        request_id = result['request_id']
        if request_id in self.contexts:
            return self._ui_result(result,request_id)
        private_context=self.broker.requests[request_id].get('setup_context')
        contracts = private_context['contracts'] if private_context else resolved.get('contracts', {})
        if not isinstance(contracts,dict) or len(canonical(contracts))>65536:
            raise ScopeError('request-invalid')
        self.contexts[request_id] = copy.deepcopy(contracts)
        manifest = self.broker.approval_manifest(request_id)
        if v3_context:
            manifest.update(protocol_revision=3,reference_items=v3_context['native_items'])
            try:
                self.initialization_v3.register_plan(request_id,v3_context['captures'],v3_context['locators'],
                    review_deadline=self.broker.requests[request_id]['review_deadline'],
                    external_bytes=len(canonical(manifest))+len(canonical(setup_context)))
            except Exception:
                self.broker.cancel(request_id)
                self.contexts.pop(request_id,None)
                raise
        if private_context:
            try:
                self.startup.register(private_context)
                self._worker('register-initialization',{'contracts':contracts})
            except Exception:
                self.broker.cancel(request_id)
                self.initialization_v3.cancel_plan(request_id)
                raise
        try:
            reference_callback={'on_reference':lambda frame:self._reference(request_id,frame)} if v3_context else {}
            self.prompts[request_id] = self.prompt.start(manifest,
                on_decision=lambda frame:self._decision(request_id,frame),
                on_revoke=lambda:self._prompt_revoked(request_id),
                on_cancel=lambda:self._prompt_revoked(request_id),**reference_callback)
        except Exception:
            self._prompt_revoked(request_id)
            raise ScopeError('approval-ui-unavailable') from None
        return self._ui_result(result,request_id)

    def _reference(self,request_id,frame):
        with self.broker.lock:
            self.broker._valid()
            request=self.broker.requests.get(request_id)
            expected={'event','request_id','nonce','request_digest','check_id','item_id','edit_revision','native_input'}
            if (not request or not request.get('setup_context') or request['setup_context']['revision']!=3 or
                    request['state']!='pending' or request['fence'].is_set() or self.broker.clock()>=request['review_deadline'] or
                    not isinstance(frame,dict) or set(frame)!=expected or frame['event']!='reference-check' or
                    frame['request_id']!=request_id or frame['nonce']!=request['nonce'] or frame['request_digest']!=request['digest']):
                raise ScopeError('decision-invalid')
            return self.initialization_v3.check_reference(request_id,frame['check_id'],frame['edit_revision'],
                frame['native_input'],item_id=frame['item_id'])

    def _decision(self, request_id, frame):
        result = self.broker.accept_decision(request_id, nonce=frame['nonce'],
            digest=frame['request_digest'],choices=frame['choices'],ttl_seconds=frame['ttl_seconds'])
        if result['grant_id']:
            self.grant_contexts[result['grant_id']] = self.contexts[request_id]
        request=self.broker.requests[request_id]
        if request.get('replacement'):
            if result['grant_id']:
                snapshots=request['replacement']['snapshots']
                self.retired.update(s['request_id'] for s in snapshots)
                for source in snapshots:
                    self.grant_contexts.pop(source['grant_id'],None)
                    prompt=self.prompts.get(source['request_id'])
                    if prompt is not None:
                        prompt.stop('grant-replaced')
            self._sync_setup_hold()
        elif request.get('setup_context') and request['setup_context'].get('revision')==3:
            self._sync_setup_hold()
        return result

    def _prompt_revoked(self, request_id):
        if request_id in self.retired:
            return
        self.broker.revoke_request(request_id)
        self.initialization_v3.cancel_plan(request_id)
        self._sync_setup_hold()
        grant_id=self.broker.requests.get(request_id,{}).get('grant_id')
        if grant_id:
            self.initialization_v3.revoke(grant_id)
        if (self.startup.active and grant_id in self.startup.used_grants) or (
            self.startup.authentication_forwarded and not self.startup.authentication_verified and grant_id in self.startup.authentication_grants):
            self.broker.emergency_revoke()
        if any(self.broker.grants[self.broker.attempts[attempt]['grant_id']]['request_id']==request_id
               for attempt in list(self.executing)):
            self.broker.emergency_revoke()

    def _action_revoked(self, attempt_id):
        attempt=self.broker.attempts.get(attempt_id)
        if not attempt:
            return
        attempt['fence'].set()
        if attempt_id in self.executing:
            self.broker.emergency_revoke()
        elif attempt_id not in self.dispatched and attempt['state'] in {'reserved','awaiting-action-confirmation'}:
            self.broker.finish(attempt_id,state='failed-before-dispatch',summary={})

    def _check_receipts(self, args):
        refs=list(args.get('read_receipts',[]))+[change.get('receipt_ref') for change in args.get('changes',[])]
        for ref in refs:
            grant=self.receipt_authorities.get(ref)
            if not grant:
                raise ScopeError('readback-required')
            self.broker._grant(*grant)

    def guard_output(self, operation, args, result):
        if operation=='execute':
            grant_id,item_id=args['grant_id'],args['item_id']
            return lambda:self.broker._grant(grant_id,item_id)
        if operation=='prepare':
            snapshot=copy.deepcopy(args)
            return lambda:(self.broker._valid(),self._check_receipts(snapshot))
        if operation=='components':
            return self.broker._valid
        return None

    def _retire_startup(self,exclude_login=False):
        for request_id,request in list(self.broker.requests.items()):
            contracts=self.contexts.get(request_id,{})
            if request_id in self.retired or not contracts or any(c.get('phase') not in {'bootstrap','login-once'} for c in contracts.values()):
                continue
            if exclude_login and any(c.get('semantics')=='login' for c in contracts.values()):
                continue
            self.retired.add(request_id)
            if request.get('grant_id'):
                self.broker.revoke(request['grant_id'])
                self.initialization_v3.revoke(request['grant_id'])
            prompt=self.prompts.get(request_id)
            if prompt is not None:
                prompt.stop()

    def status(self, request_id=None):
        result = self.broker.status(request_id) if request_id else {'state':'no-request'}
        self._sync_setup_hold()
        network=self._worker('network-status',{})
        result['pending_network']=network.get('descriptors',[])
        result['phase']=network.get('phase')
        result['setup_revisions']=[1,2,3] if network.get('protocol')==V3_WORKER_PROTOCOL else [1,2]
        if 3 in result['setup_revisions']:
            result['initialization_profiles']=list(V3_WORKER_PROTOCOL['profiles'])
        result['setup_purposes']=['bootstrap-resource','initialization-read']
        result['limits']={'active_grants':4,'pending_requests':1,'setup_items':32,'setup_bytes':32768}
        if 3 in result['setup_revisions']:
            result['limits'].update(reference_units=V3_WORKER_PROTOCOL['reference_units'],proposal_units=V3_WORKER_PROTOCOL['proposal_units'])
        result['initialization']=self.startup.status()
        if result['phase'] in {'discovery-only','grant-active'}:
            self._retire_startup()
        return self._ui_result(result,request_id) if request_id else result

    def _authorize(self, message):
        try:
            if not isinstance(message,dict):
                return False
            if message.get('kind')=='action' and set(message)=={'kind','attempt_id','consume'}:
                if message['attempt_id'] not in self.executing or type(message['consume']) is not bool:
                    return False
                return self.broker.authorize_attempt(message['attempt_id'],consume=message['consume'])
            if message.get('kind')!='network' or set(message)!={'kind','phase','attempt_id','descriptor','digest'}:
                return False
            return self._network(message)
        except Exception:
            return False

    def _startup_event(self,frame):
        try:
            with self.broker.lock:
                self.broker._valid()
                source=None
                if frame.get('kind') in {'initialization-forwarded','prerequisite-response'}:
                    with self.startup.lock:
                        source=self.startup.issued.get(frame.get('check_id'),{}).get('permit')
                    if source and source.get('kind')=='initialization-permit-v3':
                        self.broker._grant(source['grant_id'],source['item_id'])
                if frame.get('kind') in {'controls-ready','credentials-armed','authentication-forwarded'}:
                    for grant_id,item_id in self.initialization_ready.values():
                        self.broker._grant(grant_id,item_id)
                event=self.startup.event(frame)
                if source and source.get('kind')=='initialization-permit-v3' and frame['kind']=='prerequisite-response':
                    if frame['ready']:
                        self.initialization_ready[frame['prerequisite_id']]=(source['grant_id'],source['item_id'])
                    else:
                        self.initialization_ready.pop(frame['prerequisite_id'],None)
                self.broker._event(event.pop('event'),**event)
                if frame['kind']=='authentication-forwarded':
                    self._retire_startup(exclude_login=True)
                return True
        except Exception:
            self.broker.emergency_revoke()
            return False

    def _authorize_network(self,message,check_id):
        try:
            if isinstance(message,dict) and 'version' in message:
                return self._network_v3(message,check_id)
            if (not isinstance(message,dict) or message.get('kind')!='network' or
                set(message) not in ({'kind','phase','attempt_id','descriptor','digest'},
                    {'kind','phase','attempt_id','descriptor','digest','startup'}) or
                not isinstance(check_id,str) or re.fullmatch('[a-f0-9]{32}',check_id) is None):
                return False
            return self._network(message,check_id)
        except Exception:
            return False

    def _network_v3(self,message,check_id):
        if (set(message)!={'kind','version','phase','attempt_id','capture','startup'} or message['kind']!='network' or
                type(message['version']) is not int or message['version']!=3 or message['phase'] not in {'bootstrap','login-once'} or
                message['attempt_id'] is not None or not isinstance(check_id,str) or re.fullmatch('[a-f0-9]{32}',check_id) is None):
            return False
        check_deadline=self.clock()+10
        self.broker._valid()
        self.startup.matches(message)
        for grant_id,contracts in list(self.grant_contexts.items()):
            for item_id,contract in contracts.items():
                if contract.get('revision')!=3 or not self.initialization_v3.matches(grant_id,item_id,message['capture']):
                    continue
                try:
                    _,scope=self.broker._grant(grant_id,item_id)
                    if scope['parameters'].get('approved_semantics')!='initialization-read':
                        continue
                    self.startup.matches(message)
                    permit=self.broker.reserve(grant_id,item_id,'network-'+secrets.token_hex(16),scope['parameters'])
                    self.broker.finish(permit['attempt_id'],state='verified',summary={'count':1})
                    self.broker._valid();self.broker._grant(grant_id,item_id);self.startup.matches(message)
                    receipt=self.startup.issue_v3(authority=self.initialization_v3,grant_id=grant_id,item_id=item_id,
                        check_id=check_id,message=message,contract=contract,check_deadline=check_deadline)
                    self.broker._event('initialization-permit-issued',grant_id=grant_id,item_id=item_id,
                        contract_digest=receipt['prerequisite_id'],item_ids=[check_id,receipt['receipt_id']],count=1)
                    with self.broker.publication_lock:
                        self.broker._valid();self.broker._grant(grant_id,item_id);self.startup.matches(message)
                        if self.clock()>=check_deadline:
                            return False
                        self.startup.used_grants.add(grant_id)
                        return {'allowed':True,'permit':receipt}
                except ScopeError:
                    continue
        return False

    def _contract_current(self,contract,message):
        if contract.get('revision')==2:
            if (message['phase'] not in contract['phase_applicability'] or
                contract['preauth_lifecycle']!=self.startup.lifecycle):
                return False
            try:
                self.startup.matches(message)
            except ScopeError:
                return False
            return True
        return contract.get('phase')==message['phase']

    def _network(self, message, check_id=None):
        self.broker._valid()
        phase, attempt_id = message['phase'], message['attempt_id']
        if phase not in {'bootstrap','login-once','grant-active'}:
            return False
        # Startup contracts are distinct from task permits and disappear at authentication.
        candidates = list(self.grant_contexts.items())
        action = None
        if phase=='grant-active':
            if attempt_id not in self.executing:
                return False
            self.broker.authorize_attempt(attempt_id)
            action = self.broker.attempts[attempt_id]
            candidates = [(action['grant_id'],self.grant_contexts.get(action['grant_id'],{}))]
        elif attempt_id is not None:
            return False
        for grant_id, contracts in candidates:
            for item_id, contract in contracts.items():
                if not self._contract_current(contract,message):
                    continue
                if action and contract.get('parent_id')!=action['item_id']:
                    continue
                if phase in {'bootstrap','login-once'} and canonical(contract.get('descriptor'))!=canonical(message['descriptor']):
                    continue
                try:
                    _, scope=self.broker._grant(grant_id,item_id)
                except ScopeError:
                    continue
                classification=scope['parameters'].get('approved_semantics')
                expected_class='read' if contract.get('semantics')=='unclassified' else contract.get('semantics')
                if classification!=expected_class or classification not in {'read','write','bootstrap','login','initialization-read'}:
                    continue
                if classification=='initialization-read' and (check_id is None or contract.get('revision')!=2):
                    continue
                expected=copy.deepcopy(contract.get('descriptor'))
                if classification=='write':
                    if not action or not action['write']:
                        continue
                    selected=action['scope']['targets']
                    path=contract.get('target_path',[])
                    if not path or not set(selected)<=set(contract.get('targets',[])):
                        continue
                    node=expected
                    for part in path[:-1]:
                        if not isinstance(node,dict) or part not in node:
                            return False
                        node=node[part]
                    if not isinstance(node,dict) or path[-1] not in node:
                        return False
                    original=node[path[-1]]
                    if isinstance(original,list):
                        node[path[-1]]=[value for value in original if value in selected]
                    elif len(selected)==1 and original==selected[0]:
                        node[path[-1]]=selected[0]
                    else:
                        continue
                if canonical(expected)!=canonical(message['descriptor']):
                    continue
                try:
                    _, scope = self.broker._grant(grant_id,item_id)
                    descriptor=message['descriptor']
                    static=(phase in {'bootstrap','login-once'} and classification in {'bootstrap','login'} and
                        descriptor.get('method') in {'GET','HEAD'} and descriptor.get('body') is None and
                        descriptor.get('query')=={} and descriptor.get('resourceType') in {'script','stylesheet'} and
                        isinstance(descriptor.get('path'),str) and
                        re.fullmatch(r'/[A-Za-z0-9/_.~-]{0,511}\.(?:js|css)',descriptor['path'],re.IGNORECASE))
                    if static:
                        self.broker.consume_static_network(grant_id,item_id,scope['parameters'])
                    else:
                        permit = self.broker.reserve(grant_id,item_id,'network-'+secrets.token_hex(16),scope['parameters'])
                        if action and classification=='write':
                            self.broker.authorize_attempt(attempt_id,consume=True)
                        self.broker.finish(permit['attempt_id'],state='verified',summary={'count':1})
                    self.broker._valid()
                    self.broker._grant(grant_id,item_id)
                    if contract.get('revision')==2:
                        self.startup.matches(message)
                        self.startup.used_grants.add(grant_id)
                    if classification=='login':
                        self.startup.authentication_grants.add(grant_id)
                        if self.startup.active is not None:
                            self.startup.used_grants.add(grant_id)
                    if classification=='initialization-read':
                        receipt=self.startup.issue(check_id=check_id,message=message,contract=contract)
                        self.broker._event('initialization-permit-issued',contract_digest=receipt['prerequisite_id'],count=1)
                        self.broker._grant(grant_id,item_id)
                        return {'allowed':True,'permit':receipt}
                    if action:
                        self.dispatched.add(attempt_id)
                    return True
                except ScopeError:
                    continue
        return False

    def _authorize_batch(self, messages):
        if not isinstance(messages,list):
            return []
        denied=[False]*len(messages)
        try:
            if not 1<=len(messages)<=16 or len(canonical(messages))>32768:
                return denied
            messages=copy.deepcopy(messages)
            self.broker._valid()
            matches=[]
            for message in messages:
                candidates=[]
                if (isinstance(message,dict) and set(message) in ({'kind','phase','attempt_id','descriptor','digest'},
                    {'kind','phase','attempt_id','descriptor','digest','startup'}) and
                    message['kind']=='network' and message['phase'] in {'bootstrap','login-once'} and
                    message['attempt_id'] is None and isinstance(message['digest'],str) and
                    re.fullmatch(r'[a-f0-9]{64}',message['digest'])):
                    descriptor=message['descriptor']
                    if (isinstance(descriptor,dict) and descriptor.get('method')=='GET' and
                        descriptor.get('body') is None and descriptor.get('query')=={} and
                        descriptor.get('resourceType') in {'script','stylesheet'} and
                        isinstance(descriptor.get('path'),str) and
                        re.fullmatch(r'/[A-Za-z0-9/_.~-]{0,511}\.(?:js|css)',descriptor['path'],re.IGNORECASE)):
                        for grant_id,contracts in list(self.grant_contexts.items()):
                            for item_id,contract in contracts.items():
                                semantics=contract.get('semantics')
                                if (not self._contract_current(contract,message) or semantics not in {'bootstrap','login'} or
                                    canonical(contract.get('descriptor'))!=canonical(descriptor)):
                                    continue
                                try:
                                    _,scope=self.broker._grant(grant_id,item_id)
                                except ScopeError:
                                    continue
                                if scope['parameters'].get('approved_semantics')==semantics:
                                    candidates.append((grant_id,item_id,scope['parameters']))
                                    if contract.get('revision')==2:
                                        self.startup.used_grants.add(grant_id)
                matches.append(candidates)
            result=self.broker.consume_static_network_batch(matches)
            self.broker._valid()
            return result
        except Exception:
            return denied

    def execute(self, args):
        expected={'grant_id','item_id','idempotency_key','observation_id','component_ref'}
        if not isinstance(args,dict) or set(args)!=expected:
            raise ScopeError('request-invalid')
        with self.execute_lock:
            _, scope = self.broker._grant(args['grant_id'],args['item_id'])
            if args['item_id'] in self.grant_contexts.get(args['grant_id'],{}):
                raise ScopeError('capability-unsupported')  # No raw-network execution surface.
            attempt = self.broker.reserve(args['grant_id'],args['item_id'],args['idempotency_key'],scope['parameters'])
            attempt_id = attempt['attempt_id']
            if attempt['state']=='awaiting-action-confirmation':
                if attempt_id not in self.prompts:
                    manifest=self.broker.confirmation_manifest(attempt_id)
                    self.prompts[attempt_id]=self.prompt.start(manifest,
                        on_decision=lambda frame:self._action_decision(attempt_id,frame),
                        on_revoke=lambda:self._action_revoked(attempt_id),
                        on_cancel=lambda:self._action_revoked(attempt_id))
                return self._ui_result(self.broker.execution_status(attempt_id),attempt_id)
            if attempt['state']!='reserved':
                return self._ui_result(self.broker.execution_status(attempt_id),attempt_id)
            self.executing.add(attempt_id)
            try:
                output = self._worker('execute', {'attempt_id':attempt_id,'scope':attempt['scope'],
                    'observation_id':args['observation_id'],'component_ref':args['component_ref'],
                    'deadline':int((time.time()+max(0,self.broker.grants[args['grant_id']]['deadline']-self.clock()))*1000)})
                state=output.get('state','outcome-unknown')
                # A DOM click or a 200 response is never proof of business completion.
                if scope['capability']=='web.business_action' and state=='verified':
                    state='partial'
                if scope['capability']=='web.business_action' and output.get('forwarded')==0 and attempt_id not in self.dispatched:
                    state='failed-before-dispatch'
                status=self.broker.finish(attempt_id,state=state,summary=output.get('summary',{}))
                receipt=output.get('result',{}).get('receipt_ref')
                if isinstance(receipt,str):
                    self.receipt_authorities[receipt]=(args['grant_id'],args['item_id'])
                return {**status,'result':self.broker.release_output(attempt_id,output.get('result',{}))}
            except Exception as exc:
                state='outcome-unknown' if attempt_id in self.dispatched else 'failed-before-dispatch'
                self.broker.finish(attempt_id,state=state,summary={})
                if isinstance(exc,ScopeError):
                    raise
                raise ScopeError('control-failed') from None
            finally:
                self.executing.discard(attempt_id)

    def _action_decision(self, attempt_id, frame):
        return self.broker.accept_action_decision(attempt_id,nonce=frame['nonce'],
            digest=frame['request_digest'],choices=frame['choices'],ttl_seconds=frame['ttl_seconds'])

    def execution_status(self, args):
        if not isinstance(args,dict) or 'attempt_id' not in args or set(args)-{'attempt_id','read_receipts'}:
            raise ScopeError('request-invalid')
        if 'read_receipts' not in args:
            return self._ui_result(self.broker.execution_status(args['attempt_id']),args['attempt_id'])
        self.broker._valid()
        attempt=self.broker.attempts.get(args['attempt_id'])
        if not attempt or not attempt['write'] or attempt['state'] not in {'partial','outcome-unknown','accepted','running'}:
            raise ScopeError('readback-required')
        result=self._worker('reconcile',{'attempt_id':args['attempt_id'],'scope':copy.deepcopy(attempt['scope']),
            'read_receipts':args['read_receipts']})
        return self.broker.finish(args['attempt_id'],state=result['state'],summary=result['summary'],targets=result.get('targets'))

    def revoke(self, args):
        if set(args)=={'request_id'}:
            result=self.broker.cancel(args['request_id'])
            self.initialization_v3.cancel_plan(args['request_id'])
            prompt=self.prompts.get(args['request_id'])
            if prompt is not None:
                prompt.stop()
            self._sync_setup_hold()
            return result
        if set(args) in ({'grant_id'},{'grant_id','items'}):
            def affected(attempt_id):
                attempt=self.broker.attempts[attempt_id]
                if attempt['grant_id']!=args['grant_id']:
                    return False
                if 'items' not in args:
                    return True
                grant=self.broker.grants[args['grant_id']]
                names=set(args['items'])
                def depends(name):
                    return name in names or any(depends(parent) for parent in grant['items'][name]['depends_on'])
                return depends(attempt['item_id'])
            if any(affected(attempt) for attempt in list(self.executing)):
                return self._fence()
            result=self.broker.revoke(args['grant_id'],args.get('items'))
            self.initialization_v3.revoke(args['grant_id'],args.get('items'))
            with self.broker.publication_lock, self.startup.lock:
                selected=set(args.get('items',self.broker.grants[args['grant_id']]['items']))
                contracts=self.grant_contexts.get(args['grant_id'],{})
                initialization=any(contracts.get(name,{}).get('purpose')=='initialization-read' for name in selected)
                if ((self.startup.active and args['grant_id'] in self.startup.used_grants and initialization) or
                    (self.startup.authentication_forwarded and not self.startup.authentication_verified and
                     args['grant_id'] in self.startup.authentication_grants)):
                    self.broker.emergency_revoke()
                    result['session_closed']=True
            # A concurrent action cannot retain a permit after revocation.
            if any(affected(attempt) for attempt in list(self.executing)):
                self.broker.emergency_revoke()
                result['session_closed']=True
            return result
        if args=={'end_task':True}:
            return self._fence()
        raise ScopeError('request-invalid')
