from __future__ import annotations

import copy
import re
import secrets
import threading
import time

from web_authorization import Broker, ScopeError, MAX_GRANT_SECONDS, canonical, digest
from web_approval import ApprovalPrompt


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
        self.execute_lock = threading.Lock()
        self.channel.authorize = self._authorize
        self.channel.on_close = self.broker.emergency_revoke

    def _close(self):
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
        self.broker._valid()
        options={}
        if operation=='resume-login':
            remaining=self.channel.deadline/1000-time.time()
            if remaining<=0:
                self.channel.close()
                raise ScopeError('session-unavailable')
            options['timeout']=min(55,remaining)
        result = self.channel.request(operation, args, **options)
        if result.get('ok') is not True:
            code = result.get('failureCode', 'control-failed')
            if not isinstance(code, str) or len(code)>64:
                code = 'control-failed'
            raise ScopeError(code)
        if operation=='resume-login' and result.get('authenticationVerified') is True:
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
        if not isinstance(args, dict) or set(args)-{'items','setup','idempotency_key','ttl_seconds'}:
            raise ScopeError('request-invalid')
        if ('items' in args) == ('setup' in args):
            raise ScopeError('request-invalid')
        resolved = self._worker('resolve-setup' if 'setup' in args else 'resolve-items',
            {'setup':args['setup']} if 'setup' in args else {'items':args['items']})
        result = self.broker.request(resolved.get('items'), idempotency_key=args.get('idempotency_key'),
                                     ttl_seconds=args.get('ttl_seconds',MAX_GRANT_SECONDS))
        request_id = result['request_id']
        if request_id in self.contexts:
            return self._ui_result(result,request_id)
        contracts = resolved.get('contracts', {})
        if not isinstance(contracts,dict) or len(canonical(contracts))>65536:
            raise ScopeError('request-invalid')
        self.contexts[request_id] = copy.deepcopy(contracts)
        manifest = self.broker.approval_manifest(request_id)
        try:
            self.prompts[request_id] = self.prompt.start(manifest,
                on_decision=lambda frame:self._decision(request_id,frame),
                on_revoke=lambda:self._prompt_revoked(request_id),
                on_cancel=lambda:self._prompt_revoked(request_id))
        except Exception:
            self._prompt_revoked(request_id)
            raise ScopeError('approval-ui-unavailable') from None
        return self._ui_result(result,request_id)

    def _decision(self, request_id, frame):
        result = self.broker.accept_decision(request_id, nonce=frame['nonce'],
            digest=frame['request_digest'],choices=frame['choices'],ttl_seconds=frame['ttl_seconds'])
        if result['grant_id']:
            self.grant_contexts[result['grant_id']] = self.contexts[request_id]
        return result

    def _prompt_revoked(self, request_id):
        if request_id in self.retired:
            return
        self.broker.revoke_request(request_id)
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

    def _retire_startup(self):
        for request_id,request in list(self.broker.requests.items()):
            contracts=self.contexts.get(request_id,{})
            if request_id in self.retired or not contracts or any(c.get('phase') not in {'bootstrap','login-once'} for c in contracts.values()):
                continue
            self.retired.add(request_id)
            if request.get('grant_id'):
                self.broker.revoke(request['grant_id'])
            prompt=self.prompts.get(request_id)
            if prompt is not None:
                prompt.stop()

    def status(self, request_id=None):
        result = self.broker.status(request_id) if request_id else {'state':'no-request'}
        network=self._worker('network-status',{})
        result['pending_network']=network.get('descriptors',[])
        result['phase']=network.get('phase')
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

    def _network(self, message):
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
                if contract.get('phase')!=phase:
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
                if classification!=expected_class or classification not in {'read','write','bootstrap','login'}:
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
                    if action:
                        self.dispatched.add(attempt_id)
                    return True
                except ScopeError:
                    continue
        return False

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
            return self.broker.cancel(args['request_id'])
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
            # A concurrent action cannot retain a permit after revocation.
            if any(affected(attempt) for attempt in list(self.executing)):
                self.broker.emergency_revoke()
                result['session_closed']=True
            return result
        if args=={'end_task':True}:
            return self._fence()
        raise ScopeError('request-invalid')
