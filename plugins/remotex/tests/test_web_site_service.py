import copy
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))


def prepared():
    from web_site_service import SiteService
    binding = {'origin':'https://console.example:8443', 'account':'operator', 'profile':'lab',
        'session':'a'*32, 'worker':'worker', 'acquisition':'b'*32, 'profile_digest':'c'*64, 'deadline':50000.0}
    now = [100.0]
    prompts = []
    class Journal:
        def __init__(self): self.events = []; self.fail = False; self.pending = {}
        def append(self, value):
            if self.fail: raise OSError('unavailable')
            self.events.append(copy.deepcopy(value))
        def reserve(self, identity, conflicts):
            if self.pending: raise ValueError('unresolved-prior-write')
            self.pending[identity]=conflicts
        def resolve(self, identity): self.pending.pop(identity,None)
        def reserve_site(self, identity, origin): self.reserve(identity,['whole-site-session',origin])
    class Channel:
        available = True
        deadline = int(time.time()*1000)+46800000
        def __init__(self): self.calls = []; self.login = threading.Event(); self.sensitive = False
        def close(self):
            previous=self.available; self.available=False
            if previous and callable(getattr(self,'on_close',None)): self.on_close()
        def request(self, operation, args, timeout=30):
            self.calls.append((operation, copy.deepcopy(args)))
            if operation == 'resume-login':
                self.login.set()
                return {'ok':True, 'authenticationVerified':True}
            if operation == 'site-preview':
                return {'ok':True, 'action_ref':'d'*32, 'sensitive':self.sensitive,
                    'preview':{'control':'Save', 'action':args['action'], 'target':'Example record'}}
            if operation == 'site-execute':
                assert self.authorize({'kind':'site-action','attempt_id':args['attempt_id']})
                return {'ok':True,'businessSuccessVerified':False,'newObservationRequired':True}
            return {'ok':True,'components':[]}
    class Prompt:
        @staticmethod
        def start(manifest, **callbacks):
            prompts.append((copy.deepcopy(manifest), callbacks))
            return Prompt()
        def stop(self, reason='stopped'): pass
        def status(self): return {'state':'shown','shown':True,'review_remaining_seconds':170}
    channel, journal = Channel(), Journal()
    service = SiteService(channel,binding=binding,check=lambda:copy.deepcopy(binding),
        journal=journal,prompt=Prompt,clock=lambda:now[0])
    return service, channel, journal, prompts, binding, now


def approve(prompts, ttl=43200):
    manifest, callbacks = prompts[-1]
    return callbacks['on_decision']({'event':'decision','request_id':manifest['request_id'],
        'nonce':manifest['nonce'],'request_digest':manifest['request_digest'],
        'choices':[{'item_id':'site','max_uses':1,'targets':[]}], 'ttl_seconds':ttl})


def operation(key='save-1', risk='ordinary'):
    return {'observation_id':'e'*32,'component_ref':'f'*32,'action':'click',
        'risk':risk,'idempotency_key':key}


def test_site_grant_is_native_only_and_one_click_resumes_login():
    service, channel, journal, prompts, _, _ = prepared()
    result = service.begin()
    assert result['state'] == 'pending'
    manifest = prompts[0][0]
    assert manifest['ui_mode'] == 'site'
    assert manifest['binding']['origin'] == 'https://console.example:8443'
    assert manifest['wait_seconds'] == 180
    assert not service._authorize({'kind':'site-network','origin':'https://console.example:8443','method':'GET','request_id':'1'*32})
    approve(prompts)
    assert channel.login.wait(2)
    assert service.status()['state'] == 'active'
    assert service.status()['authorization_mode'] == 'site'
    assert [x['event'] for x in journal.events][:2] == ['site-requested','site-granted']


def test_cleanup_thread_failure_keeps_revocation_and_uncertain_fence_without_sync_prompt_lock():
    from unittest import mock
    service,channel,journal,prompts,_,_=prepared()
    service.begin()
    service._reserve()
    service.recovery_uncertain=True
    prompt=next(iter(service.prompts.values()))
    with mock.patch.object(threading.Thread,'start',side_effect=RuntimeError('no thread')), \
         mock.patch.object(prompt,'stop',side_effect=AssertionError('synchronous prompt lock')):
        channel.close()
    assert service.state=='revoked' and not channel.available
    assert not service.cleanup_started
    assert service.reservation_id in journal.pending


def test_site_binding_and_expiration_are_checked_on_every_permit():
    service, channel, _, prompts, binding, now = prepared()
    service.begin(); approve(prompts)
    message = {'kind':'site-network','origin':binding['origin'],'method':'POST','request_id':'1'*32}
    assert service._authorize(message)
    assert not service._authorize({**message,'origin':'https://other.example'})
    assert not service._authorize({**message,'raw_body':'not accepted'})
    now[0] += 43201
    assert not service._authorize(message)
    assert not channel.available


@pytest.mark.parametrize('field,value',[('account','other'),('acquisition','new'),('profile_digest','d'*64),('worker','new')])
def test_changed_binding_closes_only_the_owned_channel(field,value):
    service, channel, _, prompts, binding, _ = prepared()
    service.begin(); approve(prompts)
    binding[field] = value
    assert not service._authorize({'kind':'site-network','origin':binding['origin'],'method':'GET','request_id':'1'*32})
    assert not channel.available


def test_rejection_timeout_wrong_nonce_and_audit_failure_never_grant():
    service, channel, journal, prompts, _, now = prepared()
    service.begin()
    manifest, callbacks = prompts[-1]
    frame = {'nonce':'0'*64,'request_digest':manifest['request_digest'],'choices':[], 'ttl_seconds':60}
    with pytest.raises(ValueError): callbacks['on_decision'](frame)
    now[0] += 181
    with pytest.raises(ValueError): approve(prompts,60)
    assert not channel.login.is_set()
    service, channel, journal, prompts, _, _ = prepared()
    service.begin(); journal.fail = True
    with pytest.raises(ValueError): approve(prompts)
    assert not channel.login.is_set()
    assert not channel.available


def test_ordinary_write_needs_no_second_window_and_same_key_never_replays():
    service, channel, _, prompts, _, _ = prepared()
    service.begin(); approve(prompts); assert channel.login.wait(2)
    first = service.execute(operation())
    assert first['state'] == 'completed'
    assert first['result']['businessSuccessVerified'] is False
    assert service.execute(operation()) == first
    assert len(prompts) == 1
    assert [x[0] for x in channel.calls].count('site-execute') == 1
    with pytest.raises(ValueError): service.execute({**operation(),'component_ref':'1'*32})


def test_sensitive_operation_waits_for_native_confirmation_and_has_30_second_ticket():
    service, channel, _, prompts, _, now = prepared()
    service.begin(); approve(prompts); assert channel.login.wait(2)
    channel.sensitive = True
    result = service.execute(operation())
    assert result['state'] == 'awaiting-action-confirmation'
    assert not any(x[0]=='site-execute' for x in channel.calls)
    assert len(prompts) == 2
    approve(prompts,30)
    deadline = time.monotonic()+2
    while service.execution_status({'attempt_id':result['attempt_id']})['state'] in {'awaiting-action-confirmation','confirmed','executing'} and time.monotonic()<deadline:
        time.sleep(.01)
    assert service.execution_status({'attempt_id':result['attempt_id']})['state']=='completed'
    now[0] += 31
    assert not service._authorize({'kind':'site-action','attempt_id':result['attempt_id']})


def test_revoke_fences_network_actions_output_and_cannot_be_renewed():
    service, channel, _, prompts, binding, _ = prepared()
    service.begin(); approve(prompts)
    result = service.revoke({'end_task':True})
    assert result['state']=='revoked'
    assert not service._authorize({'kind':'site-network','origin':binding['origin'],'method':'GET','request_id':'1'*32})
    assert not channel.available
    with pytest.raises(ValueError): service.begin()


def test_uncertain_write_is_never_retried_even_with_another_key():
    service, channel, _, prompts, _, _ = prepared()
    service.begin(); approve(prompts); assert channel.login.wait(2)
    original = channel.request
    def request(op,args,**kwargs):
        if op=='site-execute': raise OSError('transport lost')
        return original(op,args,**kwargs)
    channel.request = request
    result = service.execute(operation())
    assert result['state']=='outcome-unknown'
    assert service.execute(operation()) == result
    with pytest.raises(ValueError): service.execute(operation('save-2'))
    assert not channel.available


def test_ui_completion_holds_reservation_until_clean_close():
    service, channel, journal, prompts, _, _ = prepared()
    service.begin(); approve(prompts); assert channel.login.wait(2)
    assert service.execute(operation())['state']=='completed'
    assert len(journal.pending)==1
    service.revoke({'end_task':True})
    assert journal.pending=={}


def test_uncompleted_network_retains_reservation_across_owned_channel_loss():
    service, channel, journal, prompts, binding, _ = prepared()
    service.begin(); approve(prompts); assert channel.login.wait(2)
    message={'kind':'site-network','origin':binding['origin'],'method':'POST','request_id':'2'*32}
    assert service._authorize(message)
    assert service._authorize(message), 'The second pre-send check belongs to the same request'
    service.revoke({'end_task':True})
    assert len(journal.pending)==1


def test_completed_network_receipt_allows_clean_close_but_cannot_be_forged_or_replayed():
    service, channel, journal, prompts, binding, _ = prepared()
    service.begin(); approve(prompts); assert channel.login.wait(2)
    message={'kind':'site-network','origin':binding['origin'],'method':'POST','request_id':'3'*32}
    assert service._authorize(message)
    assert not service._network_event({'kind':'site-network-complete','request_id':[],'known':True})
    assert not service._network_event({'kind':'site-network-complete','request_id':'4'*32,'known':True})
    assert service._network_event({'kind':'site-network-complete','request_id':'3'*32,'known':True})
    assert not service._network_event({'kind':'site-network-complete','request_id':'3'*32,'known':True})
    service.revoke({'end_task':True})
    assert journal.pending=={}


def test_slow_grant_audit_cannot_start_login_after_original_review_deadline():
    service, channel, journal, prompts, _, now = prepared()
    service.begin()
    append=journal.append
    def slow(event):
        append(event)
        if event['event']=='site-granted': now[0]+=181
    journal.append=slow
    with pytest.raises(ValueError): approve(prompts)
    assert not channel.login.is_set()
    assert not channel.available


def test_status_and_stopped_native_ack_do_not_invert_service_and_prompt_locks():
    from unittest.mock import Mock
    from web_approval import ApprovalPrompt
    service, _, _, prompts, _, _ = prepared()
    service.begin(); manifest=prompts[0][0]
    entered, revoking = threading.Event(), threading.Event()
    errors=[]
    def hold(active=True):
        entered.set()
        assert revoking.wait(3)
    def revoke():
        revoking.set();service.revoke({'end_task':True})
    prompt=ApprovalPrompt(Mock(poll=lambda:None),Mock(),manifest,
        lambda frame:{'grant_id':'a'*32,'expires_in_seconds':10},revoke,revoke)
    prompt.stopped=True
    service.prompts[service.request_id]=prompt
    service._valid=hold
    def run(callback):
        try:callback()
        except Exception as exc:errors.append(type(exc).__name__)
    status=threading.Thread(target=lambda:run(service.status),daemon=True)
    ack=threading.Thread(target=lambda:run(lambda:prompt._apply_decision({})),daemon=True)
    status.start();assert entered.wait(3);ack.start()
    status.join(3);ack.join(3)
    assert not status.is_alive() and not ack.is_alive()
    assert errors==[]


def test_failed_completion_audit_keeps_the_durable_fence_before_closing_channel():
    service, channel, journal, prompts, _, _ = prepared()
    service.begin(); approve(prompts); assert channel.login.wait(2)
    append=journal.append
    def fail_result(event):
        if event['event']=='site-action-result': raise OSError('synthetic audit failure')
        append(event)
    journal.append=fail_result
    assert service.execute(operation())['state']=='outcome-unknown'
    assert len(journal.pending)==1
    assert not channel.available
