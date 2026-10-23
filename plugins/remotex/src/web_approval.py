from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path

import credential_store
import execution
from web_authorization import ScopeError, canonical, MAX_NATIVE_REVIEW_SECONDS
from web_request_profiles import PROFILES, MAX_REFERENCE_UNITS


def _unique_pairs(pairs):
    value={}
    for key,part in pairs:
        if key in value:
            raise ValueError()
        value[key]=part
    return value


def decode_frame(raw: bytes, manifest: dict) -> dict:
    try:
        if not isinstance(raw,bytes) or len(raw)>32768 or not raw.endswith(b'\n'):
            raise ValueError()
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_pairs)
        base={'event','request_id','nonce','request_digest'}
        recovery = manifest.get('ui_mode') == 'recovery'
        v3=manifest.get('protocol_revision')==3
        events={'decision','revoke'}|({'helper-ready','reference-check'} if v3 else set())
        if not isinstance(value,dict) or value.get('event') not in events:
            raise ValueError()
        extra={'decision':({'owner_reviewed'} if recovery else {'choices','ttl_seconds'}),'revoke':set(),'helper-ready':{'protocol_revision','profiles'},
               'reference-check':{'check_id','item_id','edit_revision','native_input'}}
        expected=base|extra[value['event']]
        if set(value)!=expected:
            raise ValueError()
        for field in ('request_id','nonce','request_digest'):
            if not isinstance(value[field],str) or not secrets.compare_digest(value[field],manifest[field]):
                raise ValueError()
        if value['event']=='decision':
            if recovery:
                if value['owner_reviewed'] is not True: raise ValueError()
                return value
            if not isinstance(value['choices'],list) or len(value['choices'])>32:
                raise ValueError()
            if type(value['ttl_seconds']) is not int or not 1<=value['ttl_seconds']<=manifest['ttl_seconds']:
                raise ValueError()
            if v3:
                for choice in value['choices']:
                    if (not isinstance(choice,dict) or not {'item_id','max_uses','targets','review_ref','edit_revision'}<=set(choice) or
                            set(choice)-{'item_id','max_uses','targets','review_ref','edit_revision','output','semantic_classification'} or
                            not isinstance(choice['review_ref'],str) or len(choice['review_ref'])!=32 or
                            any(c not in '0123456789abcdef' for c in choice['review_ref']) or
                            type(choice['edit_revision']) is not int or not 1<=choice['edit_revision']<=9007199254740991):
                        raise ValueError()
        elif value['event']=='helper-ready':
            if type(value['protocol_revision']) is not int or value['protocol_revision']!=3 or value['profiles']!=list(PROFILES):
                raise ValueError()
        elif value['event']=='reference-check':
            if (not isinstance(value['check_id'],str) or len(value['check_id'])!=32 or
                    any(c not in '0123456789abcdef' for c in value['check_id']) or
                    value['item_id'] not in {row['item_id'] for row in manifest.get('reference_items',[])} or
                    type(value['edit_revision']) is not int or not 1<=value['edit_revision']<=9007199254740991 or
                    not isinstance(value['native_input'],dict)):
                raise ValueError()
        return value
    except (UnicodeError,ValueError,TypeError,KeyError) as exc:
        raise ScopeError('decision-invalid') from None


def decode_ui_receipt(raw: bytes, manifest: dict) -> dict:
    try:
        if not isinstance(raw,bytes) or len(raw)>2048 or not raw.endswith(b'\n'):
            raise ValueError()
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_pairs)
        if not isinstance(value,dict) or set(value)!={'event','request_id','nonce','request_digest','reason'}:
            raise ValueError()
        reasons={'shown':{'shown'},'closed':{'window-closed','review-expired','operator-rejected','operator-revoked'},
                 'error':{'helper-startup-failed','helper-ui-failed'},
                 'notification':{'requested','shown','unavailable','removed'}}
        if manifest.get('ui_mode') == 'recovery': reasons['closed'].add('recovery-complete')
        if value.get('event') not in reasons or value.get('reason') not in reasons[value['event']]:
            raise ValueError()
        for field in ('request_id','nonce','request_digest'):
            if not isinstance(value[field],str) or not secrets.compare_digest(value[field],manifest[field]):
                raise ValueError()
        return value
    except (UnicodeError,ValueError,TypeError,KeyError) as exc:
        raise ScopeError('ui-receipt-invalid') from exc


class ApprovalPrompt:
    """One native helper with private inherited IPC and no approve endpoint."""

    @classmethod
    def start(cls, manifest, *, on_decision, on_revoke, on_cancel, on_reference=None):
        process=job=None
        try:
            if manifest.get('protocol_revision')==3 and not callable(on_reference):
                raise ScopeError('approval-ui-unavailable')
            original_deadline=time.monotonic()+max(0,min(MAX_NATIVE_REVIEW_SECONDS,manifest['wait_seconds']))
            helper = {'site': 'web_site_approval.ps1', 'recovery': 'web_recovery_approval.ps1'}.get(manifest.get('ui_mode'), 'web_approval.ps1')
            script=Path(__file__).resolve().parents[1]/'scripts'/helper
            if manifest.get('ui_mode') == 'recovery':
                probe = subprocess.run([credential_store._powershell_path(), '-NoLogo', '-NoProfile', '-STA',
                    '-File', str(script), '-DescribeProtocol'], stdin=subprocess.DEVNULL, capture_output=True,
                    timeout=10, env=credential_store._setup_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
                if probe.returncode != 0 or len(probe.stdout) > 2048 or json.loads(probe.stdout) != {'legacy_recovery': 2, 'review_seconds': 180}:
                    raise ScopeError('approval-ui-unavailable')
            process=subprocess.Popen([credential_store._powershell_path(),'-NoLogo','-NoProfile','-STA',
                '-File',str(script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env=credential_store._setup_environment(),creationflags=subprocess.CREATE_NO_WINDOW)
            job=execution._WindowsJob(process,memory_limit_mb=None,cpu_time_seconds=None,max_processes=None)
            if not job.assigned:
                raise OSError()
            process.stdin.write(canonical(manifest)+b'\n')
            process.stdin.flush()
            prompt=cls(process,job,manifest,on_decision,on_revoke,on_cancel,on_reference=on_reference)
            prompt.review_deadline=min(prompt.review_deadline,original_deadline)
            pending_timer=threading.Timer(max(0,prompt.review_deadline-time.monotonic()),prompt._expire_pending)
            pending_timer.daemon=True
            prompt.timer=pending_timer
            threading.Thread(target=prompt._read_ui,daemon=True).start()
            threading.Thread(target=prompt._read,daemon=True).start()
            pending_timer.start()
            return prompt
        except Exception as exc:
            if job is not None:
                job.terminate()
                job.close()
            if process is not None and process.poll() is None:
                process.terminate()
            raise ScopeError('approval-ui-unavailable') from exc

    def __init__(self,process,job,manifest,on_decision,on_revoke,on_cancel,*,clock=time.monotonic,on_reference=None):
        self.process,self.job,self.manifest=process,job,manifest
        self.on_decision,self.on_revoke,self.on_cancel=on_decision,on_revoke,on_cancel
        self.lock=threading.RLock()
        self.write_lock=threading.Lock()
        self.on_reference=on_reference
        self.v3=manifest.get('protocol_revision')==3
        self.acknowledged=self.v3 or manifest.get('ui_mode') in {'site', 'recovery'}
        self.helper_ready=False
        self.decision_pending=False
        self.reference_pending=None
        self.reference_timer=None
        self.reference_attempts=0
        self.reference_checks=set()
        self.decided=False
        self.stopped=False
        self.timer=None
        self.clock=clock
        self.review_deadline=clock()+max(0,min(MAX_NATIVE_REVIEW_SECONDS,manifest['wait_seconds']))
        self.ui_event=None
        self.ui_reason=None
        self.ui_error=None
        self.shown=False
        self.notification_state='not-requested'
        self.stop_reason=None

    def status(self):
        with self.lock:
            helper_exit_code=self.process.poll()
            reason=self.stop_reason or self.ui_reason
            if reason in {'stopped','helper-exited'} and self.ui_reason:
                reason=self.ui_reason
            if helper_exit_code is not None and reason is None:
                reason='helper-exited'
            state=self.ui_event or 'starting'
            if self.stopped or helper_exit_code is not None:
                state='error' if reason in {'protocol-error','helper-startup-failed','helper-ui-failed'} else 'closed'
            remaining=max(0,int(self.review_deadline-self.clock()))
            if self.decided or self.stopped or helper_exit_code is not None or self.ui_event in {'closed','error'}:
                remaining=0
            return {'state':state,'shown':self.shown,'review_remaining_seconds':remaining,
                    'exit_reason':reason,'error_code':self.ui_error,
                    'helper_exit_code':helper_exit_code,'notification_state':self.notification_state}

    def _read_ui(self):
        seen=0
        try:
            while True:
                raw=self.process.stderr.readline(2049)
                if not raw:
                    break
                seen+=1
                # Drain the pipe, but validate/store at most eight small receipts.
                if seen>8:
                    continue
                try:
                    receipt=decode_ui_receipt(raw,self.manifest)
                except ScopeError:
                    with self.lock:
                        self.ui_error='ui-receipt-invalid'
                    continue
                with self.lock:
                    event=receipt['event']
                    if event=='notification':
                        reason=receipt['reason']
                        pending=(self.shown and not self.stopped and not self.decided and
                                 self.ui_event not in {'closed','error'} and self.clock()<self.review_deadline)
                        if reason=='requested' and pending and self.notification_state=='not-requested':
                            self.notification_state=reason
                        elif reason=='shown' and pending and self.notification_state=='requested':
                            self.notification_state=reason
                        elif reason=='unavailable' and pending and self.notification_state=='not-requested':
                            self.notification_state=reason
                        elif reason in {'unavailable','removed'} and self.notification_state in {'requested','shown'}:
                            self.notification_state=reason
                    elif event=='shown':
                        if not self.stopped and self.ui_event not in {'closed','error'}:
                            self.ui_event='shown';self.shown=True
                    else:
                        self.ui_event=event;self.ui_reason=receipt['reason']
                        if event=='error':
                            self.ui_error=receipt['reason']
        except (OSError,ValueError):
            with self.lock:
                self.ui_error='ui-receipt-unavailable'
        finally:
            self.process.stderr.close()

    def _read(self):
        reason='helper-exited'
        try:
            while not self.stopped:
                raw=self.process.stdout.readline(32769)
                if not raw:
                    break
                frame=decode_frame(raw,self.manifest)
                if frame['event']=='helper-ready':
                    with self.lock:
                        if self.helper_ready or self.decided or self.decision_pending or self.stopped:
                            raise ScopeError('decision-invalid')
                        self.helper_ready=True
                    continue
                if frame['event']=='reference-check':
                    self._begin_reference(frame)
                    continue
                if frame['event']=='decision':
                    with self.lock:
                        if self.decided or self.decision_pending or self.stopped:
                            raise ScopeError('decision-consumed')
                        if self.v3 and (not self.helper_ready or self.reference_pending is not None or self.clock()>=self.review_deadline):
                            raise ScopeError('decision-invalid')
                        if self.acknowledged:
                            self.decision_pending=True
                        else:
                            self.decided=True
                        if not self.acknowledged and self.timer is not None:
                            self.timer.cancel()
                    threading.Thread(target=self._apply_decision,args=(frame,),daemon=True).start()
                else:
                    if not self.decided and not self.decision_pending:
                        raise ScopeError('decision-invalid')
                    reason='operator-revoked'
                    break
        except Exception:
            reason='protocol-error'
        finally:
            with self.lock:
                if self.stop_reason is None:
                    self.stop_reason=reason
            try:
                if self.decided or self.decision_pending:
                    self.on_revoke()
                else:
                    self.on_cancel()
            finally:
                self.stop(reason)

    def _write_private(self,event,fields):
        frame={'event':event,**{k:self.manifest[k] for k in ('request_id','nonce','request_digest')},**fields}
        packet=canonical(frame)+b'\n'
        if len(packet)>32768:
            raise ScopeError('decision-invalid')
        with self.write_lock:
            if self.stopped:
                raise ScopeError('decision-invalid')
            self.process.stdin.write(packet)
            self.process.stdin.flush()

    def _begin_reference(self,frame):
        with self.lock:
            if (not self.helper_ready or not callable(self.on_reference) or self.decided or self.decision_pending or self.stopped or
                    self.reference_pending is not None or self.reference_attempts>=8 or
                    frame['check_id'] in self.reference_checks or self.clock()>=self.review_deadline):
                raise ScopeError('decision-invalid')
            self.reference_attempts+=1
            self.reference_checks.add(frame['check_id'])
            self.reference_pending=frame['check_id']
            self.reference_timer=threading.Timer(min(10,self.review_deadline-self.clock()),lambda:self.stop('reference-check-expired'))
            self.reference_timer.daemon=True
            self.reference_timer.start()
            threading.Thread(target=self._reference,args=(frame,),daemon=True).start()

    def _reference(self,frame):
        expected={'check_id','item_id','edit_revision','review_ref','unit_count','code'}
        try:
            try:
                result=self.on_reference(frame)
            except Exception:
                result={k:frame[k] for k in ('check_id','item_id','edit_revision')}
                result.update(review_ref=None,unit_count=0,code='ineligible')
            with self.lock:
                if self.stopped or self.clock()>=self.review_deadline or self.reference_pending!=frame['check_id']:
                    return
                if (not isinstance(result,dict) or set(result)!=expected or
                        any(result[k]!=frame[k] for k in ('check_id','item_id','edit_revision')) or
                        result['code'] not in {'ready','reference-incomplete','reference-mismatch','ineligible','expired','stale-edit'} or
                        type(result['unit_count']) is not int or not 0<=result['unit_count']<=MAX_REFERENCE_UNITS or
                        (result['review_ref'] is not None and (not isinstance(result['review_ref'],str) or
                            len(result['review_ref'])!=32 or any(c not in '0123456789abcdef' for c in result['review_ref']))) or
                        (result['code']=='ready')!=(result['review_ref'] is not None)):
                    raise ScopeError('decision-invalid')
                self.reference_timer.cancel()
                self._write_private('reference-result',result)
                self.reference_pending=None
        except Exception:
            self.stop('protocol-error')

    def _apply_decision(self, frame):
        try:
            result=self.on_decision(frame)
            with self.lock:
                stopped=self.stopped
                if not stopped and self.acknowledged:
                    if self.clock()>=self.review_deadline:
                        raise ScopeError('decision-invalid')
                    self._write_private('decision-result',{'state':'active' if result.get('grant_id') else 'rejected',
                        'grant_id':result.get('grant_id'),'expires_in_seconds':result.get('expires_in_seconds',0),
                        'effective_limits':result.get('effective_limits',{})})
                    self.decided=True
                    self.decision_pending=False
                    if self.timer is not None:
                        self.timer.cancel()
                if not stopped and not result.get('grant_id'):
                    self.stop('replacement-blocked' if result.get('state')=='replacement-blocked' else 'operator-rejected')
                    return
                if not stopped:
                    self.timer=threading.Timer(max(1,result.get('expires_in_seconds',1)),lambda:self.stop('grant-expired'))
                    self.timer.daemon=True
                    self.timer.start()
            if stopped and self.acknowledged:
                self.on_revoke()
        except Exception:
            self.on_revoke()
            self.stop()

    def _expire_pending(self):
        with self.lock:
            if not self.decided:
                self.stop('review-expired')

    def stop(self,reason='stopped'):
        with self.lock:
            if self.stop_reason is None or (self.stop_reason in {'stopped','helper-exited'} and reason not in {'stopped','helper-exited'}):
                self.stop_reason=reason
            if self.stopped:
                return
            self.stopped=True
            if self.timer is not None:
                self.timer.cancel()
            if self.reference_timer is not None:
                self.reference_timer.cancel()
            self.job.terminate()
            self.job.close()


class RecoveryPrompt(ApprovalPrompt):
    """Recovery completion acknowledgment is not a site grant or expiry timer."""

    def _apply_decision(self, frame):
        try:
            result = self.on_decision(frame)
            with self.lock:
                if self.stopped: return
                state = result.get('state')
                if state not in {'ready', 'committed-unverified'}: raise ScopeError('decision-invalid')
                self._write_private('recovery-result', {'state': state})
                self.decided = True
                self.decision_pending = False
                if self.timer is not None: self.timer.cancel()
                # The helper closes after consuming the acknowledgment; no grant timer.
        except Exception:
            self.on_cancel()
            self.stop('operator-rejected')
