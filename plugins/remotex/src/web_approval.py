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
from web_authorization import ScopeError, canonical


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
        if not isinstance(value,dict) or value.get('event') not in {'decision','revoke'}:
            raise ValueError()
        expected=base|({'choices','ttl_seconds'} if value['event']=='decision' else set())
        if set(value)!=expected:
            raise ValueError()
        for field in ('request_id','nonce','request_digest'):
            if not isinstance(value[field],str) or not secrets.compare_digest(value[field],manifest[field]):
                raise ValueError()
        if value['event']=='decision':
            if not isinstance(value['choices'],list) or len(value['choices'])>32:
                raise ValueError()
            if type(value['ttl_seconds']) is not int or not 1<=value['ttl_seconds']<=manifest['ttl_seconds']:
                raise ValueError()
        return value
    except (UnicodeError,ValueError,TypeError,KeyError) as exc:
        raise ScopeError('decision-invalid') from exc


def decode_ui_receipt(raw: bytes, manifest: dict) -> dict:
    try:
        if not isinstance(raw,bytes) or len(raw)>2048 or not raw.endswith(b'\n'):
            raise ValueError()
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_pairs)
        if not isinstance(value,dict) or set(value)!={'event','request_id','nonce','request_digest','reason'}:
            raise ValueError()
        reasons={'shown':{'shown'},'closed':{'window-closed','review-expired','operator-rejected','operator-revoked'},
                 'error':{'helper-startup-failed','helper-ui-failed'}}
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
    def start(cls, manifest, *, on_decision, on_revoke, on_cancel):
        process=job=None
        try:
            script=Path(__file__).resolve().parents[1]/'scripts'/'web_approval.ps1'
            process=subprocess.Popen([credential_store._powershell_path(),'-NoLogo','-NoProfile','-STA',
                '-File',str(script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env=credential_store._setup_environment(),creationflags=subprocess.CREATE_NO_WINDOW)
            job=execution._WindowsJob(process,memory_limit_mb=None,cpu_time_seconds=None,max_processes=None)
            if not job.assigned:
                raise OSError()
            process.stdin.write(canonical(manifest)+b'\n')
            process.stdin.flush()
            prompt=cls(process,job,manifest,on_decision,on_revoke,on_cancel)
            pending_timer=threading.Timer(max(1,manifest['wait_seconds']),prompt._expire_pending)
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

    def __init__(self,process,job,manifest,on_decision,on_revoke,on_cancel,*,clock=time.monotonic):
        self.process,self.job,self.manifest=process,job,manifest
        self.on_decision,self.on_revoke,self.on_cancel=on_decision,on_revoke,on_cancel
        self.lock=threading.RLock()
        self.decided=False
        self.stopped=False
        self.timer=None
        self.clock=clock
        self.review_deadline=clock()+max(0,min(120,manifest['wait_seconds']))
        self.ui_event=None
        self.ui_reason=None
        self.ui_error=None
        self.shown=False
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
                    'helper_exit_code':helper_exit_code}

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
                    if event=='shown':
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
                if frame['event']=='decision':
                    with self.lock:
                        if self.decided or self.stopped:
                            raise ScopeError('decision-consumed')
                        self.decided=True
                        if self.timer is not None:
                            self.timer.cancel()
                    threading.Thread(target=self._apply_decision,args=(frame,),daemon=True).start()
                else:
                    if not self.decided:
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
                if self.decided:
                    self.on_revoke()
                else:
                    self.on_cancel()
            finally:
                self.stop(reason)

    def _apply_decision(self, frame):
        try:
            result=self.on_decision(frame)
            with self.lock:
                if self.stopped:
                    return
                if not result.get('grant_id'):
                    self.stop('operator-rejected')
                    return
                self.timer=threading.Timer(max(1,result.get('expires_in_seconds',1)),lambda:self.stop('grant-expired'))
                self.timer.daemon=True
                self.timer.start()
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
            self.job.terminate()
            self.job.close()
