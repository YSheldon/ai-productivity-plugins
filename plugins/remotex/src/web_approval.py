from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
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


class ApprovalPrompt:
    """One native helper with private inherited IPC and no approve endpoint."""

    @classmethod
    def start(cls, manifest, *, on_decision, on_revoke, on_cancel):
        process=job=None
        try:
            script=Path(__file__).resolve().parents[1]/'scripts'/'web_approval.ps1'
            process=subprocess.Popen([credential_store._powershell_path(),'-NoLogo','-NoProfile','-STA',
                '-File',str(script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
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

    def __init__(self,process,job,manifest,on_decision,on_revoke,on_cancel):
        self.process,self.job,self.manifest=process,job,manifest
        self.on_decision,self.on_revoke,self.on_cancel=on_decision,on_revoke,on_cancel
        self.lock=threading.RLock()
        self.decided=False
        self.stopped=False
        self.timer=None

    def _read(self):
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
                    break
        except Exception:
            pass
        finally:
            try:
                if self.decided:
                    self.on_revoke()
                else:
                    self.on_cancel()
            finally:
                self.stop()

    def _apply_decision(self, frame):
        try:
            result=self.on_decision(frame)
            with self.lock:
                if self.stopped:
                    return
                if not result.get('grant_id'):
                    self.stop()
                    return
                self.timer=threading.Timer(max(1,result.get('expires_in_seconds',1)),self.stop)
                self.timer.daemon=True
                self.timer.start()
        except Exception:
            self.on_revoke()
            self.stop()

    def _expire_pending(self):
        with self.lock:
            if not self.decided:
                self.stop()

    def stop(self):
        with self.lock:
            if self.stopped:
                return
            self.stopped=True
            if self.timer is not None:
                self.timer.cancel()
            self.job.terminate()
            self.job.close()
