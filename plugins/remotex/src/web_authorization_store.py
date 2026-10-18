from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

import audit_log
import secure_paths
import vm_queue
from web_authorization import ScopeError, canonical


EVENT_FIELDS = frozenset({'event','binding_digest','request_id','request_digest',
    'approved_scope_digest','approved_items','count','ttl_seconds','grant_id',
    'attempt_id','item_id','capability','scope_digest','targets','state','summary',
    'item_ids','reason','generation','contract_digest','target_digest'})


class Journal:
    """Private deny-only recovery state; persistent data can never grant authority."""

    def __init__(self, root: Path):
        self.root = Path(root).absolute()
        self.key_path = self.root / 'integrity.key'
        self.state_path = self.root / 'uncertain-writes.json'
        self.lock_path = self.root / 'recovery.lock'
        self._paths()
        secure_paths.ensure_private_directory(self.root)
        with vm_queue._exclusive_lock(self.lock_path,'web authorization recovery'):
            self._paths()
            if not self.key_path.exists():
                if self.state_path.exists():
                    raise ScopeError('audit-incomplete')
                descriptor = os.open(self.key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(descriptor,'wb') as handle:
                    handle.write(secrets.token_bytes(32))
                    handle.flush()
                    os.fsync(handle.fileno())
                secure_paths.ensure_private_file(self.key_path)
            if self.key_path.stat().st_size != 32:
                raise ScopeError('audit-incomplete')
            self.key = self.key_path.read_bytes()
            secure_paths.ensure_private_file(self.key_path)
            self._load()

    def _paths(self):
        for candidate in [self.root,*self.root.parents,self.key_path,self.state_path,self.lock_path]:
            if secure_paths._network_path(candidate) or secure_paths._reparse_point(candidate):
                raise ScopeError('audit-incomplete')

    def _mac(self, value):
        return hmac.new(self.key,canonical(value),hashlib.sha256).hexdigest()

    def _load(self):
        self._paths()
        if not self.state_path.exists():
            return {'version':1,'pending':{}}
        try:
            if self.state_path.stat().st_size > 262144:
                raise ValueError()
            envelope=json.loads(self.state_path.read_text(encoding='ascii'))
            if not isinstance(envelope,dict) or set(envelope) != {'state','mac'}:
                raise ValueError()
            state=envelope['state']
            if not hmac.compare_digest(self._mac(state),envelope['mac']):
                raise ValueError()
            if not isinstance(state,dict) or set(state) != {'version','pending'} or state['version'] != 1 or not isinstance(state['pending'],dict):
                raise ValueError()
            for name,conflicts in state['pending'].items():
                if not isinstance(name,str) or len(name)!=32 or not isinstance(conflicts,list) or not conflicts:
                    raise ValueError()
                if any(not isinstance(v,str) or len(v)!=64 for v in conflicts):
                    raise ValueError()
            return state
        except (OSError,ValueError,TypeError,KeyError) as exc:
            raise ScopeError('audit-incomplete') from exc

    def _write(self, state):
        self._paths()
        body=canonical({'state':state,'mac':self._mac(state)})
        if len(body)>262144:
            raise ScopeError('audit-incomplete')
        temporary=self.root/('state-'+secrets.token_hex(16)+'.tmp')
        try:
            descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'wb') as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            secure_paths.ensure_private_file(temporary)
            os.replace(temporary,self.state_path)
        except Exception as exc:
            raise ScopeError('audit-incomplete') from exc
        finally:
            temporary.unlink(missing_ok=True)

    def reserve(self, attempt, conflicts):
        if not isinstance(attempt,str) or len(attempt)!=32 or not conflicts:
            raise ScopeError('audit-incomplete')
        keys=[self._mac(value) for value in conflicts]
        with vm_queue._exclusive_lock(self.lock_path,'web authorization recovery'):
            state=self._load()
            if attempt in state['pending'] or any(set(keys)&set(row) for row in state['pending'].values()):
                raise ScopeError('unresolved-prior-write')
            state['pending'][attempt]=keys
            self._write(state)

    def resolve(self, attempt):
        with vm_queue._exclusive_lock(self.lock_path,'web authorization recovery'):
            state=self._load()
            if attempt in state['pending']:
                state['pending'].pop(attempt)
                self._write(state)

    def append(self, event):
        if not isinstance(event,dict) or set(event)-EVENT_FIELDS or not isinstance(event.get('event'),str):
            raise ScopeError('audit-incomplete')
        audit_log.append({'event':'web-authorization','authorization':event})

    def append_many(self, events):
        if not isinstance(events,list) or not 1<=len(events)<=2 or any(
            not isinstance(event,dict) or set(event)-EVENT_FIELDS or not isinstance(event.get('event'),str)
            for event in events):
            raise ScopeError('audit-incomplete')
        audit_log.append_many([{'event':'web-authorization','authorization':event} for event in events])
