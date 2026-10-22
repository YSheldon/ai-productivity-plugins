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
SITE_SESSION_CONFLICT = {'kind':'site-session-reservation-v1'}
SITE_ORIGIN_SCOPE = {'kind':'site-origin-reservation-v1'}
OBJECT_ORIGIN_SCOPE = {'kind':'object-origin-reservation-v1'}


def _publish_no_replace(source, destination):
    """Publish one staged local file, never replacing an appearing destination."""
    if os.name == 'nt':
        import ctypes
        move = ctypes.WinDLL('kernel32', use_last_error=True).MoveFileExW
        move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        move.restype = ctypes.c_int
        if not move(str(source), str(destination), 0x8):  # WRITE_THROUGH, no replacement/copy/reboot.
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.link(source, destination)
        source.unlink()


class Journal:
    """Private deny-only recovery state; persistent data can never grant authority."""

    def __init__(self, root: Path):
        self._bind(root)
        self._paths()
        secure_paths.ensure_private_directory(self.root)
        with vm_queue._exclusive_lock(self.lock_path,'web authorization recovery'):
            self._paths()
            fresh=not self.key_path.exists() and not self.state_path.exists()
            if fresh:
                self._create_key()
                self._write({'version':1,'pending':{}})
            else:
                self._read_key()
                secure_paths.ensure_private_file(self.key_path)
            self._load()

    def _bind(self, root):
        self.root = Path(root).absolute()
        self.key_path = self.root / 'integrity.key'
        self.state_path = self.root / 'uncertain-writes.json'
        self.lock_path = self.root / 'recovery.lock'

    def _create_key(self):
        descriptor=os.open(self.key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'wb') as handle:
            handle.write(secrets.token_bytes(32));handle.flush();os.fsync(handle.fileno())
        secure_paths.ensure_private_file(self.key_path)
        self._read_key()

    def _read_key(self):
        try:
            if self.key_path.stat().st_size!=32:raise ValueError()
            self.key=self.key_path.read_bytes()
            if len(self.key)!=32:raise ValueError()
        except (OSError,ValueError) as exc:
            raise ScopeError('audit-incomplete') from exc

    @classmethod
    def existing(cls, root):
        value=cls.__new__(cls);value._bind(root);value._paths()
        if value.root.exists() and not value.root.is_dir():raise ScopeError('audit-incomplete')
        key,state=value.key_path.exists(),value.state_path.exists()
        if not key and not state:return None
        if not key or not state:raise ScopeError('audit-incomplete')
        value._read_key();value._load()
        return value

    def require_site_protocol(self):
        with vm_queue._exclusive_lock(self.lock_path,'web authorization recovery'):
            if self._load()['version']!=2:raise ScopeError('recovery-upgrade-required')

    def _paths(self):
        for candidate in [self.root,*self.root.parents,self.key_path,self.state_path,self.lock_path]:
            if secure_paths._network_path(candidate) or secure_paths._reparse_point(candidate):
                raise ScopeError('audit-incomplete')

    def _mac(self, value):
        return hmac.new(self.key,canonical(value),hashlib.sha256).hexdigest()

    def _load(self):
        self._paths()
        if not self.state_path.exists():
            raise ScopeError('audit-incomplete')
        try:
            if self.state_path.stat().st_size > 262144:
                raise ValueError()
            envelope=json.loads(self.state_path.read_text(encoding='ascii'))
            if not isinstance(envelope,dict) or set(envelope) != {'state','mac'}:
                raise ValueError()
            state=envelope['state']
            if not hmac.compare_digest(self._mac(state),envelope['mac']):
                raise ValueError()
            if not isinstance(state,dict) or set(state) != {'version','pending'} or type(state['version']) is not int or state['version'] not in {1,2} or not isinstance(state['pending'],dict):
                raise ValueError()
            for name,conflicts in state['pending'].items():
                if not isinstance(name,str) or len(name)!=32 or not isinstance(conflicts,list) or not conflicts:
                    raise ValueError()
                if any(not isinstance(v,str) or len(v)!=64 for v in conflicts):
                    raise ValueError()
                self._scope(conflicts)
            return state
        except (OSError,ValueError,TypeError,KeyError) as exc:
            raise ScopeError('audit-incomplete') from exc

    def _write(self, state, *, before_replace=None):
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
            if before_replace is not None: before_replace()
            os.replace(temporary,self.state_path)
        except Exception as exc:
            raise ScopeError('audit-incomplete') from exc
        finally:
            temporary.unlink(missing_ok=True)

    def _publish_initial(self, state, before_publish):
        self._paths()
        temporary = self.root / ('state-' + secrets.token_hex(16) + '.tmp')
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(canonical({'state': state, 'mac': self._mac(state)}))
                handle.flush()
                os.fsync(handle.fileno())
            secure_paths.ensure_private_file(temporary)
            before_publish()
            self._paths()
            _publish_no_replace(temporary, self.state_path)
        finally:
            temporary.unlink(missing_ok=True)

    def _scope(self, row):
        legacy,site,objects=(self._mac(value) for value in (SITE_SESSION_CONFLICT,SITE_ORIGIN_SCOPE,OBJECT_ORIGIN_SCOPE))
        if row[0] in {site,objects}:
            if (len(row)<2 or row[1] in {legacy,site,objects} or
                    row[0]==site and len(row)!=2 or row[0]==objects and len(row)<3 or
                    any(key in {legacy,site,objects} for key in row[2:])):
                raise ScopeError('audit-incomplete')
            return row[1],row[0]==site,set(row[2:])
        if row==[legacy]: return None,True,set()
        if any(key in {legacy,site,objects} for key in row): raise ScopeError('audit-incomplete')
        return None,False,set(row)

    @staticmethod
    def _conflict(left,right):
        left_origin,left_site,left_keys=left
        right_origin,right_site,right_keys=right
        if left_origin is not None and right_origin is not None and left_origin!=right_origin:
            return False
        if left_site or right_site:
            return True
        return bool(left_keys & right_keys)

    def _reserve(self, attempt, keys, *, site=False):
        if not isinstance(attempt,str) or len(attempt)!=32 or not keys:
            raise ScopeError('audit-incomplete')
        scope=self._scope(keys)
        with vm_queue._exclusive_lock(self.lock_path,'web authorization recovery'):
            state=self._load()
            if site and state['version']!=2:raise ScopeError('recovery-upgrade-required')
            if attempt in state['pending'] or any(self._conflict(scope,self._scope(row)) for row in state['pending'].values()):
                raise ScopeError('unresolved-prior-write')
            state['pending'][attempt]=keys
            self._write(state)

    def reserve(self, attempt, conflicts):
        if not conflicts: raise ScopeError('audit-incomplete')
        self._reserve(attempt,[self._mac(value) for value in conflicts])

    def _origin(self, origin):
        from urllib.parse import urlsplit
        if not isinstance(origin,str) or len(origin)>2048: raise ScopeError('audit-incomplete')
        value=urlsplit(origin)
        if value.scheme!='https' or not value.hostname or value.username or value.password or value.path or value.query or value.fragment:
            raise ScopeError('audit-incomplete')
        return self._mac({'origin':origin})

    def reserve_origin(self, attempt, conflicts, origin):
        if not conflicts: raise ScopeError('audit-incomplete')
        self._reserve(attempt,[self._mac(OBJECT_ORIGIN_SCOPE),self._origin(origin),*[self._mac(value) for value in conflicts]])

    def reserve_site(self, attempt, origin):
        self._reserve(attempt,[self._mac(SITE_ORIGIN_SCOPE),self._origin(origin)],site=True)

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

    def append_startup_batch(self, events):
        if not isinstance(events,list) or not 1<=len(events)<=32 or any(
            not isinstance(event,dict) or set(event)-EVENT_FIELDS or
            event.get('event') not in {'execution-reserved','execution-finished'} for event in events):
            raise ScopeError('audit-incomplete')
        audit_log.append_startup_batch([{'event':'web-authorization','authorization':dict(event)} for event in events])


def require_site_protocol(root):
    journal=Journal.existing(root)
    if journal is None or journal._load()['version']!=2:raise ScopeError('recovery-upgrade-required')


def upgrade_protocol(root, *, check_idle, confirm=False):
    """Explicit deny-only protocol transition; preview never initializes storage."""
    def inspect(journal):
        state=journal._load() if journal else {'version':0,'pending':{}}
        version=state['version']
        if version==2:return {'state':'ready','ready':True,'canUpgrade':False,'protocolVersion':2}
        reason='unresolved-prior-write' if state['pending'] else None
        if reason is None:
            try:
                if check_idle() is not True:reason='web-sessions-busy-or-unknown'
            except Exception:reason='web-sessions-busy-or-unknown'
        return {'state':'blocked' if reason else 'preview','ready':False,'canUpgrade':reason is None,
            'protocolVersion':version,**({'reason':reason} if reason else {})}
    current=Journal.existing(root)
    preview=inspect(current)
    if confirm is not True or preview['ready'] or not preview['canUpgrade']:return preview
    candidate=Journal.__new__(Journal);candidate._bind(root);candidate._paths()
    secure_paths.ensure_private_directory(candidate.root)
    # Never take queue/lease/resource locks here: old login holds one while
    # waiting for Journal construction. Lifecycle inspection must be read-only.
    with vm_queue._exclusive_lock(candidate.lock_path,'web authorization recovery'):
        current=Journal.existing(root)
        rechecked=inspect(current)
        if rechecked['ready'] or not rechecked['canUpgrade']:return rechecked
        if current is None:
            candidate._paths();candidate._create_key();current=candidate
        try:
            current._write({'version':2,'pending':{}})
        except Exception:
            try:committed=current._load()['version']==2
            except Exception:committed=False
            if committed:return {'state':'committed-unverified','ready':False,'committed':True,'protocolVersion':2}
            raise
        try:
            if current._load()!= {'version':2,'pending':{}}:raise ScopeError('audit-incomplete')
            current.append({'event':'recovery-protocol-upgraded','generation':2,'state':'committed'})
        except Exception:
            return {'state':'committed-unverified','ready':False,'committed':True,'protocolVersion':2}
        return {'state':'ready','ready':True,'canUpgrade':False,'committed':True,'protocolVersion':2}
