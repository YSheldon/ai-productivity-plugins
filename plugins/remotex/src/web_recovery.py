"""Owner-reviewed legacy recovery. Persistent evidence never grants authority."""
from __future__ import annotations

import copy
import hashlib
import io
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import replace
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import audit_log
import secure_paths
from web_authorization import ScopeError, canonical
from web_authorization import MAX_NATIVE_REVIEW_SECONDS
from web_authorization_store import Journal, SITE_SESSION_CONFLICT
import vm_queue
import web_recovery_history


@dataclass(frozen=True)
class LegacyEvidence:
    mode: Literal['initialize', 'finalize']
    root: Path
    key_identity: tuple[int, int, int, int]
    ledger_identity: tuple[int, int]
    ledger_size: int
    ledger_checkpoint: str
    scope_digest: str
    summary: dict[str, Any]
    root_identity: tuple[int, int] = field(repr=False)
    history_inventory: list[dict[str, Any]] = field(default_factory=list, repr=False)
    history_policy: Literal['strict-v1', 'reconcile-v2'] = 'reconcile-v2'


def _local(path):
    path = Path(path).absolute()
    if any(secure_paths._network_path(p) or secure_paths._reparse_point(p) for p in (path, *path.parents)):
        raise ScopeError('recovery-evidence-invalid')
    return path


def _identity(path):
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _key_only(root):
    root = _local(root)
    key = _local(root / 'integrity.key')
    _local(root / 'uncertain-writes.json')
    _local(root / 'recovery.lock')
    if not root.is_dir() or not key.is_file() or key.stat().st_size != 32:
        raise ScopeError('recovery-key-invalid')
    if (root / 'uncertain-writes.json').exists():
        # Validate existing material, but never reinterpret it as legacy key-only.
        try: Journal.existing(root)
        except ScopeError: raise ScopeError('recovery-evidence-invalid') from None
        raise ScopeError('recovery-state-present')
    return root, _identity(key)


def _scope(scope):
    if not isinstance(scope, list) or not 1 <= len(scope) <= 256:
        raise ScopeError('recovery-scope-unknown')
    names = set()
    for row in scope:
        if not isinstance(row, dict) or set(row) != {'profile', 'origin', 'account'}:
            raise ScopeError('recovery-scope-unknown')
        if any(not isinstance(v, str) or not 1 <= len(v) <= 2048 or any(ord(c) < 32 for c in v) for v in row.values()):
            raise ScopeError('recovery-scope-unknown')
        parsed = urlsplit(row['origin'])
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or
                parsed.path or parsed.query or parsed.fragment or row['profile'] in names):
            raise ScopeError('recovery-scope-unknown')
        names.add(row['profile'])
    return sorted(copy.deepcopy(scope), key=lambda row: row['profile'])


def _ledger(path):
    path = _local(path)
    try:
        with path.open('rb') as handle:
            identity = os.fstat(handle.fileno())
            raw = handle.read()
            after = os.fstat(handle.fileno())
        if (identity.st_dev, identity.st_ino, identity.st_size, identity.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError()
        if raw not in (b'', b'\x00') and not raw.endswith(b'\n'):
            raise ValueError()
        records = audit_log._records(io.BytesIO(raw))
        audit_log._verify_records(records)
        if any(row.get('schema') != audit_log.SCHEMA or not isinstance(row.get('sessionId'), str) for row in records):
            raise ValueError()
        return raw, records, (identity.st_dev, identity.st_ino)
    except Exception as exc:
        raise ScopeError('recovery-evidence-invalid') from exc


def _relevant(row):
    if row.get('event') == 'web-authorization':
        value = row.get('authorization')
        if not isinstance(value, dict) or not isinstance(value.get('event'), str):
            raise ScopeError('recovery-evidence-invalid')
        return value['event'] != 'legacy-recovery-owner-reviewed'
    tool = row.get('tool', '')
    return isinstance(tool, str) and tool.startswith('remotex_web_') and tool not in {
        'remotex_web_authorization_recovery', 'remotex_web_authorization_upgrade'}


def _strict_observations(records, scope):
    profiles = {hashlib.sha256(row['profile'].encode()).hexdigest() for row in scope}
    operations, attempts, completed, bindings = {}, {}, 0, set()
    for row in records:
        if not _relevant(row):
            continue
        request = row.get('request', {})
        if not isinstance(request, dict):
            raise ScopeError('recovery-evidence-invalid')
        profile = request.get('profileSha256')
        if profile is not None and profile not in profiles:
            raise ScopeError('recovery-scope-unknown')
        tool = row.get('tool')
        if tool in {'remotex_web_execute', 'remotex_web_site_execute'}:
            identity = (row['sessionId'], row.get('operationId'))
            if not isinstance(identity[1], str):
                raise ScopeError('recovery-evidence-invalid')
            if row.get('event') == 'operation-start':
                if identity in operations: raise ScopeError('recovery-evidence-invalid')
                operations[identity] = False
            elif row.get('event') == 'operation-finish':
                result = row.get('result', {})
                if identity not in operations or operations[identity] or not isinstance(result, dict):
                    raise ScopeError('recovery-unresolved-write')
                if result.get('state') not in {'verified', 'failed-before-dispatch'}:
                    raise ScopeError('recovery-unresolved-write')
                operations[identity] = True
        if row.get('event') != 'web-authorization': continue
        value = row.get('authorization')
        if not isinstance(value, dict): raise ScopeError('recovery-evidence-invalid')
        # Missing binding metadata is also unexplained, never evidence of no scope.
        if value.get('event') != 'recovery-protocol-upgraded':
            bindings.add(value.get('binding_digest') or '<unknown>')
        name = value.get('event')
        if name not in {'execution-reserved', 'execution-finished', 'site-action-dispatch', 'site-action-result'}:
            continue
        identity = (row['sessionId'], value.get('binding_digest'), value.get('attempt_id'))
        if not isinstance(identity[2], str) or len(identity[2]) != 32:
            raise ScopeError('recovery-evidence-invalid')
        if name in {'execution-reserved', 'site-action-dispatch'}:
            if identity in attempts: raise ScopeError('recovery-unresolved-write')
            attempts[identity] = False
        else:
            if identity not in attempts or attempts[identity] or value.get('state') not in {'verified', 'failed-before-dispatch'}:
                raise ScopeError('recovery-unresolved-write')
            attempts[identity] = True
            completed += 1
    if not all(operations.values()) or not all(attempts.values()):
        raise ScopeError('recovery-unresolved-write')
    # Legacy task-binding digests are not reversible origin/account evidence.
    # A current profile name (even in the same MCP process) cannot explain them.
    if bindings: raise ScopeError('recovery-scope-unknown')
    return {'completedAttempts': completed, 'historicalBindings': len(bindings), 'scopeCount': len(scope)}


def _observations(records, scope):
    summary, inventory = web_recovery_history.observe(records, scope)
    summary['reconciliationRequired'] = bool(inventory)
    return summary, inventory


def _idle(check_idle):
    try:
        if check_idle() is True: return
    except Exception:
        pass
    raise ScopeError('recovery-busy')


def inspect_legacy_state(root, *, audit_path, scope, check_idle):
    try:
        root, key = _key_only(root)
        scopes = _scope(scope)
        _idle(check_idle)
        raw, records, identity = _ledger(audit_path)
        summary, inventory = _observations(records, scopes)
        summary.update(classification='key-only-ambiguous', historyBasis='owner-review-required',
            missingEnvelope=True, scopes=scopes,
            uncertainty='Missing recovery data cannot prove an empty history. Historical origins/accounts are unknown and are not inferred from configured scopes. Completed means technical completion, not business verification. Do not label records synthetic without evidence. The owner must reconcile all prior effects for this shared store.')
        return LegacyEvidence('initialize', root, key, identity, len(raw), hashlib.sha256(raw).hexdigest(),
            hashlib.sha256(canonical(scopes)).hexdigest(), summary, _identity(root)[:2], inventory)
    except OSError as exc:
        raise ScopeError('recovery-evidence-invalid') from exc


def recheck_legacy_evidence(evidence, *, audit_path, scope, check_idle):
    if evidence.history_policy == 'reconcile-v2' and hashlib.sha256(canonical(evidence.history_inventory)).hexdigest() != evidence.summary.get('inventoryDigest'):
        raise ScopeError('recovery-stale')
    _local(evidence.root)
    if _identity(evidence.root)[:2] != evidence.root_identity or _identity(_local(evidence.root / 'integrity.key')) != evidence.key_identity:
        raise ScopeError('recovery-stale')
    if hashlib.sha256(canonical(_scope(scope))).hexdigest() != evidence.scope_digest:
        raise ScopeError('recovery-stale')
    _idle(check_idle)
    raw, records, identity = _ledger(audit_path)
    if (identity != evidence.ledger_identity or len(raw) < evidence.ledger_size or
            hashlib.sha256(raw[:evidence.ledger_size]).hexdigest() != evidence.ledger_checkpoint):
        raise ScopeError('recovery-stale')
    # Verify complete extension, but tolerate unrelated append-only SSH/VM work.
    prefix = audit_log._records(io.BytesIO(raw[:evidence.ledger_size]))
    if any(_relevant(row) for row in records[len(prefix):]):
        raise ScopeError('recovery-stale')
    if evidence.mode == 'initialize': _key_only(evidence.root)


def public_summary(evidence):
    value = copy.deepcopy(evidence.summary)
    value['historyPolicy'] = evidence.history_policy
    if evidence.history_policy == 'reconcile-v2':
        labels = [('Recorded verified attempts', 'verifiedAttempts'),
            ('Technically completed page reads', 'technicalReadAttempts'),
            ('Technically completed effects requiring owner reconciliation', 'technicalEffectAttempts'),
            ('Failed before dispatch', 'failedBeforeDispatchAttempts'),
            ('Unknown historical scope bindings', 'unknownScopeBindings'),
            ('Recorded MCP write operations', 'mcpWriteOperations'),
            ('Ungranted requests (not executed)', 'ungrantedRequests'),
            ('Unresolved dispatched attempts', 'unresolvedAttempts')]
        value['reviewText'] = '\r\n'.join(label + ': ' + str(value[key]) for label, key in labels)
        value['reviewText'] += '\r\nHistory first observed (UTC): ' + str(value['historyFirstObserved'] or 'Not recorded')
        value['reviewText'] += '\r\nHistory last observed (UTC): ' + str(value['historyLastObserved'] or 'Not recorded')
        value['reviewText'] += '\r\nInventory digest: ' + value['inventoryDigest']
    else:
        value['reviewText'] = 'Original strict recovery receipt. No amended history exception is applied.'
    return value


LEGACY_RECEIPT_KIND = 'legacy-key-only-recovery-receipt-v1'
RECEIPT_KIND = 'legacy-key-only-recovery-receipt-v2'
_HISTORY_COUNTS = frozenset({'completedAttempts', 'verifiedAttempts', 'failedBeforeDispatchAttempts',
    'technicalReadAttempts', 'technicalEffectAttempts', 'historicalBindings', 'unknownScopeBindings',
    'historicalProfileHashes', 'mcpWriteOperations', 'ungrantedRequests', 'unresolvedAttempts'})


def _history_counts(summary):
    return {name: summary[name] for name in sorted(_HISTORY_COUNTS)}


def _recovery_id(value):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{32}', value) is None:
        raise ScopeError('recovery-evidence-invalid')
    return value


def _journal(root):
    value = Journal.__new__(Journal)
    value._bind(_local(root))
    value._paths()
    try: value._read_key()
    except ScopeError: raise ScopeError('recovery-key-invalid') from None
    return value


def _receipt_path(journal, identity):
    return _local(journal.root / ('recovery-' + _recovery_id(identity) + '.json'))


def _private_write(path, body, *, replace_existing=False):
    staged = path.parent / ('recovery-' + secrets.token_hex(16) + '.tmp')
    try:
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        secure_paths.ensure_private_file(staged)
        if replace_existing:
            os.replace(staged, path)
        else:
            from web_authorization_store import _publish_no_replace
            _publish_no_replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)


def _save_receipt(journal, value):
    path = _receipt_path(journal, value['recovery_id'])
    _private_write(path, canonical({'receipt': value, 'mac': journal._mac(value)}), replace_existing=path.exists())


def _read_receipt(journal, identity):
    try:
        path = _receipt_path(journal, identity)
        if not path.is_file() or path.stat().st_size > 65536: raise ValueError()
        envelope = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(envelope, dict) or set(envelope) != {'receipt', 'mac'}: raise ValueError()
        value = envelope['receipt']
        fields = {'kind', 'recovery_id', 'phase', 'historyBasis', 'root_identity', 'key_identity',
            'ledger_identity', 'ledger_size', 'ledger_checkpoint', 'scope_digest'}
        if not isinstance(value, dict): raise ValueError()
        amended = value.get('kind') == RECEIPT_KIND
        if amended:
            fields |= {'inventory_digest', 'history_summary'}
            counts = value.get('history_summary')
            if (not isinstance(value.get('inventory_digest'), str) or re.fullmatch('[a-f0-9]{64}', value['inventory_digest']) is None or
                    not isinstance(counts, dict) or set(counts) != _HISTORY_COUNTS or
                    any(type(count) is not int or count < 0 for count in counts.values()) or counts['unresolvedAttempts'] != 0):
                raise ValueError()
        if (set(value) != fields or value.get('kind') not in {LEGACY_RECEIPT_KIND, RECEIPT_KIND} or value['recovery_id'] != identity or
                value['phase'] not in {'prepared', 'finalization-intent'} or
                value['historyBasis'] != ('owner-reconciled-legacy-history' if amended else 'owner-reviewed') or
                value['root_identity'] != list(_identity(journal.root)[:2]) or
                value['key_identity'] != list(_identity(journal.key_path)) or
                not isinstance(value['ledger_identity'], list) or len(value['ledger_identity']) != 2 or
                any(type(v) is not int for v in value['ledger_identity']) or
                type(value['ledger_size']) is not int or value['ledger_size'] < 0 or
                not isinstance(value['ledger_checkpoint'], str) or re.fullmatch('[a-f0-9]{64}', value['ledger_checkpoint']) is None or
                not hmac.compare_digest(journal._mac(value), envelope['mac'])):
            raise ValueError()
        return value
    except Exception as exc:
        raise ScopeError('recovery-evidence-invalid') from exc


def read_recovery_status(root, recovery_id):
    journal = _journal(root)
    receipt = _read_receipt(journal, recovery_id)
    if not journal.state_path.exists():
        return {'state': 'prepared', 'committed': False, 'ready': False}
    state = journal._load()
    if state['version'] != 2: raise ScopeError('recovery-evidence-invalid')
    marker = state['pending'].get(recovery_id)
    if marker is not None and marker != [journal._mac(SITE_SESSION_CONFLICT)]:
        raise ScopeError('recovery-evidence-invalid')
    ready = marker is None and receipt['phase'] == 'finalization-intent'
    if marker is None and not ready: raise ScopeError('recovery-evidence-invalid')
    return {'state': 'ready' if ready else 'committed-unverified', 'ready': ready,
        'committed': True, 'fenceVerified': marker is not None, 'protocolVersion': 2,
        'historyBasis': receipt['historyBasis']}


def inspect_interrupted_recovery(root, recovery_id, *, audit_path, scope, check_idle):
    journal = _journal(root)
    receipt = _read_receipt(journal, recovery_id)
    state = journal._load()
    expected = {recovery_id: [journal._mac(SITE_SESSION_CONFLICT)]}
    if state['version'] != 2 or state['pending'] != expected:
        raise ScopeError('recovery-unresolved-write')
    # Inspect the same evidence without pretending the existing envelope is absent.
    scopes = _scope(scope)
    _idle(check_idle)
    raw, records, identity = _ledger(audit_path)
    if (list(identity) != receipt['ledger_identity'] or len(raw) < receipt['ledger_size'] or
            hashlib.sha256(raw[:receipt['ledger_size']]).hexdigest() != receipt['ledger_checkpoint']):
        raise ScopeError('recovery-stale')
    amended = receipt['kind'] == RECEIPT_KIND
    if amended:
        summary, inventory = _observations(records, scopes)
        if (summary['inventoryDigest'] != receipt['inventory_digest'] or
                _history_counts(summary) != receipt['history_summary']):
            raise ScopeError('recovery-stale')
    else:
        summary, inventory = _strict_observations(records, scopes), []
    scope_digest = hashlib.sha256(canonical(scopes)).hexdigest()
    if scope_digest != receipt['scope_digest']: raise ScopeError('recovery-stale')
    summary.update(classification='interrupted-owner-reviewed-recovery', historyBasis='owner-review-required',
        missingEnvelope=False, scopes=scopes,
        uncertainty='Finalize only this authenticated technical recovery marker. A fresh owner review is required; the receipt is not approval.')
    return LegacyEvidence('finalize', journal.root, _identity(journal.key_path), identity, len(raw),
        hashlib.sha256(raw).hexdigest(), scope_digest, summary, _identity(journal.root)[:2], inventory,
        'reconcile-v2' if amended else 'strict-v1')


def _recheck(evidence):
    recheck_legacy_evidence(evidence, audit_path=audit_log.audit_path(),
        scope=evidence.summary['scopes'], check_idle=lambda: True)


def _finish_locked(journal, evidence, recovery_id, before_publish):
    receipt = _read_receipt(journal, recovery_id)
    state = journal._load()
    expected = {recovery_id: [journal._mac(SITE_SESSION_CONFLICT)]}
    if state['version'] != 2 or state['pending'] != expected:
        raise ScopeError('recovery-unresolved-write')
    before_publish()
    _recheck(replace(evidence, mode='finalize'))
    journal.append({'event': 'legacy-recovery-owner-reviewed', 'request_id': recovery_id,
        'state': 'finalization-intent', 'reason': receipt['historyBasis'], 'generation': 2})
    receipt['phase'] = 'finalization-intent'
    _save_receipt(journal, receipt)
    # Last required durable transition: no recursive resolve or subsequent receipt write.
    before_publish()
    _recheck(replace(evidence, mode='finalize'))
    current = journal._load()
    if current != state: raise ScopeError('recovery-stale')
    current['pending'].pop(recovery_id)
    def final_check():
        before_publish()
        _recheck(replace(evidence, mode='finalize'))
        if journal._load() != state: raise ScopeError('recovery-stale')
    journal._write(current, before_replace=final_check)
    return read_recovery_status(journal.root, recovery_id)


def _uncertain_result(root, identity):
    try:
        return read_recovery_status(root, identity)
    except Exception:
        return {'state': 'committed-unverified', 'ready': False, 'committed': True,
            'fenceVerified': None, 'protocolVersion': 2}


def recover_key_only_v2(evidence, *, recovery_id, before_publish, backup_root):
    _recovery_id(recovery_id)
    if evidence.mode != 'initialize' or not callable(before_publish): raise ScopeError('recovery-evidence-invalid')
    journal = _journal(evidence.root)
    with vm_queue._exclusive_lock(journal.lock_path, 'web authorization recovery'):
        _recheck(evidence)
        before_publish()
        backup = _local(Path(backup_root) / recovery_id)
        if backup.exists(): raise ScopeError('recovery-stale')
        secure_paths.ensure_private_directory(_local(backup_root))
        secure_paths.ensure_private_directory(backup)
        _private_write(backup / 'integrity.key', journal.key)
        _private_write(backup / 'evidence.json', canonical({'missingEnvelope': True,
            'historyBasis': 'owner-reconciled-legacy-history', 'summary': evidence.summary,
            'historyInventory': evidence.history_inventory,
            'ledger_checkpoint': evidence.ledger_checkpoint, 'lockMetadata': list(_identity(journal.lock_path))}))
        secure_paths.ensure_private_directory(journal.root)
        receipt = {'kind': RECEIPT_KIND, 'recovery_id': recovery_id, 'phase': 'prepared',
            'historyBasis': 'owner-reconciled-legacy-history', 'root_identity': list(evidence.root_identity),
            'inventory_digest': evidence.summary['inventoryDigest'], 'history_summary': _history_counts(evidence.summary),
            'key_identity': list(evidence.key_identity), 'ledger_checkpoint': evidence.ledger_checkpoint,
            'ledger_identity': list(evidence.ledger_identity), 'ledger_size': evidence.ledger_size,
            'scope_digest': evidence.scope_digest}
        _save_receipt(journal, receipt)
        marker = {'version': 2, 'pending': {recovery_id: [journal._mac(SITE_SESSION_CONFLICT)]}}
        def check():
            _recheck(evidence)
            before_publish()
        try:
            journal._publish_initial(marker, check)
        except Exception as exc:
            # An appearing unrelated envelope belongs to its writer, not this recovery.
            try: published = journal._load() == marker
            except Exception: published = False
            if published: return _uncertain_result(journal.root, recovery_id)
            raise ScopeError('recovery-stale') from exc
        try:
            if journal._load() != marker: raise ScopeError('recovery-stale')
            return _finish_locked(journal, evidence, recovery_id, before_publish)
        except Exception:
            return _uncertain_result(journal.root, recovery_id)


def finalize_recovery_v2(evidence, *, recovery_id, before_publish):
    _recovery_id(recovery_id)
    if evidence.mode != 'finalize' or not callable(before_publish): raise ScopeError('recovery-evidence-invalid')
    journal = _journal(evidence.root)
    with vm_queue._exclusive_lock(journal.lock_path, 'web authorization recovery'):
        before_publish()
        _recheck(evidence)
        try:
            return _finish_locked(journal, evidence, recovery_id, before_publish)
        except Exception:
            return _uncertain_result(journal.root, recovery_id)


class RecoveryService:
    """One live native owner review per MCP; receipts reconstruct evidence only."""

    def __init__(self, root, *, audit_path, scope, check_idle, prompt=None, clock=time.monotonic):
        from web_approval import RecoveryPrompt
        self.root, self.audit_path, self.scope, self.check_idle = Path(root), audit_path, scope, check_idle
        self.prompt_type, self.clock = prompt or RecoveryPrompt, clock
        self.lock = threading.RLock()
        self.cancelled = threading.Event()
        self.identity = self.evidence = self.manifest = self.prompt = self.result = None
        self.state = 'new'
        self.deadline = None

    def preview(self):
        with self.lock:
            if self.state in {'preview', 'pending', 'committing'}: return self.status(self.identity, include_ui=False)
            scope = self.scope()
            if (self.root / 'uncertain-writes.json').exists():
                journal = _journal(self.root)
                state = journal._load()
                if state['version'] == 2 and not state['pending']:
                    return {'state': 'ready', 'ready': True, 'recoveryRequired': False, 'protocolVersion': 2}
                candidates = [name for name, row in state['pending'].items() if row == [journal._mac(SITE_SESSION_CONFLICT)]]
                if len(candidates) != 1: raise ScopeError('recovery-unresolved-write')
                self.identity = candidates[0]
                self.evidence = inspect_interrupted_recovery(self.root, self.identity,
                    audit_path=self.audit_path, scope=scope, check_idle=self.check_idle)
            else:
                self.evidence = inspect_legacy_state(self.root, audit_path=self.audit_path, scope=scope, check_idle=self.check_idle)
                self.identity = secrets.token_hex(16)
            self.cancelled.clear()
            self.manifest = self.prompt = self.result = None
            self.deadline = None
            self.state = 'preview'
            return self.status(self.identity)

    def _current(self):
        if self.cancelled.is_set() or self.deadline is None or self.clock() >= self.deadline:
            raise ScopeError('review-expired')
        _idle(self.check_idle)
        if hashlib.sha256(canonical(_scope(self.scope()))).hexdigest() != self.evidence.scope_digest:
            raise ScopeError('recovery-stale')

    def open(self, recovery_id):
        _recovery_id(recovery_id)
        with self.lock:
            if recovery_id != self.identity: raise ScopeError('recovery-evidence-invalid')
            if self.state != 'preview': return self.status(recovery_id, include_ui=False)
            try:
                recheck_legacy_evidence(self.evidence, audit_path=self.audit_path, scope=self.scope(), check_idle=self.check_idle)
            except Exception:
                self.state = 'stale'
                raise
            self.deadline = self.clock() + MAX_NATIVE_REVIEW_SECONDS
            manifest = {'ui_mode': 'recovery', 'mode': self.evidence.mode, 'request_id': recovery_id,
                'nonce': secrets.token_hex(32), 'wait_seconds': MAX_NATIVE_REVIEW_SECONDS,
                'target': str(self.root), 'summary': public_summary(self.evidence)}
            manifest['request_digest'] = hashlib.sha256(canonical(manifest)).hexdigest()
            self.manifest = manifest
            self.state = 'pending'
            try:
                self.prompt = self.prompt_type.start(copy.deepcopy(manifest), on_decision=self._decision,
                    on_revoke=lambda: self._cancel_review(manifest['nonce']),
                    on_cancel=lambda: self._cancel_review(manifest['nonce']))
            except Exception:
                self.state = 'cancelled'
                self.cancelled.set()
                raise ScopeError('approval-ui-unavailable') from None
            return self.status(recovery_id, include_ui=False)

    def _decision(self, frame):
        from web_approval import decode_frame
        with self.lock:
            if self.state != 'pending' or self.manifest is None: raise ScopeError('decision-consumed')
            decoded = decode_frame(canonical(frame) + b'\n', self.manifest)
            if decoded['event'] != 'decision': raise ScopeError('decision-invalid')
            self._current()
            self.state = 'committing'
        # Cancellation sets its Event without waiting for the disk or this lock.
        try:
            if self.evidence.mode == 'initialize':
                result = recover_key_only_v2(self.evidence, recovery_id=self.identity,
                    before_publish=self._current, backup_root=self.root.parent / 'recovery-backups')
            else:
                result = finalize_recovery_v2(self.evidence, recovery_id=self.identity, before_publish=self._current)
        except Exception as exc:
            with self.lock:
                self.state = 'blocked'
                self.result = {'state': 'blocked', 'ready': False,
                    'reason': exc.code if isinstance(exc, ScopeError) else 'recovery-evidence-invalid'}
            raise ScopeError(self.result['reason']) from None
        with self.lock:
            self.result, self.state = result, result['state']
            return copy.deepcopy(result)

    def status(self, recovery_id, *, include_ui=True):
        _recovery_id(recovery_id)
        with self.lock:
            if recovery_id != self.identity:
                # A persisted receipt can report status, but never open a form.
                return read_recovery_status(self.root, recovery_id)
            state = self.state
            if state == 'pending' and self.deadline is not None and self.clock() >= self.deadline:
                self.cancelled.set()
                self.state = state = 'expired'
            value = {'state': state, 'recovery_id': recovery_id, **public_summary(self.evidence)}
            if self.result: value.update(copy.deepcopy(self.result))
            if state in {'ready', 'committed-unverified'}:
                value.update(read_recovery_status(self.root, recovery_id))
            if self.deadline is not None:
                value['review_remaining_seconds'] = max(0, int(self.deadline - self.clock())) if state == 'pending' else 0
            prompt = self.prompt
        if include_ui and prompt is not None: value['ui'] = prompt.status()
        return value

    def _cancel_review(self, nonce):
        with self.lock:
            if self.manifest is None or self.manifest['nonce'] != nonce: return
            self.cancel()

    def cancel(self):
        self.cancelled.set()
        with self.lock:
            if self.state in {'preview', 'pending'}: self.state = 'cancelled'
            prompt = self.prompt
        if prompt is not None:
            try:
                threading.Thread(target=lambda: prompt.stop('operator-rejected'), daemon=True).start()
            except RuntimeError:
                pass  # Authority is already cancelled; never take the prompt lock synchronously.
