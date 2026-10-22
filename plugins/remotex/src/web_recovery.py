"""Owner-reviewed legacy recovery. Persistent evidence never grants authority."""
from __future__ import annotations

import copy
import hashlib
import io
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import audit_log
import secure_paths
from web_authorization import ScopeError, canonical
from web_authorization_store import Journal


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
        Journal.existing(root)
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
        return not row.get('authorization', {}).get('event', '').startswith('legacy-recovery-')
    tool = row.get('tool', '')
    return isinstance(tool, str) and tool.startswith('remotex_web_') and tool not in {
        'remotex_web_authorization_recovery', 'remotex_web_authorization_upgrade'}


def _observations(records, scope):
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
        if value.get('binding_digest'): bindings.add(value['binding_digest'])
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
    return {'completedAttempts': completed, 'historicalBindings': len(bindings), 'scopeCount': len(scope)}


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
        summary = _observations(records, scopes)
        summary.update(classification='key-only-ambiguous', historyBasis='owner-review-required',
            missingEnvelope=True, scopes=scopes,
            uncertainty='Missing recovery data cannot prove an empty history. Historical bindings may include synthetic tests; the owner must reconcile all prior effects for this shared store.')
        return LegacyEvidence('initialize', root, key, identity, len(raw), hashlib.sha256(raw).hexdigest(),
            hashlib.sha256(canonical(scopes)).hexdigest(), summary, _identity(root)[:2])
    except OSError as exc:
        raise ScopeError('recovery-evidence-invalid') from exc


def recheck_legacy_evidence(evidence, *, audit_path, scope, check_idle):
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
    return copy.deepcopy(evidence.summary)
