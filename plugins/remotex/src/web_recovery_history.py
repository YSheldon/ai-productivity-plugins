"""Conservative legacy ledger classification; reconciliation never grants authority."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from web_authorization import CAPABILITIES, MAX_GRANT_SECONDS, MAX_NATIVE_REVIEW_SECONDS, ScopeError, digest


_PASSIVE = frozenset({'replacement-blocked', 'replacement-committed', 'action-confirmed',
    'output-ready', 'site-login-result', 'site-action-confirmed', 'controls-ready',
    'credentials-armed', 'authentication-forwarded', 'authentication-verified',
    'initialization-forwarded', 'prerequisite-response', 'initialization-permit-issued',
    'initialization-reference-approved'})
_ACTIONS = frozenset({'read', 'read-table', 'click', 'fill', 'select', 'check'})
_WRITES = frozenset({'remotex_web_execute', 'remotex_web_site_execute'})


def _hex(value, length):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{' + str(length) + '}', value) is None:
        raise ScopeError('recovery-scope-unknown')
    return value


def _timestamp(value, now):
    try:
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError()
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0) or parsed > now:
            raise ValueError()
        return parsed
    except (ValueError, TypeError, OverflowError):
        raise ScopeError('recovery-evidence-invalid') from None


def _ttl(value):
    if type(value) is not int or not 1 <= value <= MAX_GRANT_SECONDS:
        raise ScopeError('recovery-evidence-invalid')
    return value


def _generation(value):
    if type(value) is not int or value < 0:
        raise ScopeError('recovery-evidence-invalid')
    return value


class _History:
    def __init__(self, session, binding):
        self.session, self.binding = session, binding
        self.first = self.last = None
        self.requests, self.grants, self.attempts = {}, {}, {}
        self.site_grant = None
        self.site_closed = False
        self.site_login_verified = False
        self.document = None
        self.events = {}

    def _request(self, identity):
        value = self.requests.get(_hex(identity, 32))
        if value is None:
            raise ScopeError('recovery-scope-unknown')
        return value

    def _grant(self, identity):
        value = self.grants.get(_hex(identity, 32))
        if value is None:
            raise ScopeError('recovery-scope-unknown')
        return value

    def event(self, value, at):
        name = value['event']
        if self.last is not None and at < self.last:
            raise ScopeError('recovery-evidence-invalid')
        self.first, self.last = self.first or at, at
        self.events[name] = self.events.get(name, 0) + 1
        if name in {'site-requested', 'request-created'}:
            identity = _hex(value.get('request_id'), 32)
            if identity in self.requests or name == 'site-requested' and self.requests:
                raise ScopeError('recovery-evidence-invalid')
            self.requests[identity] = {'id': identity, 'kind': name, 'created': at.isoformat(),
                'granted': False, 'closed': False, 'decision': None}
        elif name == 'decision-recorded':
            request = self._request(value.get('request_id'))
            if request['kind'] != 'request-created' or request['decision'] is not None or request['closed']:
                raise ScopeError('recovery-evidence-invalid')
            request['decision'] = {'ttl': _ttl(value.get('ttl_seconds')),
                'scope': value.get('approved_scope_digest'), 'at': at.isoformat()}
        elif name in {'site-granted', 'grant-issued'}:
            request = self._request(value.get('request_id'))
            identity = _hex(value.get('grant_id'), 32)
            if identity in self.grants or request['granted'] or request['closed']:
                raise ScopeError('recovery-evidence-invalid')
            if name == 'site-granted':
                if request['kind'] != 'site-requested' or self.site_grant is not None:
                    raise ScopeError('recovery-evidence-invalid')
                ttl = _ttl(value.get('ttl_seconds'))
                self.site_grant = identity
            else:
                decision = request['decision']
                if request['kind'] != 'request-created' or decision is None:
                    raise ScopeError('recovery-scope-unknown')
                if _hex(value.get('approved_scope_digest'), 64) != _hex(decision['scope'], 64):
                    raise ScopeError('recovery-evidence-invalid')
                ttl = decision['ttl']
            request['granted'] = True
            self.grants[identity] = {'id': identity, 'request': request['id'],
                'created': at.isoformat(), 'ttl': ttl, 'closure': None}
        elif name in {'request-revoked', 'request-cancelled'}:
            request = self._request(value.get('request_id'))
            if request['closed'] or request['kind'] != 'request-created':
                raise ScopeError('recovery-evidence-invalid')
            request['closed'] = True
            for grant in self.grants.values():
                if grant['request'] == request['id']:
                    grant['closure'] = 'revoked'
        elif name == 'site-revoked':
            if self.site_closed or not any(r['kind'] == 'site-requested' for r in self.requests.values()):
                raise ScopeError('recovery-evidence-invalid')
            self.site_closed = True
            for request in self.requests.values():
                if request['kind'] == 'site-requested':
                    request['closed'] = True
            if self.site_grant:
                self.grants[self.site_grant]['closure'] = 'revoked'
        elif name == 'grant-revoked':
            grant = self._grant(value.get('grant_id'))
            # A partial item revocation cannot close the whole grant.
            if value.get('item_ids') == []:
                grant['closure'] = 'revoked'
        elif name in {'site-action-requested', 'execution-reserved'}:
            identity = _hex(value.get('attempt_id'), 32)
            if identity in self.attempts:
                raise ScopeError('recovery-unresolved-write')
            if name == 'site-action-requested':
                grant = self._grant(self.site_grant)
                summary = value.get('summary')
                if not isinstance(summary, dict) or summary.get('action') not in _ACTIONS or type(summary.get('sensitive')) is not bool:
                    raise ScopeError('recovery-evidence-invalid')
                action = summary['action']
                scope = _hex(value.get('scope_digest'), 64)
            else:
                grant = self._grant(value.get('grant_id'))
                action, scope = value.get('capability'), None
                if action not in CAPABILITIES:
                    raise ScopeError('recovery-evidence-invalid')
            if grant['closure']:
                raise ScopeError('recovery-unresolved-write')
            self.attempts[identity] = {'attemptId': identity, 'kind': name, 'action': action,
                'scopeDigest': scope, 'grantId': grant['id'], 'dispatched': name == 'execution-reserved', 'state': None}
        elif name == 'site-action-dispatch':
            attempt = self.attempts.get(_hex(value.get('attempt_id'), 32))
            if (not attempt or attempt['kind'] != 'site-action-requested' or attempt['dispatched'] or
                    _hex(value.get('scope_digest'), 64) != attempt['scopeDigest'] or
                    self.grants[attempt['grantId']]['closure']):
                raise ScopeError('recovery-unresolved-write')
            attempt['dispatched'] = True
        elif name in {'site-action-result', 'execution-finished'}:
            attempt = self.attempts.get(_hex(value.get('attempt_id'), 32))
            expected = 'site-action-requested' if name == 'site-action-result' else 'execution-reserved'
            allowed = {'completed', 'failed-before-dispatch'} if name == 'site-action-result' else {'verified', 'failed-before-dispatch'}
            if (not attempt or attempt['kind'] != expected or not attempt['dispatched'] or
                    attempt['state'] is not None or value.get('state') not in allowed or
                    self.grants[attempt['grantId']]['closure']):
                raise ScopeError('recovery-unresolved-write')
            attempt['state'] = value['state']
        elif name in {'authentication-forwarded', 'initialization-forwarded',
                'authentication-verified', 'prerequisite-response'}:
            # Legacy summaries omit unique request/document IDs, so terminal
            # counters cannot prove closure of a particular forwarded request.
            raise ScopeError('recovery-unresolved-write')
        elif name == 'document-opening':
            if self.document is not None:
                raise ScopeError('recovery-busy')
            self.document = {'stage': 'opening', 'generation': _generation(value.get('generation')), 'controls': False}
        elif name == 'document-committed':
            if (not self.document or self.document['stage'] != 'opening' or
                    _generation(value.get('generation')) != self.document['generation']):
                raise ScopeError('recovery-busy')
            self.document['stage'] = 'committed'
        elif name == 'controls-ready':
            generation = _generation(value.get('generation'))
            if (not self.document or self.document['stage'] != 'committed' or self.document['controls'] or
                    generation not in {self.document['generation'], self.document['generation'] + 1}):
                raise ScopeError('recovery-busy')
            self.document.update(generation=generation, controls=True)
        elif name == 'credentials-armed':
            if (not self.document or not self.document['controls'] or
                    _generation(value.get('generation')) != self.document['generation']):
                raise ScopeError('recovery-busy')
        elif name == 'resume-ended':
            if (not self.document or self.document['stage'] != 'committed' or
                    _generation(value.get('generation')) != self.document['generation']):
                raise ScopeError('recovery-busy')
            self.document = None
        elif name == 'site-login-result':
            grant = self._grant(self.site_grant)
            summary = value.get('summary')
            if (grant['closure'] or self.site_login_verified or not isinstance(summary, dict) or
                    summary.get('authentication_verified') is not True):
                raise ScopeError('recovery-unresolved-write')
            self.site_login_verified = True
        elif name in {'output-ready', 'action-confirmed', 'site-action-confirmed'}:
            attempt = self.attempts.get(_hex(value.get('attempt_id'), 32))
            if not attempt or name == 'output-ready' and attempt['state'] != 'verified':
                raise ScopeError('recovery-unresolved-write')
        elif name in {'replacement-committed', 'replacement-blocked', 'initialization-reference-approved'}:
            self._request(value.get('request_id'))
        elif name not in _PASSIVE:
            raise ScopeError('recovery-scope-unknown')
        elif not self.requests or not self.grants:
            raise ScopeError('recovery-scope-unknown')

    def finish(self, now):
        if self.site_grant is not None and not self.site_login_verified:
            raise ScopeError('recovery-unresolved-write')
        for attempt in self.attempts.values():
            if attempt['dispatched'] and attempt['state'] is None:
                raise ScopeError('recovery-unresolved-write')
        if self.document is not None:
            raise ScopeError('recovery-busy')
        for grant in self.grants.values():
            if grant['closure'] is None:
                expiry = datetime.fromisoformat(grant['created']) + timedelta(seconds=grant['ttl'])
                if now < expiry:
                    raise ScopeError('recovery-busy')
                grant['closure'] = 'expired'
        for request in self.requests.values():
            if not request['granted'] and not request['closed']:
                if now < datetime.fromisoformat(request['created']) + timedelta(seconds=MAX_NATIVE_REVIEW_SECONDS):
                    raise ScopeError('recovery-busy')
        return {'auditSession': self.session, 'bindingDigest': self.binding,
            'historicalOrigin': 'unknown', 'historicalAccount': 'unknown',
            'firstObserved': self.first.isoformat(), 'lastObserved': self.last.isoformat(),
            'requests': list(self.requests.values()), 'grants': list(self.grants.values()),
            'attempts': list(self.attempts.values()), 'events': self.events}


def observe(records, scope, *, now=None):
    """Return a review inventory, not proof of historical scope/business success."""
    now = now or datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ScopeError('recovery-evidence-invalid')
    groups, operations, profiles = {}, {}, set()
    for row in records:
        if not isinstance(row, dict):
            raise ScopeError('recovery-evidence-invalid')
        name = row.get('event')
        if name != 'web-authorization':
            tool = row.get('tool', '')
            if isinstance(tool, str) and tool.startswith('remotex_web_'):
                request = row.get('request', {})
                if not isinstance(request, dict):
                    raise ScopeError('recovery-evidence-invalid')
                if request.get('profileSha256') is not None:
                    profiles.add(_hex(request['profileSha256'], 64))
            if tool not in _WRITES:
                continue
            identity = (row.get('sessionId'), row.get('operationId'), tool)
            if any(not isinstance(part, str) or not part or len(part) > 256 for part in identity):
                raise ScopeError('recovery-evidence-invalid')
            if name == 'operation-start':
                if identity in operations:
                    raise ScopeError('recovery-evidence-invalid')
                at = _timestamp(row.get('timestamp'), now)
                operations[identity] = {'kind': 'mcp-write-operation', 'auditSession': identity[0],
                    'operationId': identity[1], 'tool': tool, 'created': at.isoformat(), 'state': None,
                    'profileHash': request.get('profileSha256'), 'historicalOrigin': 'unknown', 'historicalAccount': 'unknown'}
            elif name == 'operation-finish':
                result = row.get('result', {})
                if (identity not in operations or operations[identity]['state'] is not None or not isinstance(result, dict) or
                        result.get('state') not in {'verified', 'failed-before-dispatch'}):
                    raise ScopeError('recovery-unresolved-write')
                if _timestamp(row.get('timestamp'), now) < datetime.fromisoformat(operations[identity]['created']):
                    raise ScopeError('recovery-evidence-invalid')
                operations[identity]['state'] = result['state']
                operations[identity]['finished'] = _timestamp(row.get('timestamp'), now).isoformat()
            continue
        value = row.get('authorization')
        if not isinstance(value, dict) or not isinstance(value.get('event'), str):
            raise ScopeError('recovery-evidence-invalid')
        if value['event'] in {'legacy-recovery-owner-reviewed', 'recovery-protocol-upgraded'}:
            continue
        session = row.get('sessionId')
        if not isinstance(session, str) or not session or len(session) > 256:
            raise ScopeError('recovery-evidence-invalid')
        binding = _hex(value.get('binding_digest'), 64)
        identity = (session, binding)
        if identity not in groups:
            groups[identity] = _History(*identity)
        groups[identity].event(value, _timestamp(row.get('timestamp'), now))
    if any(value['state'] is None for value in operations.values()):
        raise ScopeError('recovery-unresolved-write')
    group_inventory = [groups[key].finish(now) for key in sorted(groups)]
    inventory = group_inventory + [operations[key] for key in sorted(operations)]
    if profiles:
        inventory.append({'kind': 'observed-profile-hashes', 'values': sorted(profiles),
            'historicalOrigin': 'unknown', 'historicalAccount': 'unknown'})
    attempts = [a for group in group_inventory for a in group['attempts'] if a['state'] is not None]
    observed = [datetime.fromisoformat(group[key]) for group in group_inventory for key in ('firstObserved', 'lastObserved')]
    observed.extend(datetime.fromisoformat(operation[key]) for operation in operations.values() for key in ('created', 'finished'))
    summary = {'scopeCount': len(scope), 'historicalBindings': len(group_inventory),
        'historyFirstObserved': min(observed).isoformat() if observed else None,
        'historyLastObserved': max(observed).isoformat() if observed else None,
        'unknownScopeBindings': len(group_inventory), 'historicalProfileHashes': len(profiles),
        'mcpWriteOperations': len(operations),
        'completedAttempts': len(attempts), 'verifiedAttempts': sum(a['state'] == 'verified' for a in attempts),
        'failedBeforeDispatchAttempts': sum(a['state'] == 'failed-before-dispatch' for a in attempts),
        'technicalReadAttempts': sum(a['state'] == 'completed' and a['action'] in {'read', 'read-table'} for a in attempts),
        'technicalEffectAttempts': sum(a['state'] == 'completed' and a['action'] not in {'read', 'read-table'} for a in attempts),
        'ungrantedRequests': sum(not r['granted'] for group in group_inventory for r in group['requests']),
        'unresolvedAttempts': 0, 'inventoryDigest': digest(inventory)}
    return summary, inventory
