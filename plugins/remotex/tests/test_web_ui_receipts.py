from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import web_approval as approval
from test_web_approval import manifest, frame
from test_web_task_service import prepared, approve
from test_web_authorization import item


def receipt(event='shown', reason='shown', packet=None, **updates):
    packet = packet or manifest()
    return {'event': event, 'request_id': packet['request_id'], 'nonce': packet['nonce'],
            'request_digest': packet['request_digest'], 'reason': reason, **updates}


def encoded(value):
    return json.dumps(value).encode('utf-8') + b'\n'


def inert_prompt(packet=None, *, now=None, data=b'', callbacks=None):
    assert callable(getattr(approval.ApprovalPrompt, 'status', None)), 'Native UI lifecycle status is missing'
    now = now if now is not None else [100.0]
    callbacks = callbacks if callbacks is not None else []
    process = SimpleNamespace(stdout=io.BytesIO(), stderr=io.BytesIO(data), poll=lambda: None)
    job = SimpleNamespace(terminate=lambda: None, close=lambda: None)
    prompt = approval.ApprovalPrompt(process, job, packet or manifest(),
        lambda value: callbacks.append(('decision', value)),
        lambda: callbacks.append(('revoke', None)), lambda: callbacks.append(('cancel', None)),
        clock=lambda: now[0])
    return prompt, now, callbacks


@pytest.mark.parametrize('event,reason', [('shown', 'shown'), ('closed', 'window-closed'),
    ('closed', 'review-expired'), ('closed', 'operator-rejected'),
    ('closed', 'operator-revoked'), ('error', 'helper-startup-failed'), ('error', 'helper-ui-failed')])
def test_bound_ui_receipts_decode_separately_from_authority(event, reason):
    assert callable(getattr(approval, 'decode_ui_receipt', None)), 'Private UI receipt decoder is missing'
    value = receipt(event, reason)
    assert approval.decode_ui_receipt(encoded(value), manifest()) == value
    with pytest.raises(ValueError, match='decision-invalid'):
        approval.decode_frame(encoded(value), manifest())


@pytest.mark.parametrize('updates', [{'nonce': 'wrong'}, {'request_id': 'f'*32},
    {'request_digest': 'f'*64}, {'event': 'decision'}, {'reason': 'private-error-canary'},
    {'choices': []}, {'approved': True}, {'reason': 1}])
def test_unknown_forged_or_widened_ui_receipts_are_fixed_errors(updates):
    assert callable(getattr(approval, 'decode_ui_receipt', None)), 'Private UI receipt decoder is missing'
    with pytest.raises(ValueError, match='ui-receipt-invalid') as error:
        approval.decode_ui_receipt(encoded({**receipt(), **updates}), manifest())
    assert 'private-error-canary' not in str(error.value)


def test_ui_decoder_rejects_duplicate_truncated_oversized_and_authority_frames():
    assert callable(getattr(approval, 'decode_ui_receipt', None)), 'Private UI receipt decoder is missing'
    for raw in (b'{"event":"shown","event":"closed"}\n', b'X'*2049, b'['*1000+b'0'+b']'*1000+b'\n',
                encoded(receipt())[:-1], encoded(frame())):
        with pytest.raises(ValueError, match='ui-receipt-invalid'):
            approval.decode_ui_receipt(raw, manifest())


def test_shown_receipt_neither_authorizes_nor_restarts_review_time():
    prompt, now, calls = inert_prompt(data=encoded(receipt()))
    assert prompt.status()['state'] == 'starting'
    assert prompt.status()['review_remaining_seconds'] == 120
    now[0] += 55
    prompt._read_ui()
    status = prompt.status()
    assert status['state'] == 'shown' and status['shown'] is True
    assert status['review_remaining_seconds'] == 65
    assert status['exit_reason'] is None and status['helper_exit_code'] is None
    assert calls == [] and not prompt.decided and not prompt.stopped
    assert manifest()['nonce'] not in json.dumps(status)


@pytest.mark.parametrize('event,reason,state', [('closed', 'window-closed', 'closed'),
    ('error', 'helper-ui-failed', 'error')])
def test_ui_terminal_receipt_is_metadata_not_a_decision_or_revocation(event, reason, state):
    prompt, _, calls = inert_prompt(data=encoded(receipt(event, reason)))
    prompt._read_ui()
    status = prompt.status()
    assert status['state'] == state and status['exit_reason'] == reason
    assert status['review_remaining_seconds'] == 0
    assert calls == [] and not prompt.decided and not prompt.stopped


def test_review_expiry_stays_terminal_after_a_late_shown_receipt():
    prompt, now, calls = inert_prompt(data=encoded(receipt()))
    now[0] += 120
    prompt._expire_pending()
    prompt._read_ui()
    status = prompt.status()
    assert status['state'] == 'closed' and status['exit_reason'] == 'review-expired'
    assert status['review_remaining_seconds'] == 0 and prompt.stopped
    assert calls == [] and not prompt.decided


def test_eof_before_decision_reports_helper_exit_not_operator_rejection():
    prompt, _, calls = inert_prompt()
    prompt.process.poll = lambda: 23
    prompt._read()
    status = prompt.status()
    assert status['exit_reason'] == 'helper-exited'
    assert status['helper_exit_code'] == 23 and status['review_remaining_seconds'] == 0
    assert calls == [('cancel', None)]


def test_failed_replacement_decision_closes_only_its_helper_with_a_truthful_reason():
    prompt,_,_=inert_prompt()
    prompt.on_decision=lambda value:{'grant_id':None,'state':'replacement-blocked'}
    prompt._apply_decision(frame())
    assert prompt.stopped is True
    assert prompt.status()['exit_reason']=='replacement-blocked'


@pytest.mark.parametrize('was_shown', [False, True])
def test_observed_helper_exit_is_terminal_before_stdout_reader_catches_up(was_shown):
    prompt, _, calls = inert_prompt(data=encoded(receipt()) if was_shown else b'')
    if was_shown:
        prompt._read_ui()
    polls = []
    prompt.process.poll = lambda: polls.append(True) or 23
    status = prompt.status()
    assert status['state'] == 'closed' and status['exit_reason'] == 'helper-exited'
    assert status['helper_exit_code'] == 23 and status['review_remaining_seconds'] == 0
    assert status['shown'] is was_shown and len(polls) == 1
    assert calls == [] and not prompt.decided and not prompt.stopped
    assert prompt.stop_reason is None


def test_late_bound_error_refines_the_passive_helper_exit_status():
    prompt, _, calls = inert_prompt(data=encoded(receipt('error', 'helper-ui-failed')))
    prompt.process.poll = lambda: 23
    assert prompt.status()['exit_reason'] == 'helper-exited'
    prompt._read_ui()
    status = prompt.status()
    assert status['state'] == 'error' and status['exit_reason'] == 'helper-ui-failed'
    assert status['review_remaining_seconds'] == 0 and status['helper_exit_code'] == 23
    assert calls == [] and not prompt.decided and not prompt.stopped
    assert prompt.stop_reason is None


def test_diagnostic_noise_is_bounded_scrubbed_and_cannot_create_authority():
    prompt, _, calls = inert_prompt(data=(b'private-error-canary\n'*1000)+encoded(receipt()))
    prompt._read_ui()
    status = prompt.status()
    assert status['error_code'] == 'ui-receipt-invalid'
    assert status['shown'] is False
    assert 'private-error-canary' not in json.dumps(status)
    assert calls == [] and not prompt.decided and not prompt.stopped


def native_fixture_prompt():
    class Fixture:
        @staticmethod
        def start(packet, **callbacks):
            assert callable(getattr(approval.ApprovalPrompt, 'status', None)), 'Native UI lifecycle status is missing'
            process = SimpleNamespace(stdout=io.BytesIO(), stderr=io.BytesIO(encoded(receipt(packet=packet))), poll=lambda: None)
            prompt = approval.ApprovalPrompt(process,
                SimpleNamespace(terminate=lambda: None, close=lambda: None), packet,
                callbacks['on_decision'], callbacks['on_revoke'], callbacks['on_cancel'], clock=lambda: 100.0)
            prompt._read_ui()
            return prompt
    return Fixture


def test_request_and_status_expose_shown_without_grant_and_cap_broker_deadline():
    service, _, _ = prepared()
    service.prompt = native_fixture_prompt()
    result = service.request({'items': [{}], 'idempotency_key': 'ui-shown'})
    assert 'approval_ui' in result, 'The request hides the native display receipt'
    assert result['approval_ui']['state'] == 'shown'
    assert result['grant_id'] is None and result['allowed_items'] == []
    service.broker.clock = lambda: 210.0
    status = service.status(result['request_id'])
    assert status['approval_ui']['review_remaining_seconds'] == 10
    assert status['grant_id'] is None


def test_action_confirmation_status_exposes_its_own_ui_receipt():
    service, channel, prompts = prepared()
    write = item('remove', write=True, targets=['host-one'])
    write['effect']['class'] = 'action-time'
    original = channel.request
    channel.request = lambda operation, args, timeout=30: ({'ok': True, 'items': [write], 'contracts': {}}
        if operation == 'resolve-items' else original(operation, args, timeout=timeout))
    service.request({'items': [{}], 'idempotency_key': 'action-ui'})
    grant = approve(service, prompts)
    service.prompt = native_fixture_prompt()
    args = {'grant_id': grant['grant_id'], 'item_id': 'remove', 'idempotency_key': 'remove-once',
            'observation_id': 'd'*32, 'component_ref': 'e'*32}
    attempt = service.execute(args)
    assert attempt['state'] == 'awaiting-action-confirmation'
    assert 'approval_ui' in attempt, 'Action confirmation hides its native UI receipt'
    assert attempt['approval_ui']['state'] == 'shown'
    status = service.execution_status({'attempt_id': attempt['attempt_id']})
    assert status['approval_ui']['state'] == 'shown'
    assert status['state'] == 'awaiting-action-confirmation'
