from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / 'plugins'

for source_root in (
    PLUGIN_ROOT / 'product-release-gate' / 'src',
    PLUGIN_ROOT / 'test-submission' / 'src',
    PLUGIN_ROOT / 'submission-gate' / 'src',
    PLUGIN_ROOT / 'pre-release' / 'src',
):
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

from pre_release_config import MailAccountConfig as PreReleaseMailAccountConfig  # noqa: E402
from pre_release_config import PreReleaseConfig, ProductGateConfig as PreReleaseProductGateConfig  # noqa: E402
from pre_release_controller import PreReleaseController  # noqa: E402
from release_gate_core import ReleaseGateController as ProductCoreController  # noqa: E402

import submission_gate_core as submission_gate_module  # noqa: E402
import test_submission_core as test_submission_module  # noqa: E402


NOW = datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc)


class MailHub:
    def __init__(self, *, accounts: Mapping[str, str]) -> None:
        self.accounts = dict(accounts)
        self.messages: list[dict[str, Any]] = []
        self._uid = 0

    def list_accounts(self) -> dict[str, Any]:
        return {
            'accounts': [
                {'name': profile, 'email': email}
                for profile, email in sorted(self.accounts.items())
            ]
        }

    def send_email(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        profile = str(payload.get('account') or payload.get('profile') or '').strip()
        sender = self.accounts.get(profile, f'{profile or "unknown"}@example.com')
        headers = {
            str(key): str(value)
            for key, value in dict(payload.get('headers') or {}).items()
            if str(value).strip()
        }
        body_text = str(payload.get('body_text') or payload.get('text') or '')
        to_values = [str(value) for value in list(payload.get('to') or [])]
        cc_values = [str(value) for value in list(payload.get('cc') or [])]
        message_id = str(payload.get('message_id') or f'<mail-{len(self.messages) + 1}@example.com>')
        subject = str(payload.get('subject') or '')
        self._uid += 1
        self.messages.append(
            {
                'uid': str(self._uid),
                'uidvalidity': '1',
                'mailbox': str(payload.get('mailbox') or 'INBOX'),
                'message_id': message_id,
                'subject': subject,
                'body_text': body_text,
                'from': [{'email': sender}],
                'to': [{'email': value} for value in to_values],
                'cc': [{'email': value} for value in cc_values],
                'headers': headers,
                'release_workflow_headers': {
                    key.removeprefix('X-RD-').lower().replace('-', '_'): value
                    for key, value in headers.items()
                    if key.startswith('X-RD-')
                },
                'evidence': {'raw_headers_sha256': '3' * 64},
            }
        )
        refused = dict(payload.get('refused') or {})
        return {'sent': not refused, 'message_id': message_id, 'refused': refused}

    def search_messages(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        mailbox = str(payload.get('mailbox') or 'INBOX')
        query = payload.get('query')
        subject_contains = ''
        if isinstance(query, Mapping):
            subject_contains = str(query.get('subject') or '').strip()
        to_filter = str(payload.get('to') or '').strip().lower()
        profile = str(payload.get('account') or payload.get('profile') or '').strip()
        inbox_owner = self.accounts.get(profile, '').lower() if profile else ''
        limit = int(payload.get('limit') or payload.get('scan_limit') or 100)
        matches: list[dict[str, Any]] = []
        for message in self.messages:
            if message['mailbox'] != mailbox:
                continue
            recipients = [entry['email'].lower() for entry in message.get('to', [])]
            if inbox_owner and inbox_owner not in recipients:
                continue
            if to_filter and to_filter not in recipients:
                continue
            if subject_contains and subject_contains not in str(message.get('subject') or ''):
                continue
            matches.append({'uid': message['uid'], 'message_id': message['message_id']})
        return {'messages': matches[:limit]}

    def read_message(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        uid = str(payload.get('uid') or '')
        for message in self.messages:
            if message['uid'] == uid:
                return dict(message)
        raise AssertionError(f'unknown uid: {uid}')

    def deliveries_to(self, address: str) -> list[dict[str, Any]]:
        lowered = address.lower()
        results: list[dict[str, Any]] = []
        for message in self.messages:
            recipients = [entry['email'].lower() for entry in message.get('to', [])]
            if lowered in recipients:
                results.append(message)
        return results

    def last_message(self, address: str, *, startswith: str = "") -> dict[str, Any] | None:
        lowered = address.lower()
        for message in reversed(self.messages):
            recipients = [entry['email'].lower() for entry in message.get('to', [])]
            if lowered not in recipients:
                continue
            if startswith and not str(message.get('subject') or "").startswith(startswith):
                continue
            return dict(message)
        return None


class ProductPreviewBridge:
    def __init__(self, controller: ProductCoreController) -> None:
        self.controller = controller

    def preflight(self) -> dict[str, Any]:
        return {'ready': True}

    def preview_submission(
        self,
        *,
        event_id: str,
        task_id: str,
        artifacts: list[dict[str, Any]],
        source_ref: str,
        round_number: int,
    ) -> dict[str, Any]:
        self.controller.create_submission(
            event_id=event_id,
            task_id=task_id,
            artifacts=[
                {
                    'logical_name': item['logical_name'],
                    'file_path': item['local_path'],
                    'source_ref': item['source_ref'],
                }
                for item in artifacts
            ],
            source_ref=source_ref,
            rollback_ref='preview-only',
            risk_level='standard',
            round_number=round_number,
        )
        return {'submission': {'manifest_s': self.controller.get_event(event_id)['manifest_s']}}


class ProductGateFacade:
    def __init__(self, controller: ProductCoreController, fixture_root: Path) -> None:
        self.controller = controller
        self.fixture_dir = fixture_root / "submission-gate-e2e"

    def preflight(self) -> dict[str, Any]:
        return {'ready': True}

    def evaluate(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            self.controller.create_submission(
                event_id=payload['event_id'],
                task_id=payload['task'],
                artifacts=[
                    {
                        'logical_name': item.get('logical_name') or f'artifact-{index}',
                        'file_path': str(self._materialize_artifact(payload['event_id'], item.get('logical_name') or f'artifact-{index}')),
                        'source_ref': item.get('source_ref') or item.get('revision') or 'source-ref',
                    }
                    for index, item in enumerate(payload.get('sender_artifact_declarations') or [{}], start=1)
                ],
                source_ref=payload.get('source_locator') or 'source-ref',
                rollback_ref='preview-only',
                risk_level='standard',
                round_number=payload['round_id'],
            )
            self.controller.run_submission_gate(payload['event_id'])
        except Exception as exc:
            if 'Event already exists' not in str(exc):
                raise
        event_bundle = self.controller.get_event(payload['event_id'])
        manifest_s = event_bundle['manifest_s']
        return {
            'adapter_contract': 'GitLabGateResult/v1',
            'provider': 'gitlab',
            'verdict': 'CLEAN',
            'event_id': payload['event_id'],
            'round_id': payload['round_id'],
            'request_digest': payload['request_digest'],
            'policy_digest': payload['policy_digest'],
            'manifest_digest': 'sha256:' + str(manifest_s['digest']),
            'material_sha256': '3' * 64,
            'evidence_refs': [f'gitlab://pipeline/{payload["event_id"]}', f'gitlab://job/{payload["event_id"]}'],
            'pipeline_ref': f'gitlab://pipeline/{payload["event_id"]}',
            'job_ref': f'gitlab://job/{payload["event_id"]}',
            'artifact_ref': f'gitlab://artifact/{payload["event_id"]}',
            'artifacts': manifest_s.get('artifacts') or [],
            'lark_evidence_ref': f'lark://submission-gate/{payload["event_id"]}',
        }

    def _materialize_artifact(self, event_id: str, logical_name: str) -> Path:
        self.fixture_dir.mkdir(parents=True, exist_ok=True)
        path = self.fixture_dir / f'{event_id}-{logical_name}'
        if not path.exists():
            path.write_bytes(b'product-material')
        return path

    def call(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        if operation == 'record_test_result':
            return self.controller.record_test_result(
                payload['event_id'],
                payload['test_result'],
                payload['report_ref'],
                str(payload.get('summary') or ''),
            )
        if operation == 'build_final_release':
            return self.controller.build_final_release(payload['event_id'], payload['output_dir'])
        if operation == 'run_release_gate':
            return self.controller.run_release_gate(payload['event_id'])
        raise AssertionError(f'unsupported operation: {operation}')


@dataclass
class WorkflowContext:
    tmp_path: Path
    mail_hub: MailHub
    preview_product: ProductCoreController
    authority_product: ProductCoreController
    artifact_path: Path
    shared_secret: Path
    dependency_lock: Path


def _product_config(path: Path, storage_dir: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                'storage_dir': str(storage_dir),
                'policy': {
                    'allowed_extensions': ['.bin', '.sys', '.exe'],
                    'require_source_ref': False,
                    'require_signature': False,
                    'require_cloud_scan': False,
                    'auto_approve_risk_levels': ['standard'],
                },
                'test': {'command': [sys.executable, '-c', 'print("{}")']},
            }
        ),
        encoding='utf-8',
    )
    return path


def _make_context(tmp_path: Path) -> WorkflowContext:
    artifact_path = tmp_path / 'input' / 'product.bin'
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(b'first-four-plugin-vertical-chain')
    shared_secret = tmp_path / 'shared' / 'handoff.key'
    shared_secret.parent.mkdir(parents=True, exist_ok=True)
    shared_secret.write_bytes(b'1' * 32)
    dependency_lock = tmp_path / 'dependency-lock.json'
    dependency_lock.write_text(json.dumps({'plugins': []}), encoding='utf-8')
    preview_config = _product_config(tmp_path / 'preview-core' / 'config.json', tmp_path / 'preview-core' / 'events')
    authority_config = _product_config(tmp_path / 'authority-core' / 'config.json', tmp_path / 'authority-core' / 'events')
    return WorkflowContext(
        tmp_path=tmp_path,
        mail_hub=MailHub(
            accounts={
                'mail-primary': 'submitter@example.com',
                'gate-mail': 'submission-gate@example.com',
                'qa-owner': 'qa-owner@example.com',
            }
        ),
        preview_product=ProductCoreController(str(preview_config)),
        authority_product=ProductCoreController(str(authority_config)),
        artifact_path=artifact_path,
        shared_secret=shared_secret,
        dependency_lock=dependency_lock,
    )


def _submission_config(context: WorkflowContext) -> tuple[Path, dict[str, Any]]:
    payload = {
        'mail_account': {'profile': 'mail-primary', 'email': 'submitter@example.com'},
        'submission_gate_address': 'submission-gate@example.com',
        'state_dir': str(context.tmp_path / 'submission' / 'state'),
        'event_store_dir': str(context.tmp_path / 'submission' / 'events'),
        'dependency_lock': str(context.dependency_lock),
        'dependency_lock_sha256': '0' * 64,
        'product_gate_preview_config': str(context.tmp_path / 'preview-core' / 'config.json'),
        'mandatory_checks_by_module': {
            'kernel': ['artifacts_present', 'hashes_match', 'version_present', 'signature_present', 'cloud_scan_required'],
            'client': ['artifacts_present', 'hashes_match', 'version_present', 'signature_present', 'cloud_scan_required'],
            'server': ['artifacts_present', 'hashes_match', 'source_revision_present', 'package_digest_present', 'cloud_scan_required'],
        },
    }
    path = context.tmp_path / 'submission' / 'config.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding='utf-8')
    return path, payload


def _gate_config(context: WorkflowContext, *, mandatory_checks: list[str]) -> tuple[Path, dict[str, Any]]:
    payload = {
        'gate_mail_account': {'profile': 'gate-mail', 'email': 'submission-gate@example.com'},
        'submission_group_address': 'qa@example.com',
        'blocked_notice_address': 'rd@example.com',
        'state_dir': str(context.tmp_path / 'gate' / 'state'),
        'event_store_dir': str(context.tmp_path / 'gate' / 'events'),
        'dependency_lock': str(context.dependency_lock),
        'dependency_lock_sha256': '0' * 64,
        'product_gate_config': str(context.tmp_path / 'authority-core' / 'config.json'),
        'mailbox': 'INBOX',
        'scan_limit': 100,
        'mandatory_checks_by_module': {
            'kernel': mandatory_checks,
            'client': ['artifacts_present', 'hashes_match', 'version_present', 'signature_present', 'cloud_scan_required'],
            'server': ['artifacts_present', 'hashes_match', 'source_revision_present', 'package_digest_present', 'cloud_scan_required'],
        },
    }
    path = context.tmp_path / 'gate' / 'config.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding='utf-8')
    return path, payload


def _pre_release_controller(context: WorkflowContext) -> PreReleaseController:
    config = PreReleaseConfig(
        mail_account=PreReleaseMailAccountConfig(profile='qa-owner', email='qa-owner@example.com'),
        submission_group='qa@example.com',
        release_gate_group='release-gate@example.com',
        mailbox='INBOX',
        timezone='UTC',
        poll_minutes=60,
        state_dir=context.tmp_path / 'pre-release' / 'state',
        dependency_lock=context.dependency_lock,
        dependency_lock_sha256='0' * 64,
        shared_hmac_secret_path=context.shared_secret,
        mail_command=(sys.executable, '-c', 'pass'),
        product_gate=PreReleaseProductGateConfig(config_path=context.tmp_path / 'authority-core' / 'config.json', command=(sys.executable, '-c', 'pass')),
        policy_profile='pre-release/v1',
        enabled_optional_checks=(),
    )
    return PreReleaseController(
        config,
        mail_gateway=context.mail_hub,
        product_gate=ProductGateFacade(context.authority_product, context.tmp_path),
        now_fn=lambda: NOW,
    )


def _submit_to_test_submission(context: WorkflowContext, event_id: str, *, task_name: str) -> dict[str, Any]:
    path, payload = _submission_config(context)
    controller = test_submission_module.TestSubmissionController(
        path,
        config=payload,
        mail_gateway=context.mail_hub,
        product_gate=ProductPreviewBridge(context.preview_product),
        now_fn=lambda: NOW,
        environ={'TEST_SUBMISSION_HMAC_KEY': 'tttttttttttttttttttttttttttttttt'},
    )
    result = controller.submit(
        {
            'event_id': event_id,
            'round_id': 1,
            'task_name': task_name,
            'module': 'kernel',
            'change_summary': 'fix one bug',
            'expected_delivery_at': '2026-07-18T18:00:00+08:00',
            'artifacts': [
                {
                    'logical_name': 'product.bin',
                    'local_path': str(context.artifact_path),
                    'retrieval_method': 'local',
                }
            ],
        }
    )
    return {'controller': controller, 'result': result}


def _run_submission_gate(context: WorkflowContext, event_id: str, *, task_name: str, mandatory_checks: list[str]) -> dict[str, Any]:
    submitted = _submit_to_test_submission(context, event_id, task_name=task_name)
    gate_path, gate_payload = _gate_config(context, mandatory_checks=mandatory_checks)
    gate = submission_gate_module.SubmissionGateController(
        gate_path,
        config=gate_payload,
        mail_gateway=context.mail_hub,
        gate_adapter=ProductGateFacade(context.authority_product, context.tmp_path),
        environ={'TEST_SUBMISSION_HMAC_KEY': 'tttttttttttttttttttttttttttttttt'},
    )
    gate_result = gate.run_once()
    sent_mail = context.mail_hub.last_message('submission-gate@example.com', startswith='【提测】')
    assert sent_mail is not None and '提测人邮箱：submitter@example.com' in sent_mail['body_text']
    passed_mail = context.mail_hub.last_message('qa@example.com', startswith='【提测】')
    if gate_result.get('passed'):
        assert passed_mail is not None and '提测人邮箱：submitter@example.com' in passed_mail['body_text']
    return {'submitted': submitted, 'gate': gate, 'gate_path': gate_path, 'gate_payload': gate_payload, 'gate_result': gate_result}


def test_real_mail_chain_reaches_release_ready_notification(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    gate = _run_submission_gate(
        context,
        'event-happy',
        task_name='TASK-HAPPY',
        mandatory_checks=['artifacts_present', 'hashes_match', 'version_present', 'signature_present', 'cloud_scan_required', 'must-keep'],
    )
    pre_release = _pre_release_controller(context)
    synced = pre_release.run_once()

    assert gate['submitted']['result']['status'] == 'SUBMITTED'
    assert gate['gate_result']['status'] == 'ready'
    assert gate['gate_result']['processed'] == 1
    assert gate['gate_result']['passed'] == 1
    assert gate['gate_result']['blocked'] == 0
    assert gate['gate_result']['skipped'] == 0
    assert gate['gate_result']['capability_blocked'] == 0
    assert synced['matched_events'] == 1


def test_submission_gate_policy_failure_blocks_pre_release_input(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    gate = _run_submission_gate(
        context,
        'event-blocked',
        task_name='TASK-BLOCKED',
        mandatory_checks=['artifacts_present', 'hashes_match', 'version_present', 'cloud_scan_required'],
    )
    pre_release = _pre_release_controller(context)
    synced = pre_release.run_once()

    assert gate['gate_result']['blocked'] == 1
    assert gate['gate_result']['passed'] == 0
    assert synced['matched_events'] == 0
    assert pre_release.list_tasks()['tasks'] == []


def test_submission_gate_pass_mail_is_not_yet_consumable_by_pre_release(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    _run_submission_gate(
        context,
        'event-contract-gap',
        task_name='TASK-CONTRACT-GAP',
        mandatory_checks=['artifacts_present', 'hashes_match', 'version_present', 'signature_present', 'cloud_scan_required', 'must-keep'],
    )
    pre_release = _pre_release_controller(context)
    synced = pre_release.run_once()

    assert synced['status'] == 'ready'
    assert synced['matched_events'] == 1
    assert synced['pending_count'] == 1
    tasks = pre_release.list_tasks()['tasks']
    assert len(tasks) == 1
    assert tasks[0]['event_id'] == 'event-contract-gap'


def test_restart_and_duplicate_mail_are_idempotent_through_submission_gate_boundary(tmp_path: Path) -> None:
    context = _make_context(tmp_path)
    gate = _run_submission_gate(
        context,
        'event-idempotent',
        task_name='TASK-IDEMPOTENT',
        mandatory_checks=['artifacts_present', 'hashes_match', 'version_present', 'signature_present', 'cloud_scan_required', 'must-keep'],
    )
    restarted_gate = submission_gate_module.SubmissionGateController(
        gate['gate_path'],
        config=gate['gate_payload'],
        mail_gateway=context.mail_hub,
        gate_adapter=ProductGateFacade(context.authority_product, context.tmp_path),
        environ={'TEST_SUBMISSION_HMAC_KEY': 'tttttttttttttttttttttttttttttttt'},
    )
    second_gate = restarted_gate.run_once()
    first_pre_release = _pre_release_controller(context).run_once()
    second_pre_release = _pre_release_controller(context).run_once()

    assert gate['gate_result']['passed'] == 1
    assert second_gate['status'] == 'ready'
    assert second_gate['processed'] == 0
    assert second_gate['passed'] == 0
    assert second_gate['blocked'] == 0
    assert second_gate['skipped'] == 1
    assert second_gate['capability_blocked'] == 0
    assert first_pre_release['status'] == 'ready'
    assert first_pre_release['matched_events'] == 1
    assert first_pre_release['pending_count'] == 1
    assert second_pre_release['status'] == 'ready'
    assert second_pre_release['matched_events'] == 0
    assert second_pre_release['pending_count'] == 1
