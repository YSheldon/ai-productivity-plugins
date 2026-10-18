from __future__ import annotations

import json
import sys
from datetime import datetime,timezone
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import queue_leases


def test_web_acquisition_identity_survives_renewal_but_not_same_second_reacquisition(tmp_path,monkeypatch):
    monkeypatch.setenv('REMOTEX_VM_QUEUE_LEASE_FILE',str(tmp_path/'leases.json'))
    monkeypatch.setattr(queue_leases,'_now',lambda:datetime(2026,10,17,tzinfo=timezone.utc))
    resource='web:'+'a'*64
    first=queue_leases._set_lease(resource,'owner',300,'lease-issued')
    renewed=queue_leases._set_lease(resource,'owner',600,'lease-renewed')
    assert len(first.get('acquisitionId',''))==32
    assert renewed['acquisitionId']==first['acquisitionId']
    heartbeat=queue_leases._set_lease(resource,'owner',600,'lease-heartbeat')
    assert heartbeat['acquisitionId']==first['acquisitionId']
    replaced=queue_leases._set_lease(resource,'owner',300,'lease-issued')
    assert replaced['acquisitionId']!=first['acquisitionId']


def test_non_web_queue_records_keep_the_existing_schema(tmp_path,monkeypatch):
    monkeypatch.setenv('REMOTEX_VM_QUEUE_LEASE_FILE',str(tmp_path/'leases.json'))
    value=queue_leases._set_lease('host:fixture','owner',300,'lease-issued')
    assert set(value)=={'requester','issuedAt','expiresAt','leaseSeconds'}
    assert json.loads((tmp_path/'leases.json').read_text())['leases']['host:fixture']==value
