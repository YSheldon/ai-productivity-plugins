from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

import verifier_product_gate_bridge as bridge  # noqa: E402


def _request(*, request_digest: str = "sha256:" + "4" * 64) -> dict[str, object]:
    return {
        "event_id": "evt-bridge",
        "round_id": 7,
        "request_digest": request_digest,
        "target_scope": {
            "release_group": "release@example.com",
            "module": "release-approval-verifier",
        },
    }


def _receipt(
    *,
    status: str = "APPROVAL_VERIFIED",
    event_id: str = "evt-bridge",
    round_id: int = 7,
    request_digest: str = "sha256:" + "4" * 64,
) -> dict[str, object]:
    return {
        "receipt_id": "receipt-bridge",
        "status": status,
        "event_id": event_id,
        "round_id": round_id,
        "request_digest": request_digest,
        "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64,
        "role_snapshot_digest": "sha256:" + "5" * 64,
        "expires_at": "2026-07-18T04:00:00Z",
    }


def _install_fake_controller(
    monkeypatch: pytest.MonkeyPatch,
    *,
    verified_receipt: dict[str, object] | None = None,
    event: dict[str, object] | None = None,
    verify_error: Exception | None = None,
) -> dict[str, object]:
    calls: dict[str, object] = {
        "load_config": [],
        "controller_init": [],
        "verify_receipt": [],
        "get_event": [],
    }

    def fake_load_config(path: Path) -> dict[str, str]:
        calls["load_config"].append(path)
        return {"loaded_from": str(path)}

    class FakeController:
        def __init__(self, *, config, config_path):
            calls["controller_init"].append(
                {
                    "config": config,
                    "config_path": config_path,
                }
            )

        def verify_receipt(self, *, path):
            calls["verify_receipt"].append(path)
            if verify_error is not None:
                raise verify_error
            return {
                "status": str(verified_receipt["status"]),
                "verified": True,
                "receipt": dict(verified_receipt or {}),
                "path": str(Path(path).resolve(strict=False)),
            }

        def get_event(self, *, event_id: str, round_id: int):
            calls["get_event"].append({"event_id": event_id, "round_id": round_id})
            return dict(event or {})

    monkeypatch.setattr(bridge, "load_config", fake_load_config)
    monkeypatch.setattr(bridge, "VerifierController", FakeController)
    return calls


def test_returns_aggregate_payload_with_target_scope_and_evidence_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    calls = _install_fake_controller(
        monkeypatch,
        verified_receipt=_receipt(),
        event={"request": _request()},
    )

    result = bridge.verify_for_product_gate(
        config_path=config_path,
        verification_ref=receipt_path,
    )

    assert result == {
        "aggregate_status": "APPROVAL_VERIFIED",
        "verification_ref": str(receipt_path.resolve()),
        "event_id": "evt-bridge",
        "round_id": 7,
        "manifest_s_digest": "sha256:" + "1" * 64,
        "manifest_r_digest": "sha256:" + "2" * 64,
        "role_snapshot_digest": "sha256:" + "5" * 64,
        "target_scope": _request()["target_scope"],
        "expires_at": "2026-07-18T04:00:00Z",
        "evidence_ref": "receipt-bridge",
    }
    assert calls["load_config"] == [config_path.resolve()]
    assert calls["verify_receipt"] == [receipt_path.resolve()]


def test_looks_up_event_using_receipt_event_id_and_round_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    calls = _install_fake_controller(
        monkeypatch,
        verified_receipt=_receipt(event_id="evt-from-receipt", round_id=12),
        event={"request": _request()},
    )

    bridge.verify_for_product_gate(
        config_path=config_path,
        verification_ref=receipt_path,
    )

    assert calls["get_event"] == [{"event_id": "evt-from-receipt", "round_id": 12}]


def test_raises_when_event_request_digest_differs_from_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    _install_fake_controller(
        monkeypatch,
        verified_receipt=_receipt(request_digest="sha256:" + "4" * 64),
        event={"request": _request(request_digest="sha256:" + "9" * 64)},
    )

    with pytest.raises(
        RuntimeError,
        match="receipt request digest differs from the frozen verifier event",
    ):
        bridge.verify_for_product_gate(
            config_path=config_path,
            verification_ref=receipt_path,
        )


def test_returns_expired_receipt_status_when_receipt_is_still_cryptographically_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    _install_fake_controller(
        monkeypatch,
        verified_receipt=_receipt(status="APPROVAL_EXPIRED"),
        event={"request": _request()},
    )

    result = bridge.verify_for_product_gate(
        config_path=config_path,
        verification_ref=receipt_path,
    )

    assert result["aggregate_status"] == "APPROVAL_EXPIRED"
    assert result["evidence_ref"] == "receipt-bridge"
    assert result["target_scope"] == _request()["target_scope"]


def test_main_returns_error_json_when_receipt_verification_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    _install_fake_controller(
        monkeypatch,
        verify_error=ValueError("invalid verification receipt"),
    )

    exit_code = bridge.main(
        ["--config", str(config_path), "--verification-ref", str(receipt_path)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert json.loads(captured.out) == {
        "error": "ValueError: invalid verification receipt"
    }
