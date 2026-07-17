from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from product_gate_adapter import (  # noqa: E402
    ProductGateAdapterError,
    ProductGateMcpAdapter,
)


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    mcp_path = (
        tmp_path
        / "plugins"
        / "product-release-gate"
        / "src"
        / "release_gate_mcp.py"
    )
    mcp_path.parent.mkdir(parents=True)
    mcp_path.write_text("# locked MCP\n", encoding="utf-8")
    config_path = tmp_path / "product-gate.json"
    config_path.write_text("{}\n", encoding="utf-8")
    lock_path = tmp_path / "dependency-lock.json"
    lock_path.write_text(
        json.dumps(
            {
                "plugins": [
                    {
                        "name": "product-release-gate",
                        "plugin_root": "plugins/product-release-gate",
                        "entrypoints": [
                            {
                                "path": "plugins/product-release-gate/src/release_gate_mcp.py",
                                "sha256": hashlib.sha256(mcp_path.read_bytes()).hexdigest(),
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return lock_path, config_path, mcp_path


def _response(payload: dict[str, object], *, error: bool = False) -> str:
    result: dict[str, object] = {
        "content": [{"type": "text", "text": json.dumps(payload)}]
    }
    if error:
        result["isError"] = True
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}) + "\n"


def test_preflight_invokes_only_the_locked_product_gate_mcp(tmp_path: Path) -> None:
    lock_path, config_path, mcp_path = _fixture(tmp_path)
    calls: list[dict[str, object]] = []

    def runner(**kwargs):
        calls.append(dict(kwargs))
        request = json.loads(kwargs["input"])
        assert request["params"]["name"] == "release_gate_unified_approval_preflight"
        return subprocess.CompletedProcess(
            kwargs["args"], 0, _response({"status": "ready", "ready": True}), ""
        )

    adapter = ProductGateMcpAdapter(lock_path, config_path, dependency_lock_sha256=hashlib.sha256(lock_path.read_bytes()).hexdigest(), runner=runner)

    result = adapter.preflight()

    assert result["status"] == "ready"
    assert calls[0]["args"] == [sys.executable, str(mcp_path)]
    assert calls[0]["shell"] is False
    assert calls[0]["env"]["PRODUCT_RELEASE_GATE_CONFIG"] == str(config_path)


def test_verified_receipt_is_consumed_with_exact_event_and_path(tmp_path: Path) -> None:
    lock_path, config_path, _mcp_path = _fixture(tmp_path)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    requests: list[dict[str, object]] = []

    def runner(**kwargs):
        request = json.loads(kwargs["input"])
        requests.append(request)
        arguments = request["params"]["arguments"]
        assert arguments == {
            "event_id": "evt-1",
            "verification_ref": str(receipt_path.resolve()),
        }
        return subprocess.CompletedProcess(
            kwargs["args"],
            0,
            _response(
                {
                    "status": "PRE_RELEASE_REQUESTED",
                    "pre_release_request_path": str(tmp_path / "pre-release.json"),
                    "pre_release_request": {"event_id": "evt-1"},
                }
            ),
            "",
        )

    adapter = ProductGateMcpAdapter(lock_path, config_path, dependency_lock_sha256=hashlib.sha256(lock_path.read_bytes()).hexdigest(), runner=runner)
    result = adapter.request_pre_release(
        request_binding={"event_id": "evt-1", "round_id": 2},
        receipt={"event_id": "evt-1"},
        receipt_path=str(receipt_path),
    )

    assert result["status"] == "PRE_RELEASE_REQUESTED"
    assert result["event_id"] == "evt-1"
    assert result["handoff_id"] == "pre-release:evt-1:2"
    assert requests[0]["params"]["name"] == "release_gate_record_unified_release_approval"


def test_adapter_rejects_rewritten_lock_even_when_entrypoint_digest_is_updated(
    tmp_path: Path,
) -> None:
    lock_path, config_path, mcp_path = _fixture(tmp_path)
    expected_lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    mcp_path.write_text("# attacker replacement\n", encoding="utf-8")
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    payload["plugins"][0]["entrypoints"][0]["sha256"] = hashlib.sha256(
        mcp_path.read_bytes()
    ).hexdigest()
    lock_path.write_text(json.dumps(payload), encoding="utf-8")

    adapter = ProductGateMcpAdapter(
        lock_path,
        config_path,
        dependency_lock_sha256=expected_lock_digest,
    )

    result = adapter.preflight()

    assert result["status"] == "CAPABILITY_BLOCKED"
    assert "dependency lock drift" in result["reason"]


def test_adapter_fails_closed_on_lock_drift_or_mcp_error(tmp_path: Path) -> None:
    lock_path, config_path, mcp_path = _fixture(tmp_path)
    mcp_path.write_text("# drifted\n", encoding="utf-8")
    adapter = ProductGateMcpAdapter(lock_path, config_path, dependency_lock_sha256=hashlib.sha256(lock_path.read_bytes()).hexdigest())

    assert adapter.preflight()["status"] == "CAPABILITY_BLOCKED"

    lock_path, config_path, _mcp_path = _fixture(tmp_path / "error")

    def runner(**kwargs):
        return subprocess.CompletedProcess(
            kwargs["args"], 0, _response({"message": "blocked"}, error=True), ""
        )

    adapter = ProductGateMcpAdapter(lock_path, config_path, dependency_lock_sha256=hashlib.sha256(lock_path.read_bytes()).hexdigest(), runner=runner)
    receipt_path = tmp_path / "error" / "receipt.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ProductGateAdapterError, match="blocked"):
        adapter.request_pre_release(
            request_binding={"event_id": "evt-2", "round_id": 1},
            receipt={"event_id": "evt-2"},
            receipt_path=str(receipt_path),
        )
