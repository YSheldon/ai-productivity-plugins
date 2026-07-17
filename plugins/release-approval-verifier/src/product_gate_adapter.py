from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from verifier_dependency_lock import DependencyLockError, resolve_locked_entrypoint


Runner = Callable[..., subprocess.CompletedProcess[str]]
_PLUGIN_NAME = "product-release-gate"
_PLUGIN_ROOT = Path("plugins/product-release-gate")
_MCP_PATH = _PLUGIN_ROOT / "src" / "release_gate_mcp.py"


class ProductGateAdapterError(RuntimeError):
    """Raised when the locked product-gate MCP cannot safely consume a receipt."""


class ProductGateMcpAdapter:
    def __init__(
        self,
        dependency_lock: str | Path,
        product_gate_config_path: str | Path,
        *,
        dependency_lock_sha256: str,
        runner: Runner | None = None,
        timeout_seconds: int = 180,
    ) -> None:
        self.dependency_lock = Path(dependency_lock).resolve(strict=False)
        self.dependency_lock_sha256 = dependency_lock_sha256
        self.product_gate_config_path = Path(product_gate_config_path).resolve(
            strict=False
        )
        self.runner = runner or subprocess.run
        if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 600:
            raise ProductGateAdapterError(
                "product gate timeout must be between 1 and 600 seconds."
            )
        self.timeout_seconds = timeout_seconds

    def preflight(self) -> dict[str, Any]:
        try:
            self._locked_mcp_path()
            if not self.product_gate_config_path.is_file():
                raise ProductGateAdapterError(
                    f"product gate config is missing: {self.product_gate_config_path}"
                )
            result = self._invoke("release_gate_unified_approval_preflight", {})
            if result.get("ready") is not True or result.get("status") != "ready":
                return {
                    "status": "CAPABILITY_BLOCKED",
                    "reason": "product gate unified approval preflight is not ready",
                    "details": result,
                }
            return {
                "status": "ready",
                "config_path": str(self.product_gate_config_path),
                "details": result,
            }
        except (OSError, ValueError, ProductGateAdapterError) as exc:
            return {"status": "CAPABILITY_BLOCKED", "reason": str(exc)}

    def request_pre_release(
        self,
        *,
        request_binding: Mapping[str, Any],
        receipt: Mapping[str, Any],
        receipt_path: str,
    ) -> dict[str, Any]:
        event_id = str(request_binding.get("event_id") or "").strip()
        receipt_event_id = str(receipt.get("event_id") or "").strip()
        if not event_id or receipt_event_id != event_id:
            raise ProductGateAdapterError(
                "verification receipt event does not match the frozen request."
            )
        reference = str(Path(receipt_path).resolve(strict=True))
        result = self._invoke(
            "release_gate_record_unified_release_approval",
            {"event_id": event_id, "verification_ref": reference},
        )
        if result.get("status") != "PRE_RELEASE_REQUESTED":
            raise ProductGateAdapterError(
                "product gate did not confirm PRE_RELEASE_REQUESTED."
            )
        handoff = result.get("pre_release_request")
        if isinstance(handoff, Mapping) and handoff.get("event_id") != event_id:
            raise ProductGateAdapterError(
                "product gate pre-release handoff returned a different event."
            )
        return {
            **result,
            "event_id": event_id,
            "handoff_id": f"pre-release:{event_id}:{request_binding.get('round_id')}",
        }

    def _invoke(self, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        mcp_path = self._locked_mcp_path()
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": dict(arguments)},
        }
        environment = dict(os.environ)
        environment["PRODUCT_RELEASE_GATE_CONFIG"] = str(
            self.product_gate_config_path
        )
        try:
            completed = self.runner(
                args=[sys.executable, str(mcp_path)],
                input=json.dumps(request, ensure_ascii=False) + "\n",
                text=True,
                capture_output=True,
                shell=False,
                timeout=self.timeout_seconds,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProductGateAdapterError(
                f"product gate MCP timed out after {self.timeout_seconds} seconds."
            ) from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise ProductGateAdapterError(
                f"product gate MCP exited with {completed.returncode}: {detail}"
            )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            raise ProductGateAdapterError(
                "product gate MCP returned an ambiguous JSON-RPC response."
            )
        try:
            response = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise ProductGateAdapterError(
                "product gate MCP returned invalid JSON."
            ) from exc
        result = response.get("result") if isinstance(response, Mapping) else None
        if not isinstance(result, Mapping) or result.get("isError") is True:
            raise ProductGateAdapterError(
                self._error_text(result) or "product gate MCP returned an error."
            )
        content = result.get("content")
        if not isinstance(content, list) or len(content) != 1:
            raise ProductGateAdapterError(
                "product gate MCP result did not contain one JSON payload."
            )
        text = content[0].get("text") if isinstance(content[0], Mapping) else None
        try:
            payload = json.loads(str(text))
        except (TypeError, json.JSONDecodeError) as exc:
            raise ProductGateAdapterError(
                "product gate MCP tool result was not JSON."
            ) from exc
        if not isinstance(payload, dict):
            raise ProductGateAdapterError(
                "product gate MCP tool result must be an object."
            )
        return payload

    def _locked_mcp_path(self) -> Path:
        try:
            return resolve_locked_entrypoint(
                self.dependency_lock,
                dependency_lock_sha256=self.dependency_lock_sha256,
                plugin_name=_PLUGIN_NAME,
                plugin_root=_PLUGIN_ROOT,
                entrypoint_path=_MCP_PATH,
            )
        except (OSError, DependencyLockError) as exc:
            raise ProductGateAdapterError(str(exc)) from exc

    @staticmethod
    def _error_text(result: Any) -> str:
        if not isinstance(result, Mapping):
            return ""
        content = result.get("content")
        if not isinstance(content, list):
            return ""
        return " ".join(
            str(item.get("text") or "").strip()
            for item in content
            if isinstance(item, Mapping) and str(item.get("text") or "").strip()
        )
