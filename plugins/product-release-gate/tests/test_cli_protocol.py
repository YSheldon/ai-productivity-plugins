from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from release_gate_cli import EXIT_OK, EXIT_USAGE, run_cli


class FakeController:
    def preflight(self) -> dict:
        return {"ready": True, "checks": []}

    def request_unified_release_approval(self, **values: object) -> dict:
        return {"status": "APPROVAL_COLLECTING", "received": values}

    def deliver_production_report(self, event_id: str) -> dict:
        return {"status": "DELIVERED", "event_id": event_id, "idempotent": True}


class FakeRuntime:
    def run_once(self) -> dict:
        return {"status": "ready", "processed": 1}

    def status(self) -> dict:
        return {"status": "ready", "queued_handoffs": 0}

    def doctor(self) -> dict:
        return {"ready": True}

    def list_events(self) -> dict:
        return {"events": []}

    def enqueue_handoff(self, event_id: str, verification_ref: str) -> dict:
        return {"status": "queued", "event_id": event_id, "verification_ref": verification_ref}


class CliProtocolTests(unittest.TestCase):
    def _run(self, args: list[str]) -> tuple[int, dict]:
        output = io.StringIO()
        code = run_cli(
            args,
            stdout=output,
            controller_factory=lambda _path: FakeController(),
            runtime_factory=lambda _controller, _path: FakeRuntime(),
        )
        return code, json.loads(output.getvalue())

    def test_common_commands_emit_stable_json_without_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = str(Path(temporary) / "config.json")
            for command, expected in (
                (["--config", config, "preflight"], {"ready": True, "checks": []}),
                (["--config", config, "run-once"], {"status": "ready", "processed": 1}),
                (["--config", config, "status"], {"status": "ready", "queued_handoffs": 0}),
                (["--config", config, "doctor"], {"ready": True}),
                (["--config", config, "list-events"], {"events": []}),
            ):
                with self.subTest(command=command[-1]):
                    code, payload = self._run(command)
                    self.assertEqual(EXIT_OK, code)
                    self.assertTrue(payload["ok"])
                    self.assertEqual(expected, payload["result"])

    def test_unified_request_uses_one_json_payload_and_no_policy_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = str(Path(temporary) / "config.json")
            request = {
                "event_id": "event-1",
                "requested_by": "bot@example.com",
                "target_scope": "preproduction",
                "round_id": 1,
                "required_roles": [{"role_id": "director", "email": "d@example.com", "required": True}],
                "role_snapshot_digest": "c" * 64,
                "expires_at": "2099-01-01T00:00:00Z",
            }
            code, payload = self._run([
                "--config", config, "request-unified-approval", "--input", json.dumps(request)
            ])

        self.assertEqual(EXIT_OK, code)
        self.assertEqual("APPROVAL_COLLECTING", payload["result"]["status"])
        self.assertEqual(request, payload["result"]["received"])

    def test_call_routes_production_report_delivery_without_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            code, payload = self._run(
                [
                    "--config",
                    str(Path(temporary) / "config.json"),
                    "call",
                    "deliver_production_report",
                    "--input",
                    json.dumps({"event_id": "event-report"}),
                ]
            )
        self.assertEqual(EXIT_OK, code)
        self.assertEqual("DELIVERED", payload["result"]["status"])

    def test_scheduler_policy_cannot_be_overridden_per_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            code, payload = self._run([
                "--config", str(Path(temporary) / "config.json"),
                "scheduler", "install", "--poll-minutes", "5",
            ])
        self.assertEqual(EXIT_USAGE, code)
        self.assertEqual("INVALID_ARGUMENT", payload["error"]["code"])

    def test_help_runs_in_a_clean_python_process_without_codex(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(PLUGIN_ROOT / "src" / "release_gate_cli.py"), "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertNotIn("codex", completed.stderr.lower())


if __name__ == "__main__":
    unittest.main()
