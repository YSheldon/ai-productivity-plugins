from __future__ import annotations

import inspect
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(SRC))

import remotex_core as core
import task_manager
import task_worker


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class TaskSecretIpcTests(unittest.TestCase):
    def test_worker_payload_round_trip_is_bounded_and_versioned(self) -> None:
        self.assertTrue(hasattr(task_manager, "_encode_worker_payload"))
        self.assertTrue(hasattr(task_worker, "_read_worker_payload"))
        encoded = task_manager._encode_worker_payload(
            b"opaque-remote-stdin",
            ["first-secret", "second-secret"],
        )
        input_bytes, secrets = task_worker._read_worker_payload(io.BytesIO(encoded))
        self.assertEqual(input_bytes, b"opaque-remote-stdin")
        self.assertEqual(secrets, ["first-secret", "second-secret"])
        with self.assertRaisesRegex(core.ToolError, "trailing"):
            task_worker._read_worker_payload(io.BytesIO(encoded + b"x"))

    def test_manager_and_worker_never_name_sensitive_task_files(self) -> None:
        manager_source = inspect.getsource(task_manager._start_owned)
        worker_source = inspect.getsource(task_worker.run)
        for filename in ("stdin.bin", "secrets.json"):
            self.assertNotIn(filename, manager_source)
            self.assertNotIn(filename, worker_source)
        self.assertIn("subprocess.PIPE", manager_source)
        self.assertIn("sys.stdin.buffer", worker_source)

    def test_sensitive_artifact_cleanup_is_explicit_and_exact(self) -> None:
        self.assertTrue(hasattr(task_manager, "cleanup_sensitive_artifacts"))
        task_id = "00000000-0000-0000-0000-000000000123"
        with tempfile.TemporaryDirectory() as directory:
            task_directory = Path(directory) / task_id
            task_directory.mkdir()
            (task_directory / "state.json").write_text(
                json.dumps({"taskId": task_id, "state": "orphaned"}),
                encoding="utf-8",
            )
            (task_directory / "stdin.bin").write_bytes(b"legacy-secret-input")
            (task_directory / "secrets.json").write_text(
                json.dumps(["legacy-secret"]),
                encoding="utf-8",
            )
            (task_directory / "keep.txt").write_text("keep", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_TASK_DIR": directory},
                clear=False,
            ):
                with self.assertRaisesRegex(core.ToolError, "confirm=true"):
                    task_manager.cleanup_sensitive_artifacts(
                        {"task_id": task_id, "confirm": False}
                    )
                result = payload(
                    task_manager.cleanup_sensitive_artifacts(
                        {"task_id": task_id, "confirm": True}
                    )
                )
            self.assertEqual(
                (task_directory / "keep.txt").read_text(encoding="utf-8"),
                "keep",
            )
        self.assertEqual(result["removedCount"], 2)
        self.assertEqual(result["remainingSensitiveArtifactCount"], 0)
        self.assertNotIn("legacy-secret", json.dumps(result))

    def test_sensitive_artifact_cleanup_refuses_running_worker(self) -> None:
        self.assertTrue(hasattr(task_manager, "cleanup_sensitive_artifacts"))
        task_id = "00000000-0000-0000-0000-000000000124"
        with tempfile.TemporaryDirectory() as directory:
            task_directory = Path(directory) / task_id
            task_directory.mkdir()
            (task_directory / "state.json").write_text(
                json.dumps({"taskId": task_id, "state": "running"}),
                encoding="utf-8",
            )
            (task_directory / "stdin.bin").write_bytes(b"legacy-secret-input")
            (task_directory / "worker.pid").write_text("42", encoding="ascii")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_TASK_DIR": directory},
                clear=False,
            ):
                with mock.patch.object(task_manager, "_pid_running", return_value=True):
                    with self.assertRaisesRegex(core.ToolError, "active worker"):
                        task_manager.cleanup_sensitive_artifacts(
                            {"task_id": task_id, "confirm": True}
                        )


if __name__ == "__main__":
    unittest.main()
