from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import windows_guest


def payload(result: dict[str, object]) -> dict[str, object]:
    content = result["content"]
    assert isinstance(content, list)
    first = content[0]
    assert isinstance(first, dict)
    return json.loads(first["text"])


class GuestCopyIntegrityTests(unittest.TestCase):
    def test_copy_from_does_not_overwrite_local_file_when_hash_readback_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "target.bin"
            local.write_bytes(b"keep")
            transferred = b"untrusted"
            remote_path = r"C:\RemoteX\Staging\target.bin"
            stdout = "\n".join(
                [
                    "REMOTEX_COPY_DATA|"
                    + base64.b64encode(transferred).decode("ascii"),
                    "REMOTEX_COPY|from|"
                    + base64.b64encode(remote_path.encode("utf-8")).decode("ascii")
                    + f"|{len(transferred)}|"
                    + "0" * 64,
                ]
            )
            cfg = {
                "profile": "guest",
                "identity": {"id": "lab-windows"},
                "stagingRoot": r"C:\RemoteX\Staging",
            }
            outcome = {
                "returncode": 0,
                "timed_out": False,
                "stdout": stdout,
                "stderr": "",
            }
            with mock.patch.object(windows_guest, "connection_config", return_value=cfg):
                with mock.patch.object(
                    windows_guest.vm_queue,
                    "profile_owner_operation",
                    return_value=nullcontext(
                        {"resource": "lab:windows", "owner": {"requester": "operator"}}
                    ),
                ):
                    with mock.patch.object(
                        windows_guest,
                        "_probe_identity",
                        return_value={"machineId": "lab-windows"},
                    ):
                        with mock.patch.object(windows_guest, "_invoke", return_value=outcome):
                            result = payload(
                                windows_guest.copy_from(
                                    {
                                        "requester": "operator",
                                        "local_path": str(local),
                                        "relative_path": "target.bin",
                                        "overwrite": "replace",
                                    }
                                )
                            )
            self.assertFalse(result["ok"])
            self.assertFalse(result["integrityMatched"])
            self.assertFalse(result["localWritten"])
            self.assertEqual(local.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
