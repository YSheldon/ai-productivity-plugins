from __future__ import annotations

import base64
import hashlib
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from contextlib import nullcontext
from pathlib import Path
from unittest import mock


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import remotex_core as core
import service_keys


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class ServiceKeyArchiveTests(unittest.TestCase):
    def _archive(self, root: Path, *, symlink: bool = False) -> Path:
        archive = root / "bundle.zip"
        prefix = "cloudquery-package/"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(
                prefix + "private/management-center/tls-client-key.pem",
                b"TLS-KEY",
            )
            if symlink:
                info = zipfile.ZipInfo(
                    prefix + "private/management-center/response-key.pem"
                )
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(info, b"response-key")
            else:
                bundle.writestr(
                    prefix + "private/management-center/response-key.pem",
                    b"RESPONSE-KEY",
                )
            bundle.writestr(prefix + "private/management-center/ignored.txt", b"ignore")
        return archive

    def test_extracts_only_the_two_allowlisted_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._archive(root)
            with mock.patch.object(service_keys, "ARCHIVE_ROOTS", (root,)):
                with service_keys._extracted_keys(archive) as extracted:
                    self.assertEqual(
                        sorted(extracted),
                        ["response-key.pem", "tls-client-key.pem"],
                    )
                    self.assertEqual(
                        extracted["tls-client-key.pem"].path.read_bytes(), b"TLS-KEY"
                    )
                    self.assertEqual(
                        extracted["response-key.pem"].path.read_bytes(), b"RESPONSE-KEY"
                    )

    def test_rejects_symlink_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(service_keys, "ARCHIVE_ROOTS", (root,)):
                with self.assertRaisesRegex(core.ToolError, "symbolic link"):
                    with service_keys._extracted_keys(
                        self._archive(root, symlink=True)
                    ):
                        pass

    def test_staging_scripts_bind_lock_ownership_and_cleanup(self) -> None:
        staging = service_keys._STAGING_PREFIX + "abc123"
        setup = service_keys._create_staging_script(staging)
        cleanup = service_keys._cleanup_script(staging)
        self.assertIn("marker=\"$lock/staging\"", setup)
        self.assertIn("trap setup_cleanup EXIT HUP INT TERM", setup)
        self.assertIn("trap - EXIT HUP INT TERM", setup)
        self.assertIn('rm -f -- "$marker"', setup)
        self.assertIn("owner=$(cat \"$marker\")", cleanup)
        self.assertIn("owner\" != \"$staging\"", cleanup)
        self.assertIn('rm -f -- "$marker"', cleanup)


class ServiceKeyDeployTests(unittest.TestCase):
    def _archive(self, root: Path) -> Path:
        archive = root / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(
                "private/management-center/tls-client-key.pem", b"TLS-KEY"
            )
            bundle.writestr(
                "private/management-center/response-key.pem", b"RESPONSE-KEY"
            )
        return archive

    def test_requires_explicit_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(core.ToolError, "confirm=true"):
                service_keys.deploy(
                    {
                        "archive_path": str(self._archive(Path(directory))),
                        "requester": "deploy-test",
                        "confirm": False,
                    }
                )

    def test_requires_managed_host_key_and_queue_resource(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._archive(root)
            with mock.patch.object(service_keys, "ARCHIVE_ROOTS", (root,)), mock.patch.object(
                service_keys.ssh_vnext,
                "connection_config",
                return_value={
                    "profile": "center",
                    "host_key_policy": "known-hosts",
                    "strict_host_key_checking": "accept-new",
                    "queue_resource": None,
                },
            ):
                with self.assertRaisesRegex(core.ToolError, "managed"):
                    service_keys.deploy(
                        {
                            "archive_path": str(archive),
                            "requester": "deploy-test",
                            "confirm": True,
                        }
                    )

            with mock.patch.object(service_keys, "ARCHIVE_ROOTS", (root,)), mock.patch.object(
                service_keys.ssh_vnext,
                "connection_config",
                return_value={
                    "profile": "center",
                    "host_key_policy": "managed",
                    "strict_host_key_checking": "yes",
                    "queue_resource": None,
                },
            ):
                with self.assertRaisesRegex(core.ToolError, "queue_resource"):
                    service_keys.deploy(
                        {
                            "archive_path": str(archive),
                            "requester": "deploy-test",
                            "confirm": True,
                        }
                    )

    def test_uploads_only_allowlisted_keys_and_returns_remote_postflight(self) -> None:
        cfg = {
            "profile": "center",
            "host": "center.example",
            "port": 22,
            "platform": "posix",
            "queue_resource": "host:center",
            "host_key_policy": "managed",
            "strict_host_key_checking": "yes",
        }
        scripts: list[str] = []
        batches: list[str] = []

        def remote_script(_cfg: dict, script: str, _timeout: int) -> dict:
            scripts.append(script)
            if "REMOTE_X_SERVICE_KEY_INSPECT" in script:
                return {"ok": True, "stdout": "TARGET_MISSING\n", "stderr": ""}
            if "REMOTE_X_SERVICE_KEY_STAGING_READY" in script:
                return {"ok": True, "stdout": "staging-ready\n", "stderr": ""}
            return {
                "ok": True,
                "stdout": (
                    "DIRECTORY\troot:root\t700\t0\n"
                    "FILE\ttls-client-key.pem\troot:root\t600\t"
                    + hashlib.sha256(b"TLS-KEY").hexdigest()
                    + "\t7\t0\n"
                    "FILE\tresponse-key.pem\troot:root\t600\t"
                    + hashlib.sha256(b"RESPONSE-KEY").hexdigest()
                    + "\t12\t0\n"
                ),
                "stderr": "",
            }

        with tempfile.TemporaryDirectory() as directory:
            archive = self._archive(Path(directory))
            with mock.patch.object(
                service_keys.ssh_vnext, "connection_config", return_value=cfg
            ), mock.patch.object(
                service_keys, "ARCHIVE_ROOTS", (Path(directory),)
            ), mock.patch.object(
                service_keys.ssh_vnext, "_enforce_host_key"
            ), mock.patch.object(
                service_keys.ssh_vnext,
                "queue_owner_operation",
                return_value=nullcontext(),
            ), mock.patch.object(
                service_keys, "_run_remote_script", side_effect=remote_script
            ), mock.patch.object(
                service_keys, "_run_sftp", side_effect=lambda _cfg, _timeout, batch: batches.append(batch)
                or {"returncode": 0, "stdout": "", "stderr": ""}
            ):
                result = payload(
                    service_keys.deploy(
                        {
                            "archive_path": str(archive),
                            "requester": "deploy-test",
                            "confirm": True,
                        }
                    )
                )

        self.assertTrue(result["ok"])
        self.assertEqual(len(batches), 2)
        self.assertIn("tls-client-key.pem", batches[0])
        self.assertIn("response-key.pem", batches[1])
        self.assertNotIn("ignored.txt", "".join(batches))
        self.assertEqual(result["targetDirectory"], service_keys.TARGET_DIRECTORY)
        self.assertEqual(result["directory"]["mode"], "0700")
        self.assertEqual(result["directory"]["owner"], "root:root")
        self.assertEqual(len(scripts), 3)

    def test_reports_remote_cleanup_failure_after_upload_error(self) -> None:
        cfg = {
            "profile": "center",
            "host_key_policy": "managed",
            "strict_host_key_checking": "yes",
            "queue_resource": "host:center",
        }
        calls: list[str] = []

        def remote_script(_cfg: dict, script: str, _timeout: int) -> dict:
            calls.append(script)
            if "REMOTE_X_SERVICE_KEY_INSPECT" in script:
                return {"ok": True, "stdout": "TARGET_MISSING\n", "stderr": ""}
            if "REMOTE_X_SERVICE_KEY_STAGING_READY" in script:
                return {"ok": True, "stdout": "staging-ready\n", "stderr": ""}
            if "refusing to clean" in script or "service-key lock is not a directory" in script:
                return {"ok": False, "stdout": "", "stderr": "cleanup denied"}
            return {"ok": False, "stdout": "", "stderr": "finalize failed"}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self._archive(root)
            with mock.patch.object(
                service_keys, "ARCHIVE_ROOTS", (root,)
            ), mock.patch.object(
                service_keys.ssh_vnext, "connection_config", return_value=cfg
            ), mock.patch.object(
                service_keys.ssh_vnext, "_enforce_host_key"
            ), mock.patch.object(
                service_keys.ssh_vnext,
                "queue_owner_operation",
                return_value=nullcontext(),
            ), mock.patch.object(
                service_keys, "_run_remote_script", side_effect=remote_script
            ), mock.patch.object(
                service_keys,
                "_run_sftp",
                return_value={"returncode": 0, "stdout": "", "stderr": ""},
            ):
                with self.assertRaisesRegex(core.ToolError, "cleanup failed"):
                    service_keys.deploy(
                        {
                            "archive_path": str(archive),
                            "requester": "deploy-test",
                            "confirm": True,
                        }
                    )
        self.assertEqual(len(calls), 4)


if __name__ == "__main__":
    unittest.main()
