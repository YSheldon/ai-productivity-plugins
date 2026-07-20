from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

import filesystem_release_adapter as adapter_module
from filesystem_release_adapter import (
    AdapterError,
    FilesystemReleaseAdapter,
    canonical_json,
    load_manifest_bundle,
    main,
    object_digest,
    safe_logical_name,
)


SOURCE_MANIFEST_DIGEST = "a" * 64
KEY_ENV = "TEST_FILESYSTEM_RELEASE_AUTH_KEY"


class FilesystemReleaseAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.key = "filesystem-release-test-key-at-least-32-bytes"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(
        self,
        name: str,
        files: dict[str, bytes],
        *,
        event_id: str | None = None,
    ) -> tuple[Path, str, Path]:
        output_dir = self.root / f"output-{name}"
        output_dir.mkdir()
        artifacts: list[dict[str, object]] = []
        for logical_name, content in sorted(files.items()):
            path = output_dir / logical_name
            path.write_bytes(content)
            sha1 = hashlib.sha1(content).hexdigest()
            artifacts.append(
                {
                    "logical_name": logical_name,
                    "file_path": str(path.resolve()),
                    "size": len(content),
                    "sha1": sha1,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "source_sha1": sha1,
                    "source_ref": f"fixture://{name}/{logical_name}",
                }
            )
        digest = object_digest(
            {
                "source_manifest_s_digest": SOURCE_MANIFEST_DIGEST,
                "artifacts": artifacts,
            }
        )
        manifest = {
            "schema_version": 1,
            "event_id": event_id or f"event-{name}",
            "source_manifest_s_digest": SOURCE_MANIFEST_DIGEST,
            "output_dir": str(output_dir.resolve()),
            "artifacts": artifacts,
            "digest": digest,
        }
        manifest_path = self.root / f"manifest-r-{name}.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        return manifest_path, digest, output_dir

    def _write_authorization(
        self,
        name: str,
        *,
        event_id: str,
        manifest_digest: str,
        target_scope: str = (
            "preproduction,production_canary,production_full"
        ),
        expires_at: datetime | None = None,
        signature: str | None = None,
    ) -> Path:
        expiry = expires_at or (
            datetime.now(timezone.utc) + timedelta(hours=1)
        )
        claims = {
            "event_id": event_id,
            "manifest_s_digest": SOURCE_MANIFEST_DIGEST,
            "manifest_r_digest": manifest_digest,
            "target_scope": target_scope,
            "expires_at": expiry.replace(microsecond=0).isoformat().replace(
                "+00:00", "Z"
            ),
        }
        actual_signature = hmac.new(
            self.key.encode("utf-8"),
            canonical_json(claims).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        credential = {
            "schema_version": 1,
            "algorithm": "HMAC-SHA256",
            "claims": claims,
            "signature": signature or actual_signature,
        }
        path = self.root / f"authorization-{name}.json"
        path.write_text(
            json.dumps(credential, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def _adapter(self, target: Path) -> FilesystemReleaseAdapter:
        return FilesystemReleaseAdapter(
            str(target),
            environ={KEY_ENV: self.key},
        )

    def _deploy(
        self,
        adapter: FilesystemReleaseAdapter,
        *,
        name: str,
        stage: str,
        manifest_path: Path,
        manifest_digest: str,
        authorization_path: Path,
    ) -> dict[str, object]:
        return adapter.deploy(
            stage=stage,
            manifest_path=manifest_path,
            authorization_path=authorization_path,
            idempotency_key=object_digest(
                {
                    "name": name,
                    "stage": stage,
                    "manifest_r_digest": manifest_digest,
                }
            ),
            expected_digest=manifest_digest,
            authorization_key_env=KEY_ENV,
        )

    def test_deploy_verify_readback_and_idempotent_replay(self) -> None:
        manifest_path, digest, _ = self._write_manifest(
            "first",
            {
                "product.bin": b"production-candidate-v1",
                "release.json": b'{"version":"1.0.0"}\n',
            },
        )
        authorization_path = self._write_authorization(
            "first",
            event_id="event-first",
            manifest_digest=digest,
        )
        target = self.root / "deployment-target"
        adapter = self._adapter(target)

        self.assertFalse(target.exists())
        deployed = self._deploy(
            adapter,
            name="first",
            stage="preproduction",
            manifest_path=manifest_path,
            manifest_digest=digest,
            authorization_path=authorization_path,
        )

        self.assertEqual("PASS", deployed["result"])
        self.assertFalse(deployed["idempotent"])
        release_root = (
            target
            / ".product-release-gate"
            / str(deployed["release_ref"])
        )
        self.assertEqual(
            b"production-candidate-v1",
            (release_root / "files" / "product.bin").read_bytes(),
        )
        inventory = json.loads(
            (release_root / "inventory.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            hashlib.sha256(b"production-candidate-v1").hexdigest(),
            inventory["artifacts"][0]["sha256"],
        )

        verified = adapter.verify(
            stage="preproduction",
            deployment_ref=str(deployed["deployment_ref"]),
            rollback_ref=str(deployed["rollback_ref"]),
            expected_digest=digest,
        )
        readback = adapter.readback(expected_digest=digest)
        replayed = self._deploy(
            adapter,
            name="first",
            stage="preproduction",
            manifest_path=manifest_path,
            manifest_digest=digest,
            authorization_path=authorization_path,
        )

        self.assertEqual("PASS", verified["result"])
        self.assertEqual(digest, verified["observed_manifest_r_digest"])
        self.assertEqual("PASS", readback["result"])
        self.assertEqual(digest, readback["observed_manifest_r_digest"])
        self.assertTrue(replayed["idempotent"])
        self.assertEqual(
            deployed["deployment_ref"],
            replayed["deployment_ref"],
        )

    def test_second_release_rolls_back_to_first_release(self) -> None:
        target = self.root / "deployment-target"
        adapter = self._adapter(target)
        first_manifest, first_digest, _ = self._write_manifest(
            "first",
            {"product.bin": b"v1"},
        )
        first_authorization = self._write_authorization(
            "first",
            event_id="event-first",
            manifest_digest=first_digest,
        )
        first = self._deploy(
            adapter,
            name="first",
            stage="preproduction",
            manifest_path=first_manifest,
            manifest_digest=first_digest,
            authorization_path=first_authorization,
        )
        second_manifest, second_digest, _ = self._write_manifest(
            "second",
            {"product.bin": b"v2"},
        )
        second_authorization = self._write_authorization(
            "second",
            event_id="event-second",
            manifest_digest=second_digest,
        )
        second = self._deploy(
            adapter,
            name="second",
            stage="production_canary",
            manifest_path=second_manifest,
            manifest_digest=second_digest,
            authorization_path=second_authorization,
        )

        rolled_back = adapter.rollback(
            stage="production_canary",
            deployment_ref=str(second["deployment_ref"]),
            rollback_ref=str(second["rollback_ref"]),
        )
        verified = adapter.verify_rollback(
            stage="production_canary",
            deployment_ref=str(second["deployment_ref"]),
            rollback_ref=str(second["rollback_ref"]),
            restored_ref=str(rolled_back["restored_ref"]),
            rollback_receipt_ref=str(
                rolled_back["rollback_receipt_ref"]
            ),
        )
        replayed = adapter.rollback(
            stage="production_canary",
            deployment_ref=str(second["deployment_ref"]),
            rollback_ref=str(second["rollback_ref"]),
        )
        readback = adapter.readback(expected_digest=first_digest)

        self.assertEqual(first["deployment_ref"], rolled_back["restored_ref"])
        self.assertEqual("PASS", verified["result"])
        self.assertTrue(replayed["idempotent"])
        self.assertEqual(first_digest, readback["observed_manifest_r_digest"])

    def test_interrupted_deployment_reconciles_from_prepared_record(self) -> None:
        manifest_path, digest, _ = self._write_manifest(
            "deploy-recovery",
            {"product.bin": b"candidate"},
        )
        authorization_path = self._write_authorization(
            "deploy-recovery",
            event_id="event-deploy-recovery",
            manifest_digest=digest,
        )
        for failure_point in ("before-current", "after-current"):
            with self.subTest(failure_point=failure_point):
                target = self.root / f"target-deploy-{failure_point}"
                adapter = self._adapter(target)
                real_write = adapter_module.atomic_write_json
                injected = False

                def interrupted_write(
                    path: Path,
                    value: dict[str, object],
                ) -> None:
                    nonlocal injected
                    before_current = (
                        failure_point == "before-current"
                        and path == adapter.layout.current
                    )
                    after_current = (
                        failure_point == "after-current"
                        and path.parent == adapter.layout.deployments
                        and value.get("status") == "ACTIVE"
                    )
                    if not injected and (before_current or after_current):
                        injected = True
                        raise OSError("simulated deployment interruption")
                    real_write(path, value)

                with patch(
                    "filesystem_release_adapter.atomic_write_json",
                    side_effect=interrupted_write,
                ):
                    with self.assertRaisesRegex(OSError, "simulated"):
                        self._deploy(
                            adapter,
                            name="deploy-recovery",
                            stage="preproduction",
                            manifest_path=manifest_path,
                            manifest_digest=digest,
                            authorization_path=authorization_path,
                        )
                self.assertTrue(injected)
                recovered = self._deploy(
                    adapter,
                    name="deploy-recovery",
                    stage="preproduction",
                    manifest_path=manifest_path,
                    manifest_digest=digest,
                    authorization_path=authorization_path,
                )
                self.assertTrue(recovered["idempotent"])
                verified = adapter.verify(
                    stage="preproduction",
                    deployment_ref=str(recovered["deployment_ref"]),
                    rollback_ref=str(recovered["rollback_ref"]),
                    expected_digest=digest,
                )
                self.assertEqual("PASS", verified["result"])

    def test_interrupted_rollback_reconciles_and_restores_previous(self) -> None:
        first_manifest, first_digest, _ = self._write_manifest(
            "rollback-recovery-first",
            {"product.bin": b"stable"},
        )
        first_authorization = self._write_authorization(
            "rollback-recovery-first",
            event_id="event-rollback-recovery-first",
            manifest_digest=first_digest,
        )
        second_manifest, second_digest, _ = self._write_manifest(
            "rollback-recovery-second",
            {"product.bin": b"candidate"},
        )
        second_authorization = self._write_authorization(
            "rollback-recovery-second",
            event_id="event-rollback-recovery-second",
            manifest_digest=second_digest,
        )
        for failure_point in ("before-current", "after-current"):
            with self.subTest(failure_point=failure_point):
                target = self.root / f"target-rollback-{failure_point}"
                adapter = self._adapter(target)
                self._deploy(
                    adapter,
                    name="rollback-recovery-first",
                    stage="preproduction",
                    manifest_path=first_manifest,
                    manifest_digest=first_digest,
                    authorization_path=first_authorization,
                )
                second = self._deploy(
                    adapter,
                    name="rollback-recovery-second",
                    stage="production_canary",
                    manifest_path=second_manifest,
                    manifest_digest=second_digest,
                    authorization_path=second_authorization,
                )
                real_write = adapter_module.atomic_write_json
                injected = False

                def interrupted_write(
                    path: Path,
                    value: dict[str, object],
                ) -> None:
                    nonlocal injected
                    before_current = (
                        failure_point == "before-current"
                        and path == adapter.layout.current
                    )
                    after_current = (
                        failure_point == "after-current"
                        and path.parent == adapter.layout.rollbacks
                        and value.get("status") == "COMPLETE"
                    )
                    if not injected and (before_current or after_current):
                        injected = True
                        raise OSError("simulated rollback interruption")
                    real_write(path, value)

                with patch(
                    "filesystem_release_adapter.atomic_write_json",
                    side_effect=interrupted_write,
                ):
                    with self.assertRaisesRegex(OSError, "simulated"):
                        adapter.rollback(
                            stage="production_canary",
                            deployment_ref=str(second["deployment_ref"]),
                            rollback_ref=str(second["rollback_ref"]),
                        )
                self.assertTrue(injected)
                recovered = adapter.rollback(
                    stage="production_canary",
                    deployment_ref=str(second["deployment_ref"]),
                    rollback_ref=str(second["rollback_ref"]),
                )
                self.assertTrue(recovered["idempotent"])
                verified = adapter.verify_rollback(
                    stage="production_canary",
                    deployment_ref=str(second["deployment_ref"]),
                    rollback_ref=str(second["rollback_ref"]),
                    restored_ref=str(recovered["restored_ref"]),
                    rollback_receipt_ref=str(
                        recovered["rollback_receipt_ref"]
                    ),
                )
                self.assertEqual("PASS", verified["result"])
                readback = adapter.readback(expected_digest=first_digest)
                self.assertEqual(first_digest, readback["observed_manifest_r_digest"])

    def test_deployed_artifact_tampering_blocks_verify_and_readback(self) -> None:
        manifest_path, digest, _ = self._write_manifest(
            "tamper",
            {"product.bin": b"trusted"},
        )
        authorization_path = self._write_authorization(
            "tamper",
            event_id="event-tamper",
            manifest_digest=digest,
        )
        target = self.root / "deployment-target"
        adapter = self._adapter(target)
        deployed = self._deploy(
            adapter,
            name="tamper",
            stage="preproduction",
            manifest_path=manifest_path,
            manifest_digest=digest,
            authorization_path=authorization_path,
        )
        deployed_file = (
            target
            / ".product-release-gate"
            / str(deployed["release_ref"])
            / "files"
            / "product.bin"
        )
        deployed_file.write_bytes(b"tampered")

        with self.assertRaisesRegex(AdapterError, "artifact size differs"):
            adapter.verify(
                stage="preproduction",
                deployment_ref=str(deployed["deployment_ref"]),
                rollback_ref=str(deployed["rollback_ref"]),
                expected_digest=digest,
            )
        with self.assertRaisesRegex(AdapterError, "artifact size differs"):
            adapter.readback(expected_digest=digest)

    def test_forged_inventory_cannot_hide_deployed_file_tampering(self) -> None:
        manifest_path, digest, _ = self._write_manifest(
            "forged-inventory",
            {"product.bin": b"trusted"},
        )
        authorization_path = self._write_authorization(
            "forged-inventory",
            event_id="event-forged-inventory",
            manifest_digest=digest,
        )
        target = self.root / "deployment-target"
        adapter = self._adapter(target)
        deployed = self._deploy(
            adapter,
            name="forged-inventory",
            stage="preproduction",
            manifest_path=manifest_path,
            manifest_digest=digest,
            authorization_path=authorization_path,
        )
        control_root = target / ".product-release-gate"
        release_root = control_root / str(deployed["release_ref"])
        deployed_file = release_root / "files" / "product.bin"
        malicious = b"changed"
        self.assertEqual(deployed_file.stat().st_size, len(malicious))
        deployed_file.write_bytes(malicious)

        inventory_path = release_root / "inventory.json"
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory["artifacts"][0]["sha1"] = hashlib.sha1(
            malicious
        ).hexdigest()
        inventory["artifacts"][0]["sha256"] = hashlib.sha256(
            malicious
        ).hexdigest()
        forged_inventory_digest = object_digest(
            {
                "manifest_r_digest": digest,
                "artifacts": inventory["artifacts"],
            }
        )
        inventory["inventory_sha256"] = forged_inventory_digest
        inventory_path.write_text(
            json.dumps(inventory),
            encoding="utf-8",
        )
        release_metadata_path = release_root / "release.json"
        release_metadata = json.loads(
            release_metadata_path.read_text(encoding="utf-8")
        )
        release_metadata["inventory_sha256"] = forged_inventory_digest
        release_metadata_path.write_text(
            json.dumps(release_metadata),
            encoding="utf-8",
        )
        current_path = control_root / "current.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["inventory_sha256"] = forged_inventory_digest
        current_path.write_text(json.dumps(current), encoding="utf-8")

        with self.assertRaisesRegex(
            AdapterError,
            "inventory artifact differs from Manifest-R",
        ):
            adapter.verify(
                stage="preproduction",
                deployment_ref=str(deployed["deployment_ref"]),
                rollback_ref=str(deployed["rollback_ref"]),
                expected_digest=digest,
            )

    def test_invalid_authorization_and_source_drift_write_nothing(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = [
            ("signature", {"signature": "0" * 64}),
            ("scope", {"target_scope": "production_full"}),
            (
                "expired",
                {
                    "expires_at": datetime.now(timezone.utc)
                    - timedelta(minutes=1)
                },
            ),
        ]
        for name, overrides in cases:
            with self.subTest(name=name):
                manifest_path, digest, _ = self._write_manifest(
                    f"invalid-{name}",
                    {"product.bin": b"candidate"},
                )
                authorization_path = self._write_authorization(
                    f"invalid-{name}",
                    event_id=f"event-invalid-{name}",
                    manifest_digest=digest,
                    **overrides,
                )
                target = self.root / f"target-invalid-{name}"
                with self.assertRaises(AdapterError):
                    self._deploy(
                        self._adapter(target),
                        name=f"invalid-{name}",
                        stage="preproduction",
                        manifest_path=manifest_path,
                        manifest_digest=digest,
                        authorization_path=authorization_path,
                    )
                self.assertFalse(target.exists())

        manifest_path, digest, output_dir = self._write_manifest(
            "source-drift",
            {"product.bin": b"candidate"},
        )
        authorization_path = self._write_authorization(
            "source-drift",
            event_id="event-source-drift",
            manifest_digest=digest,
        )
        (output_dir / "product.bin").write_bytes(b"changed-after-freeze")
        target = self.root / "target-source-drift"
        with self.assertRaisesRegex(AdapterError, "artifact size drifted"):
            self._deploy(
                self._adapter(target),
                name="source-drift",
                stage="preproduction",
                manifest_path=manifest_path,
                manifest_digest=digest,
                authorization_path=authorization_path,
            )
        self.assertFalse(target.exists())

    def test_missing_target_checks_do_not_create_directories(self) -> None:
        target = self.root / "missing-target"
        adapter = self._adapter(target)
        with self.assertRaisesRegex(AdapterError, "target directory is missing"):
            adapter.verify(
                stage="preproduction",
                deployment_ref="missing-deployment",
                rollback_ref="missing-rollback",
                expected_digest="f" * 64,
            )
        self.assertFalse(target.exists())
        with self.assertRaisesRegex(AdapterError, "target directory is missing"):
            adapter.readback(expected_digest="f" * 64)
        self.assertFalse(target.exists())

    def test_logical_names_are_portable_and_case_insensitive(self) -> None:
        for name in (" CON.dll", "CON.dll", "product.bin.", "bad\x01.bin"):
            with self.subTest(name=repr(name)):
                with self.assertRaises(AdapterError):
                    safe_logical_name(name)
        self.assertEqual("合法文件.bin", safe_logical_name("合法文件.bin"))

        output_dir = self.root / "output-case-collision"
        output_dir.mkdir()
        content = b"same-content"
        file_path = output_dir / "Product.bin"
        file_path.write_bytes(content)
        sha1 = hashlib.sha1(content).hexdigest()
        artifact = {
            "logical_name": "Product.bin",
            "file_path": str(file_path.resolve()),
            "size": len(content),
            "sha1": sha1,
            "sha256": hashlib.sha256(content).hexdigest(),
            "source_sha1": sha1,
            "source_ref": "fixture://case-collision/Product.bin",
        }
        artifacts = [
            artifact,
            {**artifact, "logical_name": "product.bin"},
        ]
        digest = object_digest(
            {
                "source_manifest_s_digest": SOURCE_MANIFEST_DIGEST,
                "artifacts": artifacts,
            }
        )
        manifest_path = self.root / "manifest-r-case-collision.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "event_id": "event-case-collision",
                    "source_manifest_s_digest": SOURCE_MANIFEST_DIGEST,
                    "output_dir": str(output_dir.resolve()),
                    "artifacts": artifacts,
                    "digest": digest,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AdapterError, "duplicate logical names"):
            load_manifest_bundle(manifest_path, digest)

    def test_target_redirect_is_rejected_without_writes(self) -> None:
        redirect = self.root / "redirect-destination"
        redirect.mkdir()
        target = self.root / "target-link"
        junction_created = False
        try:
            target.symlink_to(redirect, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            if os.name != "nt":
                self.skipTest(f"directory symlink is unavailable: {exc}")
            result = subprocess.run(
                [
                    "cmd.exe",
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(target),
                    str(redirect),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(
                    "directory symlink and junction are unavailable: "
                    f"{result.stderr or result.stdout}"
                )
            junction_created = True

        try:
            adapter = self._adapter(target)
            with self.assertRaisesRegex(AdapterError, "symlink or redirected"):
                adapter.layout.prepare_for_deploy()
            self.assertEqual([], list(redirect.iterdir()))
        finally:
            if junction_created and target.exists():
                os.rmdir(target)

    def test_cli_failure_is_machine_readable_and_has_no_side_effect(self) -> None:
        target = self.root / "cli-missing-target"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "readback",
                    "--target",
                    str(target),
                    "--expected-digest",
                    "f" * 64,
                    "--json",
                ]
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(1, exit_code)
        self.assertEqual("FAIL", payload["result"])
        self.assertEqual(
            "FILESYSTEM_ADAPTER_BLOCKED",
            payload["error_code"],
        )
        self.assertFalse(target.exists())

    def test_cli_io_failure_is_machine_readable(self) -> None:
        target = self.root / "cli-io-failure-target"
        output = io.StringIO()
        with (
            patch(
                "filesystem_release_adapter.run_operation",
                side_effect=OSError("simulated disk failure"),
            ),
            contextlib.redirect_stdout(output),
        ):
            exit_code = main(
                [
                    "readback",
                    "--target",
                    str(target),
                    "--expected-digest",
                    "f" * 64,
                    "--json",
                ]
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(1, exit_code)
        self.assertEqual("FAIL", payload["result"])
        self.assertEqual(
            "FILESYSTEM_ADAPTER_BLOCKED",
            payload["error_code"],
        )
        self.assertIn("simulated disk failure", payload["error"])
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
