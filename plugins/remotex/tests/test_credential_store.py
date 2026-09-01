from __future__ import annotations

import base64
import importlib
import importlib.util
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
import host_keys
import ssh_vnext


def credential_store_module():
    if importlib.util.find_spec("credential_store") is None:
        raise AssertionError("credential_store module must exist")
    return importlib.import_module("credential_store")


def bundle(data: dict) -> core.ConfigBundle:
    validated = core._validate_config(data)
    return core.ConfigBundle(
        data=validated,
        path=Path("config.json"),
        source="test",
        exists=True,
    )


class CredentialStoreTests(unittest.TestCase):
    def test_version_two_alias_resolves_without_public_target(self) -> None:
        store = credential_store_module()
        config = bundle(
            {
                "version": 2,
                "credentials": {
                    "lab-admin": {
                        "source": "windows-credential-manager",
                        "target": "RemoteX/lab-admin",
                    }
                },
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "credential_ref": "lab-admin",
                    }
                },
            }
        )
        resolved = store.resolve_profile_reference(
            config,
            "guest",
            config.data["profiles"]["guest"],
            "windows-guest",
        )
        public = resolved.public()
        self.assertEqual(resolved.alias, "lab-admin")
        self.assertEqual(resolved.source, "windows-credential-manager")
        self.assertEqual(resolved.configuration_version, 2)
        self.assertNotIn("RemoteX/lab-admin", str(public))
        self.assertRegex(public["targetSha256"], r"^[0-9a-f]{64}$")

    def test_version_one_inline_reference_remains_compatible(self) -> None:
        store = credential_store_module()
        config = bundle(
            {
                "version": 1,
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "credential": {
                            "source": "windows-credential-manager",
                            "target": "RemoteX/legacy-guest",
                        },
                    }
                },
            }
        )
        resolved = store.resolve_profile_reference(
            config,
            "guest",
            config.data["profiles"]["guest"],
            "windows-guest",
        )
        self.assertIsNone(resolved.alias)
        self.assertEqual(resolved.configuration_version, 1)
        self.assertEqual(
            resolved.reference_dict()["target"],
            "RemoteX/legacy-guest",
        )

    def test_profile_cannot_mix_inline_and_named_reference(self) -> None:
        with self.assertRaisesRegex(core.ToolError, "credential_ref.*credential"):
            bundle(
                {
                    "version": 2,
                    "credentials": {
                        "lab": {
                            "source": "windows-integrated",
                        }
                    },
                    "defaults": {},
                    "profiles": {
                        "guest": {
                            "kind": "windows-guest",
                            "credential_ref": "lab",
                            "credential": {"source": "windows-integrated"},
                        }
                    },
                }
            )

    def test_provider_schema_and_kind_compatibility_fail_closed(self) -> None:
        store = credential_store_module()
        with self.assertRaisesRegex(core.ToolError, "unknown credential field"):
            bundle(
                {
                    "version": 2,
                    "credentials": {
                        "bad": {
                            "source": "windows-credential-manager",
                            "target": "RemoteX/bad",
                            "note": "not allowed",
                        }
                    },
                    "defaults": {},
                    "profiles": {},
                }
            )
        with self.assertRaisesRegex(core.ToolError, "incompatible"):
            bundle(
                {
                    "version": 2,
                    "credentials": {
                        "integrated": {"source": "windows-integrated"},
                    },
                    "defaults": {},
                    "profiles": {
                        "linux": {
                            "kind": "ssh",
                            "credential_ref": "integrated",
                        }
                    },
                }
            )

    def test_alias_content_rejects_known_secret_patterns(self) -> None:
        with self.assertRaisesRegex(core.ToolError, "credential material"):
            bundle(
                {
                    "version": 2,
                    "credentials": {
                        "bad": {
                            "source": "windows-credential-manager",
                            "target": "glpat-" + ("a" * 26),
                        }
                    },
                    "defaults": {},
                    "profiles": {},
                }
            )

    def test_identity_alias_requires_pinned_fingerprint_format(self) -> None:
        with self.assertRaisesRegex(core.ToolError, "expected_public_key_sha256"):
            bundle(
                {
                    "version": 2,
                    "credentials": {
                        "ssh-key": {
                            "source": "identity-file",
                            "identity_file": "~/.ssh/id_ed25519",
                            "expected_public_key_sha256": "SHA256:not-valid",
                        }
                    },
                    "defaults": {},
                    "profiles": {},
                }
            )

    def test_presence_reports_reference_only(self) -> None:
        store = credential_store_module()
        config = bundle(
            {
                "version": 2,
                "credentials": {
                    "lab-admin": {
                        "source": "windows-credential-manager",
                        "target": "RemoteX/lab-admin",
                    }
                },
                "defaults": {},
                "profiles": {
                    "guest": {
                        "kind": "windows-guest",
                        "credential_ref": "lab-admin",
                    }
                },
            }
        )
        resolved = store.resolve_profile_reference(
            config,
            "guest",
            config.data["profiles"]["guest"],
            "windows-guest",
        )
        with mock.patch.object(
            core,
            "credential_status",
            return_value={"source": "windows-credential-manager", "ready": True},
        ):
            status = resolved.presence()
        self.assertTrue(status["present"])
        self.assertNotIn("username", status)
        self.assertNotIn("password", status)
        self.assertNotIn("RemoteX/lab-admin", str(status))

    def test_expected_ssh_fingerprint_blocks_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "id_ed25519"
            identity.write_text("fixture", encoding="utf-8")
            public_blob = base64.b64encode(b"public-key-fixture").decode("ascii")
            Path(f"{identity}.pub").write_text(
                f"ssh-ed25519 {public_blob} fixture\n",
                encoding="utf-8",
            )
            cfg = {
                "profile": "linux",
                "host": "linux.example",
                "user": "root",
                "port": 22,
                "credential_source": "identity-file",
                "identity_file": identity,
                "known_hosts_file": None,
                "strict_host_key_checking": "yes",
                "identities_only": True,
                "connect_timeout_seconds": 10,
                "expected_public_key_sha256": "SHA256:" + ("A" * 43),
            }
            outcome = {
                "returncode": 0,
                "timed_out": False,
                "stdout": "",
                "stderr": "",
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "stdout_encoding": "utf-8",
                "stderr_encoding": "utf-8",
                "duration_ms": 1,
                "process_id": 1,
                "process_tree_terminated": False,
                "terminated_process_ids": [],
                "termination_reason": None,
                "peak_memory_bytes": None,
                "resource_limits": {},
            }
            with mock.patch.object(ssh_vnext, "connection_config", return_value=cfg):
                with mock.patch.object(host_keys, "enforce", return_value={}):
                    with mock.patch.object(
                        ssh_vnext.execution,
                        "run_process",
                        return_value=outcome,
                    ) as runner:
                        with self.assertRaisesRegex(core.ToolError, "fingerprint"):
                            ssh_vnext.test_connection({})
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
