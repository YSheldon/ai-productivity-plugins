from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import inspect
import time
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(SRC))

import audit_log
import execution
import host_keys
import queue_leases
import remotex_core as core
import remotex_mcp
import ssh_vnext
import task_manager
import task_worker
import vm_queue


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class ExecutionTests(unittest.TestCase):
    def test_utf16_output_is_decoded_and_counted_as_bytes(self) -> None:
        script = (
            "import sys; "
            "sys.stdout.buffer.write('中文'.encode('utf-16-le')); "
            "sys.stderr.buffer.write('错误'.encode('utf-16-le'))"
        )
        result = execution.run_process(
            [sys.executable, "-c", script],
            timeout=10,
            output_encoding="utf-16-le",
        )
        self.assertEqual(result["stdout"], "中文")
        self.assertEqual(result["stderr"], "错误")
        self.assertEqual(result["stdout_bytes"], len("中文".encode("utf-16-le")))
        self.assertEqual(result["stdout_encoding"], "utf-16-le")

    def test_output_is_bounded_without_losing_raw_byte_count(self) -> None:
        result = execution.run_process(
            [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*1000)"],
            timeout=10,
            max_stdout_bytes=32,
        )
        self.assertEqual(result["stdout_bytes"], 1000)
        self.assertTrue(result["stdout_truncated"])
        self.assertEqual(result["stdout"], "x" * 32)

    def test_windows_job_assignment_failure_is_fail_closed(self) -> None:
        source = inspect.getsource(execution.run_process)
        self.assertIn("refusing unmanaged execution", source)
        self.assertIn("if job and not job.assigned", source)

    def test_timeout_terminates_the_process_tree(self) -> None:
        result = execution.run_process(
            [sys.executable, "-c", "import time;time.sleep(10)"],
            timeout=1,
        )
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["process_tree_terminated"])
        self.assertEqual(result["termination_reason"], "wall-time-limit")

    def test_secret_reference_is_resolved_and_redacted(self) -> None:
        with mock.patch.dict(os.environ, {"LOCAL_REMOTE_TOKEN": "do-not-leak"}, clear=False):
            resolved = execution.resolve_environment_refs(
                {"REMOTE_TOKEN": "LOCAL_REMOTE_TOKEN"}
            )
        self.assertEqual(resolved[0].remote_name, "REMOTE_TOKEN")
        self.assertNotIn("do-not-leak", json.dumps(resolved[0].public()))
        self.assertEqual(
            execution.redact("value=do-not-leak", ["do-not-leak"]),
            "value=[REDACTED SECRET]",
        )


class ScriptTransportTests(unittest.TestCase):
    def _cfg(self, platform: str = "windows") -> dict:
        return {
            "profile": "lab",
            "host": "lab.example",
            "user": "operator",
            "port": 22,
            "credential_source": "ssh-agent",
            "identity_file": None,
            "known_hosts_file": None,
            "strict_host_key_checking": "yes",
            "identities_only": False,
            "connect_timeout_seconds": 10,
            "platform": platform,
        }

    def test_windows_script_and_secret_never_enter_ssh_argv(self) -> None:
        script = "Write-Output \"中文 'quoted' C:\\\\Temp\""
        with mock.patch.dict(os.environ, {"LOCAL_SECRET": "private-value"}, clear=False):
            with mock.patch.object(ssh_vnext, "connection_config", return_value=self._cfg()):
                with mock.patch.object(
                    ssh_vnext.legacy,
                    "ssh_arguments",
                    side_effect=lambda cfg, timeout, command: ["ssh", command],
                ):
                    prepared = ssh_vnext.prepare_script(
                        {
                            "script": script,
                            "shell": "powershell",
                            "environment_refs": {"REMOTE_SECRET": "LOCAL_SECRET"},
                        }
                    )
        rendered = "\n".join(prepared["argv"])
        self.assertNotIn(script, rendered)
        self.assertNotIn("private-value", rendered)
        self.assertNotIn(script.encode("utf-8"), prepared["input_bytes"])
        self.assertNotIn(b"private-value", prepared["input_bytes"])
        self.assertIn("-EncodedCommand", rendered)

    def test_powershell_wrapper_uses_job_object_and_ps51_hash_apis(self) -> None:
        self.assertIn("RemoteXNativeJob", ssh_vnext.WINDOWS_WRAPPER)
        self.assertIn("AssignProcessToJobObject", ssh_vnext.WINDOWS_WRAPPER)
        source = Path(ssh_vnext.__file__).read_text(encoding="utf-8")
        self.assertNotIn("Convert]::ToHexString", source)
        self.assertNotIn("SHA256]::HashData", source)
        self.assertIn("ComputeHash", source)

    def test_job_assignment_failure_is_a_hard_stop(self) -> None:
        self.assertIn("if (-not $job.Assigned)", ssh_vnext.WINDOWS_WRAPPER)
        self.assertIn("Unable to assign the RemoteX PowerShell process", ssh_vnext.WINDOWS_WRAPPER)

    def test_directory_manifests_use_ordinal_sorting(self) -> None:
        self.assertNotIn(".lower()", inspect.getsource(ssh_vnext._local_integrity))
        self.assertIn("[StringComparer]::Ordinal", inspect.getsource(ssh_vnext._remote_integrity))

    def test_posix_wrapper_requires_a_real_process_group(self) -> None:
        payload_bytes = ssh_vnext._shell_payload(
            "sh",
            "echo ok",
            [],
            {"memoryMb": None, "cpuSeconds": None, "maxProcesses": 2},
            30,
        )
        wrapper = payload_bytes.decode("utf-8")
        self.assertIn("setsid is required for RemoteX process-tree isolation", wrapper)
        self.assertIn("max-process limit is unsupported", wrapper)
        self.assertNotIn('else\n  "$interpreter" "$script_file" &', wrapper)

    def test_script_result_distinguishes_empty_stdout_stderr_and_nonzero(self) -> None:
        prepared = {
            "cfg": self._cfg(),
            "shell": "powershell",
            "injections": [],
        }
        outcome = {
            "returncode": 7,
            "timed_out": False,
            "stdout": "",
            "stderr": (
                '__REMOTEX_META__{"remotePid":123,"interpreter":"powershell"}\n'
                "failure only on stderr"
            ),
            "duration_ms": 12,
            "process_id": 99,
            "stdout_bytes": 0,
            "stderr_bytes": 100,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout_encoding": "utf-8",
            "stderr_encoding": "utf-8",
            "process_tree_terminated": False,
            "terminated_process_ids": [],
            "termination_reason": None,
            "peak_memory_bytes": None,
            "resource_limits": {},
        }
        result = ssh_vnext.finalize_script(prepared, outcome)
        self.assertFalse(result["ok"])
        self.assertEqual(result["exitCode"], 7)
        self.assertEqual(result["stdout"], "")
        self.assertEqual(result["stderr"], "failure only on stderr")
        self.assertEqual(result["remotePid"], 123)

    def test_sftp_path_preserves_spaces_chinese_parentheses_and_apostrophe(self) -> None:
        path = r"C:\ProgramData\Product Gate\证据 (final)\o'hare.zip"
        quoted = ssh_vnext._sftp_path(path)
        self.assertEqual(
            quoted,
            '"C:/ProgramData/Product Gate/证据 (final)/o\'hare.zip"',
        )
        self.assertNotIn("'\\''", quoted)

    def test_copy_to_reports_sha256_match_and_actual_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "evidence file.txt"
            local.write_text("evidence", encoding="utf-8")
            local_info = ssh_vnext._local_integrity(local)
            before = {"exists": False, "requestedPath": "remote"}
            after = {
                "exists": True,
                "kind": "file",
                "bytes": local_info["bytes"],
                "sha256": local_info["sha256"],
                "entryCount": 1,
                "actualPath": r"C:\ProgramData\Product Gate\evidence file.txt",
            }
            with mock.patch.object(
                ssh_vnext,
                "connection_config",
                return_value=self._cfg(),
            ):
                with mock.patch.object(
                    ssh_vnext,
                    "_remote_integrity",
                    side_effect=[before, after],
                ):
                    with mock.patch.object(core, "executable_available", return_value=True):
                        with mock.patch.object(
                            ssh_vnext,
                            "_run_sftp",
                            return_value={
                                "returncode": 0,
                                "timed_out": False,
                                "stdout": "",
                                "stderr": "",
                                "duration_ms": 5,
                                "process_id": 10,
                                "stdout_bytes": 0,
                                "stderr_bytes": 0,
                                "stdout_truncated": False,
                                "stderr_truncated": False,
                                "stdout_encoding": "utf-8",
                                "stderr_encoding": "utf-8",
                                "process_tree_terminated": False,
                                "terminated_process_ids": [],
                                "termination_reason": None,
                                "peak_memory_bytes": None,
                                "resource_limits": {},
                            },
                        ) as transfer:
                            result = payload(
                                ssh_vnext.copy_to(
                                    {
                                        "local_path": str(local),
                                        "remote_path": (
                                            r"C:\ProgramData\Product Gate\evidence file.txt"
                                        ),
                                        "verify": "sha256",
                                        "overwrite": "fail",
                                    }
                                )
                            )
        self.assertEqual(result["protocol"], "sftp")
        self.assertTrue(result["integrityMatched"])
        self.assertEqual(result["localSha256"], result["remoteSha256"])
        batch = transfer.call_args.args[2]
        self.assertIn('"C:/ProgramData/Product Gate/evidence file.txt"', batch)

    def test_synchronous_script_terminates_on_output_limit(self) -> None:
        prepared = {
            "cfg": self._cfg(),
            "shell": "powershell",
            "argv": ["ssh", "fixed"],
            "input_bytes": b"payload",
            "injections": [],
            "secrets": [],
            "timeout": 30,
            "max_stdout_bytes": 1024,
            "max_stderr_bytes": 1024,
            "output_encoding": "utf-8",
            "limits": {
                "memoryMb": None,
                "cpuSeconds": None,
                "maxProcesses": None,
            },
        }
        outcome = {
            "returncode": 0,
            "timed_out": False,
            "stdout": "",
            "stderr": "",
            "duration_ms": 1,
            "process_id": 1,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout_encoding": "utf-8",
            "stderr_encoding": "utf-8",
            "process_tree_terminated": False,
            "terminated_process_ids": [],
            "termination_reason": None,
            "peak_memory_bytes": None,
            "resource_limits": {},
        }
        with mock.patch.object(
            ssh_vnext.execution,
            "run_process",
            return_value=outcome,
        ) as runner:
            ssh_vnext._run_prepared_script(prepared)
        self.assertTrue(runner.call_args.kwargs["terminate_on_output_limit"])


class QueueLeaseTests(unittest.TestCase):
    def _config(self, directory: str) -> Path:
        identity = Path(directory) / "id_ed25519"
        identity.write_text("fixture", encoding="utf-8")
        known = Path(directory) / "known_hosts"
        known.write_text("fixture", encoding="utf-8")
        config = Path(directory) / "config.json"
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "defaults": {"ssh": "ssh-lab"},
                    "profiles": {
                        "ssh-lab": {
                            "kind": "ssh",
                            "host": "lab.example",
                            "user": "operator",
                            "platform": "windows",
                            "queue_resource": "vm:shared-lab",
                            "credential": {
                                "source": "identity-file",
                                "identity_file": str(identity),
                            },
                            "known_hosts_file": str(known),
                        },
                        "rdp-lab": {
                            "kind": "rdp",
                            "host": "lab.example",
                            "queue_resource": "vm:shared-lab",
                            "credential": {
                                "source": "windows-credential-manager",
                                "target": "TERMSRV/lab.example",
                            },
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        return config

    def test_ssh_and_rdp_share_fifo_lease_without_auto_transfer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(directory)
            environment = {
                "REMOTEX_CONFIG": str(config),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
                "REMOTEX_VM_QUEUE_LEASE_FILE": str(Path(directory) / "leases.json"),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                first = payload(
                    queue_leases.queue_claim(
                        {
                            "profile": "ssh-lab",
                            "requester": "alice",
                            "confirm": True,
                            "lease_seconds": 60,
                        }
                    )
                )
                second = payload(
                    queue_leases.queue_claim(
                        {
                            "profile": "rdp-lab",
                            "requester": "bob",
                            "confirm": True,
                            "lease_seconds": 60,
                        }
                    )
                )
                renewed = payload(
                    queue_leases.queue_renew(
                        {
                            "profile": "ssh-lab",
                            "requester": "alice",
                            "lease_seconds": 120,
                        }
                    )
                )
                released = payload(
                    queue_leases.queue_release(
                        {"profile": "ssh-lab", "requester": "alice"}
                    )
                )
                waiting = payload(
                    queue_leases.queue_status(
                        {"profile": "rdp-lab", "requester": "bob"}
                    )
                )
        self.assertTrue(first["claimed"])
        self.assertEqual(second["claim_status"], "queued-owner-active")
        self.assertEqual(renewed["renew_status"], "renewed")
        self.assertEqual(released["action_required"], "notify-first-waiter-to-confirm-claim")
        self.assertEqual(waiting["state"], "unowned")
        self.assertEqual(waiting["next_waiter"], "bob")
        self.assertTrue(waiting["claim_available"])
        self.assertIsNone(waiting["owner"])

    def test_expired_lease_releases_but_never_assigns_waiter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(directory)
            lease_file = Path(directory) / "leases.json"
            environment = {
                "REMOTEX_CONFIG": str(config),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
                "REMOTEX_VM_QUEUE_LEASE_FILE": str(lease_file),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                queue_leases.queue_claim(
                    {
                        "profile": "ssh-lab",
                        "requester": "alice",
                        "confirm": True,
                        "lease_seconds": 60,
                    }
                )
                queue_leases.queue_request(
                    {"profile": "rdp-lab", "requester": "bob"}
                )
                leases = json.loads(lease_file.read_text(encoding="utf-8"))
                leases["leases"]["vm:shared-lab"]["expiresAt"] = "2000-01-01T00:00:00Z"
                lease_file.write_text(json.dumps(leases), encoding="utf-8")
                status = payload(
                    queue_leases.queue_status(
                        {"profile": "rdp-lab", "requester": "bob"}
                    )
                )
                claimed = payload(
                    queue_leases.queue_claim(
                        {
                            "profile": "rdp-lab",
                            "requester": "bob",
                            "confirm": True,
                            "lease_seconds": 60,
                        }
                    )
                )
        self.assertEqual(status["state"], "unowned")
        self.assertIsNone(status["owner"])
        self.assertEqual(status["next_waiter"], "bob")
        self.assertEqual(claimed["claim_status"], "claimed")
        self.assertEqual(claimed["owner"]["requester"], "bob")

    def test_ssh_side_effects_share_the_queue_and_cannot_preempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(directory)
            environment = {
                "REMOTEX_CONFIG": str(config),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
                "REMOTEX_VM_QUEUE_LEASE_FILE": str(Path(directory) / "leases.json"),
            }
            outcome = {
                "returncode": 0,
                "timed_out": False,
                "stdout": "ok",
                "stderr": "",
                "duration_ms": 5,
                "process_id": 10,
                "stdout_bytes": 2,
                "stderr_bytes": 0,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "stdout_encoding": "utf-8",
                "stderr_encoding": "utf-8",
                "process_tree_terminated": False,
                "terminated_process_ids": [],
                "termination_reason": None,
                "peak_memory_bytes": None,
                "resource_limits": {},
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch.object(
                    ssh_vnext.legacy,
                    "ssh_arguments",
                    return_value=["ssh", "fixed"],
                ):
                    with mock.patch.object(
                        ssh_vnext.execution,
                        "run_process",
                        return_value=outcome,
                    ) as runner:
                        with self.assertRaisesRegex(core.ToolError, "requester"):
                            ssh_vnext.run_command(
                                {"profile": "ssh-lab", "command": "hostname"}
                            )
                        queue_leases.queue_claim(
                            {
                                "profile": "ssh-lab",
                                "requester": "alice",
                                "confirm": True,
                                "lease_seconds": 120,
                            }
                        )
                        with self.assertRaisesRegex(core.ToolError, "cannot preempt"):
                            ssh_vnext.run_command(
                                {
                                    "profile": "ssh-lab",
                                    "requester": "bob",
                                    "command": "hostname",
                                }
                            )
                        result = payload(
                            ssh_vnext.run_command(
                                {
                                    "profile": "ssh-lab",
                                    "requester": "alice",
                                    "command": "hostname",
                                }
                            )
                        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["stdout"], "ok")
        self.assertEqual(runner.call_count, 1)

    def test_legacy_owner_is_prompted_and_can_migrate_to_a_lease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = self._config(directory)
            environment = {
                "REMOTEX_CONFIG": str(config),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
                "REMOTEX_VM_QUEUE_LEASE_FILE": str(Path(directory) / "leases.json"),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                vm_queue.claim("vm:shared-lab", "alice", True)
                before = payload(
                    queue_leases.queue_status(
                        {"profile": "ssh-lab", "requester": "alice"}
                    )
                )
                health = queue_leases.health()
                migrated = payload(
                    queue_leases.queue_renew(
                        {
                            "profile": "ssh-lab",
                            "requester": "alice",
                            "lease_seconds": 120,
                        }
                    )
                )
                after = payload(
                    queue_leases.queue_status(
                        {"profile": "ssh-lab", "requester": "alice"}
                    )
                )
        self.assertEqual(before["lease"]["state"], "legacy-unleased")
        self.assertTrue(before["lease"]["renewRequired"])
        self.assertTrue(health["session_end_prompt_required"])
        self.assertEqual(health["legacy_unleased_count"], 1)
        self.assertEqual(migrated["renew_status"], "migrated-legacy-owner")
        self.assertEqual(migrated["lease"]["requester"], "alice")
        self.assertNotEqual(after["lease"].get("state"), "legacy-unleased")


class StatusAndAuditTests(unittest.TestCase):
    def test_selected_profile_readiness_is_independent_from_overall_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "profiles": {
                            "good": {
                                "kind": "ssh",
                                "host": "good.example",
                                "user": "root",
                            },
                            "bad": {
                                "kind": "ssh",
                                "host": "bad.example",
                                "user": "root",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            def fake_status(name: str, raw: dict) -> dict:
                ready = name == "good"
                return {
                    "profile": name,
                    "kind": "ssh",
                    "ready": ready,
                    "errors": [] if ready else ["fixture failure"],
                }

            environment = {
                "REMOTEX_CONFIG": str(config),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
                "REMOTEX_VM_QUEUE_LEASE_FILE": str(Path(directory) / "leases.json"),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch.dict(
                    remotex_mcp.STATUS_HANDLERS,
                    {"ssh": fake_status},
                    clear=False,
                ):
                    with mock.patch.object(
                        host_keys,
                        "profile_summary",
                        return_value={"governanceState": "registered"},
                    ):
                        result = payload(remotex_mcp.status({"profile": "good"}))
        self.assertEqual(result["overallStatus"], "not-ready")
        self.assertFalse(result["ok"])
        self.assertTrue(result["selectedProfileReady"])
        self.assertEqual(result["selectedProfile"]["profile"], "good")

    def test_managed_unregistered_profile_is_not_reported_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "profiles": {
                            "managed": {
                                "kind": "ssh",
                                "host": "managed.example",
                                "user": "root",
                                "host_key_policy": "managed",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "REMOTEX_CONFIG": str(config),
                "REMOTEX_VM_QUEUE_FILE": str(Path(directory) / "queue.json"),
                "REMOTEX_VM_QUEUE_LEASE_FILE": str(Path(directory) / "leases.json"),
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                with mock.patch.dict(
                    remotex_mcp.STATUS_HANDLERS,
                    {
                        "ssh": lambda name, raw: {
                            "profile": name,
                            "kind": "ssh",
                            "ready": True,
                            "errors": [],
                        }
                    },
                    clear=False,
                ):
                    with mock.patch.object(
                        host_keys,
                        "profile_summary",
                        return_value={
                            "policy": "managed",
                            "governanceState": "unregistered",
                        },
                    ):
                        result = payload(
                            remotex_mcp.status({"profile": "managed"})
                        )
        self.assertFalse(result["selectedProfileReady"])
        self.assertIn("not registered", result["selectedProfile"]["errors"][0])

    def test_audit_is_hash_linked_and_never_records_script_or_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_AUDIT_FILE": str(path)},
                clear=False,
            ):
                started = time.monotonic()
                operation = audit_log.begin(
                    "remotex_ssh_run_script",
                    {
                        "profile": "lab",
                        "script": "Write-Output do-not-record",
                        "environment_refs": {"TOKEN": "LOCAL_SECRET"},
                    },
                    remotex_mcp.SERVER_VERSION,
                )
                audit_log.finish(
                    operation,
                    "remotex_ssh_run_script",
                    core.tool_result({"ok": True, "exitCode": 0}),
                    remotex_mcp.SERVER_VERSION,
                    started,
                )
                exported = payload(audit_log.export({}))
                raw = path.read_text(encoding="utf-8")
        self.assertTrue(exported["chainValid"])
        self.assertEqual(exported["entryCount"], 2)
        self.assertNotIn("Write-Output do-not-record", raw)
        self.assertNotIn("do-not-record", raw)
        self.assertNotIn("LOCAL_SECRET=", raw)
        self.assertIn("scriptSha256", raw)

    def test_audit_metadata_is_attached_to_error_results(self) -> None:
        result = audit_log.attach_metadata(
            core.error_result("fixture failure"),
            "operation-fixture",
        )
        self.assertEqual(
            result["_meta"]["remotex"]["operationId"],
            "operation-fixture",
        )
        self.assertEqual(result["_meta"]["remotex"]["sessionId"], audit_log.SESSION_ID)


class HostKeyAndTaskTests(unittest.TestCase):
    def test_host_key_fingerprint_is_sha256_of_ssh_blob(self) -> None:
        blob = base64.b64encode(b"ssh-wire-key").decode("ascii")
        fingerprint = host_keys._fingerprint(blob)
        expected = base64.b64encode(
            __import__("hashlib").sha256(b"ssh-wire-key").digest()
        ).decode("ascii").rstrip("=")
        self.assertEqual(fingerprint, f"SHA256:{expected}")

    def test_managed_host_key_policy_blocks_unregistered_and_changed_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "host-keys.json"
            cfg = {
                "profile": "lab",
                "host": "lab.example",
                "port": 22,
                "host_key_policy": "managed",
                "strict_host_key_checking": "yes",
            }
            observed = [
                {
                    "algorithm": "ssh-ed25519",
                    "fingerprint": "SHA256:observed",
                    "hostField": "lab.example",
                }
            ]
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_HOSTKEY_FILE": str(registry)},
                clear=False,
            ):
                with mock.patch.object(host_keys, "_scan", return_value=(observed, [])):
                    with self.assertRaisesRegex(core.ToolError, "not registered"):
                        host_keys.enforce(cfg, 5)
                    registry.write_text(
                        json.dumps(
                            {
                                "schema": host_keys.SCHEMA,
                                "profiles": {
                                    "lab": {
                                        "host": "lab.example",
                                        "port": 22,
                                        "fingerprints": ["SHA256:observed"],
                                        "approvedAt": "2026-07-25T00:00:00Z",
                                    }
                                },
                                "events": [],
                            }
                        ),
                        encoding="utf-8",
                    )
                    matched = host_keys.enforce(cfg, 5)
                    self.assertEqual(matched["matchSource"], "remotex-registry")
                    observed.append(
                        {
                            "algorithm": "ecdsa-sha2-nistp256",
                            "fingerprint": "SHA256:unapproved-extra",
                            "hostField": "lab.example",
                        }
                    )
                    host_keys.enforce(cfg, 5)
                    observed[:] = [
                        {
                            "algorithm": "ssh-ed25519",
                            "fingerprint": "SHA256:changed",
                            "hostField": "lab.example",
                        }
                    ]
                    with self.assertRaisesRegex(core.ToolError, "absent"):
                        host_keys.enforce(cfg, 5)

    def test_host_key_approval_persists_only_the_confirmed_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "host-keys.json"
            known_hosts = Path(directory) / "known_hosts"
            cfg = {
                "profile": "lab",
                "host": "lab.example",
                "port": 22,
                "host_key_policy": "managed",
                "strict_host_key_checking": "yes",
                "known_hosts_file": known_hosts,
                "connect_timeout_seconds": 10,
            }
            first_blob = base64.b64encode(b"approved-key").decode("ascii")
            second_blob = base64.b64encode(b"unapproved-key").decode("ascii")
            first = host_keys._fingerprint(first_blob)
            second = host_keys._fingerprint(second_blob)
            keys = [
                {
                    "algorithm": "ssh-ed25519",
                    "fingerprint": first,
                    "hostField": "lab.example",
                },
                {
                    "algorithm": "ssh-rsa",
                    "fingerprint": second,
                    "hostField": "lab.example",
                },
            ]
            lines = [
                f"lab.example ssh-ed25519 {first_blob}",
                f"lab.example ssh-rsa {second_blob}",
            ]
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_HOSTKEY_FILE": str(registry)},
                clear=False,
            ):
                with mock.patch.object(
                    ssh_vnext,
                    "connection_config",
                    return_value=cfg,
                ):
                    with mock.patch.object(
                        host_keys,
                        "_scan",
                        return_value=(keys, lines),
                    ):
                        result = payload(
                            host_keys.approve(
                                {
                                    "profile": "lab",
                                    "fingerprint": first,
                                    "confirm": True,
                                }
                            )
                        )
                saved = json.loads(registry.read_text(encoding="utf-8"))
                known = known_hosts.read_text(encoding="utf-8")
        self.assertEqual(result["fingerprints"], [first])
        self.assertEqual(saved["profiles"]["lab"]["fingerprints"], [first])
        self.assertIn(first_blob, known)
        self.assertNotIn(second_blob, known)

    def test_registered_host_key_for_an_old_endpoint_is_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory) / "host-keys.json"
            registry.write_text(
                json.dumps(
                    {
                        "schema": host_keys.SCHEMA,
                        "profiles": {
                            "lab": {
                                "host": "old.example",
                                "port": 22,
                                "fingerprints": ["SHA256:old"],
                                "approvedAt": "2026-07-25T00:00:00Z",
                            }
                        },
                        "events": [],
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_HOSTKEY_FILE": str(registry)},
                clear=False,
            ):
                summary = host_keys.profile_summary(
                    "lab",
                    {
                        "kind": "ssh",
                        "host": "new.example",
                        "user": "root",
                        "host_key_policy": "managed",
                    },
                )
        self.assertEqual(summary["governanceState"], "endpoint-mismatch")
        self.assertFalse(summary["endpointMatched"])

    def test_task_spec_never_contains_script_or_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tasks"
            injection = execution.EnvironmentInjection(
                remote_name="TOKEN",
                value="task-secret-value",
                source="environment",
                reference="LOCAL_TOKEN",
                secret=True,
            )
            prepared = {
                "cfg": {
                    "profile": "lab",
                    "host": "lab.example",
                    "port": 22,
                },
                "shell": "powershell",
                "argv": ["ssh", "fixed-wrapper"],
                "input_bytes": b"opaque-stdin-payload",
                "injections": [injection],
                "secrets": ["task-secret-value"],
                "timeout": 60,
                "max_stdout_bytes": 1024,
                "max_stderr_bytes": 1024,
                "output_encoding": "utf-8",
                "limits": {
                    "memoryMb": 128,
                    "cpuSeconds": 10,
                    "maxProcesses": 4,
                },
            }
            process = mock.Mock(pid=4321)
            with mock.patch.dict(os.environ, {"REMOTEX_TASK_DIR": str(root)}, clear=False):
                with mock.patch.object(ssh_vnext, "prepare_script", return_value=prepared):
                    with mock.patch.object(
                        task_manager.subprocess,
                        "Popen",
                        return_value=process,
                    ):
                        result = payload(
                            task_manager.start(
                                {
                                    "script": "Write-Output task-secret-value",
                                    "shell": "powershell",
                                }
                            )
                        )
                task_dir = root / result["taskId"]
                spec_text = (task_dir / "spec.json").read_text(encoding="utf-8")
                secrets_text = (task_dir / "secrets.json").read_text(encoding="utf-8")
        self.assertNotIn("Write-Output", spec_text)
        self.assertNotIn("task-secret-value", spec_text)
        self.assertIn("task-secret-value", secrets_text)
        self.assertTrue(result["resumeSupported"])

    def test_task_worker_uses_the_persisted_queue_owner(self) -> None:
        self.assertIn("queueResource", inspect.getsource(task_manager._start_owned))
        self.assertIn("leased_owner_operation", inspect.getsource(task_worker._queue_operation))
        self.assertIn("requester", task_manager.TOOLS["remotex_ssh_task_start"]["inputSchema"]["properties"])

    def test_task_worker_persists_status_collects_and_removes_secret_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tasks"
            prepared = {
                "cfg": {
                    "profile": "local-test",
                    "host": "localhost",
                    "port": 22,
                },
                "shell": "sh",
                "argv": [
                    sys.executable,
                    "-c",
                    "import sys; print(sys.stdin.buffer.read().decode('utf-8'))",
                ],
                "input_bytes": b"worker-completed",
                "injections": [],
                "secrets": ["transient-task-secret"],
                "timeout": 20,
                "max_stdout_bytes": 1024,
                "max_stderr_bytes": 1024,
                "output_encoding": "utf-8",
                "limits": {
                    "memoryMb": None,
                    "cpuSeconds": None,
                    "maxProcesses": None,
                },
            }
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_TASK_DIR": str(root)},
                clear=False,
            ):
                with mock.patch.object(
                    ssh_vnext,
                    "prepare_script",
                    return_value=prepared,
                ):
                    started = payload(
                        task_manager.start(
                            {"script": "not-persisted", "shell": "sh"}
                        )
                    )
                task_id = started["taskId"]
                task_dir = root / task_id
                deadline = time.monotonic() + 15
                current = None
                while time.monotonic() < deadline:
                    current = payload(task_manager.status({"task_id": task_id}))
                    if current["finished"]:
                        break
                    time.sleep(0.05)
                self.assertIsNotNone(current)
                self.assertTrue(current["finished"])
                self.assertFalse((task_dir / "stdin.bin").exists())
                self.assertFalse((task_dir / "secrets.json").exists())
                collected = payload(
                    task_manager.collect(
                        {"task_id": task_id, "cleanup": True}
                    )
                )
        self.assertEqual(collected["state"], "completed")
        self.assertIn("worker-completed", collected["stdout"])
        self.assertTrue(collected["taskArtifactsRemoved"])
        self.assertFalse(task_dir.exists())

    def test_task_cancel_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            task_id = "00000000-0000-0000-0000-000000000001"
            task_dir = Path(directory) / task_id
            task_dir.mkdir()
            (task_dir / "state.json").write_text(
                json.dumps({"taskId": task_id, "state": "running"}),
                encoding="utf-8",
            )
            (task_dir / "worker.pid").write_text("99999999", encoding="ascii")
            with mock.patch.dict(
                os.environ,
                {"REMOTEX_TASK_DIR": directory},
                clear=False,
            ):
                first = payload(task_manager.cancel({"task_id": task_id}))
                second = payload(task_manager.cancel({"task_id": task_id}))
        self.assertEqual(first["cancelStatus"], "already-stopped")
        self.assertEqual(second["cancelStatus"], "already-finished")
        self.assertTrue(second["idempotent"])


if __name__ == "__main__":
    unittest.main()
