from __future__ import annotations

import csv
import hashlib
import importlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import audit_log
import remotex_core as core
import remotex_mcp
import windows_guest


NOW = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)


class UsageReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "key"
        self.key.write_text("fixture-not-a-private-key", encoding="utf-8")
        self.config = {
            "version": 2, "credentials": {
                "shared": {"source": "identity-file", "identity_file": str(self.key)},
                "windows": {"source": "windows-integrated"},
                "unused": {"source": "identity-file", "identity_file": str(self.root / "missing")},
            }, "profiles": {
                "ssh-amd64": {"kind": "ssh", "host": "example.invalid", "credential_ref": "shared", "queue_resource": "host:one"},
                "ssh-x86": {"kind": "ssh", "host": "other.invalid", "credential_ref": "shared", "queue_resource": "host:two"},
                "guest-arm64": {"kind": "windows-guest", "host": "guest.invalid", "credential_ref": "windows", "host_identity": "arm-host", "guest_machine_id": "machine-a", "queue_resource": "host:arm"},
            }, "defaults": {},
        }
        self.write("config.json", self.config)
        env = mock.patch.dict(os.environ, {
            "REMOTEX_CONFIG": str(self.root / "config.json"),
            "REMOTEX_AUDIT_FILE": str(self.root / "audit.jsonl"),
            "REMOTEX_VM_QUEUE_FILE": str(self.root / "queue.json"),
            "REMOTEX_VM_QUEUE_LEASE_FILE": str(self.root / "leases.json"),
            "REMOTEX_GUEST_RECEIPT_FILE": str(self.root / "receipts.json"),
            "REMOTEX_REPORT_DIR": str(self.root / "reports"),
        })
        env.start()
        self.addCleanup(env.stop)
        self.write("queue.json", {"version": 1, "resources": {}})
        self.write("leases.json", {"schema": "RemoteXQueueLeases/v1", "leases": {}, "events": []})
        self.records = []

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")

    def module(self):
        self.assertTrue("remotex_usage_report" in remotex_mcp.TOOLS, "usage report tool missing")
        return importlib.import_module("usage_report")

    def report(self, **args):
        module = self.module()
        with mock.patch.object(module, "_now", return_value=NOW):
            return json.loads(module.report(args)["content"][0]["text"])

    def audit(self, event, identifier, time, **extra):
        record = {"schema": "RemoteXAudit/v1", "event": event, "operationId": identifier,
                  "timestamp": time, "previousHash": self.records[-1]["entryHash"] if self.records else None, **extra}
        record["entryHash"] = hashlib.sha256(audit_log._canonical(record)).hexdigest()
        self.records.append(record)
        (self.root / "audit.jsonl").write_bytes(b"".join(audit_log._canonical(r) + b"\n" for r in self.records))

    def call(self, identifier, profile, time="2026-10-09T10:00:00Z", result=None, tool="remotex_ssh_run_command"):
        self.audit("operation-start", identifier, time, tool=tool, request={"profile": profile, "script": "DO-NOT-EXPORT"})
        if result is not None:
            self.audit("operation-finish", identifier, time, tool=tool, result=result)

    def receipt(self, architecture="x64", machine="machine-a", valid=True):
        r = {"schema": windows_guest.RECEIPT_SCHEMA, "createdAtUtc": "2026-10-08T10:00:00Z", "profile": "guest-arm64",
             "pass": False, "vmIdentity": {"id": "arm-host", "identityKind": "physical-host", "guestMachineId": machine,
             "queueResource": "host:arm", "guestEndpoint": {"host": "guest.invalid", "port": 5985}},
             "evidence": {"architecture": architecture, "osVersion": "10.0.26200", "machineId": machine}, "runId": "test"}
        r["sha256"] = hashlib.sha256(audit_log._canonical(r)).hexdigest()
        if not valid:
            r["evidence"]["osVersion"] = "1.2.3"
        self.write("receipts.json", {"schema": windows_guest.RECEIPT_STATE_SCHEMA, "receipts": {r["sha256"]: r}})

    def test_shared_credential_groups_calls_and_counts_start_once(self):
        self.call("a", "ssh-amd64", result={"ok": True})
        self.call("b", "ssh-x86", result={"isError": True})
        self.call("c", "ssh-x86")
        self.call("old", "ssh-amd64", time="2026-01-01T00:00:00Z", result={"ok": True})
        report = self.report(credential_ref="shared", days=7)
        self.assertEqual(len(report["credentials"]), 1)
        group = report["credentials"][0]
        self.assertEqual(group["usage"]["remoteCalls"], 3)
        self.assertEqual(group["usage"]["failedCalls"], 1)
        self.assertEqual(group["usage"]["unfinishedCalls"], 1)
        self.assertEqual(group["usage"]["lastUsedAtUtc"], "2026-10-09T10:00:00Z")
        self.assertEqual(set(group["profiles"]), {"ssh-amd64", "ssh-x86"})
        self.assertNotIn("DO-NOT-EXPORT", json.dumps(report))
        self.assertNotIn(str(self.key), json.dumps(report))

    def test_management_calls_are_not_remote_usage_and_absent_profile_not_defaulted(self):
        self.call("a", "ssh-amd64", result={"ok": True}, tool="remotex_vm_queue_status")
        self.call("b", None, result={"ok": True})
        report = self.report()
        self.assertEqual(report["credentials"][0]["usage"]["remoteCalls"], 0)
        self.assertEqual(report["summary"]["unattributedCalls"], 1)

    def test_missing_audit_is_unknown_coverage_and_unused_alias_is_queryable(self):
        report = self.report(credential_ref="unused")
        self.assertFalse(report["coverage"]["audit"]["available"])
        self.assertEqual(report["credentials"][0]["profiles"], [])
        self.assertFalse(report["credentials"][0]["referencePresent"])

    def test_invalid_filters_rejected(self):
        for args in ({"days": 0}, {"days": True}, {"days": 366}, {"days": "7"},
                     {"credential_ref": "shared", "profile": "ssh-x86"}, {"profile": "missing"},
                     {"credential_ref": "missing"}, {"password": "no"}):
            with self.subTest(args=args), self.assertRaises(core.ToolError):
                self.report(**args)

    def test_tampered_audit_fails_without_leaking_record(self):
        self.call("a", "ssh-amd64", result={"ok": True})
        file = self.root / "audit.jsonl"
        file.write_text(file.read_text().replace("DO-NOT-EXPORT", "SECRET-CANARY"))
        with self.assertRaises(core.ToolError) as error:
            self.report()
        self.assertNotIn("SECRET-CANARY", str(error.exception))

    def test_duplicate_start_is_not_double_counted_and_flagged(self):
        self.call("a", "ssh-amd64", result={"ok": True})
        self.audit("operation-start", "a", "2026-10-09T10:00:00Z", tool="remotex_ssh_run_command", request={"profile":"ssh-amd64"})
        report = self.report(credential_ref="shared")
        self.assertEqual(report["credentials"][0]["usage"]["remoteCalls"], 1)
        self.assertEqual(report["coverage"]["audit"]["duplicateStarts"], 1)

    def test_verified_receipt_does_not_promote_64bit_to_amd64(self):
        self.receipt()
        p = self.report(profile="guest-arm64")["profiles"][0]
        self.assertEqual(p["system"]["osVersion"], "10.0.26200")
        self.assertEqual(p["system"]["bitness"], 64)
        self.assertIsNone(p["system"]["nativeArchitecture"])
        self.assertEqual(p["system"]["architectureLabel"], "Arm64")

    def test_conflicting_architecture_is_explicit(self):
        self.receipt(architecture="x86")
        self.assertTrue(self.report(profile="guest-arm64")["profiles"][0]["system"]["architectureConflict"])

    def test_tampered_or_wrong_machine_receipt_is_not_used(self):
        for kwargs in ({"valid": False}, {"machine": "different"}):
            self.receipt(**kwargs)
            self.assertIsNone(self.report(profile="guest-arm64")["profiles"][0]["system"]["osVersion"])

    def test_changed_endpoint_receipt_is_not_used(self):
        self.receipt()
        self.config["profiles"]["guest-arm64"]["host"] = "new.invalid"
        self.write("config.json", self.config)
        self.assertIsNone(self.report(profile="guest-arm64")["profiles"][0]["system"]["osVersion"])

    def test_queue_renewals_are_unioned_and_release_clips_reservation(self):
        self.write("leases.json", {"schema":"RemoteXQueueLeases/v1", "leases":{}, "events":[
            {"event":"lease-issued","resource":"host:one","requester":"a","timestamp":"2026-10-10T08:00:00Z","expiresAt":"2026-10-10T10:00:00Z"},
            {"event":"lease-renewed","resource":"host:one","requester":"a","timestamp":"2026-10-10T09:00:00Z","expiresAt":"2026-10-10T12:00:00Z"},
            {"event":"lease-released","resource":"host:one","requester":"a","timestamp":"2026-10-10T11:00:00Z"},
        ]})
        report = self.report(profile="ssh-amd64", days=1)
        q = report["queues"][0]
        self.assertEqual(q["observedReservedSeconds"], 10800)
        self.assertEqual(q["observedReservationPercent"], 12.5)
        self.assertEqual(q["coverage"], "recorded-intervals-lower-bound")

    def test_expired_owner_not_mutated_and_current_lease_visible(self):
        self.write("queue.json", {"version":1,"resources":{"host:one":{"owner":{"requester":"a","claimed_at":"2026-10-10T08:00:00Z"},"waiters":[]}}})
        self.write("leases.json", {"schema":"RemoteXQueueLeases/v1","leases":{"host:one":{"requester":"a","issuedAt":"2026-10-10T08:00:00Z","expiresAt":"2026-10-10T09:00:00Z","leaseSeconds":3600}},"events":[]})
        before = {p: p.read_bytes() for p in (self.root / "queue.json", self.root / "leases.json")}
        q = self.report(profile="ssh-amd64")["queues"][0]
        self.assertEqual(q["state"], "expired-persisted-owner")
        self.assertEqual(before, {p:p.read_bytes() for p in before})

    def test_export_escapes_html_and_csv_formulas_in_unique_directory(self):
        name = '=2+3<script>alert(1)</script>'
        self.config["profiles"][name] = self.config["profiles"].pop("ssh-x86")
        self.write("config.json", self.config)
        module = self.module()
        with mock.patch.object(module, "_now", return_value=NOW):
            result = json.loads(module.export_report({})["content"][0]["text"])
        directory = Path(result["directory"])
        self.assertTrue(directory.is_relative_to(self.root / "reports"))
        html = (directory / "report.html").read_text(encoding="utf-8")
        self.assertNotIn('<script>', html)
        with (directory / "profiles.csv").open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertIn("'" + name, [r["profile"] for r in rows])
        for filename, digest in result["sha256"].items():
            self.assertEqual(hashlib.sha256((directory / filename).read_bytes()).hexdigest(), digest)

    def test_legacy_heartbeat_migration_is_counted_and_expiry_clipped(self):
        self.write("leases.json", {"schema":"RemoteXQueueLeases/v1", "leases":{}, "events":[
            {"event":"lease-heartbeat-migrated","resource":"host:one","requester":"a","timestamp":"2026-10-10T08:00:00Z","expiresAt":"2026-10-10T10:00:00Z"},
        ]})
        q = self.report(profile="ssh-amd64", days=1)["queues"][0]
        self.assertEqual(q["observedReservedSeconds"], 7200)

    def test_malformed_profile_argument_in_historical_audit_is_not_replayed(self):
        self.call("bad", ["not-a-profile"], result={"isError":True})
        report = self.report()
        self.assertEqual(report["summary"]["usage"]["remoteCalls"], 1)
        self.assertEqual(report["summary"]["unattributedCalls"], 1)

    def test_future_receipt_is_not_current_evidence(self):
        self.receipt()
        file = self.root / "receipts.json"
        r = next(iter(json.loads(file.read_text())["receipts"].values()))
        r.pop("sha256")
        r["createdAtUtc"] = "2026-11-01T00:00:00Z"
        r["sha256"] = hashlib.sha256(audit_log._canonical(r)).hexdigest()
        self.write("receipts.json", {"schema":windows_guest.RECEIPT_STATE_SCHEMA,"receipts":{r["sha256"]:r}})
        report = self.report(profile="guest-arm64")
        self.assertIsNone(report["profiles"][0]["system"]["osVersion"])

    def test_inline_reference_and_shared_queue_deduplicate_independently(self):
        inline = {"source":"identity-file","identity_file":str(self.key)}
        self.config["profiles"] = {name:{"kind":"ssh","host":"example.invalid","credential":inline,"queue_resource":"one"} for name in ("a","b")}
        self.config["credentials"] = {}
        self.write("config.json", self.config)
        self.call("a", "a", result={"ok":True})
        report = self.report()
        self.assertEqual(len(report["credentials"]), 1)
        self.assertEqual(len(report["queues"]), 1)
        self.assertEqual(report["credentials"][0]["usage"]["remoteCalls"], 1)

    def test_vsphere_reports_observed_vm_resources(self):
        self.config["credentials"]["vc"] = {"source":"environment","username_env":"TEST_VC_USER","password_env":"TEST_VC_PASSWORD"}
        self.config["profiles"]["vc"] = {"kind":"vsphere","url":"https://vcenter.invalid","credential_ref":"vc","queue_resource":"cluster"}
        self.write("config.json", self.config)
        self.write("leases.json", {"schema":"RemoteXQueueLeases/v1","leases":{},"events":[
            {"event":"lease-issued","resource":"cluster:/dc/vm/test","requester":"a","timestamp":"2026-10-10T08:00:00Z","expiresAt":"2026-10-10T09:00:00Z"},
        ]})
        report = self.report(credential_ref="vc")
        self.assertEqual(report["queues"][0]["resource"], "cluster:/dc/vm/test")

    def test_mcp_query_and_export_tools_are_callable(self):
        module = self.module()
        with mock.patch.object(module, "_now", return_value=NOW):
            reply = remotex_mcp.handle_request({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"remotex_usage_report","arguments":{"credential_ref":"shared"}}})
        value = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(value["filter"]["credentialRef"], "shared")
        self.assertTrue(value["ok"])
        listing = remotex_mcp.handle_request({"jsonrpc":"2.0","id":2,"method":"tools/list"})
        self.assertIn("remotex_usage_export", [tool["name"] for tool in listing["result"]["tools"]])

    def test_vsphere_template_matches_suffix_and_repeated_vm_exactly(self):
        module = self.module()
        resources = {"fleet:vm1:maintenance", "fleet:vm2:production", "fleet:unrelated"}
        self.assertEqual(module._resource_names("vc", {"kind":"vsphere","queue_resource":"fleet:{virtual_machine}:maintenance"}, resources), ["fleet:vm1:maintenance"])
        self.assertEqual(module._resource_names("vc", {"kind":"vsphere","queue_resource":"{virtual_machine}:maintenance"}, resources), ["fleet:vm1:maintenance"])
        self.assertEqual(module._resource_names("vc", {"kind":"vsphere","queue_resource":"{virtual_machine}:{virtual_machine}"}, {"vm1:vm1","vm1:vm2"}), ["vm1:vm1"])

    def test_filtered_alias_uses_same_normalization_as_credential_resolver(self):
        self.config["profiles"]["ssh-x86"]["credential_ref"] = " shared "
        self.write("config.json", self.config)
        self.call("one", "ssh-x86", result={"ok":True})
        report = self.report(credential_ref="shared")
        self.assertEqual(set(report["credentials"][0]["profiles"]), {"ssh-x86", "ssh-amd64"})
        self.assertEqual(report["credentials"][0]["usage"]["remoteCalls"], 1)

    def test_audit_profile_selector_uses_runtime_normalization(self):
        self.call("one", " ssh-amd64 ", result={"ok":True})
        report = self.report(credential_ref="shared")
        self.assertEqual(report["credentials"][0]["usage"]["remoteCalls"], 1)
        self.assertEqual(report["summary"]["removedProfileCalls"], 0)

    def test_vsphere_resource_uses_runtime_whitespace_normalization(self):
        module = self.module()
        self.assertEqual(module._resource_names("vc", {"kind":"vsphere","queue_resource":" cluster "}, {"cluster:vm1"}), ["cluster:vm1"])
        self.assertEqual(module._resource_names("vc", {"kind":"vsphere","url":" https://vcenter.invalid/ "}, {"vsphere:https://vcenter.invalid:vm1"}), ["vsphere:https://vcenter.invalid:vm1"])


if __name__ == "__main__":
    unittest.main()
