from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import audit_log
import credential_store
import credential_tools
import queue_leases
import remotex_core as core
import secure_paths
import vm_identity
import vm_queue
import windows_guest


SCHEMA = "RemoteXUsageReport/v1"
NOTES = [
    "Local metadata only; no remote connection or queue acquisition is performed.",
    "Credential attribution uses current profile bindings, not historical proof of the credential used.",
    "Calls are deduplicated by operationId; diagnostics include task polling and connection tests.",
    "Last-used time covers the available audit history; call counts cover the selected rolling window.",
    "Credential activity includes failed attempts and does not prove successful authentication.",
    "Architecture labels come from configuration names; 64-bit receipts do not identify AMD64 versus Arm64.",
    "System versions are historical, identity-bound receipts, not current test admission or an OS edition inventory.",
    "Queue reservation is a recorded lower bound, not CPU utilization or actual machine activity.",
    "Lease history retains at most 1000 events; unrecorded intervals and access outside RemoteX are unknown.",
    "Shared queue resources are deduplicated; profile and credential counts are not machine counts.",
    "Sources are sampled under their own locks, not as one transaction across all state files.",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except ValueError:
        return None


def _stamp(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _percent(numerator: float, denominator: float) -> float | None:
    return round(100 * numerator / denominator, 2) if denominator else None


def _arguments(args: dict[str, Any]) -> tuple[str | None, str | None, int]:
    if set(args) - {"profile", "credential_ref", "days"}:
        raise core.ToolError("Unsupported usage report argument")
    values = []
    for name in ("profile", "credential_ref"):
        value = args.get(name)
        if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 256):
            raise core.ToolError(f"{name} must be a non-empty selector")
        values.append(value.strip() if value else None)
    if all(values):
        raise core.ToolError("Pass profile or credential_ref, not both")
    days = args.get("days", 30)
    if type(days) is not int or not 1 <= days <= 365:
        raise core.ToolError("days must be an integer between 1 and 365")
    return values[0], values[1], days


def _audit_snapshot() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = audit_log.audit_path()
    if not path.exists():
        return [], {"available": False, "entryCount": 0, "chainValid": None, "sha256": None}
    try:
        with audit_log._PROCESS_LOCK, audit_log._locked_file(path) as handle:
            records = audit_log._records(handle)
            last_hash = audit_log._verify_records(records)
            handle.seek(0)
            digest = hashlib.sha256(handle.read().lstrip(b"\x00")).hexdigest()
    except (OSError, core.ToolError) as exc:
        raise core.ToolError("Usage report audit snapshot is unavailable or failed integrity validation") from exc
    return records, {"available": True, "entryCount": len(records), "chainValid": True,
                     "sha256": digest, "lastEntryHash": last_hash}


def _category(tool: str) -> str:
    if tool.startswith("remotex_vm_queue_"):
        return "queue"
    if re.match(r"remotex_(status$|audit_|credential_|profile_|usage_|web_profile_setup|web_runtime_setup|ssh_host_key_|ssh_agent_)", tool):
        return "management"
    if re.search(r"(_test|_about|_list_vms|_list_snapshots|_preflight|_task_status|_session_status|_key_fingerprint)$", tool):
        return "diagnostic"
    if tool.startswith(("remotex_ssh_", "remotex_windows_guest_", "remotex_vmware_", "remotex_vsphere_", "remotex_rdp_", "remotex_web_")):
        return "work"
    return "other"


def _operations(records: list[dict[str, Any]], now: datetime, coverage: dict[str, Any]) -> list[dict[str, Any]]:
    starts: dict[str, dict[str, Any]] = {}
    finishes: dict[str, dict[str, Any]] = {}
    counts = {"duplicateStarts": 0, "duplicateFinishes": 0, "invalidRecords": 0}
    times = []
    for entry in records:
        time = _time(entry.get("timestamp"))
        identifier = entry.get("operationId")
        if not time or not isinstance(identifier, str):
            counts["invalidRecords"] += 1
            continue
        if time > now:
            counts["invalidRecords"] += 1
            continue
        times.append(time)
        event = entry.get("event")
        if event == "operation-start":
            tool, request = entry.get("tool"), entry.get("request")
            if not isinstance(tool, str) or not isinstance(request, dict):
                counts["invalidRecords"] += 1
                continue
            profile = request.get("profile")
            if profile is not None and not isinstance(profile, str):
                counts["invalidRecords"] += 1
                profile = None
            elif isinstance(profile, str):
                profile = profile.strip() or None
            if identifier in starts:
                counts["duplicateStarts"] += 1
                if (tool, profile) != (starts[identifier]["tool"], starts[identifier]["profile"]):
                    raise core.ToolError("Usage report found conflicting duplicate operation IDs")
                continue
            starts[identifier] = {"time": time, "tool": tool, "profile": profile, "category": _category(tool)}
        elif event == "operation-finish":
            if identifier in finishes:
                counts["duplicateFinishes"] += 1
                continue
            finishes[identifier] = entry
    for identifier, op in starts.items():
        finish = finishes.get(identifier)
        valid = finish and finish.get("tool") == op["tool"] and _time(finish["timestamp"]) >= op["time"]
        op["result"] = finish.get("result") if valid and isinstance(finish.get("result"), dict) else None
    coverage.update(counts)
    coverage.update({"firstAtUtc": _stamp(min(times)) if times else None,
                     "lastAtUtc": _stamp(max(times)) if times else None,
                     "orphanFinishes": len(set(finishes) - set(starts))})
    return list(starts.values())


def _metrics(ops: list[dict[str, Any]], start: datetime) -> dict[str, Any]:
    selected = [op for op in ops if op["time"] >= start]
    remote = [op for op in selected if op["category"] in {"work", "diagnostic"}]
    failed = successful = unknown = unfinished = 0
    for op in remote:
        result = op["result"]
        if result is None:
            unfinished += 1
        elif any(result.get(k) is True for k in ("isError", "timedOut", "timed_out")) or result.get("ok") is False or any(
            type(result.get(k)) is int and result[k] != 0 for k in ("exitCode", "returncode", "clientReturnCode")
        ):
            failed += 1
        elif result.get("ok") is True or any(type(result.get(k)) is int and result[k] == 0 for k in ("exitCode", "returncode", "clientReturnCode")):
            successful += 1
        else:
            unknown += 1
    last = max((op["time"] for op in ops if op["category"] in {"work", "diagnostic"}), default=None)
    return {"allCalls": len(selected), "remoteCalls": len(remote),
            "workCalls": sum(op["category"] == "work" for op in selected),
            "diagnosticCalls": sum(op["category"] == "diagnostic" for op in selected),
            "queueCalls": sum(op["category"] == "queue" for op in selected),
            "managementCalls": sum(op["category"] == "management" for op in selected),
            "otherCalls": sum(op["category"] == "other" for op in selected),
            "failedCalls": failed, "successfulCalls": successful, "unknownOutcomeCalls": unknown,
            "unfinishedCalls": unfinished, "knownOutcomeSuccessPercent": _percent(successful, successful + failed),
            "lastUsedAtUtc": _stamp(last)}


def _state_snapshot() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        # Match the lease -> queue lock order used by queue acquisition.
        with queue_leases._locked() as (_, leases):
            with vm_queue._locked_state() as (_, queue):
                pass
        with windows_guest._locked_receipts() as receipts:
            pass
    except (OSError, core.ToolError) as exc:
        raise core.ToolError("Usage report local queue or receipt state is unavailable") from exc
    return queue, leases, receipts


def _receipt_index(state: dict[str, Any], now: datetime) -> tuple[list[dict[str, Any]], int]:
    valid, invalid = [], 0
    for digest, receipt in state["receipts"].items():
        if not isinstance(receipt, dict):
            invalid += 1
            continue
        unsigned = dict(receipt)
        unsigned.pop("sha256", None)
        time = _time(receipt.get("createdAtUtc"))
        if (receipt.get("schema") != windows_guest.RECEIPT_SCHEMA or receipt.get("sha256") != digest
                or windows_guest._hash_receipt(unsigned) != digest or not time or time > now
                or not isinstance(receipt.get("vmIdentity"), dict) or not isinstance(receipt.get("evidence"), dict)):
            invalid += 1
            continue
        valid.append(receipt)
    return sorted(valid, key=lambda r: _time(r["createdAtUtc"]), reverse=True), invalid


def _system(name: str, raw: dict[str, Any], receipts: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    label = " ".join(str(raw.get(k) or "") for k in ("vm_identity", "host_identity", "queue_resource")) + " " + name
    architecture = ("Arm64" if re.search(r"arm64|aarch64", label, re.I) else
                    "AMD64" if re.search(r"amd64|x86_64|x64", label, re.I) else
                    "x86" if re.search(r"x86|i[3-6]86", label, re.I) else None)
    result = {"osVersion": None, "bitness": None, "nativeArchitecture": None,
              "architectureLabel": architecture, "architectureLabelSource": "configuration-name" if architecture else None,
              "architectureConflict": False, "evidenceAtUtc": None, "evidenceAgeDays": None,
              "evidenceSha256": None, "evidenceSource": "unavailable"}
    try:
        binding = vm_identity.binding_for_profile(name, raw, require_identity=False)
    except core.ToolError:
        result["evidenceSource"] = "current-identity-unavailable"
        return result
    if not binding:
        return result
    for receipt in receipts:
        identity, evidence = receipt["vmIdentity"], receipt["evidence"]
        keys = ("id", "identityKind", "queueResource", "guestMachineId", "guestEndpoint", "vmwareUuid")
        if any(identity.get(k) != binding.get(k) for k in keys):
            continue
        if str(evidence.get("machineId", "")).casefold() != str(binding.get("guestMachineId", "")).casefold():
            continue
        version = evidence.get("osVersion")
        if not isinstance(version, str) or not re.fullmatch(r"\d+(?:\.\d+){1,3}", version):
            continue
        bits = {"x64": 64, "x86": 32}.get(evidence.get("architecture"))
        result.update({"osVersion": version, "bitness": bits, "evidenceAtUtc": receipt["createdAtUtc"],
                       "evidenceSha256": receipt["sha256"], "evidenceSource": "historical-preflight-receipt",
                       "evidenceAgeDays": round((now - _time(receipt["createdAtUtc"])).total_seconds() / 86400, 2),
                       "architectureConflict": bool((architecture in {"AMD64", "Arm64"} and bits == 32) or (architecture == "x86" and bits == 64))})
        break
    return result


def _resource_names(name: str, raw: dict[str, Any], known: set[str]) -> list[str]:
    kind = core.normalize_kind(raw.get("kind"))
    if kind == "ssh":
        return [vm_queue._validate_resource(raw["queue_resource"])] if raw.get("queue_resource") else []
    if kind == "vsphere":
        configured = raw.get("queue_resource")
        if configured:
            configured = vm_queue._validate_resource(configured)
            if "{virtual_machine}" in configured:
                placeholder = re.escape("{virtual_machine}")
                pattern = re.escape(configured).replace(placeholder, "(?P<vm>.+)", 1).replace(placeholder, "(?P=vm)")
                return sorted(resource for resource in known if re.fullmatch(pattern, resource))
            prefix = configured + ":"
        else:
            url = core._text(raw.get("url")).strip().rstrip("/")
            parsed = urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                return []
            prefix = f"vsphere:{url}:"
        return sorted(resource for resource in known if resource.startswith(prefix))
    try:
        return [vm_queue.resolve_profile_resource(name)["resource"]]
    except core.ToolError:
        return []


def _queue_rows(resources: set[str], queue: dict[str, Any], leases: dict[str, Any], start: datetime, now: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    active: dict[str, dict[str, Any]] = {}
    spans: dict[str, list[tuple[datetime, datetime]]] = {}
    events = leases["events"]
    invalid = 0
    valid = []
    def add(resource: str, record: dict[str, Any], end: datetime) -> None:
        end = min(record["end"], end, now)
        if end > record["start"]:
            spans.setdefault(resource, []).append((record["start"], end))
    for event in events:
        if not isinstance(event, dict) or not _time(event.get("timestamp")) or not isinstance(event.get("resource"), str):
            invalid += 1
            continue
        valid.append(event)
    valid.sort(key=lambda e: _time(e["timestamp"]))
    for event in valid:
        resource, time = event.get("resource"), _time(event["timestamp"])
        if resource not in resources or time > now:
            continue
        prior = active.get(resource)
        if event.get("event") in {"lease-issued", "lease-auto-acquired", "lease-renewed", "lease-heartbeat", "lease-migrated", "lease-heartbeat-migrated"}:
            end = _time(event.get("expiresAt"))
            if not end or end <= time:
                invalid += 1
                continue
            if prior and prior["requester"] == event.get("requester") and time <= prior["end"]:
                prior["end"] = end
            else:
                if prior:
                    add(resource, prior, time)
                active[resource] = {"start": time, "end": end, "requester": event.get("requester")}
        elif event.get("event") in {"lease-released", "lease-expired", "lease-recovered"} and prior and prior["requester"] == event.get("requester"):
            add(resource, prior, time)
            active.pop(resource)
    for resource, record in active.items():
        add(resource, record, now)
    rows = []
    for resource in sorted(resources):
        entry = queue["resources"].get(resource, {})
        owner, waiters = entry.get("owner"), entry.get("waiters", [])
        lease = leases["leases"].get(resource)
        coherent = bool(owner and lease and owner["requester"] == lease["requester"])
        expiry = _time(lease.get("expiresAt")) if lease else None
        if coherent:
            add(resource, {"start": _time(lease["issuedAt"]), "end": expiry}, now)
        state = ("held" if coherent and expiry > now else "expired-persisted-owner" if coherent else
                 "owner-lease-inconsistent-or-legacy" if owner or lease else "waiting-unowned" if waiters else "unowned")
        merged: list[list[datetime]] = []
        for left, right in sorted(spans.get(resource, [])):
            left, right = max(left, start), min(right, now)
            if right <= left:
                continue
            if merged and left <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], right)
            else:
                merged.append([left, right])
        seconds = sum((right - left).total_seconds() for left, right in merged)
        rows.append({"resource": resource, "state": state, "owner": owner.get("requester") if owner else None,
                     "waiterCount": len(waiters), "leaseExpiresAtUtc": _stamp(expiry),
                     "observedReservedSeconds": round(seconds, 3),
                     "observedReservationPercent": _percent(seconds, (now - start).total_seconds()),
                     "coverage": "recorded-intervals-lower-bound"})
    return rows, {"retainedEvents": len(events), "historyMayBeTruncated": len(events) >= 1000,
                  "firstEventAtUtc": valid[0]["timestamp"] if valid else None, "invalidEvents": invalid,
                  "reservationIsLowerBound": True}


def build_report(args: dict[str, Any]) -> dict[str, Any]:
    requested_profile, requested_ref, days = _arguments(args)
    now = _now()
    start = now - timedelta(days=days)
    bundle = core.load_config()
    profiles = bundle.data["profiles"]
    if requested_profile and requested_profile not in profiles:
        raise core.ToolError("Usage report profile not found")
    if requested_ref and requested_ref not in bundle.data.get("credentials", {}):
        raise core.ToolError("Usage report credential_ref not found")
    records, audit = _audit_snapshot()
    operations = _operations(records, now, audit)
    queue, leases, receipt_state = _state_snapshot()
    receipts, invalid_receipts = _receipt_index(receipt_state, now)
    known_resources = set(queue["resources"]) | set(leases["leases"]) | {
        e["resource"] for e in leases["events"] if isinstance(e, dict) and isinstance(e.get("resource"), str)
    }
    grouped: dict[str, dict[str, Any]] = {}
    profile_rows = []
    selected_resources: set[str] = set()
    for name, raw in sorted(profiles.items()):
        if requested_profile and name != requested_profile:
            continue
        if requested_ref and core._text(raw.get("credential_ref")).strip() != requested_ref:
            continue
        kind = core.normalize_kind(raw.get("kind"))
        reference = key = None
        failure = None
        if kind != "vmware-workstation":
            try:
                reference = credential_store.resolve_profile_reference(bundle, name, raw, kind)
                key = credential_tools._reference_key(reference)
                grouped.setdefault(key, {"reference": reference, "profiles": []})["profiles"].append(name)
            except core.ToolError:
                failure = "credential-reference-invalid"
        resources = _resource_names(name, raw, known_resources)
        selected_resources.update(resources)
        profile_rows.append({"profile": name, "kind": kind, "credentialId": key,
                             "credentialRef": reference.alias if reference else None,
                             "credentialFailureCode": failure, "queueResources": resources,
                             "system": _system(name, raw, receipts, now),
                             "usage": _metrics([op for op in operations if op["profile"] == name], start)})
    # Unused aliases are useful inventory entries and remain directly queryable.
    if not requested_profile:
        for alias in sorted(bundle.data.get("credentials", {})):
            if requested_ref and alias != requested_ref:
                continue
            reference = credential_store.resolve_named_reference(bundle, alias)
            grouped.setdefault(credential_tools._reference_key(reference), {"reference": reference, "profiles": []})
    queue_rows, queue_coverage = _queue_rows(selected_resources, queue, leases, start, now)
    credentials = []
    for key, group in sorted(grouped.items()):
        reference, consumers = group["reference"], group["profiles"]
        try:
            present = reference.presence().get("present")
        except (OSError, core.ToolError):
            present = None
        members = [row for row in profile_rows if row["profile"] in consumers]
        credentials.append({"credentialId": key, "credentialRef": reference.alias, "source": reference.source,
                            "referencePresent": present, "profiles": consumers,
                            "systems": [{"profile": row["profile"], **row["system"]} for row in members],
                            "queueResources": sorted({r for row in members for r in row["queueResources"]}),
                            "usage": _metrics([op for op in operations if op["profile"] in consumers], start)})
    selected_names = {row["profile"] for row in profile_rows}
    scope_ops = [op for op in operations if op["profile"] in selected_names] if requested_ref or requested_profile else operations
    active_count = sum(c["usage"]["remoteCalls"] > 0 for c in credentials)
    return {"ok": True, "schema": SCHEMA, "generatedAtUtc": _stamp(now),
            "window": {"days": days, "startAtUtc": _stamp(start), "endAtUtc": _stamp(now)},
            "filter": {"profile": requested_profile, "credentialRef": requested_ref},
            "summary": {"profiles": len(profile_rows), "credentialReferences": len(credentials),
                        "presentCredentials": sum(c["referencePresent"] is True for c in credentials),
                        "missingCredentials": sum(c["referencePresent"] is False for c in credentials),
                        "activeCredentials": active_count, "credentialActivityPercent": _percent(active_count, len(credentials)),
                        "systemEvidenceProfiles": sum(bool(p["system"]["osVersion"]) for p in profile_rows),
                        "architectureConflicts": sum(p["system"]["architectureConflict"] for p in profile_rows),
                        "heldResources": sum(q["state"] == "held" for q in queue_rows),
                        "waitingRequests": sum(q["waiterCount"] for q in queue_rows),
                        "unattributedCalls": sum(not op["profile"] and op["time"] >= start for op in operations),
                        "removedProfileCalls": sum(bool(op["profile"]) and op["profile"] not in profiles and op["time"] >= start for op in operations),
                        "usage": _metrics(scope_ops, start)},
            "credentials": credentials, "profiles": profile_rows, "queues": queue_rows,
            "coverage": {"audit": audit, "queue": queue_coverage,
                         "systemReceipts": {"valid": len(receipts), "invalid": invalid_receipts},
                         "credentialAttribution": "current-profile-bindings", "remoteProbesPerformed": False},
            "notes": NOTES}


def report(args: dict[str, Any]) -> dict[str, Any]:
    return core.tool_result(build_report(args))


def _csv_value(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else "" if value is None else str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text


def _flat(row: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, value in row.items():
        if key in {"usage", "system"}:
            result.update({f"{key}.{k}": v for k, v in value.items()})
        else:
            result[key] = value
    return result


def _table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "<p>No matching records.</p>"
    fields = list(rows[0])
    def display(value: Any) -> str:
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        return html.escape("Unknown" if value is None else str(value))
    return '<div class="table-wrap"><table><thead><tr>' + ''.join(f"<th>{html.escape(k)}</th>" for k in fields) + '</tr></thead><tbody>' + ''.join(
        '<tr>' + ''.join(f"<td>{display(row.get(k))}</td>" for k in fields) + '</tr>' for row in rows
    ) + '</tbody></table></div>'


def render_html(data: dict[str, Any]) -> str:
    credentials = [{"Credential": c["credentialRef"] or c["credentialId"], "Provider": c["source"],
                    "Present": c["referencePresent"], "Profiles": c["profiles"],
                    "Remote calls": c["usage"]["remoteCalls"], "Failed calls": c["usage"]["failedCalls"],
                    "Last used (UTC)": c["usage"]["lastUsedAtUtc"]} for c in data["credentials"]]
    profiles = [{"Profile": p["profile"], "Credential": p["credentialRef"] or p["credentialId"],
                 "OS version": p["system"]["osVersion"], "OS bitness": p["system"]["bitness"],
                 "Architecture label": p["system"]["architectureLabel"], "Conflict": p["system"]["architectureConflict"],
                 "Observed (UTC)": p["system"]["evidenceAtUtc"], "Calls": p["usage"]["remoteCalls"],
                 "Last used (UTC)": p["usage"]["lastUsedAtUtc"]} for p in data["profiles"]]
    summary = data["summary"]
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RemoteX usage report</title><style>' + (
        'body{font:14px/1.55 system-ui,sans-serif;color:#20252b;background:white;margin:0;letter-spacing:0}'
        'main{max-width:1440px;margin:auto;padding:24px}h1{font-size:26px}h2{font-size:19px;border-bottom:2px solid #277c68;padding-bottom:8px;margin-top:28px}'
        '.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;padding:8px;border-bottom:1px solid #dce2e5;overflow-wrap:anywhere;min-width:90px}'
        'th{background:#eef4f2}tr:nth-child(even){background:#f8fafb}p,li{overflow-wrap:anywhere}.stats{font-size:18px;padding:16px 0;border-block:1px solid #dce2e5}'
        '@media(max-width:640px){main{padding:16px}.stats{font-size:16px}}'
    ) + '</style><main><h1>RemoteX usage report</h1><p>' + html.escape(data["generatedAtUtc"]) + f' | {data["window"]["days"]} days</p><p class="stats">{summary["profiles"]} profiles | {summary["credentialReferences"]} credential references | {summary["missingCredentials"]} missing | {summary["activeCredentials"]} active</p><p>Architecture labels are configuration hints. Historical receipts do not prove current native ISA. Queue reservations are recorded lower bounds.</p><details><summary>Measurement notes</summary><ul>' + ''.join('<li>' + html.escape(note) + '</li>' for note in data["notes"]) + '</ul></details><h2>Credentials</h2>' + _table(credentials) + '<h2>Systems</h2>' + _table(profiles) + '<h2>Queue reservations</h2>' + _table(data["queues"]) + '<h2>Evidence coverage</h2><pre style="white-space:pre-wrap;overflow-wrap:anywhere">' + html.escape(json.dumps(data["coverage"], ensure_ascii=False, indent=2)) + '</pre><p><a href="report.json">JSON</a> | <a href="credentials.csv">Credentials CSV</a> | <a href="profiles.csv">Profiles CSV</a> | <a href="queues.csv">Queues CSV</a></p></main></html>'


def export_report(args: dict[str, Any]) -> dict[str, Any]:
    data = build_report(args)
    root = core.expand_path(os.environ["REMOTEX_REPORT_DIR"], "REMOTEX_REPORT_DIR") if os.environ.get("REMOTEX_REPORT_DIR") else vm_queue.queue_path().parent / "reports"
    if secure_paths._network_path(root) or any(secure_paths._reparse_point(p) for p in [root, *root.parents]):
        raise core.ToolError("Usage report directory must be local without reparse points")
    directory = root / ("usage-" + uuid.uuid4().hex)
    directory.mkdir(parents=True, exist_ok=False)
    secure_paths.ensure_private_directory(directory)
    for name, rows in (("credentials", data["credentials"]), ("profiles", data["profiles"]), ("queues", data["queues"])):
        flattened = [_flat(row) for row in rows]
        fields = list(flattened[0]) if flattened else []
        with (directory / f"{name}.csv").open("x", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(fields)
            writer.writerows([_csv_value(row.get(k)) for k in fields] for row in flattened)
    (directory / "report.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (directory / "report.html").write_text(render_html(data), encoding="utf-8")
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir() if p.is_file()}
    return core.tool_result({"ok": True, "directory": str(directory), "reportHtml": str(directory / "report.html"),
                             "sha256": hashes, "summary": data["summary"]})


INPUT_SCHEMA = {"type": "object", "properties": {
    "credential_ref": {"type": "string", "description": "Optional configured credential alias; omit with profile."},
    "profile": {"type": "string", "description": "Optional profile, including legacy inline credentials."},
    "days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 30},
}, "additionalProperties": False}
TOOLS = {
    "remotex_usage_report": {"description": "Report local per-credential systems, architecture evidence, call activity, queue reservations and last use. No remote probes or queue mutations.", "inputSchema": INPUT_SCHEMA, "handler": report},
    "remotex_usage_export": {"description": "Export the local usage report as private HTML, JSON and CSV files in a unique RemoteX report directory.", "inputSchema": INPUT_SCHEMA, "handler": export_report},
}
