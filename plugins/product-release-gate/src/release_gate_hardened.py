from __future__ import annotations

from pathlib import Path
from typing import Any

from release_gate_core import (
    RESULT_FAIL,
    RESULT_PASS,
    ReleaseGateController,
    as_list,
    object_digest,
    overall_result,
    result,
    sha1_file,
    sha256_file,
)


class HardenedReleaseGateController(ReleaseGateController):
    """Release controller with physical final-directory verification."""

    def run_release_gate(self, event_id: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") not in {"RELEASE_GATING", "RELEASE_BLOCKED"}:
            raise ValueError(f"Release gate cannot run from status {event.get('status')}")

        manifest_s = self._load_manifest(event_id, "manifest-s.json")
        manifest_r = self._load_manifest(event_id, "manifest-r.json")
        source_items = as_list(manifest_s.get("artifacts"), "manifest-s.artifacts")
        final_items = as_list(manifest_r.get("artifacts"), "manifest-r.artifacts")
        source = {str(item["logical_name"]): item for item in source_items}
        final = {str(item["logical_name"]): item for item in final_items}
        source_names_unique = len(source) == len(source_items)
        final_names_unique = len(final) == len(final_items)

        expected_manifest_s_digest = object_digest({"artifacts": source_items})
        expected_manifest_r_digest = object_digest(
            {
                "source_manifest_s_digest": manifest_r.get("source_manifest_s_digest"),
                "artifacts": final_items,
            }
        )
        digest_ok = (
            source_names_unique
            and final_names_unique
            and manifest_s.get("digest")
            == event.get("manifest_s_digest")
            == expected_manifest_s_digest
            and manifest_r.get("source_manifest_s_digest") == event.get("manifest_s_digest")
            and manifest_r.get("digest")
            == event.get("manifest_r_digest")
            == expected_manifest_r_digest
        )
        entries: list[dict[str, Any]] = [
            result(
                "R-01",
                "final manifest integrity",
                RESULT_PASS if digest_ok else RESULT_FAIL,
                "Manifest-S and Manifest-R digests and names are valid"
                if digest_ok
                else "manifest digest, source binding, or logical-name uniqueness differs",
            )
        ]

        configured_output = Path(str(event.get("final_output_dir") or "")).resolve()
        manifest_output = Path(str(manifest_r.get("output_dir") or "")).resolve()
        output_binding_ok = configured_output == manifest_output
        mapping_ok = output_binding_ok and all(
            name in source
            and item.get("source_sha1") == source[name].get("sha1")
            and item.get("source_sha256")
            == source[name].get("sha256")
            and Path(str(item.get("file_path") or "")).resolve() == manifest_output / name
            for name, item in final.items()
        )
        entries.append(
            result(
                "R-02",
                "submission source mapping",
                RESULT_PASS if mapping_ok else RESULT_FAIL,
                "all final paths and hashes map to Manifest-S"
                if mapping_ok
                else "a final path, source hash, or output-directory binding is invalid",
            )
        )

        actual_files: set[str] = set()
        actual_directories: set[str] = set()
        if manifest_output.is_dir():
            for path in manifest_output.rglob("*"):
                relative = path.relative_to(manifest_output).as_posix()
                if path.is_file():
                    actual_files.add(relative)
                elif path.is_dir():
                    actual_directories.add(relative + "/")

        manifest_omissions = set(source) - set(final)
        disk_omissions = set(final) - actual_files
        omissions = sorted(manifest_omissions | disk_omissions)
        entries.append(
            result(
                "R-03",
                "no submission omissions",
                RESULT_PASS if not omissions else RESULT_FAIL,
                "no submitted or frozen final artifacts are missing"
                if not omissions
                else f"missing: {', '.join(omissions)}",
            )
        )

        manifest_extras = set(final) - set(source)
        disk_extras = actual_files - set(final)
        extras = sorted(manifest_extras | disk_extras | actual_directories)
        entries.append(
            result(
                "R-04",
                "no unsubmitted extras",
                RESULT_PASS if not extras else RESULT_FAIL,
                "the final directory contains only Manifest-R files"
                if not extras
                else f"extra: {', '.join(extras)}",
            )
        )

        for name, artifact in final.items():
            path = Path(str(artifact.get("file_path") or ""))
            actual_sha1 = sha1_file(path) if path.is_file() else None
            actual_sha256 = sha256_file(path) if path.is_file() else None
            source_sha1 = source.get(name, {}).get("sha1")
            source_sha256 = source.get(name, {}).get("sha256")
            matches = (
                actual_sha1 == artifact.get("sha1") == source_sha1
                and actual_sha256
                == artifact.get("sha256")
                == source_sha256
            )
            entries.append(
                result(
                    "R-05",
                    "final SHA1/SHA256 consistency",
                    RESULT_PASS if matches else RESULT_FAIL,
                    "final SHA1/SHA256 matches Manifest-S and Manifest-R"
                    if matches
                    else "final SHA1/SHA256 differs from Manifest-S or Manifest-R",
                    name,
                )
            )
            check_artifact = {
                "logical_name": name,
                "file_path": str(path),
                "sha1": actual_sha1 or artifact.get("sha1", ""),
                "sha256": actual_sha256 or artifact.get("sha256", ""),
            }
            entries.append(self._signature_result("R-06", check_artifact))
            entries.append(self._cloud_scan_result("R-07", check_artifact))

        entries.append(self._test_approval_result(event))
        rollback_ref = str(event.get("rollback_ref") or "").strip()
        entries.append(
            result(
                "R-09",
                "rollback readiness",
                RESULT_PASS if rollback_ref else RESULT_FAIL,
                rollback_ref if rollback_ref else "rollback_ref is required",
                evidence_ref=rollback_ref or None,
            )
        )
        report_preview = self._render_report(event, manifest_s, manifest_r)
        entries.append(
            result(
                "R-10",
                "report renderability",
                RESULT_PASS if report_preview else RESULT_FAIL,
                "report can be rendered" if report_preview else "report rendering failed",
            )
        )

        overall = overall_result(entries)
        execution = self._save_execution(event, "N5", entries, overall)
        source_drift = any(
            entry["rule_id"] in {"R-01", "R-02", "R-03", "R-04", "R-05"}
            and entry["result"] != RESULT_PASS
            for entry in entries
        )
        if overall == RESULT_PASS:
            self._transition(event, "RELEASE_READY", "all release rules passed")
            next_action = (
                "release material is ready; execute deployment only through the approved deployment controller"
            )
        elif source_drift:
            self._transition(event, "SUBMISSION_BLOCKED", "final material drift requires a new submission round")
            next_action = "create a new submission round and repeat T, test, approval, and R gates"
        else:
            self._transition(event, "RELEASE_BLOCKED", "release gate has non-PASS results")
            next_action = "correct final evidence and rerun the release gate"
        self._save_event(event)
        return {
            "event_id": event_id,
            "status": event["status"],
            "overall": overall,
            "execution": execution,
            "next_action": next_action,
        }
