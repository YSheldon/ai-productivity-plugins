from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_ERROR = "ERROR"
VALID_TEST_RESULTS = {"PASS", "FAIL", "BLOCKED"}
VALID_RISK_LEVELS = {"standard", "high", "emergency"}
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")


class GateError(Exception):
    pass


def default_config_path(
    environ: dict[str, str] | None = None,
    *,
    platform: str | None = None,
) -> Path:
    environment = os.environ if environ is None else environ
    override = str(environment.get("PRODUCT_RELEASE_GATE_CONFIG") or "").strip()
    if override:
        return Path(os.path.expandvars(override)).expanduser().resolve(strict=False)
    current_platform = platform or os.name
    if current_platform in {"nt", "win32"} or current_platform.startswith("win"):
        root = Path(
            str(environment.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        )
    else:
        root = Path(str(environment.get("XDG_CONFIG_HOME") or Path.home() / ".config"))
    return (root / "product-release-gate" / "config.json").resolve(strict=False)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def object_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha1_file(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GateError(f"Missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(f"Invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def safe_event_id(event_id: str) -> str:
    value = str(event_id or "").strip()
    if not EVENT_ID_RE.fullmatch(value):
        raise GateError("event_id must use letters, digits, '.', '_' or '-' and be at most 121 characters")
    return value


def safe_logical_name(value: str) -> str:
    name = str(value or "").strip()
    if not name or name in {".", ".."} or "/" in name or "\\" in name or ":" in name:
        raise GateError("logical_name must be a single file name without path components")
    return name


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def default_config() -> dict[str, Any]:
    return {
        "storage_dir": str(Path.home() / ".codex" / "product-release-gate" / "events"),
        "runtime": {
            "state_dir": str(Path.home() / ".codex" / "product-release-gate" / "state"),
            "poll_minutes": 60,
            "scheduler_mode": "auto",
        },
        "policy": {
            "allowed_extensions": [".exe", ".dll", ".sys", ".msi", ".zip"],
            "require_source_ref": True,
            "require_signature": True,
            "require_cloud_scan": True,
            "allow_unchanged_artifacts": False,
            "auto_approve_risk_levels": ["standard"],
        },
        "signature": {
            "expected_thumbprints": [],
            "expected_subject_contains": "",
        },
        "cloud_scan": {"command": [], "clean_verdict": "CLEAN", "timeout_seconds": 90},
        "test": {"command": [], "timeout_seconds": 3600},
        "production": {
            "enabled": False,
            "approval_workflow": {
                "mode": "legacy_external",
                "verify_command": [],
                "timeout_seconds": 120,
            },
        },
    }


def load_config(config_path: str | None = None) -> tuple[dict[str, Any], Path | None]:
    chosen = config_path or os.environ.get("PRODUCT_RELEASE_GATE_CONFIG")
    config = default_config()
    if not chosen:
        return config, None
    path = Path(os.path.expandvars(chosen)).expanduser()
    raw = read_json(path)
    if not isinstance(raw, dict):
        raise GateError(f"Configuration must be a JSON object: {path}")
    return deep_merge(config, raw), path


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GateError(f"{label} must be an array")
    return value


def result(
    rule_id: str,
    name: str,
    status: str,
    detail: str,
    artifact: str | None = None,
    evidence_ref: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "rule_id": rule_id,
        "name": name,
        "result": status,
        "detail": detail,
    }
    if artifact:
        entry["artifact"] = artifact
    if evidence_ref:
        entry["evidence_ref"] = evidence_ref
    return entry


def overall_result(entries: list[dict[str, Any]]) -> str:
    return RESULT_PASS if entries and all(entry["result"] == RESULT_PASS for entry in entries) else "BLOCKED"


def execution_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class ReleaseGateController:
    def __init__(self, config_path: str | None = None) -> None:
        self.config, self.config_path = load_config(config_path)
        self.storage_dir = Path(os.path.expandvars(str(self.config["storage_dir"]))).expanduser().resolve()

    def preflight(self) -> dict[str, Any]:
        policy = self.config["policy"]
        signature_config = self.config.get("signature") or {}
        raw_thumbprints = signature_config.get("expected_thumbprints")
        thumbprints_valid = (
            isinstance(raw_thumbprints, list)
            and bool(raw_thumbprints)
            and all(
                isinstance(value, str)
                and re.fullmatch(r"[0-9A-Fa-f]{40}", re.sub(r"[^0-9A-Fa-f]", "", value))
                for value in raw_thumbprints
            )
        )
        cloud_command = self.config.get("cloud_scan", {}).get("command") or []
        test_command = self.config.get("test", {}).get("command") or []
        checks = [
            {
                "name": "storage",
                "required": True,
                "configured": bool(str(self.storage_dir)),
                "detail": str(self.storage_dir),
            },
            {
                "name": "signature_verifier",
                "required": bool(policy.get("require_signature")),
                "configured": os.name == "nt" if policy.get("require_signature") else True,
                "detail": "Windows Authenticode verifier" if os.name == "nt" else "Windows is required for Authenticode verification",
            },
            {
                "name": "signature_trust_policy",
                "required": bool(policy.get("require_signature")),
                "configured": thumbprints_valid if policy.get("require_signature") else True,
                "detail": "signature.expected_thumbprints must contain exact 40-hex certificate thumbprints",
            },
            {
                "name": "cloud_scan_adapter",
                "required": bool(policy.get("require_cloud_scan")),
                "configured": isinstance(cloud_command, list) and bool(cloud_command),
                "detail": "cloud_scan.command must emit JSON with verdict=CLEAN",
            },
            {
                "name": "test_orchestrator",
                "required": True,
                "configured": isinstance(test_command, list) and bool(test_command),
                "detail": "test.command must emit JSON with result=PASS or result=FAIL",
            },
        ]
        missing = [check["name"] for check in checks if check["required"] and not check["configured"]]
        return {
            "ready": not missing,
            "missing_required_integrations": missing,
            "config_path": str(self.config_path) if self.config_path else None,
            "storage_dir": str(self.storage_dir),
            "checks": checks,
            "policy": {
                "auto_approve_risk_levels": self.config["policy"].get("auto_approve_risk_levels", []),
                "allowed_extensions": self.config["policy"].get("allowed_extensions", []),
            },
        }

    def _event_dir(self, event_id: str) -> Path:
        return self.storage_dir / safe_event_id(event_id)

    def _event_path(self, event_id: str) -> Path:
        return self._event_dir(event_id) / "event.json"

    def _load_event(self, event_id: str) -> dict[str, Any]:
        event = read_json(self._event_path(event_id))
        if not isinstance(event, dict):
            raise GateError(f"Event is not a JSON object: {event_id}")
        return event

    def _save_event(self, event: dict[str, Any]) -> None:
        write_json(self._event_path(event["event_id"]), event)

    def _load_manifest(self, event_id: str, name: str) -> dict[str, Any]:
        manifest = read_json(self._event_dir(event_id) / name)
        if not isinstance(manifest, dict):
            raise GateError(f"{name} is not a JSON object")
        return manifest

    def _save_manifest(self, event_id: str, name: str, manifest: dict[str, Any]) -> None:
        write_json(self._event_dir(event_id) / name, manifest)

    def _transition(self, event: dict[str, Any], new_status: str, reason: str) -> None:
        old_status = event.get("status")
        event["status"] = new_status
        event.setdefault("history", []).append(
            {"at": utc_now(), "from": old_status, "to": new_status, "reason": reason}
        )

    def _save_execution(
        self,
        event: dict[str, Any],
        phase: str,
        entries: list[dict[str, Any]],
        overall: str,
    ) -> dict[str, Any]:
        identifier = execution_id(phase.lower())
        execution = {
            "execution_id": identifier,
            "event_id": event["event_id"],
            "phase": phase,
            "rule_snapshot_id": event["rule_snapshot_id"],
            "manifest_s_digest": event["manifest_s_digest"],
            "manifest_r_digest": event.get("manifest_r_digest"),
            "started_at": utc_now(),
            "finished_at": utc_now(),
            "overall": overall,
            "results": entries,
        }
        path = self._event_dir(event["event_id"]) / "executions" / f"{identifier}.json"
        write_json(path, execution)
        event["last_execution_id"] = identifier
        event["last_execution_path"] = str(path)
        return execution

    def _baseline_index(self, baseline_manifest_path: str | None) -> dict[str, str]:
        if not baseline_manifest_path:
            return {}
        baseline = read_json(Path(baseline_manifest_path).expanduser())
        artifacts = baseline.get("artifacts") if isinstance(baseline, dict) else None
        if not isinstance(artifacts, list):
            raise GateError("baseline_manifest_path must point to a manifest with an artifacts array")
        index: dict[str, str] = {}
        for artifact in artifacts:
            if isinstance(artifact, dict) and artifact.get("logical_name") and artifact.get("sha1"):
                index[str(artifact["logical_name"])] = str(artifact["sha1"])
        return index

    def create_submission(
        self,
        event_id: str,
        task_id: str,
        artifacts: list[dict[str, Any]],
        source_ref: str,
        rollback_ref: str,
        risk_level: str = "standard",
        round_number: int = 1,
        rule_snapshot_id: str | None = None,
        baseline_manifest_path: str | None = None,
        new_round_of: str | None = None,
    ) -> dict[str, Any]:
        identifier = safe_event_id(event_id)
        if self._event_path(identifier).exists():
            raise GateError(f"Event already exists: {identifier}")
        if not str(task_id or "").strip():
            raise GateError("task_id is required")
        if risk_level not in VALID_RISK_LEVELS:
            raise GateError(f"risk_level must be one of: {', '.join(sorted(VALID_RISK_LEVELS))}")
        if int(round_number) < 1:
            raise GateError("round_number must be at least 1")
        artifact_values = as_list(artifacts, "artifacts")
        if not artifact_values:
            raise GateError("At least one artifact is required")
        baseline = self._baseline_index(baseline_manifest_path)
        prepared: list[dict[str, Any]] = []
        seen_names: set[str] = set()
        for raw in artifact_values:
            if not isinstance(raw, dict):
                raise GateError("Each artifact must be an object")
            logical_name = safe_logical_name(str(raw.get("logical_name") or ""))
            if logical_name in seen_names:
                raise GateError(f"Duplicate logical_name: {logical_name}")
            seen_names.add(logical_name)
            path = Path(os.path.expandvars(str(raw.get("file_path") or ""))).expanduser().resolve()
            if not path.is_file():
                raise GateError(f"Artifact file does not exist: {path}")
            sha1 = sha1_file(path)
            old_sha1 = baseline.get(logical_name)
            change_type = "new" if old_sha1 is None else ("unchanged" if old_sha1 == sha1 else "updated")
            prepared.append(
                {
                    "logical_name": logical_name,
                    "file_path": str(path),
                    "size": path.stat().st_size,
                    "sha1": sha1,
                    "extension": path.suffix.lower(),
                    "source_ref": str(raw.get("source_ref") or source_ref or "").strip(),
                    "change_type": change_type,
                }
            )
        manifest = {
            "event_id": identifier,
            "phase": "Manifest-S",
            "created_at": utc_now(),
            "artifacts": prepared,
        }
        manifest["digest"] = object_digest({"artifacts": manifest["artifacts"]})
        event = {
            "event_id": identifier,
            "task_id": str(task_id).strip(),
            "round_number": int(round_number),
            "risk_level": risk_level,
            "source_ref": str(source_ref or "").strip(),
            "rollback_ref": str(rollback_ref or "").strip(),
            "new_round_of": str(new_round_of or "").strip() or None,
            "status": "SUBMISSION_GATING",
            "rule_snapshot_id": str(rule_snapshot_id or f"local-{utc_now()}").strip(),
            "manifest_s_digest": manifest["digest"],
            "manifest_r_digest": None,
            "test": None,
            "approval": None,
            "last_execution_id": None,
            "history": [
                {"at": utc_now(), "from": None, "to": "SUBMISSION_GATING", "reason": "submission created"}
            ],
        }
        self._save_manifest(identifier, "manifest-s.json", manifest)
        self._save_event(event)
        return {
            "event": event,
            "manifest_s": manifest,
            "next_action": "release_gate_run_submission_gate",
        }

    def _artifact_integrity_result(self, rule_id: str, artifact: dict[str, Any]) -> dict[str, Any]:
        path = Path(artifact["file_path"])
        name = artifact["logical_name"]
        if not path.is_file():
            return result(rule_id, "artifact integrity", RESULT_ERROR, "artifact file is missing", name)
        actual = sha1_file(path)
        if actual != artifact["sha1"]:
            return result(rule_id, "artifact integrity", RESULT_FAIL, "SHA1 differs from the frozen manifest", name)
        return result(rule_id, "artifact integrity", RESULT_PASS, f"SHA1={actual}", name)

    def _extension_result(self, rule_id: str, artifact: dict[str, Any]) -> dict[str, Any]:
        allowed = {str(value).lower() for value in self.config["policy"].get("allowed_extensions", [])}
        extension = str(artifact.get("extension") or "").lower()
        if extension in allowed:
            return result(rule_id, "allowed extension", RESULT_PASS, f"extension {extension} is allowed", artifact["logical_name"])
        return result(rule_id, "allowed extension", RESULT_FAIL, f"extension {extension or '<none>'} is not allowed", artifact["logical_name"])

    def _source_result(self, rule_id: str, artifact: dict[str, Any]) -> dict[str, Any]:
        required = bool(self.config["policy"].get("require_source_ref"))
        source_ref = str(artifact.get("source_ref") or "").strip()
        if not required:
            return result(rule_id, "source reference", RESULT_PASS, "source reference is optional", artifact["logical_name"])
        if source_ref:
            return result(rule_id, "source reference", RESULT_PASS, source_ref, artifact["logical_name"], source_ref)
        return result(rule_id, "source reference", RESULT_FAIL, "source_ref is required", artifact["logical_name"])

    def _signature_result(self, rule_id: str, artifact: dict[str, Any]) -> dict[str, Any]:
        if not self.config["policy"].get("require_signature"):
            return result(rule_id, "product signature", RESULT_PASS, "signature check is disabled by policy", artifact["logical_name"])
        if os.name != "nt":
            return result(rule_id, "product signature", RESULT_ERROR, "Authenticode verification requires Windows", artifact["logical_name"])
        raw_path = str(artifact["file_path"])
        path_payload = base64.b64encode(raw_path.encode("utf-8")).decode("ascii")
        script = (
            "$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + path_payload + "'));"
            "$signature=Get-AuthenticodeSignature -LiteralPath $path;"
            "$subject=if($signature.SignerCertificate){[string]$signature.SignerCertificate.Subject}else{''};"
            "$thumbprint=if($signature.SignerCertificate){[string]$signature.SignerCertificate.Thumbprint}else{''};"
            "[PSCustomObject]@{status=[string]$signature.Status;status_message=[string]$signature.StatusMessage;subject=$subject;thumbprint=$thumbprint}|ConvertTo-Json -Compress"
        )
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return result(rule_id, "product signature", RESULT_ERROR, f"signature verifier failed: {exc}", artifact["logical_name"])
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "signature verifier returned an error").strip()[:600]
            return result(rule_id, "product signature", RESULT_ERROR, detail, artifact["logical_name"])
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return result(rule_id, "product signature", RESULT_ERROR, "signature verifier returned invalid JSON", artifact["logical_name"])
        status = str(payload.get("status") or "")
        subject = str(payload.get("subject") or "")
        thumbprint = re.sub(r"[^0-9A-Fa-f]", "", str(payload.get("thumbprint") or "")).upper()
        signature_config = self.config.get("signature") or {}
        raw_thumbprints = signature_config.get("expected_thumbprints")
        expected_thumbprints = {
            normalized
            for value in raw_thumbprints
            if isinstance(value, str)
            for normalized in [re.sub(r"[^0-9A-Fa-f]", "", value).upper()]
            if re.fullmatch(r"[0-9A-F]{40}", normalized)
        } if isinstance(raw_thumbprints, list) else set()
        expected = str(signature_config.get("expected_subject_contains") or "").strip()
        if status != "Valid":
            return result(rule_id, "product signature", RESULT_FAIL, f"Authenticode status={status}: {payload.get('status_message')}", artifact["logical_name"])
        if not expected_thumbprints or thumbprint not in expected_thumbprints:
            return result(
                rule_id,
                "product signature",
                RESULT_FAIL,
                "signer certificate thumbprint is not in the exact allowlist",
                artifact["logical_name"],
            )
        if expected and expected not in subject:
            return result(rule_id, "product signature", RESULT_FAIL, "signer subject does not match policy", artifact["logical_name"])
        evidence = f"thumbprint:{thumbprint};subject:{subject}"
        return result(rule_id, "product signature", RESULT_PASS, "Authenticode status=Valid", artifact["logical_name"], evidence or None)

    def _run_configured_json_command(
        self,
        section: str,
        context: dict[str, str],
    ) -> tuple[dict[str, Any] | None, str | None]:
        section_config = self.config.get(section, {})
        command = section_config.get("command") if isinstance(section_config, dict) else None
        if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
            return None, f"{section}.command is not configured"
        try:
            expanded = [item.format_map(context) for item in command]
        except KeyError as exc:
            return None, f"{section}.command uses an unknown placeholder: {exc}"
        timeout = int(section_config.get("timeout_seconds") or 90)
        try:
            completed = subprocess.run(
                expanded,
                capture_output=True,
                text=True,
                timeout=max(1, timeout),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return None, f"{section} adapter failed: {exc}"
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or f"exit code {completed.returncode}").strip()[:1000]
            return None, f"{section} adapter failed: {detail}"
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return None, f"{section} adapter must write a JSON object to stdout"
        if not isinstance(payload, dict):
            return None, f"{section} adapter must write a JSON object to stdout"
        return payload, None

    def _cloud_scan_result(self, rule_id: str, artifact: dict[str, Any]) -> dict[str, Any]:
        if not self.config["policy"].get("require_cloud_scan"):
            return result(rule_id, "cloud scan", RESULT_PASS, "cloud scan is disabled by policy", artifact["logical_name"])
        payload, error = self._run_configured_json_command(
            "cloud_scan",
            {
                "sha1": str(artifact["sha1"]),
                "file_path": str(artifact["file_path"]),
                "logical_name": str(artifact["logical_name"]),
            },
        )
        if error:
            return result(rule_id, "cloud scan", RESULT_ERROR, error, artifact["logical_name"])
        assert payload is not None
        verdict = str(payload.get("verdict") or "").upper()
        expected = str(self.config.get("cloud_scan", {}).get("clean_verdict") or "CLEAN").upper()
        evidence = str(payload.get("evidence_ref") or payload.get("report_ref") or "").strip()
        if verdict != expected:
            return result(rule_id, "cloud scan", RESULT_FAIL, f"cloud verdict={verdict or '<missing>'}", artifact["logical_name"], evidence or None)
        return result(rule_id, "cloud scan", RESULT_PASS, f"cloud verdict={verdict}", artifact["logical_name"], evidence or None)

    def run_submission_gate(self, event_id: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") not in {"SUBMISSION_GATING", "SUBMISSION_BLOCKED"}:
            raise GateError(f"Submission gate cannot run from status {event.get('status')}")
        manifest = self._load_manifest(event_id, "manifest-s.json")
        artifacts = as_list(manifest.get("artifacts"), "manifest-s.artifacts")
        entries: list[dict[str, Any]] = []
        for artifact in artifacts:
            entries.append(self._artifact_integrity_result("T-01", artifact))
            entries.append(self._extension_result("T-02", artifact))
            entries.append(self._source_result("T-03", artifact))
            entries.append(self._signature_result("T-05", artifact))
            entries.append(self._cloud_scan_result("T-06", artifact))
        unique_names = len({item.get("logical_name") for item in artifacts}) == len(artifacts)
        computed_digest = object_digest({"artifacts": artifacts})
        entries.append(
            result(
                "T-04",
                "Manifest-S digest",
                RESULT_PASS if computed_digest == manifest.get("digest") else RESULT_FAIL,
                "frozen manifest digest verified" if computed_digest == manifest.get("digest") else "manifest digest does not match artifacts",
            )
        )
        entries.append(
            result(
                "T-07",
                "Manifest-S completeness",
                RESULT_PASS if unique_names and bool(artifacts) else RESULT_FAIL,
                "all logical names are unique" if unique_names and artifacts else "manifest contains duplicate or no artifacts",
            )
        )
        unchanged = [item["logical_name"] for item in artifacts if item.get("change_type") == "unchanged"]
        allow_unchanged = bool(self.config["policy"].get("allow_unchanged_artifacts"))
        entries.append(
            result(
                "T-08",
                "Artifact change classification",
                RESULT_PASS if allow_unchanged or not unchanged else RESULT_FAIL,
                "all artifacts are new or updated" if not unchanged else f"unchanged artifacts: {', '.join(unchanged)}",
            )
        )
        overall = overall_result(entries)
        execution = self._save_execution(event, "N1", entries, overall)
        if overall == RESULT_PASS:
            self._transition(event, "TESTING", "all submission rules passed")
            next_action = "release_gate_run_tests"
        else:
            self._transition(event, "SUBMISSION_BLOCKED", "submission gate has non-PASS results")
            next_action = "create a new submission round after correction"
        self._save_event(event)
        return {
            "event_id": event_id,
            "status": event["status"],
            "overall": overall,
            "execution": execution,
            "next_action": next_action,
        }

    def _apply_test_result(
        self,
        event: dict[str, Any],
        test_result: str,
        report_ref: str,
        summary: str,
    ) -> dict[str, Any]:
        normalized = str(test_result or "").upper()
        if normalized not in VALID_TEST_RESULTS:
            raise GateError("test_result must be PASS, FAIL, or BLOCKED")
        event["test"] = {
            "result": normalized,
            "report_ref": str(report_ref or "").strip(),
            "summary": str(summary or "").strip(),
            "recorded_at": utc_now(),
        }
        if normalized != RESULT_PASS:
            event["approval"] = None
            self._transition(event, "SUBMISSION_BLOCKED", "test result is not PASS")
            next_action = "create a new submission round after correction"
        elif event["risk_level"] in set(self.config["policy"].get("auto_approve_risk_levels", [])):
            event["approval"] = {
                "status": "AUTO_APPROVED",
                "approval_ref": "policy-as-code",
                "at": utc_now(),
            }
            self._transition(event, "RELEASE_PREPARING", "test passed and policy auto-approved this risk level")
            next_action = "release_gate_build_final_release"
        else:
            event["approval"] = {"status": "PENDING", "approval_ref": None, "at": utc_now()}
            self._transition(event, "TEST_APPROVAL_REQUIRED", "test passed but risk level requires explicit authorization")
            next_action = "release_gate_record_test_approval"
        self._save_event(event)
        return {
            "event_id": event["event_id"],
            "status": event["status"],
            "test": event["test"],
            "approval": event["approval"],
            "next_action": next_action,
        }

    def run_tests(self, event_id: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") != "TESTING":
            raise GateError(f"Tests cannot run from status {event.get('status')}")
        event_dir = self._event_dir(event_id)
        payload, error = self._run_configured_json_command(
            "test",
            {
                "event_id": event_id,
                "event_dir": str(event_dir),
                "manifest_s_path": str(event_dir / "manifest-s.json"),
                "manifest_s_digest": str(event["manifest_s_digest"]),
            },
        )
        if error:
            raise GateError(error)
        assert payload is not None
        return self._apply_test_result(
            event,
            str(payload.get("result") or ""),
            str(payload.get("report_ref") or payload.get("evidence_ref") or ""),
            str(payload.get("summary") or ""),
        )

    def record_test_result(
        self,
        event_id: str,
        test_result: str,
        report_ref: str,
        summary: str = "",
    ) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") != "TESTING":
            raise GateError(f"Test result cannot be recorded from status {event.get('status')}")
        return self._apply_test_result(event, test_result, report_ref, summary)

    def record_test_approval(self, event_id: str, decision: str, approval_ref: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") != "TEST_APPROVAL_REQUIRED":
            raise GateError(f"Test approval cannot be recorded from status {event.get('status')}")
        normalized = str(decision or "").upper()
        if normalized not in {"APPROVE", "REJECT"}:
            raise GateError("decision must be APPROVE or REJECT")
        if not str(approval_ref or "").strip():
            raise GateError("approval_ref is required")
        event["approval"] = {
            "status": "APPROVED" if normalized == "APPROVE" else "REJECTED",
            "approval_ref": str(approval_ref).strip(),
            "at": utc_now(),
        }
        if normalized == "APPROVE":
            self._transition(event, "RELEASE_PREPARING", "explicit test approval recorded")
            next_action = "release_gate_build_final_release"
        else:
            self._transition(event, "SUBMISSION_BLOCKED", "test approval rejected")
            next_action = "create a new submission round after correction"
        self._save_event(event)
        return {
            "event_id": event_id,
            "status": event["status"],
            "approval": event["approval"],
            "next_action": next_action,
        }

    def build_final_release(self, event_id: str, output_dir: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") != "RELEASE_PREPARING":
            raise GateError(f"Final material cannot be produced from status {event.get('status')}")
        destination_root = Path(os.path.expandvars(str(output_dir or ""))).expanduser().resolve()
        if destination_root.exists() and any(destination_root.iterdir()):
            raise GateError("output_dir must be empty to prevent untracked final material")
        destination_root.mkdir(parents=True, exist_ok=True)
        manifest_s = self._load_manifest(event_id, "manifest-s.json")
        final_artifacts: list[dict[str, Any]] = []
        for artifact in as_list(manifest_s.get("artifacts"), "manifest-s.artifacts"):
            source = Path(artifact["file_path"])
            if not source.is_file():
                raise GateError(f"Submission artifact is missing: {source}")
            destination = destination_root / safe_logical_name(str(artifact["logical_name"]))
            shutil.copy2(source, destination)
            final_sha1 = sha1_file(destination)
            final_artifacts.append(
                {
                    "logical_name": artifact["logical_name"],
                    "file_path": str(destination),
                    "size": destination.stat().st_size,
                    "sha1": final_sha1,
                    "source_sha1": artifact["sha1"],
                    "source_ref": artifact["source_ref"],
                }
            )
        manifest_r = {
            "event_id": event_id,
            "phase": "Manifest-R",
            "created_at": utc_now(),
            "source_manifest_s_digest": event["manifest_s_digest"],
            "output_dir": str(destination_root),
            "artifacts": final_artifacts,
        }
        manifest_r["digest"] = object_digest(
            {
                "source_manifest_s_digest": manifest_r["source_manifest_s_digest"],
                "artifacts": final_artifacts,
            }
        )
        self._save_manifest(event_id, "manifest-r.json", manifest_r)
        event["manifest_r_digest"] = manifest_r["digest"]
        event["final_output_dir"] = str(destination_root)
        self._transition(event, "RELEASE_GATING", "final material copied from the approved submission manifest")
        self._save_event(event)
        return {
            "event_id": event_id,
            "status": event["status"],
            "manifest_r": manifest_r,
            "next_action": "release_gate_run_release_gate",
        }

    def _test_approval_result(self, event: dict[str, Any]) -> dict[str, Any]:
        test = event.get("test") or {}
        approval = event.get("approval") or {}
        approved = test.get("result") == RESULT_PASS and approval.get("status") in {"AUTO_APPROVED", "APPROVED"}
        return result(
            "R-08",
            "test and approval binding",
            RESULT_PASS if approved else RESULT_FAIL,
            "test PASS and approval are bound to this event" if approved else "test PASS and approval are both required",
        )

    def run_release_gate(self, event_id: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        if event.get("status") not in {"RELEASE_GATING", "RELEASE_BLOCKED"}:
            raise GateError(f"Release gate cannot run from status {event.get('status')}")
        manifest_s = self._load_manifest(event_id, "manifest-s.json")
        manifest_r = self._load_manifest(event_id, "manifest-r.json")
        source = {
            str(item["logical_name"]): item
            for item in as_list(manifest_s.get("artifacts"), "manifest-s.artifacts")
        }
        final = {
            str(item["logical_name"]): item
            for item in as_list(manifest_r.get("artifacts"), "manifest-r.artifacts")
        }
        entries: list[dict[str, Any]] = []
        digest_ok = (
            manifest_r.get("source_manifest_s_digest") == event.get("manifest_s_digest")
            and manifest_r.get("digest") == event.get("manifest_r_digest")
        )
        entries.append(
            result(
                "R-01",
                "final manifest integrity",
                RESULT_PASS if digest_ok else RESULT_FAIL,
                "Manifest-R is bound to the current Manifest-S" if digest_ok else "Manifest-R digest or source binding differs",
            )
        )
        mapping_ok = all(
            name in source and item.get("source_sha1") == source[name].get("sha1")
            for name, item in final.items()
        )
        entries.append(
            result(
                "R-02",
                "submission source mapping",
                RESULT_PASS if mapping_ok else RESULT_FAIL,
                "all final files map to submission files" if mapping_ok else "a final file has no valid Manifest-S mapping",
            )
        )
        omissions = sorted(set(source) - set(final))
        extras = sorted(set(final) - set(source))
        entries.append(
            result(
                "R-03",
                "no submission omissions",
                RESULT_PASS if not omissions else RESULT_FAIL,
                "no submission artifacts are missing" if not omissions else f"missing: {', '.join(omissions)}",
            )
        )
        entries.append(
            result(
                "R-04",
                "no unsubmitted extras",
                RESULT_PASS if not extras else RESULT_FAIL,
                "no extra final artifacts" if not extras else f"extra: {', '.join(extras)}",
            )
        )
        for name, artifact in final.items():
            path = Path(str(artifact.get("file_path") or ""))
            actual = sha1_file(path) if path.is_file() else None
            source_sha1 = source.get(name, {}).get("sha1")
            matches = actual == artifact.get("sha1") == source_sha1
            entries.append(
                result(
                    "R-05",
                    "final SHA1 consistency",
                    RESULT_PASS if matches else RESULT_FAIL,
                    "final SHA1 matches Manifest-S" if matches else "final SHA1 differs from Manifest-R or Manifest-S",
                    name,
                )
            )
            signature_artifact = {
                "logical_name": name,
                "file_path": str(path),
                "sha1": actual or artifact.get("sha1", ""),
            }
            entries.append(self._signature_result("R-06", signature_artifact))
            entries.append(self._cloud_scan_result("R-07", signature_artifact))
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
                RESULT_PASS if bool(report_preview) else RESULT_FAIL,
                "report can be rendered" if report_preview else "report rendering failed",
            )
        )
        overall = overall_result(entries)
        execution = self._save_execution(event, "N5", entries, overall)
        source_drift = any(
            entry["rule_id"] in {"R-02", "R-03", "R-04", "R-05"}
            and entry["result"] != RESULT_PASS
            for entry in entries
        )
        if overall == RESULT_PASS:
            self._transition(event, "RELEASE_READY", "all release rules passed")
            next_action = "release material is ready; execute deployment only through the approved deployment controller"
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

    def _render_report(
        self,
        event: dict[str, Any],
        manifest_s: dict[str, Any],
        manifest_r: dict[str, Any] | None = None,
    ) -> str:
        lines = [
            "# Product Release Gate Report",
            "",
            f"- Event: {event['event_id']}",
            f"- Task: {event['task_id']}",
            f"- Round: {event['round_number']}",
            f"- Risk level: {event['risk_level']}",
            f"- State: {event['status']}",
            f"- Manifest-S digest: {event['manifest_s_digest']}",
            f"- Manifest-R digest: {event.get('manifest_r_digest') or 'not generated'}",
            f"- Submission artifacts: {len(manifest_s.get('artifacts') or [])}",
            f"- Final artifacts: {len((manifest_r or {}).get('artifacts') or [])}",
            "",
            "## Test Evidence",
        ]
        test = event.get("test") or {}
        approval = event.get("approval") or {}
        lines.extend(
            [
                f"- Result: {test.get('result') or 'not recorded'}",
                f"- Report: {test.get('report_ref') or 'not recorded'}",
                f"- Approval: {approval.get('status') or 'not recorded'}",
                "",
                "## Latest Gate Execution",
                f"- Execution: {event.get('last_execution_id') or 'not recorded'}",
                f"- Receipt: {event.get('last_execution_path') or 'not recorded'}",
                "",
                "## Safety Boundary",
                "- RELEASE_READY proves gate completion only. Deployment and production credentials remain outside this plugin.",
            ]
        )
        return "\n".join(lines) + "\n"

    def generate_report(self, event_id: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        manifest_s = self._load_manifest(event_id, "manifest-s.json")
        manifest_r_path = self._event_dir(event_id) / "manifest-r.json"
        manifest_r = read_json(manifest_r_path) if manifest_r_path.exists() else None
        report = self._render_report(event, manifest_s, manifest_r)
        path = self._event_dir(event_id) / "report.md"
        path.write_text(report, encoding="utf-8")
        return {"event_id": event_id, "report_path": str(path), "report": report}

    def get_event(self, event_id: str) -> dict[str, Any]:
        event = self._load_event(event_id)
        manifest_s = self._load_manifest(event_id, "manifest-s.json")
        manifest_r_path = self._event_dir(event_id) / "manifest-r.json"
        manifest_r = read_json(manifest_r_path) if manifest_r_path.exists() else None
        return {"event": event, "manifest_s": manifest_s, "manifest_r": manifest_r}
