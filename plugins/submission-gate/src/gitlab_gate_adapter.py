from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping

from release_workflow_core import GateAdapterContractError, validate_gitlab_gate_result


_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TERMINAL_FAILURES = frozenset(
    {"failed", "canceled", "cancelled", "skipped", "manual"}
)
_RUNNING_STATES = frozenset(
    {"created", "pending", "preparing", "running", "waiting_for_resource"}
)
_MAX_JSON_BYTES = 16 * 1024 * 1024
_ARTIFACT_PATH_TEMPLATE = (
    "artifacts/{pipeline_id}-{job_id}-submission-gate/result.json"
)


class AdapterError(RuntimeError):
    pass


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


class UrllibTransport:
    def __init__(self, base_url: str, *, ca_bundle: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.context = ssl.create_default_context(cafile=ca_bundle or None)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.context),
            _NoRedirectHandler(),
        )

    def request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
        body: dict[str, Any] | None = None,
    ) -> Any:
        payload = self._request(method, path, headers=headers, body=body)
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdapterError("GitLab API returned invalid JSON") from exc

    def request_bytes(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
    ) -> bytes:
        return self._request(method, path, headers=headers, body=None)

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
        body: dict[str, Any] | None,
    ) -> bytes:
        data = None
        request_headers = dict(headers)
        request_headers["Accept"] = "application/json"
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=request_headers,
            method=method,
        )
        try:
            with self.opener.open(
                request,
                timeout=60,
            ) as response:
                payload = response.read(_MAX_JSON_BYTES + 1)
                if len(payload) > _MAX_JSON_BYTES:
                    raise AdapterError("GitLab API response exceeds the size limit")
                return payload
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise AdapterError(
                f"GitLab API HTTP {exc.code}: {detail or exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise AdapterError(f"GitLab API connection failed: {exc.reason}") from exc


class GitLabGateAdapter:
    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        environ: Mapping[str, str] | None = None,
        transport: Any | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = _validate_config(config)
        self.environ = os.environ if environ is None else environ
        self.sleep_fn = sleep_fn
        self.monotonic_fn = monotonic_fn
        self.transport = transport or UrllibTransport(
            self.config["base_url"],
            ca_bundle=self.config["ca_bundle"],
        )

    def preflight(self) -> dict[str, Any]:
        token_env = self.config["token_env"]
        if not str(self.environ.get(token_env) or ""):
            return {
                "ready": False,
                "status": "CAPABILITY_BLOCKED",
                "reason": "GitLab token environment variable is not configured",
                "token_env": token_env,
            }
        branch_path = urllib.parse.quote(self.config["ref"], safe="")
        try:
            branch = self.transport.request_json(
                "GET",
                self._project_path(f"/repository/branches/{branch_path}"),
                headers=self._headers(),
            )
        except AdapterError as exc:
            return {
                "ready": False,
                "status": "CAPABILITY_BLOCKED",
                "reason": f"GitLab protected ref preflight failed: {exc}",
                "token_env": token_env,
            }
        if (
            not isinstance(branch, Mapping)
            or str(branch.get("name") or "") != self.config["ref"]
            or branch.get("protected") is not True
        ):
            return {
                "ready": False,
                "status": "CAPABILITY_BLOCKED",
                "reason": "GitLab ref is unavailable or not protected",
                "token_env": token_env,
            }
        try:
            commit_sha = _extract_commit_sha(branch)
        except AdapterError as exc:
            return {
                "ready": False,
                "status": "CAPABILITY_BLOCKED",
                "reason": str(exc),
                "token_env": token_env,
            }
        return {
            "ready": True,
            "status": "ready",
            "base_url": self.config["base_url"],
            "project_id": self.config["project_id"],
            "ref": self.config["ref"],
            "job_name": self.config["job_name"],
            "token_env": token_env,
            "tls_verified": True,
            "protected_ref_verified": True,
            "protected_ref_commit_sha": commit_sha,
        }

    def evaluate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        preflight = self.preflight()
        if preflight["ready"] is not True:
            raise AdapterError(str(preflight["reason"]))
        normalized_request = _validate_adapter_request(request)
        expected_commit_sha = str(preflight["protected_ref_commit_sha"])
        request_json = canonical_json(normalized_request)
        request_sha256 = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        variables = [
            {
                "key": "PMG_SUBMISSION_GATE_REQUEST",
                "value": "1",
                "variable_type": "env_var",
            },
            {
                "key": "PMG_SUBMISSION_REQUEST_B64",
                "value": base64.b64encode(request_json.encode("utf-8")).decode("ascii"),
                "variable_type": "env_var",
            },
            {
                "key": "PMG_SUBMISSION_REQUEST_SHA256",
                "value": request_sha256,
                "variable_type": "env_var",
            },
            {
                "key": "PMG_SUBMISSION_EVENT_ID",
                "value": normalized_request["event_id"],
                "variable_type": "env_var",
            },
            {
                "key": "PMG_SUBMISSION_ROUND_ID",
                "value": str(normalized_request["round_id"]),
                "variable_type": "env_var",
            },
        ]
        pipeline = self.transport.request_json(
            "POST",
            self._project_path("/pipeline"),
            headers=self._headers(),
            body={"ref": self.config["ref"], "variables": variables},
        )
        pipeline_id, pipeline_ref, pipeline_sha = self._validate_pipeline(pipeline)
        if pipeline_sha != expected_commit_sha:
            raise AdapterError(
                "GitLab pipeline commit does not match the preflight protected ref"
            )
        deadline = self.monotonic_fn() + self.config["timeout_seconds"]
        job: dict[str, Any] | None = None
        while self.monotonic_fn() <= deadline:
            pipeline_state = self.transport.request_json(
                "GET",
                self._project_path(f"/pipelines/{pipeline_id}"),
                headers=self._headers(),
            )
            observed_id, observed_ref, observed_sha = self._validate_pipeline(
                pipeline_state
            )
            if (
                observed_id != pipeline_id
                or observed_ref != pipeline_ref
                or observed_sha != pipeline_sha
            ):
                raise AdapterError("GitLab pipeline identity changed while polling")
            jobs = self.transport.request_json(
                "GET",
                self._project_path(f"/pipelines/{pipeline_id}/jobs?per_page=100"),
                headers=self._headers(),
            )
            if not isinstance(jobs, list):
                raise AdapterError("GitLab pipeline jobs response must be an array")
            matches = [
                item
                for item in jobs
                if isinstance(item, Mapping)
                and str(item.get("name") or "") == self.config["job_name"]
            ]
            if len(matches) > 1:
                raise AdapterError("GitLab pipeline contains duplicate gate jobs")
            if matches:
                candidate = dict(matches[0])
                status = str(candidate.get("status") or "").lower()
                if status == "success":
                    job = candidate
                    break
                if status in _TERMINAL_FAILURES:
                    raise AdapterError(
                        f"GitLab submission gate job {status}"
                    )
                if status not in _RUNNING_STATES:
                    raise AdapterError(
                        f"GitLab submission gate job has unsupported status: {status or '<empty>'}"
                    )
            pipeline_status = str(
                (pipeline_state or {}).get("status")
                if isinstance(pipeline_state, Mapping)
                else ""
            ).lower()
            if pipeline_status in _TERMINAL_FAILURES:
                raise AdapterError(
                    f"GitLab submission gate pipeline {pipeline_status}"
                )
            self.sleep_fn(self.config["poll_interval_seconds"])
        if job is None:
            raise AdapterError("GitLab submission gate timed out")

        job_id = job.get("id")
        job_ref = str(job.get("web_url") or "").strip()
        if type(job_id) is not int or job_id <= 0 or not job_ref:
            raise AdapterError("GitLab gate job identity is incomplete")
        self._validate_job_binding(
            job,
            pipeline_id=pipeline_id,
            pipeline_sha=pipeline_sha,
        )
        self._validate_web_url(job_ref, kind="job")
        artifact_path = _ARTIFACT_PATH_TEMPLATE.format(
            pipeline_id=pipeline_id,
            job_id=job_id,
        )
        artifact_ref = (
            job_ref.rstrip("/")
            + "/artifacts/file/"
            + urllib.parse.quote(artifact_path, safe="/")
        )
        encoded_artifact_path = urllib.parse.quote(artifact_path, safe="/")
        raw_result = self.transport.request_bytes(
            "GET",
            self._project_path(
                f"/jobs/{job_id}/artifacts/{encoded_artifact_path}"
            ),
            headers=self._headers(),
        )
        if len(raw_result) > _MAX_JSON_BYTES:
            raise AdapterError("GitLab gate result exceeds the size limit")
        try:
            result = json.loads(raw_result.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdapterError("GitLab gate result is invalid JSON") from exc
        if not isinstance(result, dict):
            raise AdapterError("GitLab gate result must be one JSON object")
        try:
            evidence = validate_gitlab_gate_result(
                result,
                expected_bindings={
                    "event_id": normalized_request["event_id"],
                    "round_id": normalized_request["round_id"],
                    "task": normalized_request["task"],
                    "module": normalized_request["module"],
                    "request_digest": normalized_request["request_digest"],
                    "policy_digest": normalized_request["policy_digest"],
                },
            )
        except GateAdapterContractError as exc:
            raise AdapterError(str(exc)) from exc
        if evidence.pipeline_ref != pipeline_ref:
            raise AdapterError("gate result pipeline_ref does not match the triggered pipeline")
        if evidence.job_ref != job_ref:
            raise AdapterError("gate result job_ref does not match the successful job")
        if evidence.artifact_ref != artifact_ref:
            raise AdapterError("gate result artifact_ref does not match the downloaded artifact")
        return result

    def _headers(self) -> dict[str, str]:
        return {
            "PRIVATE-TOKEN": str(self.environ[self.config["token_env"]]),
        }

    def _project_path(self, suffix: str) -> str:
        project = urllib.parse.quote(str(self.config["project_id"]), safe="")
        return f"/api/v4/projects/{project}{suffix}"

    def _validate_pipeline(self, value: Any) -> tuple[int, str, str]:
        if not isinstance(value, Mapping):
            raise AdapterError("GitLab pipeline response must be an object")
        pipeline_id = value.get("id")
        pipeline_ref = str(value.get("web_url") or "").strip()
        if type(pipeline_id) is not int or pipeline_id <= 0 or not pipeline_ref:
            raise AdapterError("GitLab pipeline identity is incomplete")
        if str(value.get("ref") or "") != self.config["ref"]:
            raise AdapterError("GitLab pipeline ref does not match the configured protected ref")
        pipeline_sha = str(value.get("sha") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40}", pipeline_sha):
            raise AdapterError("GitLab pipeline commit SHA is incomplete")
        self._validate_web_url(pipeline_ref, kind="pipeline")
        return pipeline_id, pipeline_ref, pipeline_sha

    def _validate_job_binding(
        self,
        job: Mapping[str, Any],
        *,
        pipeline_id: int,
        pipeline_sha: str,
    ) -> None:
        pipeline = job.get("pipeline")
        commit = job.get("commit")
        if not isinstance(pipeline, Mapping) or pipeline.get("id") != pipeline_id:
            raise AdapterError("GitLab gate job does not belong to the triggered pipeline")
        if str(pipeline.get("ref") or "") != self.config["ref"]:
            raise AdapterError("GitLab gate job pipeline ref is not the protected ref")
        if str(job.get("ref") or "") != self.config["ref"]:
            raise AdapterError("GitLab gate job ref is not the protected ref")
        if not isinstance(commit, Mapping) or (
            str(commit.get("id") or "").strip().lower() != pipeline_sha
        ):
            raise AdapterError("GitLab gate job commit does not match the pipeline")

    def _validate_web_url(self, value: str, *, kind: str) -> None:
        expected = urllib.parse.urlsplit(self.config["base_url"])
        observed = urllib.parse.urlsplit(value)
        try:
            expected_port = expected.port or 443
            observed_port = observed.port or 443
        except ValueError as exc:
            raise AdapterError(f"GitLab {kind} URL has an invalid port") from exc
        if (
            observed.scheme != "https"
            or observed.hostname != expected.hostname
            or observed_port != expected_port
            or observed.username
            or observed.password
            or observed.query
            or observed.fragment
        ):
            raise AdapterError(f"GitLab {kind} URL is not bound to the configured origin")


def _extract_commit_sha(branch: Mapping[str, Any]) -> str:
    commit = branch.get("commit")
    sha = (
        str(commit.get("id") or "").strip().lower()
        if isinstance(commit, Mapping)
        else ""
    )
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise AdapterError("GitLab protected ref commit SHA is incomplete")
    return sha


def _validate_config(config: Mapping[str, Any]) -> dict[str, Any]:
    base_url = str(config.get("base_url") or "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise AdapterError("base_url must be one credential-free HTTPS origin")
    try:
        parsed.port
    except ValueError as exc:
        raise AdapterError("base_url has an invalid port") from exc
    project_id = config.get("project_id")
    if type(project_id) is not int or project_id <= 0:
        raise AdapterError("project_id must be a positive integer")
    ref = str(config.get("ref") or "").strip()
    job_name = str(config.get("job_name") or "").strip()
    token_env = str(config.get("token_env") or "").strip()
    if not ref or not job_name:
        raise AdapterError("ref and job_name are required")
    configured_artifact_path = str(
        config.get("artifact_path") or ""
    ).strip().replace("\\", "/")
    if configured_artifact_path and (
        configured_artifact_path != _ARTIFACT_PATH_TEMPLATE
    ):
        raise AdapterError(
            "artifact_path is fixed to the pipeline/job-bound template"
        )
    if not _ENV_NAME_RE.fullmatch(token_env):
        raise AdapterError("token_env must be one environment variable name")
    if config.get("verify_tls") is False:
        raise AdapterError("TLS verification cannot be disabled")
    ca_bundle = str(config.get("ca_bundle") or "").strip()
    if ca_bundle and not Path(ca_bundle).expanduser().is_file():
        raise AdapterError("ca_bundle does not exist")
    timeout_seconds = int(config.get("timeout_seconds") or 900)
    poll_interval_seconds = float(config.get("poll_interval_seconds", 5))
    if timeout_seconds < 1 or timeout_seconds > 7200:
        raise AdapterError("timeout_seconds must be between 1 and 7200")
    if poll_interval_seconds < 0 or poll_interval_seconds > 60:
        raise AdapterError("poll_interval_seconds must be between 0 and 60")
    return {
        "base_url": base_url,
        "project_id": project_id,
        "ref": ref,
        "job_name": job_name,
        "artifact_path_template": _ARTIFACT_PATH_TEMPLATE,
        "token_env": token_env,
        "timeout_seconds": timeout_seconds,
        "poll_interval_seconds": poll_interval_seconds,
        "ca_bundle": str(Path(ca_bundle).expanduser().resolve()) if ca_bundle else "",
    }


def _validate_adapter_request(request: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "event_id",
        "round_id",
        "task",
        "module",
        "retrieval_method",
        "source_locator",
        "revision",
        "version",
        "retrieval_instructions",
        "request_digest",
        "policy_profile",
        "policy_digest",
        "effective_checks",
        "sender_artifact_declarations",
    }
    if set(request) != required:
        raise AdapterError("adapter request fields do not match SubmissionGateAdapterRequest/v1")
    if request.get("schema") != "SubmissionGateAdapterRequest/v1":
        raise AdapterError("adapter request schema is invalid")
    if not isinstance(request.get("event_id"), str) or not request["event_id"].strip():
        raise AdapterError("adapter request event_id is required")
    if type(request.get("round_id")) is not int or request["round_id"] <= 0:
        raise AdapterError("adapter request round_id must be positive")
    for field in ("task", "module", "retrieval_method", "policy_profile"):
        if not isinstance(request.get(field), str) or not request[field].strip():
            raise AdapterError(f"adapter request {field} is required")
    for field in ("request_digest", "policy_digest"):
        if not _SHA256_DIGEST_RE.fullmatch(str(request.get(field) or "")):
            raise AdapterError(f"adapter request {field} is invalid")
    checks = request.get("effective_checks")
    declarations = request.get("sender_artifact_declarations")
    if not isinstance(checks, list) or not checks or any(
        not isinstance(item, str) or not item.strip() for item in checks
    ):
        raise AdapterError("adapter request effective_checks must be a non-empty string array")
    if not isinstance(declarations, list):
        raise AdapterError("adapter request sender_artifact_declarations must be an array")
    if request["retrieval_method"] == "svn":
        if not str(request.get("source_locator") or "").strip():
            raise AdapterError("SVN adapter request source_locator is required")
        if not str(request.get("revision") or "").isdigit():
            raise AdapterError("SVN adapter request revision must be numeric")
    return json.loads(canonical_json(request))


def load_adapter_config(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterError(f"cannot read adapter config: {exc}") from exc
    if not isinstance(payload, dict):
        raise AdapterError("adapter config must be one JSON object")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Protected GitLab submission-gate adapter")
    parser.add_argument("--config", required=True)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        adapter = GitLabGateAdapter(load_adapter_config(args.config))
        if args.preflight:
            result = adapter.preflight()
            print(json.dumps({"ok": bool(result.get("ready")), "result": result}, ensure_ascii=False))
            return 0 if result.get("ready") else 3
        raw = sys.stdin.buffer.read(_MAX_JSON_BYTES + 1)
        if len(raw) > _MAX_JSON_BYTES:
            raise AdapterError("adapter request exceeds the size limit")
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise AdapterError("adapter request must be one JSON object")
        result = adapter.evaluate(request)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))
        return 0
    except (AdapterError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {"code": "GATE_ADAPTER_FAILED", "message": str(exc)},
                },
                ensure_ascii=False,
            )
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
