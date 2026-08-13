from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from gitlab_gate_adapter import (
    AdapterError,
    GitLabGateAdapter,
    _NoRedirectHandler,
)


PIPELINE_REF = "https://gitlab.example.test/ai/product-material-gate-ci/-/pipelines/101"
JOB_REF = "https://gitlab.example.test/ai/product-material-gate-ci/-/jobs/202"
ARTIFACT_PATH = "artifacts/101-202-submission-gate/result.json"
ARTIFACT_REF = JOB_REF + "/artifacts/file/" + ARTIFACT_PATH
COMMIT_SHA = "a" * 40


def _request() -> dict[str, Any]:
    return {
        "schema": "SubmissionGateAdapterRequest/v1",
        "event_id": "event-1",
        "round_id": 1,
        "task": "TASK-1",
        "module": "client",
        "retrieval_method": "svn",
        "source_locator": "https://svn.example.test/repos/client",
        "revision": "1047",
        "version": "8.2.0",
        "retrieval_instructions": "",
        "request_digest": "sha256:" + "1" * 64,
        "policy_profile": "submission-gate/v1",
        "policy_digest": "sha256:" + "2" * 64,
        "effective_checks": [
            "provenance_locator_present",
            "fixed_revision_present",
            "trusted_retrieval_succeeded",
            "retrieved_nonempty",
            "audit_recorded",
        ],
        "sender_artifact_declarations": [],
    }


def _result(request: dict[str, Any]) -> dict[str, Any]:
    artifact_bytes = b"retrieved-client"
    evidence_refs = sorted([PIPELINE_REF, JOB_REF, ARTIFACT_REF])
    manifest_s: dict[str, Any] = {
        "schema": "ProductMaterialManifestS/v1",
        "event_id": request["event_id"],
        "round_id": request["round_id"],
        "task": request["task"],
        "module": request["module"],
        "policy_profile": request["policy_profile"],
        "policy_digest": request["policy_digest"],
        "effective_checks": request["effective_checks"],
        "artifacts": [
            {
                "logical_name": "retrieved-client.pkg",
                "file_name": "retrieved-client.pkg",
                "size": len(artifact_bytes),
                "sha1": hashlib.sha1(artifact_bytes).hexdigest(),
                "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "source_ref": request["source_locator"] + "@" + request["revision"],
            }
        ],
        "evidence_refs": evidence_refs,
    }
    canonical = json.dumps(
        manifest_s,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    manifest_s["manifest_s_digest"] = "sha256:" + hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()
    return {
        "adapter_contract": "GitLabGateResult/v1",
        "provider": "gitlab",
        "verdict": "CLEAN",
        "event_id": request["event_id"],
        "round_id": request["round_id"],
        "request_digest": request["request_digest"],
        "policy_digest": request["policy_digest"],
        "manifest_digest": manifest_s["manifest_s_digest"],
        "material_sha256": manifest_s["artifacts"][0]["sha256"],
        "evidence_refs": evidence_refs,
        "pipeline_ref": PIPELINE_REF,
        "job_ref": JOB_REF,
        "artifact_ref": ARTIFACT_REF,
        "rollback_ref": "gitlab://ref/protected-release-baseline",
        "manifest_s": manifest_s,
        "lark_evidence_ref": "lark://doc/1",
    }


class FakeTransport:
    def __init__(
        self,
        result: dict[str, Any],
        *,
        job_status: str = "success",
        protected_ref: bool = True,
        branch_sha: str = COMMIT_SHA,
        pipeline_sha: str = COMMIT_SHA,
        job_pipeline_id: int = 101,
        job_ref: str = "main",
        job_web_url: str = JOB_REF,
    ) -> None:
        self.result = result
        self.job_status = job_status
        self.protected_ref = protected_ref
        self.branch_sha = branch_sha
        self.pipeline_sha = pipeline_sha
        self.job_pipeline_id = job_pipeline_id
        self.job_ref = job_ref
        self.job_web_url = job_web_url
        self.calls: list[dict[str, Any]] = []

    def request_json(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
        body: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append(
            {"method": method, "path": path, "headers": dict(headers), "body": body}
        )
        if path.endswith("/repository/branches/main"):
            return {
                "name": "main",
                "protected": self.protected_ref,
                "commit": {"id": self.branch_sha},
            }
        if method == "POST":
            return {
                "id": 101,
                "status": "pending",
                "ref": "main",
                "sha": self.pipeline_sha,
                "web_url": PIPELINE_REF,
            }
        if path.endswith("/pipelines/101"):
            return {
                "id": 101,
                "status": "success",
                "ref": "main",
                "sha": self.pipeline_sha,
                "web_url": PIPELINE_REF,
            }
        if path.endswith("/pipelines/101/jobs?per_page=100"):
            return [
                {
                    "id": 202,
                    "name": "submission_gate",
                    "status": self.job_status,
                    "web_url": self.job_web_url,
                    "ref": self.job_ref,
                    "commit": {"id": self.pipeline_sha},
                    "pipeline": {
                        "id": self.job_pipeline_id,
                        "ref": self.job_ref,
                    },
                }
            ]
        raise AssertionError(f"unexpected JSON request: {method} {path}")

    def request_bytes(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
    ) -> bytes:
        self.calls.append(
            {"method": method, "path": path, "headers": dict(headers), "body": None}
        )
        return json.dumps(self.result, ensure_ascii=False).encode("utf-8")


def _config() -> dict[str, Any]:
    return {
        "base_url": "https://gitlab.example.test",
        "project_id": 59,
        "ref": "main",
        "job_name": "submission_gate",
        "token_env": "PMG_GITLAB_TOKEN",
        "timeout_seconds": 60,
        "poll_interval_seconds": 0,
    }


def test_adapter_triggers_exact_pipeline_and_returns_bound_manifest() -> None:
    request = _request()
    transport = FakeTransport(_result(request))
    adapter = GitLabGateAdapter(
        _config(),
        environ={"PMG_GITLAB_TOKEN": "secret-token"},
        transport=transport,
        sleep_fn=lambda _seconds: None,
    )

    result = adapter.evaluate(request)

    assert result["manifest_s"]["manifest_s_digest"] == result["manifest_digest"]
    assert result["pipeline_ref"] == PIPELINE_REF
    create = next(call for call in transport.calls if call["method"] == "POST")
    assert create["method"] == "POST"
    assert create["headers"]["PRIVATE-TOKEN"] == "secret-token"
    variables = {item["key"]: item["value"] for item in create["body"]["variables"]}
    decoded = base64.b64decode(variables["PMG_SUBMISSION_REQUEST_B64"]).decode("utf-8")
    assert json.loads(decoded) == request
    assert variables["PMG_SUBMISSION_REQUEST_SHA256"] == hashlib.sha256(
        decoded.encode("utf-8")
    ).hexdigest()
    assert "secret-token" not in json.dumps(result)
    assert "secret-token" not in json.dumps(create["body"])
    artifact_download = next(
        call
        for call in transport.calls
        if call["method"] == "GET"
        and "/jobs/202/artifacts/" in call["path"]
    )
    assert artifact_download["path"].endswith(
        "/jobs/202/artifacts/" + ARTIFACT_PATH
    )


def test_adapter_rejects_user_configured_or_stale_artifact_path() -> None:
    config = _config()
    config["artifact_path"] = "artifacts/submission-gate/result.json"

    with pytest.raises(AdapterError, match="pipeline/job-bound"):
        GitLabGateAdapter(
            config,
            environ={"PMG_GITLAB_TOKEN": "token"},
            transport=FakeTransport(_result(_request())),
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://gitlab.example.test",
        "https://user@gitlab.example.test",
        "https://gitlab.example.test/group",
        "https://gitlab.example.test:bad",
    ],
)
def test_adapter_rejects_non_origin_gitlab_base_url(base_url: str) -> None:
    config = _config()
    config["base_url"] = base_url

    with pytest.raises(AdapterError, match="base_url"):
        GitLabGateAdapter(
            config,
            environ={"PMG_GITLAB_TOKEN": "token"},
            transport=FakeTransport(_result(_request())),
        )


def test_adapter_rejects_tampered_result_and_failed_job() -> None:
    request = _request()
    tampered = _result(request)
    tampered["manifest_s"]["task"] = "FORGED"
    adapter = GitLabGateAdapter(
        _config(),
        environ={"PMG_GITLAB_TOKEN": "token"},
        transport=FakeTransport(tampered),
        sleep_fn=lambda _seconds: None,
    )
    with pytest.raises(AdapterError, match="Manifest-S digest"):
        adapter.evaluate(request)

    failed = GitLabGateAdapter(
        _config(),
        environ={"PMG_GITLAB_TOKEN": "token"},
        transport=FakeTransport(_result(request), job_status="failed"),
        sleep_fn=lambda _seconds: None,
    )
    with pytest.raises(AdapterError, match="job.*failed"):
        failed.evaluate(request)


def test_adapter_preflight_requires_token_without_exposing_it() -> None:
    adapter = GitLabGateAdapter(
        _config(),
        environ={},
        transport=FakeTransport(_result(_request())),
    )

    preflight = adapter.preflight()

    assert preflight == {
        "ready": False,
        "status": "CAPABILITY_BLOCKED",
        "reason": "GitLab token environment variable is not configured",
        "token_env": "PMG_GITLAB_TOKEN",
    }


def test_adapter_preflight_requires_accessible_protected_ref() -> None:
    adapter = GitLabGateAdapter(
        _config(),
        environ={"PMG_GITLAB_TOKEN": "token"},
        transport=FakeTransport(_result(_request()), protected_ref=False),
    )

    preflight = adapter.preflight()

    assert preflight["ready"] is False
    assert preflight["status"] == "CAPABILITY_BLOCKED"
    assert "protected" in preflight["reason"].lower()


def test_adapter_preflight_fails_closed_on_missing_protected_ref_commit() -> None:
    adapter = GitLabGateAdapter(
        _config(),
        environ={"PMG_GITLAB_TOKEN": "token"},
        transport=FakeTransport(_result(_request()), branch_sha=""),
    )

    preflight = adapter.preflight()

    assert preflight["ready"] is False
    assert preflight["status"] == "CAPABILITY_BLOCKED"
    assert "commit SHA" in preflight["reason"]


def test_gitlab_transport_never_follows_redirects() -> None:
    handler = _NoRedirectHandler()

    assert (
        handler.redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://evil.example.test/",
        )
        is None
    )


@pytest.mark.parametrize(
    ("transport", "message"),
    [
        (FakeTransport(_result(_request()), pipeline_sha="b" * 40), "commit"),
        (FakeTransport(_result(_request()), job_pipeline_id=999), "triggered pipeline"),
        (FakeTransport(_result(_request()), job_ref="feature"), "protected ref"),
        (
            FakeTransport(
                _result(_request()),
                job_web_url="https://evil.example.test/ai/project/-/jobs/202",
            ),
            "configured origin",
        ),
    ],
)
def test_adapter_rejects_unbound_pipeline_or_job_identity(
    transport: FakeTransport,
    message: str,
) -> None:
    adapter = GitLabGateAdapter(
        _config(),
        environ={"PMG_GITLAB_TOKEN": "token"},
        transport=transport,
        sleep_fn=lambda _seconds: None,
    )

    with pytest.raises(AdapterError, match=message):
        adapter.evaluate(_request())
