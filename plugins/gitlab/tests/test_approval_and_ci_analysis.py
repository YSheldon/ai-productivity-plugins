from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "gitlab_mcp.py"


def load_module():
    spec = importlib.util.spec_from_file_location("gitlab_mcp_analysis_test", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


class FakeClient:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict | None]] = []

    def request(self, method: str, path: str, query: dict | None = None, **_kwargs):
        self.calls.append((method, path, query))
        assert self.responses, f"unexpected request: {method} {path}"
        return self.responses.pop(0)


def test_approval_state_is_candidate_bound_sanitized_and_non_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    sha = "a" * 40
    fake = FakeClient(
        [
            {
                "iid": 17,
                "sha": sha,
                "target_branch": "main",
                "state": "opened",
                "author": {"username": "must-not-be-returned"},
            },
            {
                "approved": True,
                "approvals_left": 0,
                "approvals_required": 1,
                "approved_by": [{"user": {"username": "release-approver"}}],
            },
        ]
    )
    monkeypatch.setattr(module, "client", lambda _args: fake)

    result = payload(
        module.get_merge_request_approval_state(
            {
                "project": "group/repo",
                "iid": 17,
                "expected_candidate_sha": sha,
                "expected_target_branch": "main",
            }
        )
    )

    assert fake.calls == [
        ("GET", "/projects/group%2Frepo/merge_requests/17", None),
        ("GET", "/projects/group%2Frepo/merge_requests/17/approvals", None),
    ]
    assert result == {
        "project": "group/repo",
        "merge_request_iid": 17,
        "state": "opened",
        "candidate_sha": sha,
        "target_branch": "main",
        "approved": True,
        "approvals_left": 0,
        "approvals_required": 1,
        "meets_required_approval": True,
        "candidate_matches_expected": True,
        "target_branch_matches_expected": True,
        "authoritative_for_release": False,
        "authentication_boundary": "configured-profile-not-ci-job-token",
    }
    serialized = json.dumps(result)
    assert "must-not-be-returned" not in serialized
    assert "release-approver" not in serialized


@pytest.mark.parametrize(
    "approval_payload",
    [
        {"approved": "true", "approvals_left": 0, "approvals_required": 1},
        {"approved": True, "approvals_left": False, "approvals_required": 1},
        {"approved": True, "approvals_left": 0, "approvals_required": "1"},
    ],
)
def test_approval_state_rejects_malformed_authority_fields(
    monkeypatch: pytest.MonkeyPatch,
    approval_payload: dict,
) -> None:
    module = load_module()
    fake = FakeClient(
        [
            {"iid": 3, "sha": "b" * 40, "target_branch": "main", "state": "opened"},
            approval_payload,
        ]
    )
    monkeypatch.setattr(module, "client", lambda _args: fake)

    with pytest.raises(module.ToolError, match="malformed"):
        module.get_merge_request_approval_state({"project": 12, "iid": 3})


def test_ci_lint_analysis_returns_only_structural_job_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake = FakeClient(
        [
            {
                "valid": True,
                "errors": [],
                "warnings": ["password: leaked-value with spaces"],
                "merged_yaml": "variables:\n  SECRET: leaked-value",
                "jobs": [
                    {
                        "name": "build:linux",
                        "stage": "build",
                        "scripts": ["curl -H 'PRIVATE-TOKEN: leaked-value'"],
                        "variables": [{"key": "SECRET", "value": "leaked-value"}],
                        "tag_list": ["linux"],
                        "when": "on_success",
                        "allow_failure": False,
                        "needs": [],
                    },
                    {
                        "name": "test:linux",
                        "stage": "test",
                        "script": "echo leaked-value",
                        "tags": ["linux"],
                        "when": "on_success",
                        "allow_failure": True,
                        "needs": [{"name": "build:linux", "optional": False}],
                        "only": {"refs": ["merge_requests"]},
                    },
                ],
            }
        ]
    )
    monkeypatch.setattr(module, "client", lambda _args: fake)

    result = payload(
        module.analyze_ci_config(
            {"project": "group/repo", "ref": "feature/ci", "dry_run": True}
        )
    )

    assert fake.calls == [
        (
            "GET",
            "/projects/group%2Frepo/ci/lint",
            {"content_ref": "feature/ci", "include_jobs": "true", "dry_run": "true"},
        )
    ]
    assert result["valid"] is True
    assert result["job_count"] == 2
    assert result["stage_job_counts"] == {"build": 1, "test": 1}
    assert result["jobs"] == [
        {
            "name": "build:linux",
            "stage": "build",
            "tags": ["linux"],
            "when": "on_success",
            "allow_failure": False,
            "needs": [],
            "has_only": False,
            "has_except": False,
        },
        {
            "name": "test:linux",
            "stage": "test",
            "tags": ["linux"],
            "when": "on_success",
            "allow_failure": True,
            "needs": ["build:linux"],
            "has_only": True,
            "has_except": False,
        },
    ]
    assert "allow-failure-review" in {item["id"] for item in result["recommendations"]}
    assert result["analysis_limits"]["cache_and_rules"] == "not_exposed_by_ci_lint_jobs"
    serialized = json.dumps(result)
    assert "leaked-value" not in serialized
    assert "with spaces" not in serialized
    assert "merged_yaml" not in serialized
    assert "script" not in serialized
    assert "variables" not in serialized


def test_ci_lint_analysis_rejects_malformed_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake = FakeClient([{"valid": True, "errors": [], "warnings": [], "jobs": {}}])
    monkeypatch.setattr(module, "client", lambda _args: fake)

    with pytest.raises(module.ToolError, match="malformed"):
        module.analyze_ci_config({"project": 1, "ref": "main"})


def test_pipeline_efficiency_uses_job_timings_without_returning_raw_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()
    fake = FakeClient(
        [
            [
                {
                    "id": 11,
                    "name": "build-a",
                    "stage": "build",
                    "status": "success",
                    "duration": 40.0,
                    "queued_duration": 25.0,
                    "started_at": "2026-08-10T10:00:00Z",
                    "finished_at": "2026-08-10T10:00:40Z",
                    "runner": {"token": "must-not-leak"},
                },
                {
                    "id": 12,
                    "name": "build-b",
                    "stage": "build",
                    "status": "success",
                    "duration": 30.0,
                    "queued_duration": 20.0,
                    "started_at": "2026-08-10T10:00:00Z",
                    "finished_at": "2026-08-10T10:00:30Z",
                },
                {
                    "id": 13,
                    "name": "test",
                    "stage": "test",
                    "status": "success",
                    "duration": 20.0,
                    "queued_duration": 2.0,
                    "started_at": "2026-08-10T10:00:40Z",
                    "finished_at": "2026-08-10T10:01:00Z",
                },
                {
                    "id": 14,
                    "name": "manual-release",
                    "stage": "release",
                    "status": "manual",
                    "duration": None,
                    "queued_duration": None,
                    "started_at": None,
                    "finished_at": None,
                },
            ]
        ]
    )
    monkeypatch.setattr(module, "client", lambda _args: fake)

    result = payload(module.analyze_pipeline_efficiency({"project": 99, "pipeline_id": 123}))

    assert fake.calls == [
        (
            "GET",
            "/projects/99/pipelines/123/jobs",
            {"per_page": 100, "include_retried": "false"},
        )
    ]
    assert result["job_count"] == 4
    assert result["executed_job_count"] == 3
    assert result["total_execution_seconds"] == 90.0
    assert result["total_queue_seconds"] == 47.0
    assert result["pipeline_wall_clock_seconds"] == 60.0
    assert result["execution_to_wall_clock_ratio"] == 1.5
    assert result["stage_metrics"] == [
        {"stage": "build", "job_count": 2, "execution_seconds": 70.0, "queue_seconds": 45.0},
        {"stage": "test", "job_count": 1, "execution_seconds": 20.0, "queue_seconds": 2.0},
    ]
    assert result["queue_bottlenecks"][0] == {
        "job_id": 11,
        "name": "build-a",
        "stage": "build",
        "queue_seconds": 25.0,
        "execution_seconds": 40.0,
    }
    assert "runner-capacity-review" in {item["id"] for item in result["recommendations"]}
    serialized = json.dumps(result)
    assert "must-not-leak" not in serialized
    assert '"runner":' not in serialized


def test_new_tools_do_not_accept_credentials_or_raw_output() -> None:
    module = load_module()
    expected = {
        "gitlab_get_merge_request_approval_state",
        "gitlab_analyze_ci_config",
        "gitlab_analyze_pipeline_efficiency",
    }
    assert expected.issubset(module.TOOLS)
    for name in expected:
        schema = module.TOOLS[name]["inputSchema"]
        assert schema["additionalProperties"] is False
        properties = schema["properties"]
        assert "token" not in properties
        assert "job_token" not in properties
        assert "raw" not in properties


def test_new_tools_reject_nonpositive_resource_ids_before_api_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_module()

    def unexpected_client(_args):
        raise AssertionError("API client should not be created")

    monkeypatch.setattr(module, "client", unexpected_client)
    with pytest.raises(module.ToolError, match="iid"):
        module.get_merge_request_approval_state({"project": 1, "iid": 0})
    with pytest.raises(module.ToolError, match="pipeline_id"):
        module.analyze_pipeline_efficiency({"project": 1, "pipeline_id": -1})


@pytest.mark.parametrize("timing", [float("nan"), float("inf"), float("-inf")])
def test_pipeline_efficiency_rejects_nonfinite_timings(
    monkeypatch: pytest.MonkeyPatch,
    timing: float,
) -> None:
    module = load_module()
    fake = FakeClient(
        [
            [
                {
                    "id": 1,
                    "name": "build",
                    "stage": "build",
                    "duration": timing,
                    "queued_duration": 0,
                    "started_at": "2026-08-10T10:00:00Z",
                    "finished_at": "2026-08-10T10:00:01Z",
                }
            ]
        ]
    )
    monkeypatch.setattr(module, "client", lambda _args: fake)

    with pytest.raises(module.ToolError, match="timing"):
        module.analyze_pipeline_efficiency({"project": 1, "pipeline_id": 1})
