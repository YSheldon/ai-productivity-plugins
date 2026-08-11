# Merge Request Approval and Scope Gate

This plugin includes a CI-only verifier that binds a real GitLab merge request
approval to the candidate commit, target branch, merge request IID, and the raw
SHA-256 of a reviewed scope file. It is independent from the interactive MCP
profile and accepts only GitLab's `CI_JOB_TOKEN` for the authority check.

## Required GitLab Controls

Configure at least one required merge request approval rule for the protected
target branch. Disable direct pushes, require a successful merge request
pipeline, prevent self-approval and approval by commit authors where the GitLab
tier exposes those settings, and reset approvals when new commits are pushed.

The CI job fails unless the approvals endpoint returns both
`approved == true` and `approvals_left == 0`. A personal access token,
comment, label, reviewer assignment, or user-provided boolean is never accepted
as a substitute.

## GitLab Compatibility Gate

At the time of version `0.4.0`, GitLab's official CI job-token endpoint list
allows `GET /projects/:id/merge_requests/:iid` but does **not** list
`GET /projects/:id/merge_requests/:iid/approvals`. The fine-grained
`READ_MERGE_REQUESTS` permission does not list the approvals endpoint either.

Consequently, the verifier intentionally fails closed with 401/403/404 on a
stock instance. Deploy this live approval mode only after an administrator has
verified that the exact GitLab instance explicitly supports the approvals
endpoint for `CI_JOB_TOKEN`, such as a reviewed self-managed extension or a
future GitLab release that documents the endpoint. Job-token allowlisting alone
does not grant an endpoint that GitLab does not expose.

Do not work around this boundary with a PAT, project access token, pipeline
variable, label, comment, or `CI_MERGE_REQUEST_APPROVED` fallback. For stock
GitLab, use protected-branch MR approval as the merge authority and perform the
scope hash/build in a protected-branch pipeline after merge. That alternative
does not provide a live `approvals_left` receipt and must be documented as a
different trust model.

Official compatibility references:

- https://docs.gitlab.com/ci/jobs/ci_job_token/
- https://docs.gitlab.com/ci/jobs/fine_grained_permissions/

## Scope File Contract

Commit the credential-free scope JSON as part of the reviewed MR, and set
`GITLAB_APPROVAL_SCOPE_FILE` to its absolute checkout path. A protected GitLab
CI File variable is also supported when the instance's protected-variable rules
make it available to the detached MR pipeline. The file must use this exact
JSON contract:

```json
{
  "format": "gitlab-mr-approval-scope/v1",
  "candidate_sha": "0123456789abcdef0123456789abcdef01234567",
  "target_branch": "main",
  "approval_source": "gitlab_mr",
  "merge_request_iid": "42",
  "prepared_at": "2026-08-10T12:00:00Z",
  "approved_at": "2026-08-10T12:30:00Z",
  "prepared_by": "release-preparer",
  "approved_by": "release-approver",
  "scope": {
    "id": "release-2026-08-10",
    "items": [
      "artifact:server",
      "artifact:web",
      "deployment:production"
    ]
  }
}
```

The verifier rejects unknown or missing fields, duplicate JSON keys, duplicate
scope items, malformed identities or timestamps, credential-like content,
symlinks, non-regular files, oversized files, and group/world write permissions
on POSIX. Read access is allowed because the scope is deliberately
credential-free. Windows UNC/network paths are rejected. `prepared_by` and
`approved_by` must
differ, and `approved_by` must be a username returned by the live GitLab
approval response.

Scope items are stable authorization identifiers, not arbitrary data. Put
product-specific decisions in a separately reviewed artifact and reference its
immutable ID or digest as a scope item. Do not put passwords, tokens, private
keys, connection strings, environment overrides, or embedded configuration in
this file.

On Windows, POSIX mode bits do not establish DACL protection. Use a dedicated
Runner, run this verifier before candidate-controlled scripts, and restrict the
job workspace and temporary directory ACL to the Runner service identity,
Administrators, and SYSTEM.

## CI Job

After the compatibility gate above passes, vendor or otherwise make the
verifier available to the repository, then run it in a detached merge request
pipeline. Fork/source-project and merged-result pipelines are rejected because
their project or candidate identity can differ:

```yaml
approval_scope_gate:
  stage: verify
  variables:
    GITLAB_APPROVAL_SCOPE_FILE: "$CI_PROJECT_DIR/.gitlab/approval-scope.json"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - when: never
  cache: []
  script:
    - python3 plugins/gitlab/scripts/verify_mr_approval_scope.py > approval-scope-gate.json
  artifacts:
    when: always
    paths:
      - approval-scope-gate.json
```

The verifier also requires `CI_API_V4_URL`, `CI_PROJECT_ID`,
`CI_MERGE_REQUEST_PROJECT_ID`, `CI_MERGE_REQUEST_IID`, `CI_COMMIT_SHA`,
`CI_MERGE_REQUEST_TARGET_BRANCH_NAME`, `CI_MERGE_REQUEST_EVENT_TYPE`,
`CI_PIPELINE_SOURCE`, `CI_JOB_ID`, and `CI_JOB_TOKEN`. It requires
`CI_PIPELINE_SOURCE=merge_request_event`, a detached MR event, and matching
pipeline/MR project IDs.

Do not add `rules:changes` to this job and do not restore its result from a
cache. Every candidate commit must perform a fresh GitLab API check.

The JSON result contains the candidate SHA, MR IID, target branch, scope ID,
scope SHA-256, job ID, and sanitized approval counts. Bind those values into the
release artifact or its immutable build manifest, then verify them again at
deployment. The gate proves candidate/scope consistency against GitLab at job
time; it does not protect against a privileged Runner administrator replacing
both the artifact and its verifier.
