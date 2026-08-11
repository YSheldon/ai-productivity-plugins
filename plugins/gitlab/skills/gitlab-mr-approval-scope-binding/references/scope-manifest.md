# Generic Scope Manifest Contract

Use exact format `gitlab-mr-approval-scope/v1` and the following fixed fields:

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
    "items": ["artifact:server", "deployment:production"]
  }
}
```

Rules:

- Candidate SHA, target branch, and MR IID must match the current MR pipeline.
- `approval_source` is exactly `gitlab_mr`.
- Timestamps are non-zero UTC values and approval cannot predate preparation.
- Preparer and approver are different safe identifiers.
- Approver equals a GitLab username in the live approval response.
- `scope` contains exactly `id` and a non-empty list of unique stable item IDs.
- Unknown fields, duplicate keys/items, credentials, free-form configuration,
  and embedded product data are rejected.

Reference product-specific decisions by immutable ID or digest. Validate those
decisions in their owning system; this generic contract intentionally does not
define product schemas.
