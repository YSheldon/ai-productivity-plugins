---
name: gitlab-mr-approval-scope-binding
description: Configure and verify a fail-closed, product-neutral GitLab merge request release gate using CI_JOB_TOKEN, live approval state, and a reviewed scope-file SHA-256 bound to the candidate build.
---

# GitLab MR Approval and Scope Binding

Use this workflow for protected release approvals, deployment authorization,
artifact scope binding, or replacing ad-hoc approval booleans with GitLab's real
merge request authority.

## Invariants

- Require at least one configured GitLab MR approval on the protected target
  branch.
- Query the live MR and `/approvals` endpoints from an MR pipeline using only
  `CI_JOB_TOKEN`.
- Require `approved == true`, `approvals_left == 0`, and at least one required
  approval.
- Bind the exact MR IID, candidate SHA, target branch, and raw scope-file
  SHA-256 to the release artifact or immutable build manifest.
- Never infer approval from comments, labels, assignments, screenshots, or an
  environment boolean.
- Never accept a personal access token as a CI authority fallback.
- Never print tokens, full approval responses, or unnecessary identities.
- Treat GitLab job-token endpoint support as an admission gate. Current stock
  GitLab documentation does not list the MR approvals endpoint for job tokens.

## Workflow

1. Resolve the project, MR IID, actual candidate SHA, and target branch.
2. Use `gitlab_get_merge_request_approval_state` only for interactive inspection.
   Its configured profile credential is not release authority.
3. Configure protected-branch approval rules, successful MR pipelines, approval
   reset on new commits, and self/author-approval restrictions where available.
4. Check the instance compatibility boundary in
   `../../docs/mr-approval-scope-gate.md`. Do not assume job-token allowlisting
   grants the unlisted approvals endpoint.
5. Commit the credential-free scope JSON in the reviewed MR and set
   `GITLAB_APPROVAL_SCOPE_FILE` to its absolute checkout path. A protected File
   variable is optional only when GitLab makes it available to this MR pipeline.
   Use the exact contract in `references/scope-manifest.md`.
6. Run `scripts/verify_mr_approval_scope.py` in a detached target-project MR
   pipeline before candidate-controlled build scripts. Do not add
   `rules:changes` or cache its result.
7. Bind the returned scope digest, MR IID, SHA, and target branch into the build.
8. Recheck those values at deployment and retain only sanitized evidence.

Stop on missing CI variables, non-2xx responses, redirects, transport errors,
malformed JSON, incomplete approval, identity mismatch, scope mutation,
credential-like content, or an insecure scope file. Do not downgrade these
failures to warnings.

On a stock GitLab version that rejects `/approvals` for `CI_JOB_TOKEN`, stop.
Do not fall back to a PAT or an overridable approval boolean. Use GitLab's
protected-branch approval enforcement and a post-merge protected build as a
separately documented trust model.

Read `references/scope-manifest.md` before preparing or reviewing a scope file.
See `../../docs/mr-approval-scope-gate.md` for the CI example and platform
boundaries.
