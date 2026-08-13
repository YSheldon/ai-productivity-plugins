# Submission Gate

`submission-gate` provides four surfaces: MCP, Skill, standalone CLI, and unattended OS scheduling. It scans one configured mailbox for `【提测】` mail, validates structured content and `X-RD-*` headers, triggers one protected GitLab `submission_gate` job, validates its bound `GitLabGateResult/v1`, and sends a PASS or BLOCKED response mail.

Key properties:

- zero manual JSON editing through `submission_gate_cli.py setup`
- `submission_gate_cli.py run-once` executes the headless mailbox scan exactly once with the same gate controller used by the scheduler
- `submission_gate_cli.py preflight`, `status`, and `doctor` expose the same readiness, queue, and health evidence without requiring Codex runtime
- zero prompts on setup rerun
- no credentials written into plugin config
- GitLab credentials are read only from the configured environment variable (default `PMG_GITLAB_TOKEN`)
- TLS verification cannot be disabled; an enterprise CA bundle may be configured
- the protected-ref head commit, exact pipeline, single gate job, and result artifact are bound and polled with bounded timeouts
- pipeline/job links must remain on the configured GitLab HTTPS origin; redirects are never followed with the token
- CLEAN requires a canonical full Manifest-S and a nonempty rollback baseline reference
- Manifest-S binds task, module, frozen policy, actual file size, SHA1, SHA256, source reference, and evidence references
- the adapter entrypoint, credential-free adapter config, and imported shared contract files are SHA-256 locked; preflight fails closed on timeout, startup failure, integrity drift, or non-explicit success
- Codex is optional
- CLI fallback and unattended scheduler use the same controller and idempotent store
- duplicate mail is ignored by `uidvalidity + uid + message_id + event_id + round_id`
- HMAC is optional: valid HMAC is marked `合规插件发起（已验证）`; missing HMAC is marked unverified and continues; a claimed but invalid HMAC fails closed
- zero effective checks or missing required integrations fail closed

## Setup

Use `submission_gate_cli.py setup`. First setup asks only for the two mail groups plus GitLab base URL and project ID when they were not supplied as CLI arguments. Setup writes a credential-free `gitlab-gate-adapter.json`, freezes an integrity manifest for the adapter, its config, and its imported shared contract, runs preflight, executes one headless scan, and installs the unattended scheduler. Reruns reuse the managed values without prompts.

The protected GitLab job must publish
`artifacts/<pipeline-id>-<job-id>-submission-gate/result.json`. The adapter
derives this path from the exact triggered pipeline/job and it is not
user-configurable. The job must retrieve the fixed source revision using
runner-side credentials, perform the configured checks, and return
`rollback_ref`; client-side SVN or cloud-scan credentials are not accepted.
