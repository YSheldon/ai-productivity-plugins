# Test Submission

`test-submission` provides four surfaces: MCP, Skill, standalone CLI, and unattended OS scheduling. It collects one explicit `kernel` / `client` / `server` submission and sends a structured `【提测】` request through the locked `imap-smtp-mail` CLI.

- Local submissions require reachable files, compute SHA-1/SHA-256, and create a local Manifest-S preview through the locked `product-release-gate` runtime.
- SVN submissions require only a source locator, fixed numeric revision, and declared version. They do not invent local file hashes, signatures, cloud-scan verdicts, or a Manifest-S; the protected GitLab CI gate retrieves the exact revision and produces those evidence records.

Key properties:

- zero manual JSON editing through `test_submission_cli.py setup`
- `test_submission_cli.py run-once` retries only durable pending outbound mail
- `test_submission_cli.py preflight`, `status`, and `doctor` expose readiness and local state without needing Codex
- zero prompts on setup rerun
- no credentials written into plugin config
- Codex is optional
- CLI fallback and OS retry scheduler both use the same controller and store
- module is required on every submit; there is no default module
- all subprocess calls use argument arrays with `shell=False`
- `preflight` reports `local_ready` and `svn_ready` independently, so an SVN-only sender is not blocked by an unused local preview profile
- HMAC is optional. When `TEST_SUBMISSION_HMAC_KEY` exists, the message is marked `合规插件发起（HMAC 已附带）`; without it, the same request continues as `普通兼容模式（未验证）`. A receiver must still block a claimed but invalid HMAC.

Use the Skill for operator guidance, the CLI for automation, the MCP server for Codex orchestration, and the scheduler only for retrying local pending outbound mail.
