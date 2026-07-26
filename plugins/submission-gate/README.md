# Submission Gate

`submission-gate` provides four surfaces: MCP, Skill, standalone CLI, and unattended OS scheduling. It scans one configured mailbox for `【提测】` mail, validates structured content and `X-RD-*` headers, creates the authoritative event through the locked `product-release-gate` CLI, runs the submission gate, and sends a PASS or BLOCKED response mail.

Key properties:

- zero manual JSON editing through `submission_gate_cli.py setup`
- `submission_gate_cli.py run-once` executes the headless mailbox scan exactly once with the same gate controller used by the scheduler
- `submission_gate_cli.py preflight`, `status`, and `doctor` expose the same readiness, queue, and health evidence without requiring Codex runtime
- zero prompts on setup rerun
- no credentials written into plugin config
- Codex is optional
- CLI fallback and unattended scheduler use the same controller and idempotent store
- duplicate mail is ignored by `uidvalidity + uid + message_id + event_id + round_id`
- HMAC is optional: valid HMAC is marked `合规插件发起（已验证）`; missing HMAC is marked unverified and continues; a claimed but invalid HMAC fails closed
- zero effective checks or missing required integrations fail closed
