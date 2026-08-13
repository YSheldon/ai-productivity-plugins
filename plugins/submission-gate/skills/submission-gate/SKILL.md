---
name: submission-gate
description: Scan structured `【提测】` mail, verify optional HMAC, and execute a protected GitLab submission gate with a bound Manifest-S result.
---

# Submission Gate

Use this plugin for unattended test-submission mailbox processing.

- MCP-first when Codex is available.
- CLI fallback when Codex is unavailable.
- `submission_gate_cli.py setup` creates or refreshes the single configuration with zero manual JSON editing.
- Setup reruns stay zero-prompt when the managed config already exists.
- `submission_gate_cli.py run-once` scans recent `【提测】` mail and processes only unseen durable work.
- `scheduler install` uses skip-all-missed and ignore-new semantics.
- Codex is optional.
- HMAC is optional. A valid HMAC receives the compliant-plugin verified badge; missing HMAC continues with an unverified badge; a claimed invalid HMAC must block.
- Setup generates a credential-free GitLab adapter config. The token is read from `PMG_GITLAB_TOKEN` (or the configured environment-variable name), never from plugin config.
- Setup freezes SHA-256 values for the adapter entrypoint, its credential-free config, and all imported shared contract files. Any later drift blocks preflight and execution.
- A CLEAN result must bind the exact pipeline/job/artifact, a canonical full Manifest-S, and a nonempty rollback baseline reference.
- Zero effective checks, incomplete fallback content, or missing authoritative gate capability must block.

See `references/configuration.md` for config requirements and `references/automation-contract.md` for unattended scan guarantees.
