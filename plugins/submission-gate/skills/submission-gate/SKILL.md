---
name: submission-gate
description: Scan structured `【提测】` mail, verify optional HMAC, and execute the authoritative submission gate through the locked product-release-gate runtime.
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
- Zero effective checks, incomplete fallback content, or missing authoritative gate capability must block.

See `references/configuration.md` for config requirements and `references/automation-contract.md` for unattended scan guarantees.
