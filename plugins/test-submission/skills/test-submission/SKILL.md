---
name: test-submission
description: Create one explicit product-material submission with zero manual JSON editing, then send the signed request through the locked mail bridge.
---

# Test Submission

Use this plugin when a developer needs to create one `【提测】` request with zero manual JSON editing.

- MCP-first when Codex is available.
- CLI fallback when Codex is unavailable.
- `test_submission_cli.py setup` creates or refreshes the single configuration and reruns with zero prompts when the config already exists.
- `test_submission_cli.py run-once` retries only pending outbound mail under an OS scheduler.
- `scheduler install` uses skip-all-missed and ignore-new semantics.
- Codex is optional.
- Every submit must explicitly set `module` to `kernel`, `client`, or `server`.
- The controller writes one signed machine block and one durable local event before send completion is claimed.

See `references/configuration.md` for required config fields and `references/automation-contract.md` for unattended retry behavior.
