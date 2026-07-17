# Pre Release

pre-release is the tester-side plugin in the product material workflow suite. It turns SUBMISSION_GATE_PASS messages into local pending tasks, records a minimal PASS or FAIL conclusion, uses the locked product-release-gate shared kernel to build Manifest-R, and sends a PRERELEASE_REQUEST handoff to the release-gate mailbox.

## Surfaces

- MCP server: py -3 ./src/pre_release_mcp.py
- Standalone CLI: py -3 ./src/pre_release_cli.py
- Skill: skills/pre-release/SKILL.md
- OS scheduler: scheduler install|status|remove

Each surface uses the same JSON config, the same state directory, the same locked product-release-gate binding, the same append-only HMAC/SHA256 audit chain, and the same run lock. There is no Codex runtime dependency.

## Setup Contract

`py -3 ./src/pre_release_cli.py setup`:

- bootstraps marketplace dependencies through the existing product-release-gate bootstrap profile;
- resolves the pinned product-release-gate CLI and imap-smtp-mail CLI from the dependency lock;
- validates the configured mail account without writing credentials;
- creates or reuses one shared handoff HMAC file under the state directory;
- writes one config file with zero manual JSON editing;
- runs `preflight`, `run-once`, `status`, `doctor`, and `verify-audit`;
- installs one OS scheduler and confirms status.

The setup path is bounded to at most four prompts on first setup and reruns with zero prompts when the config already exists.

## Workflow

1. `run-once` scans the submission mailbox.
   - When a valid ProductMaterialWorkflow/v1 machine event with a valid HMAC is present, the task is marked 合规插件发起（已验证）.
   - When the machine event or HMAC is absent, the plugin falls back to the canonical human-readable mail body and marks the source as 普通邮件发起（未验证）.
   - When a machine event claims authentication but the HMAC is invalid, the message is blocked as AUTHENTICATION_FAILED.
2. `list-tasks` shows pending tasks with Manifest-S digest, module, source message id, and the current unified state.
3. `create-request` records the tester decision.
   - FAIL moves the task to TEST_FAILED and never builds Manifest-R or sends mail.
   - PASS requires an output_dir, calls the locked product-release-gate CLI to record the test result and build Manifest-R, and fails closed if the kernel does not return a real manifest_r_digest.
   - The outbound `【发布门禁检查】...` mail always contains a signed machine event, frozen policy digests, checklist results, provenance badge propagation, and evidence refs.

## Common Commands

- `py -3 ./src/pre_release_cli.py setup --non-interactive`
- `py -3 ./src/pre_release_cli.py preflight`
- `py -3 ./src/pre_release_cli.py run-once`
- `py -3 ./src/pre_release_cli.py status`
- `py -3 ./src/pre_release_cli.py doctor`
- `py -3 ./src/pre_release_cli.py scheduler install|status|remove`

## SVN Policy

For `retrieval_method=svn`, the plugin accepts the embedded-core canonical SVN policy:

- fixed `revision` and repository provenance are mandatory;
- user-supplied file hashes, signature evidence, and cloud-scan evidence are not required inputs;
- GitLab build evidence is optional and omitted when the upstream request is SVN-based.

## Configuration

See config/config.example.json. Installation config intentionally excludes:

- default module;
- default final output directory;
- test-result source.

## Audit

`verify-audit` validates the append-only HMAC/SHA256 hash-chain audit. Any tamper, sequence break, HMAC mismatch, or missing shared secret causes CAPABILITY_BLOCKED.
