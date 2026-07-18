# Release Gate

`release-gate` is the service-side mailbox automation in the product material workflow suite. It reads `PRERELEASE_REQUEST` mail, verifies provenance and local policy, invokes the locked product-release-gate shared kernel, and sends either `RELEASE_GATE_PASS` as `【发布申请】...` or a `【发布阻断】...` notice.

## Surfaces

- MCP server: `py -3 ./src/release_gate_mcp.py`
- Standalone CLI: `py -3 ./src/release_gate_cli.py`
- Skill: `skills/release-gate/SKILL.md`
- OS scheduler: `scheduler install|status|remove`

Each surface uses the same JSON config, the same state directory, the same locked product-release-gate binding, the same append-only HMAC/SHA256 audit chain, and the same run lock. There is no Codex runtime dependency.

## Setup Contract

`py -3 ./src/release_gate_cli.py setup`:

- bootstraps marketplace dependencies through the existing `release-gate` bootstrap profile;
- resolves the pinned product-release-gate CLI and imap-smtp-mail CLI from the dependency lock;
- validates the configured mail account without writing credentials;
- creates or reuses one shared handoff HMAC file under the state directory;
- writes one config file;
- runs `preflight`, `run-once`, `status`, `doctor`, and `verify-audit`;
- installs one OS scheduler and confirms status.

The setup path is bounded to at most four prompts, requires zero manual JSON editing, and reruns with zero prompts when the config already exists.

## Workflow

1. `run-once` scans the release-gate mailbox.
   - A valid `ProductMaterialWorkflow/v1` machine event with a valid HMAC is treated as `合规插件发起（已验证）`.
   - If the machine event or HMAC is absent, the plugin falls back to the canonical human-readable body and continues as `普通邮件发起（未验证）`.
   - If a machine event claims authentication but the HMAC is invalid, the request is blocked as `AUTHENTICATION_FAILED`.
2. The plugin enforces the canonical required checks:
   - `hmac`
   - `manifest`
   - `test_result`
   - `shared_kernel_release_gate`
3. Success reaches only `RELEASE_READY_NOTIFIED`; it never mints `RELEASE_AUTHORIZED`.
4. Verified intake outbound mail carries a signed machine event, frozen policy digests, checklist results, provenance badges, evidence refs, and the submitter email when available.
5. Unverified fallback outbound mail carries only authoritative Manifest-S/Manifest-R bindings plus explicit `UNVERIFIED` and `NOT_PROPAGATED` markers; sender-supplied provenance, policy digests, and checklist claims are never propagated.
6. The plugin never performs production deployment; it stops at the `RELEASE_READY_NOTIFIED` boundary.

## SVN Policy

For `retrieval_method=svn`, the embedded-core canonical SVN policy applies:

- fixed revision and repository provenance are mandatory;
- user-supplied file hashes, signature evidence, and cloud-scan evidence are not required inputs;
- signature, cloud-scan, and hash-match checks remain optional only when separately configured by the shared kernel.

## Audit

`verify-audit` validates the append-only HMAC/SHA256 hash-chain audit. Any tamper, sequence break, HMAC mismatch, or missing shared secret causes `CAPABILITY_BLOCKED`.
