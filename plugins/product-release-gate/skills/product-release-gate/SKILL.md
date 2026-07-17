---
name: product-release-gate
description: Create and execute fail-closed product material gates, bound release authorization, phased deployment, rollback, and production evidence through the Product Release Gate MCP server.
---

# Product Release Gate

Use this plugin for submission, testing, final-material production, release authorization, staged deployment, rollback, and durable production reports.

Run `py -3 src/release_gate_cli.py setup` for zero manual JSON editing. A setup rerun reuses the same configuration with zero prompts. MCP, this Skill, the standalone CLI, and the OS scheduler all use the same controller; Codex is optional.

## Required Workflow

1. Start the MCP server with one protected `PRODUCT_RELEASE_GATE_CONFIG`. Per-call `config_path` overrides are forbidden. Call `release_gate_preflight`; never interpret a missing required integration as PASS.
2. Create Manifest-S from real local artifacts. The controller computes SHA1 values; never submit narrative hashes.
3. Run the submission gate. Any non-PASS result returns to a new submission round unless the same frozen checkpoint can be safely replayed.
4. Run tests or ingest a trusted callback. High and emergency risk require an auditable test approval.
5. Build Manifest-R into an empty directory and run the release gate. File drift, omissions, extras, signature failure, scan failure, or approval mismatch blocks release. Authenticode must match an exact configured certificate-thumbprint allowlist.
6. Treat `RELEASE_READY` as an intermediate state. Call `release_gate_production_preflight` before requesting production authority.
7. Create the bound authorization request. Use the configured external approval system and read the instance back; do not invent an approval reference.
8. Record release authorization only when the verifier returns the same event, actor, decision, Manifest-S digest, Manifest-R digest, and explicit comma-separated stage scope. The signed ledger request, not mutable event fields, is authoritative. The controller then issues an expiring scoped credential and enters `RELEASE_AUTHORIZED`.
9. Check deployment capabilities. If state becomes `CAPABILITY_BLOCKED`, preserve the origin checkpoint, build and merge the missing adapter through the approved repository workflow, deploy it, then replay the checkpoint. Required detectors cannot be waived.
10. Execute `preproduction`, `production_canary`, and `production_full` in order. The credential must authorize the current stage, and deploy/verify receipts must bind the configured target and exact authorized Manifest-R digest.
11. On deployment or verification failure, allow the controller to run rollback plus an independent rollback-verification adapter. Never advance after `ROLLED_BACK` or `ROLLBACK_FAILED`.
12. Run production readback. A mismatch must roll back full production. Generate the production report and verify the HMAC-signed event chain. Send notifications only after the report exists; notification success is not production truth.

## Authority Boundaries

- Visual Companion clicks prove design consent only. They cannot replace external approval, protected-branch policy, test evidence, release authorization, credentials, or target readback.
- External tools supply evidence and actions; the release event store remains the state truth.
- GitLab/GitHub proves source and merge state. Feishu proves approval. SSH/deployment adapters execute targets. IMAP/SMTP and WeCom deliver reports and escalation notices.
- AI may create, test, review, and merge a missing capability only through configured repository controls. It cannot self-grant production credentials or approval authority.
- Authorization and audit HMAC keys must be separate, at least 32 bytes, and supplied through the runtime secret manager rather than configuration or artifacts.

## Completion Standard

Do not claim completion from local files, tests, `RELEASE_READY`, or `RELEASE_AUTHORIZED` alone. Completion requires the authorized Manifest-R to pass pre-production, canary, full deployment, production readback, hash-chain verification, report generation, and the configured external delivery/readback evidence.

Use `config/config.example.json` for adapter placeholders and the exact JSON contracts.
