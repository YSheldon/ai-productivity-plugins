---
name: product-release-gate
description: Create and execute fail-closed product material gates, bound release authorization, phased deployment, rollback, and production evidence through the Product Release Gate MCP server.
---

# Product Release Gate

Use this plugin for submission, testing, final-material production, release authorization, staged deployment, rollback, and durable production reports.

Run `py -3 src/release_gate_cli.py setup` as the final scheduler identity for zero manual JSON editing. Setup safely initializes or reuses the separate authorization/audit credentials, binds the runtime identity, installs one scheduler only after credential and unified-approval preflight, and returns the remaining production-preflight gaps without enabling deployment or report automation. A setup rerun reuses the same configuration and credentials with zero prompts and no rotation. MCP, this Skill, the standalone CLI, and the OS scheduler all use the same controller; Codex is optional.

## Filesystem Production Bootstrap

When all three deployment stages use filesystem targets, prefer `py -3 scripts/bootstrap_filesystem_production.py` over hand-written adapter commands. Supply three distinct, non-overlapping absolute targets plus the protected output config. The bootstrap must:

- install the packaged filesystem adapter into a dedicated versioned directory;
- pin the Python and adapter SHA256 plus every deploy/verify/rollback/readback argv template;
- reject filesystem roots, duplicate/overlapping targets, symlinks, Junctions, embedded secrets, and mutable in-place upgrades;
- keep production and all automatic actions disabled;
- avoid creating any deployment target during bootstrap.

Do not enable the generated config until external approval, separate authorization/audit keys, signature trust, scan, test, mail, recipient, and live-target checks are proven. Every frozen artifact must carry size, SHA1, and SHA256. Consumers must follow `<target>/.product-release-gate/current.json` to the content-addressed release `files` directory. A local bootstrap PASS proves only the deployment binding; it is not production deployment evidence.

## Unattended Credentials

On Windows, the preferred `setup` command automatically runs the safe `init` operation
under the exact account that will run the release scheduler. Use
`scripts/provision_windows_credentials.py status` for independent audit; use manual
`init` only for a bootstrap configuration when setup is intentionally not used. The
initializer creates only missing authorization/audit keys in that account's Windows
Credential Manager, writes only non-secret target references to config, never prints
values, and never rotates existing keys. It also stores only a SHA-256 fingerprint of
the process-token SID. Require
`runtime_identity_bound=true`, `runtime_identity_matches=true`,
`principal_values_returned=false`, and `ready=true`. Normal `init` must reject an
identity change. An approved service-account migration uses `rebind` with
`--confirm-runtime-identity-rebind`, followed by full preflight and a controlled release.
When `production.enabled=true`, identity binding is mandatory even if an old config
omits the object or says `required=false`. Treat `runtime.identity_binding` in
production preflight as a hard gate.
Protected CI environment variables take precedence when present. Treat a mail profile
created under a different CurrentUser DPAPI identity as unavailable in production.

## Required Workflow

1. Start the MCP server with one protected `PRODUCT_RELEASE_GATE_CONFIG`. Per-call `config_path` overrides are forbidden. Call `release_gate_preflight`; never interpret a missing required integration as PASS.
2. Create Manifest-S from real local artifacts. The controller computes SHA1 and SHA256 values; never submit narrative hashes.
3. Run the submission gate. Any non-PASS result returns to a new submission round unless the same frozen checkpoint can be safely replayed.
4. Run tests or ingest a trusted callback. High and emergency risk require an auditable test approval.
5. Build Manifest-R into a new, non-existent output path and run the release gate. The controller stages, durably copies, verifies SHA1/SHA256, and atomically publishes the complete directory; any failure cleans it and leaves `RELEASE_PREPARING`. File drift, omissions, extras, signature failure, scan failure, or approval mismatch blocks release. Authenticode must match an exact configured certificate-thumbprint allowlist.
6. Treat `RELEASE_READY` as an intermediate state. Call `release_gate_production_preflight` before requesting production authority.
7. When `production.svn_release_gate.required=true`, call `release_gate_build_svn_live_handoff`. Provide only product/SVN coordinates and the logical-name-to-SVN-path mapping; never supply expected hashes. The tool derives every SHA1, SHA256, and size from `ProductReleaseGateManifestR/v1` and freezes `ProductMaterialWorkflow/v1`.
8. Promote the handoff to protected GitLab project 59 and run `live_gate`. Create a local `ProductMaterialGatePipelineLocator/v1` containing only project, pipeline, and job IDs, then call `release_gate_record_svn_live_gate_receipt`. The pinned bundled verifier must read GitLab and the artifact ZIP independently. BLOCKED stops release; only a current verified CLEAN receipt restores the prior checkpoint.
9. Create the bound authorization request. Use the configured external approval system and read the instance back; do not invent an approval reference. The controller re-verifies the GitLab receipt and every frozen file first.
10. Record release authorization only when the verifier returns the same event, actor, decision, Manifest-S digest, Manifest-R digest, and explicit comma-separated stage scope. The signed ledger request, not mutable event fields, is authoritative. The controller then issues an expiring scoped credential and enters `RELEASE_AUTHORIZED`.
11. Check deployment capabilities. If state becomes `CAPABILITY_BLOCKED`, preserve the origin checkpoint, build and merge the missing adapter through the approved repository workflow, deploy it, then replay the checkpoint. Required detectors cannot be waived.
12. Execute `preproduction`, `production_canary`, and `production_full` in order. The credential must authorize the current stage, and deploy/verify receipts must bind the configured target and exact authorized Manifest-R digest.
13. On deployment or verification failure, allow the controller to run rollback plus an independent rollback-verification adapter. Never advance after `ROLLED_BACK` or `ROLLBACK_FAILED`.
14. Run production readback. A mismatch must roll back full production. Generate the production report, verify the HMAC-signed event chain, then call `release_gate_deliver_production_report`. The `【发布完成】任务-模块-时间` message must have a sealed SMTP receipt and exact authenticated IMAP readback. Pending or unknown SMTP outcomes never permit automatic resend and never count as completion; notification success is not production truth.

## Authority Boundaries

- Visual Companion clicks prove design consent only. They cannot replace external approval, protected-branch policy, test evidence, release authorization, credentials, or target readback.
- External tools supply evidence and actions; the release event store remains the state truth.
- GitLab/GitHub proves source and merge state. Feishu proves approval. SSH/deployment adapters execute targets. IMAP/SMTP and WeCom deliver reports and escalation notices.
- AI may create, test, review, and merge a missing capability only through configured repository controls. It cannot self-grant production credentials or approval authority.
- Authorization and audit HMAC keys must be separate, at least 32 bytes, and supplied through the runtime secret manager rather than configuration or artifacts.
- `PRODUCT_RELEASE_GATE_GITLAB_TOKEN` is a separate read-only verifier secret. Keep it out of JSON, handoffs, locators, logs, and reports. Pin the verifier command as `svn_release_gate_receipt` in the deployment dependency lock.
- The protected GitLab runtime attestation must bind `PMG_REQUEST_ID` and `PMG_REQUEST_SHA256` to the exact ProgramData request before gate execution. A successful unrelated pipeline or a locally edited receipt is never evidence.

## Completion Standard

Do not claim completion from local files, tests, `RELEASE_READY`, or `RELEASE_AUTHORIZED` alone. Completion requires the authorized Manifest-R to pass pre-production, canary, full deployment, production readback, hash-chain verification, report generation, and the configured external delivery/readback evidence.

Use `config/config.example.json` for adapter placeholders and the exact JSON contracts.
