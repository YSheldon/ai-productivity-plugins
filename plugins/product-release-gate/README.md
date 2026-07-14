# Product Release Gate

This Codex plugin implements a fail-closed product-material and production-release control plane.

```text
submission -> submission gate -> test -> test approval -> final material
-> release gate -> RELEASE_READY -> bound release approval -> RELEASE_AUTHORIZED
-> pre-production -> production canary -> production full -> production readback
-> PRODUCTION_VERIFIED
```

`RELEASE_READY` is an intermediate gate result. It is not production authorization and does not prove deployment.

## Configuration

Copy `config/config.example.json` to a protected location and set:

```powershell
$env:PRODUCT_RELEASE_GATE_CONFIG = "C:\path\to\product-release-gate.json"
$env:PRODUCT_RELEASE_GATE_AUTH_KEY = "<secret from the credential manager>"
$env:PRODUCT_RELEASE_GATE_AUDIT_KEY = "<different secret from the credential manager>"
```

Both keys must be at least 32 bytes and must be different. Configure an exact 40-hex Authenticode certificate thumbprint allowlist; a merely valid signature is not sufficient. Set `production.enabled=true` only after every production adapter is configured. Adapter commands execute as argument arrays without a shell.

The MCP process reads `PRODUCT_RELEASE_GATE_CONFIG` once at startup. Tool calls cannot override `config_path`; restart the server to load an approved configuration change.

## Required Flow

1. Run `release_gate_preflight` and reject missing submission, scan, signature, or test capabilities.
2. Freeze real artifacts into Manifest-S with `release_gate_create_submission`.
3. Run the submission gate and automated tests.
4. Record the auditable test approval when policy requires it.
5. Build Manifest-R only from the approved Manifest-S and run the release gate.
6. Run `release_gate_production_preflight`; missing required adapters remain fail-closed.
7. Freeze an approval request with `release_gate_request_release_authorization`.
8. Read back the external approval and call `release_gate_record_release_authorization` only when its event, actor, decision, Manifest-S, and Manifest-R fields match.
9. Run `release_gate_ensure_deployment_capabilities`. A missing capability creates a replayable request and state `CAPABILITY_BLOCKED`; it is never waived.
10. Run `preproduction`, `production_canary`, and `production_full` in order with `release_gate_run_deployment_stage`.
11. Run `release_gate_run_production_readback` and require the target to report the exact authorized Manifest-R digest.
12. Generate the production report and verify the HMAC-signed control-event chain.

The existing test result is the first stage of the four-stage rollout. The deployment controller executes the remaining pre-production, canary, and full-production stages.

## Adapter Contracts

Authorization verification must read the external approval and return the exact requested stage scope:

```json
{"result":"APPROVE","approval_ref":"...","approved_by":"...","manifest_s_digest":"...","manifest_r_digest":"...","target_scope":"preproduction,production_canary,production_full","evidence_ref":"..."}
```

Deployment must return `result=PASS`, the configured `target_ref`, `deployment_ref`, `rollback_ref`, and `deployed_manifest_r_digest`. Stage verification must return `result=PASS`, the same `target_ref`, `verification_ref`, and `observed_manifest_r_digest`.

Rollback is a two-adapter contract. The rollback adapter must echo the exact `target_ref`, `deployment_ref`, and `rollback_ref` and return non-empty `restored_ref` and `rollback_receipt_ref`. The independent rollback-verification adapter must bind those same references and return a non-empty `verification_ref`. Either adapter failing leaves the event in `ROLLBACK_FAILED`.

Final production readback must return `result=PASS`, the configured `target_ref`, `readback_ref`, and `observed_manifest_r_digest`. A full-production readback mismatch automatically invokes the bound full-production rollback.

Any missing field, adapter error, digest mismatch, expired credential, stage-order violation, file drift, or non-PASS result blocks advancement. Deployment or verification failure automatically invokes the configured rollback adapter for the current stage.

## Security Boundaries

- The event store retains frozen manifests, execution receipts, authorization requests, scoped credentials, HMAC-sealed stage and rollback receipts, reports, and an append-only HMAC-SHA256 control-event chain.
- A separately HMAC-signed local ledger anchor detects record-boundary truncation. Whole-store rollback still requires an external immutable audit anchor or independent report readback.
- Authorization credentials and audit evidence use separate HMAC secrets read from environment variables; neither secret is written to artifacts.
- Every authorization scope names explicit deployment stages. A credential for pre-production cannot authorize canary or full production.
- A Visual Companion click is design consent only. It cannot satisfy test approval or production authorization.
- External approval, Git protected branches, production credentials, deterministic checks, and target readback remain separate authorities.
- The plugin orchestrates configured adapters; it never embeds production credentials or grants itself missing permissions.
