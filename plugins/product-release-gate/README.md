# Product Release Gate

This Codex plugin implements a fail-closed product-material and production-release control plane.

Codex is optional. The same controller is exposed through MCP, Skill, `release_gate_cli.py`, and an unattended OS scheduler. Run `py -3 src/release_gate_cli.py setup`, then use `preflight`, `run-once`, `status`, `doctor`, and `scheduler status`; setup creates the shared configuration without manual JSON editing.

The unified multi-role verifier first stops at `PRE_RELEASE_REQUESTED`. The independent product-release-gate runtime must re-read that frozen receipt before requesting and issuing a scoped production credential. Production automation is opt-in: `runtime.auto_authorize_verified_pre_release`, `runtime.auto_deploy_authorized_releases`, `runtime.auto_generate_production_report`, and `runtime.auto_deliver_production_report` are independently visible and deployment/report flags default to `false`.

```text
submission -> submission gate -> test -> test approval -> final material
-> release gate -> RELEASE_READY -> bound release approval -> RELEASE_AUTHORIZED
-> pre-production -> production canary -> production full -> production readback
-> PRODUCTION_VERIFIED
```

`RELEASE_READY` is an intermediate gate result. It is not production authorization and does not prove deployment.

When all four production automation switches are explicitly enabled, one locked `run-once` may re-verify the independent approval, issue the scoped credential, advance `preproduction -> production_canary -> production_full`, perform final target readback, generate the HMAC-sealed production report, send it once, and require exact IMAP readback. Every stage uses the controller's existing idempotency, adapter lock, receipt verification, approval-revocation checks, and rollback path. Any blocked capability, adapter error, receipt mismatch, readback failure, or report-integrity failure stops later actions and returns `CAPABILITY_BLOCKED`.

## Configuration

Copy `config/config.example.json` to a protected location and set:

```powershell
$env:PRODUCT_RELEASE_GATE_CONFIG = "C:\path\to\product-release-gate.json"
py -3 scripts/provision_windows_credentials.py `
  --config $env:PRODUCT_RELEASE_GATE_CONFIG status
py -3 scripts/provision_windows_credentials.py `
  --config $env:PRODUCT_RELEASE_GATE_CONFIG init
```

Run `init` as the exact Windows account used by the unattended scheduler. It creates only
missing per-user Credential Manager values, records only their non-secret target names in
the JSON configuration, never prints values, and never rotates existing credentials. CI
may instead inject `PRODUCT_RELEASE_GATE_AUTH_KEY` and
`PRODUCT_RELEASE_GATE_AUDIT_KEY` as protected masked variables; environment values take
precedence. Both keys must be at least 32 bytes and must be different.

`init` also binds `runtime.identity_binding.principal_sha256` to a SHA-256
fingerprint of the current process-token SID. The SID, account name, and credential
values are never stored in JSON or returned by `status`. Require all of
`runtime_identity_bound=true`, `runtime_identity_matches=true`, and `ready=true`
before enabling production. The controller reports `runtime.identity_binding` in
production preflight and refuses authorization/audit secret use or deployment secret
injection when the scheduled-task identity differs.
When `production.enabled=true`, this check is mandatory even if a legacy or hand-written
configuration omits `identity_binding` or sets `required=false`; deleting the field is
not a bypass.

A normal `init` never silently changes an existing identity binding. For an approved
service-account migration, stop the scheduler and all automatic actions, protect the
config for the new account, then run as that account:

```powershell
py -3 scripts/provision_windows_credentials.py --config $env:PRODUCT_RELEASE_GATE_CONFIG rebind --confirm-runtime-identity-rebind
```

Configure an exact 40-hex Authenticode certificate thumbprint allowlist; a merely valid signature is not sufficient. Set `production.enabled=true` only after every production adapter is configured. `production.deployment.dependency_lock` and `production.deployment.dependency_lock_sha256` bind the deploy, verify, rollback, rollback-verify, and readback argv templates to one locked adapter manifest. Adapter commands execute as argument arrays without a shell, and the controller re-verifies the lock digest plus every pinned executable/script SHA-256 immediately before each invocation.

`production.report_delivery` is disabled by default. Before enabling it, review the locked mail profile, exact sender account, report recipients, module, mailbox, dependency-lock digest, and readback timeout. The report subject is `【发布完成】任务-模块-时间`. Delivery uses a deterministic Message-ID, writes a sealed send intent before SMTP, records the accepted SMTP outcome (including an empty refused map), and requires one exact authenticated IMAP readback. If the process loses the SMTP outcome, it will not resend automatically.

The MCP process reads `PRODUCT_RELEASE_GATE_CONFIG` once at startup. Tool calls cannot override `config_path`; restart the server to load an approved configuration change.

## Built-in Filesystem Production Adapter

For three local or mounted filesystem targets, generate a locked production configuration instead of hand-editing deployment commands:

```powershell
py -3 scripts/bootstrap_filesystem_production.py `
  --output-config C:\ProgramData\ProductReleaseGate\config.json `
  --adapter-dir C:\ProgramData\ProductReleaseGate\adapters\filesystem-1.0.0 `
  --preproduction-target D:\ReleaseTargets\Preproduction `
  --canary-target D:\ReleaseTargets\Canary `
  --production-target D:\ReleaseTargets\Production
```

The bootstrap copies the packaged adapter into a dedicated immutable directory and locks the exact Python executable, adapter SHA-256, and all five command templates: deploy, verify, rollback, rollback verification, and production readback. It rejects root paths, duplicate or overlapping stage targets, symlinks, Windows Junctions, target/config overlap, embedded secret values, and in-place replacement of a changed adapter. Choose a new adapter directory for upgrades.

The generated configuration deliberately keeps `production.enabled`, automatic authorization, automatic deployment, automatic report generation, and automatic report delivery disabled.

It records only secret environment-variable names. It never writes authorization or audit secret values. Enable production only after the independent authorization verifier, distinct authorization/audit secrets, signature trust policy, cloud-scan and test adapters, mail identities, recipients, and real target access have passed live preflight.

Each stage stores content-addressed releases under:

```text
<target>/.product-release-gate/releases/<manifest-r-digest>/files/
```

`current.json` is the atomic active-release pointer. Target consumers must resolve that pointer and consume its `files` directory; they must not assume files are copied directly into the target root. Deployment copies and synchronizes every file, verifies size plus SHA1 and SHA256, writes a PREPARED receipt, atomically switches the pointer, and then seals the ACTIVE receipt. Interrupted deployment and rollback are reconciled idempotently on retry. Verification and readback recompute the frozen Manifest-R binding and deployed inventory; changing both a file and its local inventory does not hide tampering.

Manifest-S and Manifest-R require both SHA1 and SHA256 for every artifact. A legacy Manifest-R without SHA256 must be rebuilt and re-approved; it cannot be silently accepted. The built-in filesystem adapter does not replace approval, signing, cloud scan, testing, mail delivery, or an external immutable audit anchor.

Final material must be built into a new, non-existent output path. The controller durably copies every artifact into a private sibling staging directory, verifies SHA1 and SHA256, and publishes the complete directory in one filesystem switch. Copy, hash, publication, or state-write failure removes the private output and leaves the event at `RELEASE_PREPARING`; a partial directory is never accepted as Manifest-R.

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
12. Generate the production report, verify the HMAC-signed control-event chain, then call `release_gate_deliver_production_report`. Completion requires its sealed SMTP and exact IMAP readback receipt; a pending readback never causes an automatic resend.

The existing test result is the first stage of the four-stage rollout. The deployment controller executes the remaining pre-production, canary, and full-production stages.

## Adapter Contracts

Authorization verification must read the external approval and return the exact requested stage scope:

```json
{"result":"APPROVE","approval_ref":"...","approved_by":"...","manifest_s_digest":"...","manifest_r_digest":"...","target_scope":"preproduction,production_canary,production_full","evidence_ref":"..."}
```

Deployment must return `result=PASS`, the configured `target_ref`, `deployment_ref`, `rollback_ref`, and `deployed_manifest_r_digest`. Stage verification must return `result=PASS`, the same `target_ref`, `verification_ref`, and `observed_manifest_r_digest`.

Rollback is a two-adapter contract. The rollback adapter must echo the exact `target_ref`, `deployment_ref`, and `rollback_ref` and return non-empty `restored_ref` and `rollback_receipt_ref`. The independent rollback-verification adapter must bind those same references and return a non-empty `verification_ref`. Either adapter failing leaves the event in `ROLLBACK_FAILED`.

Final production readback must return `result=PASS`, the configured `target_ref`, `readback_ref`, and `observed_manifest_r_digest`. A full-production readback mismatch automatically invokes the bound full-production rollback.

The deployment lock must pin every production adapter argv template and every executable/script entrypoint used by those commands. Supported shapes are one pinned executable (`deployment-adapter.exe ...`) or a pinned interpreter plus pinned script (`python.exe deployment_adapter.py ...`). Any lock drift, command drift, missing file, path escape, unknown command shape, entrypoint digest drift, or entrypoint under a `test`, `tests`, `fixture`, `fixtures`, `mock`, `mocks`, `demo`, `demos`, `example`, or `examples` path blocks the stage before the adapter is invoked. A minimal lock file looks like:

```json
{
  "schema_version": 1,
  "root": ".",
  "commands": {
    "deploy": {
      "argv_template": [
        "C:\Python313\python.exe",
        "C:\deploy\deployment_adapter.py",
        "deploy",
        "{stage}",
        "{manifest_r_digest}",
        "{target_ref}"
      ],
      "entrypoints": [
        {"argv_index": 0, "path": "C:\Python313\python.exe", "sha256": "..."},
        {"argv_index": 1, "path": "deployment_adapter.py", "sha256": "..."}
      ]
    }
  }
}
```

Any missing field, adapter error, digest mismatch, expired credential, stage-order violation, lock drift, command drift, file drift, or non-PASS result blocks advancement. Deployment or verification failure automatically invokes the configured rollback adapter for the current stage.

## Security Boundaries

- The event store retains frozen manifests, execution receipts, authorization requests, scoped credentials, HMAC-sealed stage and rollback receipts, reports, and an append-only HMAC-SHA256 control-event chain.
- A separately HMAC-signed local ledger anchor detects record-boundary truncation. Whole-store rollback still requires an external immutable audit anchor or independent report readback.
- Authorization credentials and audit evidence use separate HMAC secrets read from environment variables; neither secret is written to artifacts.
- Every authorization scope names explicit deployment stages. A credential for pre-production cannot authorize canary or full production.
- A Visual Companion click is design consent only. It cannot satisfy test approval or production authorization.
- External approval, Git protected branches, production credentials, deterministic checks, and target readback remain separate authorities.
- The plugin orchestrates configured adapters; it never embeds production credentials or grants itself missing permissions.
