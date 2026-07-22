# Production Credentials and Evidence Runbook

This runbook turns the production release gate from a configured test harness into a
repeatable, unattended production workflow. It is deliberately fail-closed: a missing
credential, adapter, lock digest, or readback receipt blocks the release and must not be
waived by changing an event file.

## 1. Separate the trust domains

Do not use one account or one secret for every phase.

| Capability | Provision once | Minimum authority | Required receipt |
| --- | --- | --- | --- |
| Release authorization | `PRODUCT_RELEASE_GATE_AUTH_KEY` and a real approval verifier | Sign and verify scoped release authorization only | `APPROVE`, approval reference, actor, Manifest-S digest, Manifest-R digest, target scope |
| Audit chain | `PRODUCT_RELEASE_GATE_AUDIT_KEY` | Append/sign the local control-event chain only | HMAC-valid event chain and ledger anchor |
| Deployment | Per-stage deployment service identity | Deploy and verify only the configured stage | `PASS`, target reference, deployment reference, rollback reference, deployed Manifest-R digest |
| Production readback | Separate read-only target identity | Read the active release and its inventory | `PASS`, target reference, readback reference, observed Manifest-R digest |
| Rollback | Rollback-capable identity or bounded deployment identity | Restore an earlier immutable release only | Matching target/deployment/rollback references, restored reference, rollback receipt |
| Rollback verification | Independent verification path | Read-only verification of the restored release | Matching references and verification reference |
| Report delivery | Locked `imap-smtp-mail` profile | Send the final report and read one mailbox | SMTP accepted result plus exact authenticated IMAP readback |
| Cloud scan | Protected `PMG_CLOUD_SCAN_TOKEN` | Submit and poll `/api/v1/scans` only | Scan id and required-engine `CLEAN` verdicts |

The authorization key is not the external approval account password. The audit key is
not a deployment credential. The mail password is not an audit key. Keep these domains
independent so that compromise or rotation of one capability cannot silently authorize
another.

## 2. Store secrets outside the repository

Use protected and masked GitLab variables for CI jobs. For an unattended Windows
scheduler, store the signing keys in Windows Credential Manager under the exact account
that runs the scheduled task. The controller resolves `key_env` first, then the configured
`credential_target`; the deploy adapter receives only the authorization key in its child
environment. Never put secret values in JSON, locks, event files, arguments, logs, or mail.

Required secret inputs are:

```text
PRODUCT_RELEASE_GATE_AUTH_KEY   # at least 32 random bytes
PRODUCT_RELEASE_GATE_AUDIT_KEY  # a different secret, at least 32 random bytes
PMG_CLOUD_SCAN_TOKEN             # protected and masked; only for the live scan adapter
```


After the disabled deployment configuration has been generated, initialize the two
per-user credentials from a shell running as the final scheduler identity:

```powershell
py -3 scripts/provision_windows_credentials.py `
  --config C:\ProgramData\ProductReleaseGate\config.json status

py -3 scripts/provision_windows_credentials.py `
  --config C:\ProgramData\ProductReleaseGate\config.json init
```

`init` creates only missing values, never prints them, never rotates an existing value,
and records only the non-secret Credential Manager target names in the JSON config. Run
`status` again and require `ready=true`. Rotation intentionally requires a separate
incident/change procedure because it invalidates outstanding authorization and audit
receipts.
The `imap-smtp-mail` profile owns its SMTP and IMAP credentials. Bind the profile to a
protected service account and reference the profile from
`production.report_delivery`; do not copy its password into this plugin's config.

The approval, deployment, readback, and rollback adapters must obtain their service
credentials from the protected runtime identity or an approved secret broker. The
argument templates contain references and event placeholders only; they never contain
inline secrets. For the built-in filesystem adapter, the Windows scheduled-task account
and its NTFS permissions are the deployment, verification, readback, and rollback
credential. There is no deployment-password field in the plugin JSON.

If policy requires a separate read-only identity for final readback or rollback
verification, use separate immutable service adapters. The built-in filesystem adapter
executes every operation as the controller process identity and cannot impersonate a
second account.

The mail profile is also identity-scoped: a profile protected with CurrentUser DPAPI
under an administrator or developer account is not a production profile for a different
service identity. Run the `imap-smtp-mail` setup once as the final release-control
identity, then verify both IMAP and SMTP before enabling report delivery.

## 3. Replace the test adapters

The current first-practice configuration is intentionally not production-ready when it
points at `first_practice_adapter_compat.py`. Replace every production command with a
real, immutable adapter:

```text
production.authorization.verify_command
production.deployment.deploy_command
production.deployment.verify_command
production.deployment.rollback_command
production.deployment.rollback_verify_command
production.readback.command
production.report_delivery.command
```

Each command must be an argument array, not a shell string. The deployment lock must pin
the executable/interpreter, adapter entrypoint, command templates, and SHA256 digest.
The controller rejects paths under tests, fixtures, mocks, demos, examples, or
compatibility adapters.

For filesystem targets, generate the locked adapter configuration rather than hand
editing command arrays:

```powershell
py -3 scripts/bootstrap_filesystem_production.py `
  --output-config C:\ProgramData\ProductReleaseGate\config.json `
  --adapter-dir C:\ProgramData\ProductReleaseGate\adapters\filesystem-1.0.0 `
  --preproduction-target D:\ReleaseTargets\Preproduction `
  --canary-target D:\ReleaseTargets\Canary `
  --production-target D:\ReleaseTargets\Production
```

For service or container targets, the equivalent adapter must implement the same receipt
contracts and be installed under a protected immutable deployment directory.

## 4. Configure the external approval verifier

The verifier must read the approval system and return JSON bound to the current event:

```json
{
  "result": "APPROVE",
  "approval_ref": "...",
  "approved_by": "...",
  "manifest_s_digest": "...",
  "manifest_r_digest": "...",
  "target_scope": "preproduction,production_canary,production_full",
  "evidence_ref": "..."
}
```

Any decision other than `APPROVE`, an expired approval, a scope mismatch, or a digest
mismatch blocks authorization. The gate records the response; it does not infer
approval from a sent email or from a human-readable report.

## 5. Configure deployment, rollback, and readback

Use separate target references for `preproduction`, `production_canary`, and
`production_full`. A deployment adapter must return the exact target reference and a
unique deployment/rollback reference. Verification must recompute the frozen Manifest-R
digest rather than trusting a local status flag.

Rollback is two steps: invoke `rollback_command`, then invoke the independent
`rollback_verify_command`. A failed deployment or verification automatically enters the
rollback path. If rollback verification also fails, the event remains
`ROLLBACK_FAILED` and must be handled as an incident.

Final production readback must be read-only and must return the authorized Manifest-R
digest. A mismatch after `production_full` invokes the bound full-production rollback;
the release is never marked verified on a partial or stale response.

## 6. Configure final report delivery and readback

Keep `production.report_delivery.enabled=false` until the mail profile and its lock have
passed preflight. Configure:

```text
profile
sender_email
recipients
mailbox
dependency_lock
dependency_lock_sha256
command
timeout_seconds
readback_timeout_seconds
```

The controller writes a sealed send intent before SMTP, records the accepted SMTP result,
and searches the authenticated IMAP mailbox for the deterministic Message-ID bound to
the release event. A lost SMTP outcome is `REPORT_READBACK_PENDING`; it is not an
automatic resend condition. Completion requires both the send receipt and exact IMAP
readback receipt.

## 7. Preflight and acceptance sequence

Keep all automatic switches disabled during provisioning:

```text
auto_authorize_verified_pre_release=false
auto_deploy_authorized_releases=false
auto_generate_production_report=false
auto_deliver_production_report=false
```

Run the following sequence on the protected Runner:

1. Run `--attest-only` and require `PMG_LIVE_GATE_STATUS=ATTESTED;CODE=OK`.
2. Run `release_gate_production_preflight` and resolve every `missing_capabilities` entry.
3. Run `release_gate_request_release_authorization` and verify the external approval response.
4. Run `release_gate_ensure_deployment_capabilities` and require `CAPABILITY_READY`.
5. Exercise preproduction, canary, and full production in order with a controlled release.
6. Run final production readback and require `PRODUCTION_VERIFIED`.
7. Generate the HMAC-sealed report, deliver it once, and require `REPORT_READBACK_VERIFIED`.
8. Enable automatic switches only after all receipts are independently reviewed.

The minimum successful state chain is:

```text
CAPABILITY_READY
AUTHORIZED
PREPRODUCTION_VERIFIED
CANARY_VERIFIED
PRODUCTION_VERIFIED
REPORT_READBACK_VERIFIED
```

Until the real `/api/v1/scans` service, protected token, real adapters, and external
approval/mail identities are provisioned, the correct result is `CAPABILITY_BLOCKED`,
not a simulated production success.

## 8. Production provisioning worksheet

Do not promote `first_practice_adapter_compat.py` or edit a first-practice configuration
in place. Generate a new disabled configuration in a protected production directory.
The following non-secret inputs are required before a controlled release can begin:

| Input | Required value | Acceptance evidence |
| --- | --- | --- |
| Runtime identity | Dedicated Windows scheduled-task account and stable SID | `whoami /user` captured under the task identity; task status names the same account |
| Configuration | Protected absolute config path and immutable adapter directory | Only administrators and the runtime identity can modify them |
| Stage targets | Distinct pre-production, canary, and full-production paths or service endpoints | No overlap; adapter self-check and access test pass |
| Deployment authority | Runtime account ACL or adapter-specific secret-broker binding | Deploy and verify only the intended stage |
| Rollback authority | Permission to restore the previous immutable release | Controlled rollback plus independent rollback verification pass |
| Production readback | Read-only adapter or documented use of the filesystem runtime identity | Exact authorized Manifest-R digest is returned from the active target |
| Approval verifier | Role source, approval/audit document locations, release group, and trusted inbound issuer | One current event returns an exact digest- and scope-bound `APPROVE` receipt |
| Product signature policy | Exact allowed Authenticode certificate thumbprints | A valid signature from an unlisted certificate is rejected |
| Mail delivery | Identity-local `imap-smtp-mail` profile, sender, recipients, and mailbox | SMTP accepted result and exact IMAP Message-ID readback pass |
| Cloud scan | Live `/api/v1/scans` endpoint and protected `PMG_CLOUD_SCAN_TOKEN` | Required engines return `CLEAN`; until implemented this remains blocked |

Run these steps as the final scheduled-task identity:

1. Generate a fresh disabled config with `bootstrap_filesystem_production.py` or install
   equivalent immutable service adapters.
2. Run `provision_windows_credentials.py ... init`, then `... status`; require
   `ready=true`, distinct authorization/audit credentials, and
   `secret_values_returned=false`.
3. Configure and test the identity-local mail profile. Do not reuse a developer's DPAPI
   profile for the service account.
4. Configure the independent approval verifier and signature thumbprint allowlist.
5. Grant the minimum target permissions and record the runtime SID plus ACL evidence.
6. Run production preflight and resolve every missing capability. Keep all automation
   switches disabled.
7. Execute one controlled release through pre-production, canary, full production,
   production readback, forced rollback, rollback verification, report delivery, and
   exact IMAP report readback.
8. Review the receipts independently, then enable only the automation switches approved
   by the production change record.

Retain these non-secret artifacts for audit:

- Runtime SID and scheduled-task identity evidence.
- Adapter lock file, lock digest, and entrypoint digests.
- Credential status JSON without secret values.
- Approval receipt and frozen Manifest-S/Manifest-R digests.
- Stage deployment, verification, rollback, and rollback-verification receipts.
- Production readback receipt bound to the authorized Manifest-R digest.
- Final report digest, deterministic Message-ID, SMTP accepted/refused result, and exact
  authenticated IMAP mailbox/UID readback receipt.
