# Usage Reports

RemoteX 0.5.8 exposes two tools:

- `remotex_usage_report`: return a structured local report.
- `remotex_usage_export`: generate a unique private report directory containing
  `report.html`, `report.json`, `credentials.csv`, `profiles.csv`, and `queues.csv`.
  The result includes absolute paths and SHA-256 hashes for every file.

Both tools accept the same arguments:

```json
{"credential_ref": "lab-admin", "days": 30}
```

Use `profile` instead of `credential_ref` to inspect one profile, including a
legacy inline credential. Omit both selectors to include all profiles and all
named aliases, including unused aliases. `days` is an integer from 1 to 365;
the default is 30. Times and rolling window boundaries are UTC.

Example prompts:

```text
Use RemoteX to report usage for credential_ref lab-admin over the last 7 days.
Export a RemoteX report for all credentials over the last 30 days.
Show the system-version and architecture evidence for profile windows-lab.
```

## Contents

Each credential has a stable report ID (`alias:NAME` or a digest-based inline
reference), provider, reference presence, consuming profiles, system evidence,
queue-resource links, call counts and last use. A shared alias is grouped once;
its profiles may represent multiple systems or architectures. A missing
reference is distinct from failed remote authentication. No credential values,
credential-manager targets, key paths, scripts or raw command output are
included. This report does not enumerate unrelated Credential Manager entries.

System evidence comes from hash-verified historical Windows preflight receipts
matched to the current identity, endpoint, machine identifier, queue resource,
and configured VMware UUID where applicable. The report includes OS version,
bitness, collection timestamp, age and receipt hash. Failed test-admission
receipts can still contain valid historical inventory observations; they never
become current admission proof. SSH-only/RDP-only profiles without matching
receipts report unknown OS versions. The report does not start remote probes.

The current receipt format normalizes architecture to x86/x64 bitness. Thus
`nativeArchitecture` remains null: 64-bit does not distinguish AMD64 and Arm64.
`architectureLabel` extracts a configuration-name hint, identifies its source,
and flags contradictions with receipt bitness. Labels are not verified CPU ISA.
The OS version number is not an OS product name, edition or complete patch list.

## Call Metrics

The audit hash chain is checked before aggregation. Calls are deduplicated by
`operationId`, then paired with completion records. Conflicting duplicate IDs
and corrupt audit chains block the report. Identical duplicate starts are
counted once and exposed in coverage metadata. Future or malformed records are
excluded and counted. The current report call may appear as an unfinished
management call in its own snapshot; it is never remote usage.

Windowed calls are split into work, diagnostics, queue, management and other.
Remote calls combine work and diagnostics; diagnostics include connection tests,
preflight checks, inventory and asynchronous task polling. Known successful,
failed, unknown-outcome and unfinished remote calls are separate. A successful
tool outcome does not prove the requested business result. `lastUsedAtUtc`
searches all available remote-call history, even outside the selected window.

Credential activity percent is the number of current credential groups with
remote calls in the window divided by current credential groups in scope.
Failed attempts count as activity. Attribution uses current Profile bindings:
the ledger cannot prove which older credential was used before rotation or a
binding change. Calls lacking a Profile are not assigned to a default Profile.
Unattributed and removed-profile call counts are exposed separately.

## Queue Metrics

Queue and lease snapshots use the existing locks without calling status,
claim, recovery or expiry handlers. An expired persisted owner remains intact.
Current ownership, inconsistent ownership, waiting count and lease expiry are
reported. vSphere profiles include VM resources observed in local queue/lease
history; missing history does not imply that the vCenter has no VMs.

Reservation intervals are clipped to expiry, release, report time and the
selected window. Overlapping intervals and renewals are merged per resource.
The percentage is recorded reserved seconds divided by window seconds. This
is a lower bound because only the last 1000 lease events are retained. It is
not CPU utilization, actual working time, global lab utilization, or activity
through SSH/RDP clients outside RemoteX. Resource totals must not be summed
across credentials that share resources.

## Storage And Safety

Exports default to a unique `reports/usage-UUID` directory beside the local
queue file. An operator may configure `REMOTEX_REPORT_DIR`; network paths and
reparse-point paths are rejected. The newly created directory is protected
using the existing RemoteX path-protection helper before report files are
written. HTML values are escaped; CSV formula-like cells are neutralized.
No caller-supplied output path or overwrite option is accepted.

Reports can contain internal Profile/resource names and usage metadata. Keep
exports local unless sharing is intended. The source files are not copied into
the report. Sources are sampled separately under their locks; the report is
not a cross-file transaction. Normal MCP call auditing still occurs. No queue
owner, credential, remote host, or preflight receipt is modified.
