# RemoteX: Operations, Credentials, and Evidence

[Home](../README.md) | [Install](installation.md) | [Reference](../plugins/remotex/README.md)

RemoteX uses named profiles and local credential references for SSH, SFTP, RDP,
authenticated Windows guests, VMware Workstation, vSphere/ESXi, and Edge sign-in.
It is a toolkit for controlled operations, not a password-sharing service or a
global machine scheduler.

## Per-Credential Reports

**Demo data only.** The tables below illustrate report fields using synthetic
records, not a live inventory or application screenshot. The actual report
exports separate credential, system, queue, and coverage sections as local HTML,
JSON, and CSV files. No real host, account, credential, or activity log is used.

Example window: 30 days ending January 15, 2026, 12:00 UTC.

| Credential alias | Profile | Remote calls | Failed calls | Last use (UTC) |
| --- | --- | --- | --- | --- |
| lab-x86-operator | lab-x86 | 18 | 1 | 2026-01-14 09:20 |
| lab-amd64-operator | lab-amd64 | 42 | 0 | 2026-01-15 10:45 |
| lab-arm64-operator | lab-arm64 | 27 | 2 | 2026-01-15 11:10 |

| Profile | Historical OS evidence | Bitness | Configured architecture | Recorded reservation hours | Reservation lower bound |
| --- | --- | --- | --- | --- | --- |
| lab-x86 | 10.0.19045 | 32-bit | x86 | 6 | 0.8% |
| lab-amd64 | 10.0.22631 | 64-bit | AMD64 | 14 | 1.9% |
| lab-arm64 | 10.0.26100 | 64-bit | ARM64 | 9 | 1.3% |

The example reservations use a 720-hour window. OS observations are dated
January 13, 2026; architecture labels are configured hints, not independently
verified native ISA. These numbers are invented examples, not measured results.
OS version/build evidence is not a product-name assertion; a `10.0` prefix
alone does not distinguish Windows 10 from Windows 11.

```text
Use RemoteX to report the last 30 days of activity by credential reference.
Include observed OS versions, architecture labels, calls, queue reservations, and last use.
Do not connect to remote hosts or change queues.
```

Use `remotex_usage_report` for structured output or `remotex_usage_export` for files.
Scope either tool with `credential_ref` or `profile`, not both. `days` accepts
1-365 and defaults to 30. Architecture labels are configuration hints; historical
receipts do not prove current native ISA. Queue percentages are recorded reservation
lower bounds, not CPU/RAM load. [Metric definitions](../plugins/remotex/docs/usage-reports.md).

## Secure Web Sign-In

**Workflow illustration, not a screenshot of a live credential dialog.** Passwords
are entered in a visible local Windows credential window. The agent sees only
reference presence and sanitized operation results.

```mermaid
flowchart LR
    A[Preview exact origin and account] --> B[User approves profile scope]
    B --> C[Local Windows credential input]
    C --> D[Credential-free TLS and page probe]
    D --> E[Acquire local FIFO lease]
    E --> F[Submit once in isolated Edge]
    F --> G[Verified or needs user check]
    G --> H[Observe same page and passive result codes]
    H --> I[Close session and release own lease]
```

1. Inspect the login page to identify unique element-ID selectors.
2. Preview an HTTPS profile, account identifier, and credential alias. Confirm the scope before opening the local password window.
3. Use normal system TLS trust. For a private endpoint, a user may explicitly approve its exact origin and a trusted-channel-verified leaf certificate SHA-256 pin.
4. Run the credential-free probe. A wrong, expired, or not-yet-valid pinned certificate blocks HTTP transmission.
5. Acquire the local queue for the authorized operation and submit once in isolated Edge.
6. Distinguish `submitted`, `needs-user-check`, and `verified`. With current host browser permission, use `remotex_web_observe` and `remotex_web_read_result` in that same session.
7. Validate the actual read-only business result separately. Close the session and release its queue.

```text
Use RemoteX to preview a web-console profile for https://console.example:6868
with the operator account and the web-console-operator credential alias.
Use the element IDs observed on its login page. Do not accept a password in chat.
```

The hostname is intentionally non-operational. Do not invent selectors or use a
demo pin as real trust. Web sign-in requires **Windows, Edge, Node.js 24+, and
Playwright Core 1.62.1**. Pins substitute for CA/hostname identity checks only at
the approved origin; validity checks remain. No global trust-store change or
browser warning bypass is performed. [Full guide](../plugins/remotex/docs/web-credentials.md).

```text
Use RemoteX to sign in to my existing web-console profile, then read the center
page and passive read-only business response codes in the same session.
Do not submit forms, change settings, issue tasks, or copy cookies.
Stop if the host's browser permission is denied or cannot be established.
```

Same-session control does not register the isolated window as a generic browser
tab. Navigation is restricted to fresh observed same-document fragment links;
it never executes arbitrary link click handlers. Server-side effects of a site
route still require user authorization. Observation and passive result reading
send no application request of their own.

## Shared Hosts Without Preemption

`remotex_vm_queue_acquire` admits a free FIFO resource for an already authorized
task, reuses its own active lease without extending it, or joins behind another
owner. Host-maintenance and service-resource conflicts are also checked.
Queues are local and cooperative; they cannot detect every direct SSH/RDP user.

```text
Use RemoteX to acquire the configured lab-amd64 queue for this authorized task.
If another task owns it, join the queue and report the position without preemption.
```

Physical Windows hosts use authenticated host identity rather than requiring a
VMX binding. VM operations retain identity, preflight, and snapshot requirements.
Queue admission never grants permission to reboot or deploy.

## Other Recent Improvements

- Secure setup, rotation, deletion, and batch missing-reference checks.
- Secret-free asynchronous task IPC and verified SFTP-first transfers.
- A fixed management-center service-key deployment operation with hash, ownership, permission, and non-symlink checks. This is not a general arbitrary-key installer.
- SSH host-key discovery compatibility fixes that do not weaken connection trust.

See the [version history](../CHANGELOG.md) and [tool reference](../plugins/remotex/README.md#tool-summary).
