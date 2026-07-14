# Tool Routing

Use the lightest available tool that can produce authoritative evidence. Test each configured connection before writes.

| Tool | Authoritative role | Not authoritative for |
| --- | --- | --- |
| Visual Companion | Versioned visual design presentation and click evidence | Production approval or gate PASS |
| `lark-cli` | Source documents, event records, tasks, unified approval, cloud readback | Replacing deterministic gate evidence |
| `gitlab` | Repositories, issues, branches, merge requests, CI, protected merge evidence | Granting external credentials or production access |
| `product-release-gate` | Frozen submission/release manifests and fail-closed material checks | Claiming production deployment happened |
| `ssh` | Strict-host-key remote deployment, observation, and rollback | Approving its own command or weakening trust policy |
| `imap-smtp-mail` | Requirement/evidence intake, report delivery, mailbox readback | Release authorization |
| `wecom-codex-usage` | Operational notification, escalation, and status links | Gate or approval decisions |

## Capability Factory

- New independent scanners, adapters, and services go to the approved internal GitLab namespace.
- Changes to an existing plugin go to that plugin's authoritative source repository.
- The originating event retains its checkpoint while GitLab records the capability contract, implementation, CI evidence, and merge.
- After registration, rerun the exact blocked check against the original immutable input.

Use WeCom for timely operational state and mail for durable reports. Notify on meaningful transitions, not every retry. A successful notification proves delivery only.
