# Release Approval Verifier

This plugin provides the independent verifier for the release approval workflow. In production, it freezes approver roles from a Feishu role document and validates reply mail against the frozen role, thread, manifest, role snapshot, authentication path, expiry window, and unique `Message-ID`.

The same controller is available through four surfaces: MCP, Skill, standalone CLI, and unattended OS scheduling. Codex is optional. Run `py -3 src/verifier_cli.py setup` for zero manual JSON configuration, provide the trusted inbound MTA issuer through `--trusted-authserv-ids` or `RELEASE_APPROVAL_VERIFIER_TRUSTED_AUTHSERV_IDS`, then use `preflight`, `run-once`, `status`, and `doctor` from either MCP or the CLI. Setup generates a profile-specific dependency lock and pins its SHA-256 in the credential-free runtime config; do not hand-edit either value.

Static roles are test-only and are rejected for production mode. The scheduler always invokes the standalone CLI, rejects overlap through an OS-kernel lock, and skips missed runs rather than replaying them.

Mail authentication is fail-closed. Only `Authentication-Results` issued by a configured `allowed_authserv_ids` entry is trusted. DMARC `header.from` and DKIM `header.d` must align with the frozen role address. SPF requires a trusted `spf=pass`, an aligned Return-Path, and `Received-SPF: pass` as corroboration; `Received-SPF` alone never authorizes a decision.

## Core Inputs

- Feishu role document URL plus heading, default `## 审批角色`
- Release group address, mailbox folder, and verifier mail profile; credentials remain in the mail plugin
- One frozen state directory plus the setup-generated dependency lock path and SHA-256
- Reminder policy, authentication policy, and audit document URL

## Current Scope

- `src/verifier_config.py` loads one credential-free config source
- `src/role_snapshot.py` fetches and hashes the enabled role table from Feishu
- `src/decision_parser.py` strips quoted text, signatures, and disclaimers before deterministic reply classification
- `src/message_validator.py` quarantines drifted or unauthenticated mail before it can affect verifier state
- `src/verifier_store.py` persists snapshots, validated decisions, quarantined messages, and a local audit chain
- `src/release_approval_verifier_mcp.py` exposes structured MCP tools
- `skills/release-approval-verifier/SKILL.md` provides MCP-first and CLI-fallback operation
- `src/verifier_cli.py` runs independently of Codex and emits stable JSON
- `src/verifier_scheduler.py` installs and verifies one scoped OS schedule

`APPROVAL_VERIFIED` permits only the `PRE_RELEASE_REQUESTED` handoff. It never means `RELEASE_AUTHORIZED`, credential issuance, or deployment completion.

Feishu role document parsing is required in production. Static roles are test-only.
