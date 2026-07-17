# Configuration

`setup` creates the credential-free single configuration used by every surface. It discovers IMAP/SMTP profiles and asks only for missing values: verifier mail profile when ambiguous, release group, Feishu role document URL, Feishu audit document URL, and trusted inbound MTA authserv-id values. With one discovered mail profile, standard setup remains within four prompts.

Secrets stay in their owning providers. `RELEASE_APPROVAL_VERIFIER_AUDIT_KEY` is loaded from the process environment or credential manager, must contain at least 32 bytes, and is never written to JSON, SQLite payloads, email, or Feishu.

The production role source is always the configured Feishu document section. Static roles are test-only. Role changes apply only to a new round and a new role-snapshot digest.

Use `RELEASE_APPROVAL_VERIFIER_CONFIG` only as the process-level path override. MCP calls and individual CLI operations cannot replace policy fields.
