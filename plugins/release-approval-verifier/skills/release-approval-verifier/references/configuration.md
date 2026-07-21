# Configuration

`setup` creates the credential-free single configuration used by every surface. It discovers IMAP/SMTP profiles and asks only for missing values: verifier mail profile when ambiguous, release group, Feishu role document URL, Feishu audit document URL, and trusted inbound MTA authserv-id values. With one discovered mail profile, standard setup remains within four prompts.

Secrets stay in their owning providers. `RELEASE_APPROVAL_VERIFIER_AUDIT_KEY` is loaded from the process environment or credential manager, must contain at least 32 bytes, and is never written to JSON, SQLite payloads, email, or Feishu.

The production role source is always the configured Feishu document section. Static roles are test-only. Role changes apply only to a new round and a new role-snapshot digest.

The configured section heading defaults to `## 审批角色`. Its first Markdown table must use exactly these columns:

```markdown
| role_id | email | required | enabled |
| --- | --- | --- | --- |
```

Every enabled row requires a unique email address, and at least one enabled role must be required. The runtime fetches the document with `lark-cli docs +fetch --api-version v2 --doc <url> --doc-format markdown --as user --format pretty`; an unreadable or malformed section fails closed as `CAPABILITY_BLOCKED`.

On Windows, the runtime resolves the installed npm `@larksuite/cli` Node entry and launches it directly with `shell=False`; it does not pass the role document URL through `cmd.exe` or concatenate a shell command.

Use `RELEASE_APPROVAL_VERIFIER_CONFIG` only as the process-level path override. MCP calls and individual CLI operations cannot replace policy fields.
