# Configuration

Run `py -3 ./src/release_approval_cli.py setup` instead of editing JSON. The wizard discovers safe defaults, asks at most four prompts, and writes one credential-free config at `default_config_path`. A rerun uses the existing config with zero prompts.

Use `--config <path>` or `RELEASE_APPROVAL_CONFIG` only when a managed deployment requires a non-default location.

Required invariants:

- `role_email` exactly matches `mail_account.email`.
- `release_group` is a delivery address, not a display label.
- `request_authentication.allowed_sender_emails` freezes the product-release-gate sending account; it is never inferred from the subject or body.
- `request_authentication.allowed_authserv_ids` freezes which MTA-authenticated `Authentication-Results` issuers are trusted for DMARC/DKIM/SPF decisions. Supply them during setup with `--trusted-authserv-ids` or `RELEASE_APPROVAL_TRUSTED_AUTHSERV_IDS`; never leave the example issuer in production.
- `request_authentication.accepted_paths` permits only `dmarc`, `dkim`, or `spf`; setup enables all three and runtime still requires sender/domain alignment. SPF additionally requires both `Authentication-Results` and `Received-SPF` to pass.
- `page.host` is loopback-only.
- `dependency_lock` is the bootstrap-produced absolute lock file.
- `audit.document_url` is optional, must be an absolute HTTP(S) URL, and may be supplied with `--audit-document-url` or `RELEASE_APPROVAL_AUDIT_DOCUMENT_URL`.
- Passwords, tokens, authorization codes, and other credentials are forbidden.
- MCP, standalone CLI, Skill, and OS scheduler all use this same file.