# Configuration

- `gate_mail_account` points to the mailbox account used for IMAP scan and SMTP replies.
- `submission_group_address` receives PASS notices.
- `blocked_notice_address` receives block notices when the sender cannot be safely inferred.
- `mandatory_checks_by_module` defines the non-disableable checks. An empty effective set is `GATE_POLICY_INVALID`.
- `product_gate_config` is the authoritative local `product-release-gate` config used by the gate service.
- `dependency_lock` and `dependency_lock_sha256` are setup-managed and must not be hand-edited.
