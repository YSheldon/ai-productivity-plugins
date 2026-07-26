# Automation Contract

- `run-once` scans only the configured mailbox and processes structured or canonical fallback `【提测】` mail.
- The scheduler must skip all missed runs and ignore overlap through OS scheduler semantics plus the local processed-mail store.
- Missing HMAC is nonblocking and explicitly unverified. A claimed invalid HMAC, missing locked mail account, incomplete request, or missing authoritative gate integration blocks processing.
- PASS and BLOCKED notifications still require SMTP acceptance before they are counted as delivered.
