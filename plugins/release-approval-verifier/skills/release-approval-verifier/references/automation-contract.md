# Automation Contract

The OS scheduler invokes the absolute Python executable and `verifier_cli.py --config <path> run-once`. Windows Task Scheduler uses `IgnoreNew` and disables catch-up; systemd uses a non-persistent user timer; cron is a documented fallback. All backends skip all missed runs.

Every run acquires a non-expiring OS-kernel lock. Concurrent work returns `RUN_ALREADY_ACTIVE` before mail, business, or audit effects. Orphan metadata is recovered only after the kernel lock is acquired.

Reminders are sent only during configured working hours, only to missing roles, and in the original thread. The reminder count advances only after SMTP acceptance. Failures retry the same idempotency key.

Aggregate receipts use HMAC-SHA256, bind the frozen event, round, manifests, request, role snapshot, expiry, decisions, and audit evidence, and are immutable. A later decision creates revocation or hold evidence rather than deleting an older receipt.
