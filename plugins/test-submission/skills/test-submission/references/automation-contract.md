# Automation Contract

- `run-once` retries only durable pending outbound submissions.
- The scheduler must skip all missed runs and ignore overlap by relying on OS-level schedule semantics plus the local event lock.
- Missing dependency lock, missing HMAC key, missing mail account, or missing shared gate preview all fail closed.
- SMTP acceptance is required before a submission is marked sent.
