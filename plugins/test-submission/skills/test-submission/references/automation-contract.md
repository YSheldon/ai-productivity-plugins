# Automation Contract

- `run-once` retries only durable pending outbound submissions.
- The scheduler must skip all missed runs and ignore overlap by relying on OS-level schedule semantics plus the local event lock.
- Missing dependency lock, missing mail account, or a required local preview capability fails closed. A missing HMAC key is nonblocking and produces an explicit unverified transport badge; a claimed invalid HMAC remains blocking at the receiving gate.
- SMTP acceptance is required before a submission is marked sent.
