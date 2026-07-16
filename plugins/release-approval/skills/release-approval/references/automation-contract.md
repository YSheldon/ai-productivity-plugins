# Automation Contract

`release_approval_start_setup` is the only setup entrypoint.

It must:

- run only the fixed allowlisted bootstrap profile
- stop with `FRESH_TASK_REQUIRED` if bootstrap installed or upgraded anything
- validate the configured account email against locked mail inventory
- create exactly one hourly Codex automation
- invoke `release_approval_run_once` immediately after automation creation
- record the automation id, dependency lock, and first-run evidence

`release_approval_run_once` must stay deterministic and minimal:

- read recent release-request mail through the locked MailGateway
- validate the frozen machine block before acting
- use `UIDVALIDITY`, `UID`, and `Message-ID` idempotency
- create or reuse exactly one page per event/round/role
- retry known-unsent decisions
- auto-open only newly created pages
- return `CAPABILITY_BLOCKED` instead of falling back to subject-only trust when readback/thread evidence is incomplete
