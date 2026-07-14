---
name: daily-vuln-bulletin-email
description: Generate, validate, and send 每日漏洞播报 through live Feishu subscribers and an audited domestic-mail transport. Use for authoritative engineering sync, source-overview formatting, severity badges, MIME Subject checks, recipient-header privacy, SMTP delivery, or exact IMAP readback.
---

# Daily Vulnerability Bulletin Email

Use this skill for production `每日漏洞播报` delivery. Keep report generation,
recipient authority, MIME construction, transport, recipient privacy, and
readback as separate verified stages.

## Delivery Architecture

```text
engineering sync -> action/report boundary -> selected-capability plugin preflight
-> Feishu live subscribers -> per-recipient content build
-> outgoing .eml MIME + recipient-privacy preflight
-> SMTP / China Email send -> exact Message-ID IMAP readback
-> raw-header + MIME + privacy audit -> artifact + automation memory
```

Read [references/delivery-contract.md](references/delivery-contract.md),
[references/header-privacy-contract.md](references/header-privacy-contract.md),
and [references/plugin-install-contract.md](references/plugin-install-contract.md)
before real sends. Use
[assets/domestic-email-shell.html](assets/domestic-email-shell.html) as the
HTML shell. Run both
[scripts/verify_bulletin_mime.py](scripts/verify_bulletin_mime.py) and
[scripts/verify_recipient_privacy.py](scripts/verify_recipient_privacy.py) on
the exact serialized `.eml` before SMTP and on both IMAP readbacks after SMTP.

## Plugin Preflight And Consent-Gated Installation

Run the read-only preflight before accessing Feishu, SMTP, or IMAP. Require only
the capabilities used by the selected delivery path:

- Realtime Feishu subscriber source:
  `lark-cli@ai-productivity-plugins`.
- Plugin-native SMTP/IMAP transport and readback:
  `imap-smtp-mail@ai-productivity-plugins`.
- A separately validated local SMTP/IMAP script is a different transport
  capability. Record its executable and proof; do not infer it from an
  installed plugin.

```powershell
python scripts/check_bulletin_plugins.py `
  --require lark-cli@ai-productivity-plugins `
  --require imap-smtp-mail@ai-productivity-plugins `
  --json-out plugin-preflight.json
```

Interpret the result as follows:

1. `0` / `ready`: every selected capability is installed and enabled.
2. `2` / `consent_required`: exact plugin IDs are available but absent. Do not
   install, send, or fall back. Report the IDs, configured marketplace,
   persistent effects, and `ON_INSTALL` authentication behavior; wait for
   explicit approval.
3. `3` / `blocked`: inventory failure, unavailable capability, or disabled
   plugin. Do not guess a repair command or substitute another marketplace.

After explicit approval of the listed IDs only, run the exact commands emitted
by the preflight, then rerun it and continue only after `ready`:

```powershell
codex plugin add lark-cli@ai-productivity-plugins --json
codex plugin add imap-smtp-mail@ai-productivity-plugins --json
```

Never auto-install without explicit approval. Keep credentials out of command
lines, generated artifacts, email bodies, and automation memory. A successful
installation does not prove the capability works; perform the selected source
and transport checks separately. If the current session cannot discover a newly
installed capability, stop the formal send and require a fresh session.

## Non-Negotiable Gates

1. Synchronize the authoritative engineering checkout before deciding whether
   a dated action report exists. Do not reset or overwrite local changes.
2. Read the Feishu subscriber document in realtime. Send only when
   `ok=true`, `source=feishu`, and the deduplicated valid-email list is
   nonempty. The SMTP envelope list and comma-joined audit value must match it
   exactly and in order.
3. Default to one message per subscriber with one visible `To:` address. Never
   put the complete subscriber list in visible `To:` or `Cc:` for a production
   bulletin. Aggregate/disclosed mode requires explicit operator choice and is
   recorded as `disclosure`, not as privacy-safe delivery.
4. Run `verify_recipient_privacy.py` before SMTP and on both IMAP readbacks.
   Block raw `Bcc:`, visible `Cc:`, explicit `X-Originating-IP` or
   `X-Client-IP`, malformed addresses, and individual-mode messages with
   multiple visible recipients. Report `Received:` count only; do not claim
   transport metadata can be removed.
5. Generate local Markdown, plain text, HTML, `outgoing.eml`, and content
   metrics before sending. Never place local paths in the email body or source
   links.
6. Build a `multipart/alternative` message with a Unicode string `Subject`;
   do not assign a live `Header` object to modern `EmailPolicy` headers.
7. Run the MIME verifier against `outgoing.eml` with the exact formal subject.
   Block missing raw `Subject:`, decoded-subject mismatch, empty body parts, or
   an incompatible HTML shell.
8. Send once only. Do not create drafts for a formal daily send. Never use
   stale subscribers or a Gmail fallback for the China Email production path.
9. Find the sent message using exact `Message-ID` scans of Sent and Inbox. Do
   not use IMAP `TEXT` search as a selector. Save the complete raw `.eml` from
   each mailbox and run both verifiers on both.
10. A missing or mismatched raw `Subject:` is a delivery failure even when SMTP
    accepts the message. A requested subject in a JSON send record is not proof
    of delivery.
11. Do not auto-resend after a post-send audit failure. Preserve the evidence
    and remediate through the approved operational path to avoid duplicates.

## Bulletin Content Contract

- Formal subject: `【猎鹰安全】每日漏洞播报｜YYYY-MM-DD`.
- `From:` is visible to recipients and is not an anonymity boundary.
- `Received:` may expose relay hostnames, timestamps, and public IP metadata.
  Record counts only; never put raw values in artifacts or memory.
- Send readable `text/plain` and client-compatible `text/html` alternatives.
- Use the full-width outer presentation table and centered 720px inner table.
  Keep critical styles inline; do not rely on external CSS, JavaScript, remote
  images, or client-specific features.
- Use email headings in `【标题】` form. Put `【今日优先处置建议】` before
  detailed vulnerability cards.
- Keep the fixed source-overview table in local Markdown. Render the email
  overview as stacked cards with `来源`, `命中`, and `关注`.
- Every key vulnerability in text and HTML includes `来源图标/来源`,
  `严重级别`, `影响范围`, `主要风险`, `应对措施`, and `来源链接`.
- Use `🟥 Critical` and `🟨 High`; never output bare English severity labels.
- Always include `【内核/驱动相关】` and `【信创相关】`, explicitly stating no
  hit when applicable.
- Source links must remain public `http://` or `https://` URLs. Never emit a
  local Windows path as a source link.

## Completeness Gate

Compare the candidate with the latest successful bulletin when one exists.
Record candidate and baseline character counts, headings, CVE count, source
rows, URLs, and key-vulnerability blocks.

Block the send when a required section, source total, severity split, key field,
source URL, severity badge, or recipient-privacy verdict is missing. Also block
when the candidate body falls below 75% of the successful baseline without an
explained lower-hit boundary, or when Critical/High findings exist but the body
has no `🟥 Critical` or `🟨 High` badge.

## Required Artifacts

Persist one report directory containing:

- `bulletin.md`, `email.txt`, `email.html`, and `outgoing.eml`
- `subscribers.live.json`, `plugin-preflight.json`, and `content-metrics.json`
- `header-privacy-audit.json` with counts, verdict, and redacted reasons only
- `plugin-install-results.json` only when a user-approved installation occurred
- `send-result.json` with actual transport recipients and `Message-ID`; do not
  claim a thread ID unless the transport provides one
- `sent-readback.eml`, `inbox-readback.eml`, and verifier JSON outputs
- `readback-result.json` with exact Message-ID lookup, raw subject, MIME parts,
  privacy counts, and final decision

Append sync result, action boundary, live recipient list, preflight/install
result, send identifiers, and readback verdict to automation memory without
overwriting prior rules. Do not append secrets, raw header values, or recipient
addresses to memory.

## Verification Commands

```powershell
python scripts/verify_bulletin_mime.py outgoing.eml --expected-subject "【猎鹰安全】每日漏洞播报｜YYYY-MM-DD" --strict-layout --json-out outgoing-mime-audit.json
python scripts/verify_recipient_privacy.py outgoing.eml --mode individual --json-out outgoing-header-privacy.json
python scripts/verify_bulletin_mime.py sent-readback.eml --expected-subject "【猎鹰安全】每日漏洞播报｜YYYY-MM-DD" --strict-layout --json-out sent-mime-audit.json
python scripts/verify_recipient_privacy.py sent-readback.eml --mode individual --json-out sent-header-privacy.json
python scripts/verify_bulletin_mime.py inbox-readback.eml --expected-subject "【猎鹰安全】每日漏洞播报｜YYYY-MM-DD" --strict-layout --json-out inbox-mime-audit.json
python scripts/verify_recipient_privacy.py inbox-readback.eml --mode individual --json-out inbox-header-privacy.json
```

The correct post-send selector is: select mailbox, `UID SEARCH ALL`, fetch
header fields for a bounded latest UID window, compare exact `Message-ID`, then
fetch complete MIME source only for an exact match.

## Failure Handling

- Consent-required preflight: do not install or send until the exact IDs are
  approved.
- Blocked preflight: do not add, update, or substitute marketplaces.
- Feishu source failure or recipient mismatch: block before SMTP.
- Local MIME/Subject failure: rebuild before SMTP.
- Multiple visible recipients in individual mode: mark a recipient-privacy
  failure; do not hide it behind the requested recipient list.
- SMTP failure: preserve artifacts and report the exact transport error.
- Sent/Inbox readback failure: do not resend; preserve the Message-ID and report
  the missing proof.
- Raw Subject or MIME mismatch: mark delivery failed even if the body exists;
  fix the builder and validate with a new controlled message before any
  operational resend.
