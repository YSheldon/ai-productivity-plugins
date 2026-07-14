# Delivery Contract

## Recipient Authority

Use the realtime Feishu subscriber result as the only recipient source. Require
`ok=true`, `source=feishu`, and one or more valid deduplicated addresses. Keep
caches only for audit, never as a send fallback.

## Outgoing Wire Contract

Build a `multipart/alternative` email with a Unicode string subject. Serialize
the message once to `outgoing.eml`, then validate that exact byte stream before
SMTP. A requested subject stored in application metadata is not evidence that
an RFC `Subject:` header exists on the wire.

The preflight accepts only when all are true:

- raw `Subject:` exists and decodes exactly to the formal subject
- plain text and HTML alternatives both contain meaningful visible content
- HTML uses the full-width outer and responsive 720px inner presentation-table
  shell
- recipient envelope equals the realtime Feishu list exactly
- vulnerability content and severity/layout gates pass
- recipient-header privacy policy passes

## Recipient Header Contract

The logical subscriber list and visible mail headers are different surfaces. The
default production mode sends one message per subscriber:

- exactly one address in visible `To:`
- no visible `Cc:`
- no raw `Bcc:` in the serialized or delivered message
- no `X-Originating-IP` or `X-Client-IP`
- `Received:` may exist; record only its count because relays can expose a
  hostname and public IPv4 address

Putting all subscribers in a single `To:` header makes every address visible to
every recipient. It is a disclosure finding even when the SMTP envelope is
correct. Use `references/header-privacy-contract.md` and run
`scripts/verify_recipient_privacy.py` before SMTP and after IMAP readback.

## Post-Send Proof

Use the returned `Message-ID` as the lookup key. In each mailbox, run `UID
SEARCH ALL`, inspect a bounded latest UID window's `MESSAGE-ID` headers, then
fetch complete raw message only for an exact match. Save the bytes as
`sent-readback.eml` and `inbox-readback.eml`; rerun both wire verifiers.

The formal delivery proof includes the real raw subject, content type,
plain/HTML sizes, mailbox UID, Message-ID, actual envelope recipients,
recipient-header counts, and verifier decision. Missing Subject, missing body,
privacy failure, or mismatch is a failed delivery audit, even if SMTP returned
success.

## Remediation Boundary

Do not resend automatically after a post-send audit failure. Preserve failed
artifacts, identify whether the builder or transport changed the wire message,
fix the pre-send gate, validate with a controlled message, and then follow the
approved operational resend path.
