# Mail Header Privacy Contract

## What The Recipient Sees

The plugin treats mailbox delivery metadata as a separate privacy surface from
credential leakage:

- Every recipient can normally see the sender address in `From:`.
- Every address placed in visible `To:` or `Cc:` is visible to the recipients of
  that message. A comma-joined eight-address `To:` is an intentional recipient
  disclosure, not a secret leak, but it is still a privacy finding.
- `Bcc:` is expected to be removed from delivered headers. If it survives in a
  delivered message, block the result and record only the count.
- `Received:` headers are added by mail infrastructure and can expose relay
  hostnames, timestamps, and sometimes a public IPv4 address. This plugin does
  not promise to remove or anonymize transport metadata.
- Explicit `X-Originating-IP` and `X-Client-IP` headers are treated as
  disclosure risks and are blocked by the strict audit.

Do not copy raw addresses, hostnames, IPs, authorization codes, or full headers
into the report, audit JSON, email body, or automation memory. The audit should
report counts, booleans, and a redacted reason only.

## Default Sending Mode

The default mode is `individual`: send one message per subscriber with exactly
one visible `To:` address. This preserves the live subscriber list while
preventing recipients from learning who else subscribed.

An aggregate message with multiple visible `To:` or `Cc:` addresses is not an
acceptable default for a production bulletin. It may be used only when the
operator explicitly chooses a disclosed-recipient mode and accepts the privacy
finding in the run record.

For a Bcc-based implementation, validate both the serialized outgoing message
and the delivered IMAP raw message. The delivered message must not contain a
`Bcc:` header, and the visible `To:` count must still satisfy the chosen policy.

## Audit Outcomes

The privacy audit uses these outcomes:

- `pass`: one visible recipient in individual mode, no visible `Cc`, no raw
  `Bcc`, no explicit origin-IP headers; `Received:` metadata is reported only as
  a count.
- `disclosure`: multiple visible recipients or an explicitly allowed aggregate
  mode. This is not a secret finding, but it is not privacy-safe.
- `block`: malformed headers, visible `Cc`, delivered `Bcc`, explicit origin-IP
  headers, or an individual-mode message with more than one visible address.
