# RemoteX Legacy Key-Only Recovery Design

Status: approved in-chat design, recorded for implementation-plan review.
No product implementation or real recovery is performed by this document.

## Intent And Baseline

The operator has no trusted backup of the missing recovery envelope. RemoteX
0.7.0 correctly blocks a key-only layout before reading login credentials, but
that layout can also result from an old reader initializing its integrity key
before its first mutation. Missing data cannot prove an empty history.

Provide one explicit, native, owner-reviewed recovery path. After this one-time
transition, ordinary site tasks retain one Allow Automation decision. Do not
change center business code or specialize recovery to a business endpoint.

Implementation baseline: main adc10704c57224441b5d4b750800cd97d81c16cf.
Proposed release: RemoteX 0.7.1. Product/UI/documentation text remains English.

## Non-Negotiable Boundaries

- Default login and ordinary upgrade never initialize a key-only store.
- Recovery cannot delete, rotate, export to chat, or replace the original key.
- Existing valid, corrupt, or newly appearing recovery envelopes are never
  replaced by an empty envelope through this entry point.
- Missing/invalid key, broken audit chain, known unresolved writes, or active or
  unknown web lifecycle state blocks recovery. There is no force/reset flag.
- Human owner review is an explicit one-time recovery exception, not proof that
  no historical data was ever lost. The audit basis must say owner-reviewed.
- No password prompt, credential-manager read, remote connection, queue claim,
  queue release, SSH/VM change, or forced process termination belongs to recovery.
- Keep the 180-second native review bound, 12-hour site-grant cap and 30-second
  sensitive business-action ticket. Recovery grants no site authority.
- A preview does not create or change recovery material or its permissions.
  Normal MCP invocation auditing is separate from recovery-store mutation.

## Eligibility And Review Evidence

Recognize a local, non-reparse store containing a 32-byte integrity key and no
uncertain-writes.json. Enumerate all configured and historical web scopes, not
only the currently requested profile. Unexplained scope cannot be omitted.

Verify a complete audit prefix and conservatively correlate reservation/result
and write-tool start/finish records. Counts alone, a completed UI click, or a
successful HTTP response do not prove business completion. Known unfinished or
unknown write outcomes block; unrecorded-history uncertainty must be explicit
in the owner's review. Synthetic records must not be labeled production proof.

Bind a private preview to canonical root identity, key file identity/size/mtime,
verified ledger prefix, web-scope metadata and lifecycle observations. Neither
key bytes nor credential-derived hashes enter public results or the native form.
The public API receives an opaque recovery_id and sanitized counts/codes only.

New unrelated SSH/VM audit records may extend a verified prefix without renewing
the review. New relevant web activity, changed scope/key/root, broken continuity,
an incomplete append or an uncertain lifecycle requires a fresh preview or blocks.
Never take an audit writer's initialization path merely to read evidence.

## Public Flow And Native Decision

One new tool, remotex_web_authorization_recovery:

1. confirm=false without recovery_id: inspect and return a read-only preview.
2. confirm=true with that recovery_id: revalidate and open a native recovery form;
   this only requests review, never supplies approval.
3. confirm=false with recovery_id: return status without replaying a write.

Permit one pending recovery per MCP process. Repeating the same request returns
its current status and does not open another window or restart its timer.
Competing processes remain safe through locked commit and no-overwrite publish.

The native form shows the fixed recovery target, all affected scopes, observed
evidence, remaining uncertainty and the proposed v2 transition. It has one
initially unchecked owner-review statement, Recover Legacy State and Cancel.
The operator must be able to vouch that prior effects have been reconciled;
otherwise cancel. There is no JSON import, category picker or password field.

Only the original private native pipe can deliver the nonce/digest-bound,
one-use decision. A chat answer, public argument or receipt file cannot approve.
Use a recovery-specific acknowledgment, not a synthetic site grant_id.

## Commit, Protection And Evidence

Use the existing exclusive recovery lock. Do not acquire queue/lease/resource
locks while holding it. Inspect lifecycle proofs read-only. Recheck the live
decision, original deadline/cancellation, absent envelope, original key identity,
scope and relevant ledger extension immediately before publication.

After native confirmation, create an owner-private local backup and recovery
receipt outside the repository. Preserve the key in place; record that the old
envelope was absent rather than inventing an old empty state.

Publish the standard authenticated v2 envelope with a temporary deny-only
reservation owned by recovery_id. Reuse the existing unscoped
SITE_SESSION_CONFLICT representation, understood by 0.7.0 readers. This marker
blocks old/new web writers until finalization; 0.6.9 readers reject version 2.
Do not introduce a new envelope shape or weaken normal conflict checks.

The first publication must not replace a concurrently created destination. Use
a same-directory staged file, private permissions, fsync, and a Windows
no-replacement publish operation. MoveFileExW with WRITE_THROUGH and without
REPLACE_EXISTING/COPY_ALLOWED/DELAY_UNTIL_REBOOT is the planned primitive.
Verify its actual existing-destination behavior in a Windows regression.
Reference: [Microsoft MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

After authenticating readback and persisting the recovery audit/receipt, remove
only this recovery's temporary marker under the same lock. Do not clear other
entries. No further required durable write follows that final state transition.

Before publication, cancellation/failure leaves the original key-only state.
After publication, failure leaves v2 and the protective marker where possible,
and reports committed-unverified without claiming protection that cannot be
read back. Never roll back to v1 or reconstruct an empty file on retry.

A later status read is non-mutating. Completing an interrupted technical recovery
requires a fresh native decision, authenticated receipt, exact ownership of the
temporary marker and fresh evidence. A receipt alone never authorizes clearing.
An existing real pending entry, missing receipt or ambiguous ownership blocks.
After an MCP restart, a read-only preview may reconstruct a finalization intent
from authenticated receipt/state; it cannot reconstruct approval. The next
native review uses a fresh nonce and deadline. It never republishes an empty
envelope over existing v2 state.

## Compatibility And User Experience

Recovery success closes its own form; it is not an active site-grant window.
Closing a completed recovery form cannot undo the protocol transition. Existing
site/granular forms retain their original close/revoke behavior.

Installation alone never applies recovery. Old web consumers need an idle reload
where required; SSH/VM work is not interrupted. Keep exact-origin/certificate,
credential isolation, supported-host-browser access and queue requirements for
subsequent login. Successful recovery is not successful authentication.

Improve the missing-state diagnostic without relabeling every audit failure:
distinguish recovery-state-missing from invalid key, bad MAC and broken ledger.
The ordinary login gate stays closed and points to the read-only recovery preview.

## Acceptance

- Actual 0.6.9 key-only fixture is eligible only for owner review, never auto reset.
- Preview, cancellation, expiry and forged/public approval leave original bytes.
- Known unresolved writes, scope ambiguity and corrupt evidence remain blocked.
- Old-writer races and appearing envelopes cannot be overwritten.
- Interrupted commits retain protection; repeat/status never reinitializes data.
- Existing 0.7.0 readers recognize the temporary fence and preserve later writes.
- Native synthetic recovery requires a real human; automated fixtures are labeled.
- Full local regression, independent review and exact-candidate Windows CI pass
  before publication/installation. Preserve failures; do not skip unrelated tests.
- Real recovery still needs the operator's action-time native confirmation.
- Production login/read remains separate and awaits supported Edge access.
