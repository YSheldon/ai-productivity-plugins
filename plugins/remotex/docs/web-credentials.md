# Web Credentials

RemoteX 0.5.12 provides Windows-only credential management for one HTTPS web origin
and account. It uses the existing Windows Credential Manager and visible
Get-Credential window, plus an isolated Microsoft Edge session. It does not
read Edge's password database or attach to the user's existing tabs.

## Setup

Use `remotex_web_profile_setup` with `confirm=false`:

```json
{
  "profile": "web-console",
  "url": "https://console.example:6868/#/",
  "account": "security",
  "credential_ref": "web-console-security",
  "username_selector": "#loginName",
  "password_selector": "#loginPass",
  "submit_selector": "#loginBtn",
  "confirm": false
}
```

Selectors must come from inspection of the login page and refer to unique
element IDs. An optional `success_selector` identifies a post-login indicator
that was not visible before submission. Without it, submission remains
`needs-user-check`; hiding a login form alone is not authentication proof.
Passwords, tokens, cookies, arbitrary scripts, debugging ports and arbitrary
credential-manager targets are never tool arguments.

After approving the preview, repeat with `confirm=true`. The secure local
window pre-fills the expected account; entering another account is rejected.
The original website password is stored locally. This does not change the
website password. Setup preserves the existing protected backup/rollback flow.
`remotex_credential_setup`, `remotex_credential_delete` and
`remotex_credential_doctor` also work with the web alias.

The credential target and queue resource are derived from the exact normalized
HTTPS origin and account. A web credential cannot be reused by another protocol
or by changing a Profile's origin/account. The `RemoteX/Web/` target namespace
is reserved, including case variants. Web profiles require version 2 config.

## Runtime And Probe

First establish current browser access through the host's supported interface,
including a successful read of the intended browser surface. Denied, disabled,
unavailable, or unknown access stops web operations. RemoteX is not a fallback
around host browser policy and does not offer a trusted policy-introspection API.
The client/skill enforces this prerequisite; `browserPolicyAttested=false` must
not be interpreted as a runtime policy attestation. Do not change host settings,
use raw CDP, or switch transports to bypass an access decision.
After denial, owned-session status/closure and queue release after confirmed
closure are cleanup only; they do not authorize further page interaction.

Install Microsoft Edge and Node.js 24 or newer. `remotex_web_runtime_setup`
first checks for Playwright Core 1.62.1 in the private runtime or Codex bundle.
With `confirm=true`, it can install that pinned package from the shipped lock
file using npm with lifecycle scripts disabled. It does not install Edge or
change browser policy. Operators can use `REMOTEX_PLAYWRIGHT_MODULE` to locate
an existing matching package; this is local trusted configuration, not MCP input.

`remotex_web_probe({"profile":"web-console"})` opens and closes an isolated
Edge session and checks the HTTPS page and controls without reading credentials.
By default, self-signed, expired, untrusted or name-mismatched certificates stop
the flow. Use a valid hostname and a certificate trusted by the local system,
or explicitly approve the exact-origin certificate pin described below.
There is no global ignore-certificate switch or automatic trust-store change.

## Exact-Origin Certificate Trust

For a private endpoint that cannot use normal CA/hostname validation, first
verify the leaf certificate's SHA-256 fingerprint through a trusted server
console or another trusted channel. Network discovery alone is not approval.
After the user explicitly approves that fingerprint and HTTPS origin, pass
`certificate_sha256` to `remotex_web_profile_setup`. The field accepts 64 hex
digits or 32 colon-separated hex byte pairs. The preview returns the normalized
pin and exact origin; `confirm=true` stores the approved binding.

For an existing profile, use `remotex_web_certificate_trust` with `profile`,
`origin`, `certificate_sha256`, and `confirm=false` to preview a change. Repeat
the approved request with `confirm=true`. `origin` must exactly match the stored
scheme, host and port, without a path. To revoke only the pin and restore normal
system CA/hostname validation, set `certificate_sha256` to JSON `null`; this
does not delete the password or change other profiles. Active browser sessions
must be closed before changing their trust. A changed profile/trust snapshot
is rejected if a login was waiting to acquire its resource lock.

The pin substitutes for CA-chain and hostname identity validation only at that
origin. Each new TLS connection must present the exact leaf certificate and
pass its validity dates before any HTTP header, cookie or request body can be
sent. A changed, expired or not-yet-valid certificate blocks the operation;
never silently replace a pin. The helper does not follow redirects, reuse TLS
sessions, alter Edge flags to ignore errors, or install certificates into the
system trust store. The ordinary strict-TLS path is unchanged for profiles
without a pin. After any trust change, run the credential-free probe again.

`certificate-pin-mismatch` and `certificate-validity-failed` are separate from
`tls-or-navigation-failed`. Pins and endpoints are local configuration metadata;
do not publish actual internal endpoint/fingerprint pairs in repository examples.

## Login And Lifetime

Acquire the derived web queue using the current task's requester. The lease
must cover the requested `session_seconds` (60-1800, default 900) plus 45 seconds.
Then call `remotex_web_login` with `profile`, `requester` and `confirm=true`.
The result's `webSessionId` is the session identifier; it is distinct from the
MCP audit `sessionId`.

The helper receives credentials once through an anonymous stdin pipe. Secrets
are not passed through argv, environment, stdout/stderr or receipt files. A
Windows kill-on-close job ties the browser process tree to its local supervisor.
An active-session marker prevents premature queue release/recovery while normal
waiter registration remains available. Closing the browser does not itself
revoke the website's server-side session.

Use `remotex_web_session_status` with `session_id`. States distinguish opening,
submitted, verified, needs-user-check, failed and closed. A receipt reports only
fixed status fields, never page text, cookies, DOM, screenshots or raw errors.
Submission is performed once. MFA/CAPTCHA and unexpected flows require the user.
Use `remotex_web_session_close` with the same `requester` and `confirm=true`, read back closed state,
then release the queue. Sessions also close after their bounded lifetime.
The supervisor checks that the lease still covers the session; shortening it
below that deadline closes the owned browser. A local closed-job receipt permits
marker cleanup even if the original cleanup-lock attempt was busy.

## Browser Network Boundary

The isolated browser runs offline behind a reject-only loopback proxy. A local
driver broker handles only same-origin HTTPS requests with system TLS trust or
an explicitly approved per-origin certificate pin and
rejects redirects rather than replaying credential-bearing requests. Service
workers and WebSockets are blocked. A synthetic STUN UDP/TURN TCP canary runs
at each browser start; failure blocks the login. These controls are tested
against the installed Edge runtime, not a claim of OS-grade browser confinement.
External protocol handlers and arbitrary post-login workflows are outside the
supported controlled flow. The authorized same-origin application still
receives the password as in a normal browser sign-in.

## Responsive Windows

Visible login and probe contexts use `viewport: null`. This disables Playwright's
default fixed 1280x720 viewport so normal Edge window resizing changes the page's
available width and height. It does not change browser zoom, display scaling,
site CSS, TLS verification, or the isolated-session security boundaries.
The internal synthetic network canary retains its own deterministic viewport.

`remotex_web_observe` includes bounded read-only `geometry` fields in CSS pixels:
`viewport` is the current inner width/height, `window` is the outer width/height,
and `content` measures the configured success region. `mode` is `window` or
`emulated`, derived from the actual Playwright page configuration. These fields
do not resize the browser or expose an arbitrary window-control API.

Site-defined minimum widths, fixed-size widgets, browser chrome, and DPI can
still affect layout. Compare both viewport and content dimensions when validating
a real console; a larger outer window alone is not sufficient evidence.
Existing windows keep their creation-time settings. Finish them normally, then
start a new owned session after reconnecting the updated MCP process.

## Same-Session Controlled Operations

After `authenticationVerified=true`, use the following tools with the original
`session_id` and `requester` in the MCP process that started login:

| Tool | Output or operation | Boundary |
| --- | --- | --- |
| `remotex_web_observe` | Visible text, current route, fresh link references | Success region only; 16,000 text characters, 100 candidate links, no editable/hidden/embedded/canvas content |
| `remotex_web_navigate` | Preview with `confirm=false`, navigate with `confirm=true` | Fresh observed same-document fragment link only; no caller URL, arbitrary click handler, form, script, or raw HTTP |
| `remotex_web_read_result` | Passive result-code summaries with timestamps | Last 20 of at most 64 retained responses, never sends a request |

Observation references expire after 30 seconds, are invalidated when the page
changes, and are consumed by navigation. The DOM node and destination are
rechecked. Navigation still needs authorization for the destination: a site's
router can have effects, so this is not a blanket read-only guarantee.
Read-only acceptance can use observation and passive results without navigation.

The response projection accepts only root-level `nResult`, `code`, `status`,
`success`, `total`, and `count` numeric/boolean values from bounded JSON XHR/fetch
responses received after authentication. It omits bodies, headers, cookies,
query values, and arbitrary string fields. A read-like command name is only a
label, not proof of the endpoint's semantics. No response is replayed.

`authenticationVerified`, `sameSessionControlAvailable`, and actual business
success are separate checks. A result keeps `businessSuccessVerified=false`:
the caller must evaluate current command/path, HTTP status, result code, and
the user's acceptance criteria. An empty list means no eligible response was
observed, not success. Host/task permissions and target scope are not inferred.

The private pipe stays in memory and is available only to the original
supervisor. Each call checks owner, covering lease, deadline and unchanged
profile/trust, then rechecks origin and the authenticated page. Closing the
browser, losing the lease, EOF, or an uncertain command timeout ends control.
Timeouts close the worker instead of replaying a potentially completed action.
Status/closure receipts remain content-free; page and response output is not
written to the RemoteX audit log. Sanitized tool results are still visible to
the calling host and may be retained in its conversation history.

This does not register the isolated window in Codex's supported browser list.
`webSessionId` is not a browser `tabId`. Existing sessions cannot be adopted by
another process or version; finish them normally and start a new session after
reconnecting the affected idle MCP client. Existing profiles, pins, SSH/VM
configuration and credential references require no migration.

This design uses Microsoft's documented
[Playwright Edge support](https://learn.microsoft.com/en-us/microsoft-edge/playwright/).
[Playwright routing](https://playwright.dev/docs/network) alone is not a complete
network boundary; Chromium documents the
[limits of proxy and DNS controls](https://new.chromium.org/developers/design-documents/network-stack/socks-proxy/).

## Diagnostics

Codex's browser-control error `Unable to load browser request-header policy`
occurs before a site interaction. Retry the supported browser interface once;
if it persists, report that host-side interface failure separately from site
authentication. Do not weaken request-header policy. A successful subsequent
page read proves recovery for that attempt, not a diagnosed root cause.

`REMOTEX_WEB_STATE_DIR` selects a protected local runtime/session directory.
Normal reports show web login activity through its Profile's credential alias;
they do not infer an operating-system version from a web console.

The local credential helper uses an absolute Windows PowerShell executable and
a child-only system `PSModulePath`. It does not inherit PowerShell 7 module
search paths, module cache overrides or secret environment variables. This
avoids `Get-Credential` disappearing when launched through a PowerShell 7 parent.
Failure receipts expose only `prompt-unavailable`, `account-mismatch`,
`credential-write-failed` or `presence-readback-failed`, never exception text.
Stored, cancelled and failed exit codes are handled separately. On cancellation
or failure the profile wizard rolls back the new configuration; a window launch
alone is not evidence that a credential was saved.
