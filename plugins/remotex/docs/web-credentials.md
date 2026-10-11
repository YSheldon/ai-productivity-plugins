# Web Credentials

RemoteX 0.5.9 adds Windows-only credential management for one HTTPS web origin
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

Install Microsoft Edge and Node.js 24 or newer. `remotex_web_runtime_setup`
first checks for Playwright Core 1.62.1 in the private runtime or Codex bundle.
With `confirm=true`, it can install that pinned package from the shipped lock
file using npm with lifecycle scripts disabled. It does not install Edge or
change browser policy. Operators can use `REMOTEX_PLAYWRIGHT_MODULE` to locate
an existing matching package; this is local trusted configuration, not MCP input.

`remotex_web_probe({"profile":"web-console"})` opens and closes an isolated
Edge session and checks the HTTPS page and controls without reading credentials.
Self-signed, expired, untrusted or name-mismatched certificates stop the flow.
Use a valid hostname and a certificate trusted by the local system. There is
no ignore-certificate switch or automatic trust-store modification.

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
driver broker handles only same-origin HTTPS requests with strict TLS and
rejects redirects rather than replaying credential-bearing requests. Service
workers and WebSockets are blocked. A synthetic STUN UDP/TURN TCP canary runs
at each browser start; failure blocks the login. These controls are tested
against the installed Edge runtime, not a claim of OS-grade browser confinement.
External protocol handlers and arbitrary post-login workflows are outside the
supported automated login flow. The authorized same-origin application still
receives the password as in a normal browser sign-in.

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
