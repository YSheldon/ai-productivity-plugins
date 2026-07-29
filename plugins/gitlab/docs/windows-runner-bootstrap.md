# Verified Windows Project Runner Bootstrap

`bootstrap_windows_project_runner.ps1` installs the reviewed GitLab
Runner administration runtime and provisions one policy-bound Windows project
Runner. It is intended for the one-time administrator step after the protected
policy and signed `gitlab-runner.exe` have been initialized.

## Security contract

- Run from an elevated PowerShell 7 console.
- Python is downloaded from a fixed HTTPS URL and accepted only when its
  SHA-256, Authenticode signer, and file version match the pinned values.
- GitLab administration files are downloaded from one immutable repository
  commit and accepted only when every SHA-256 matches.
- Python and the GitLab administration files are copied to protected Program
  Files trees before any GitLab lifecycle action is executed.
- The script accepts only policy `product-material-gate-runner1`.
- The Runner manager token is entered through hidden console input and stored
  only in the current administrator's Windows Credential Manager.
- The token is never accepted as an argument, written to a file, or returned in
  the receipt. The script fails if it remains after the Runner reaches ready.
- Ready requires the exact Runner identity schema, a running automatic service
  under NetworkService, and a protected identity receipt.

## Operator steps

1. Initialize the reviewed policy and signed Runner binary.
2. Place this script in an operator-controlled staging directory.
3. Run it from PowerShell 7 as administrator.
4. When prompted, enter a short-lived project-scoped token with GitLab
   `create_runner` and `manage_runner` permissions.
5. Keep the generated `artifacts/runner-provisioning-result.json` and its
   displayed SHA-256 with the deployment evidence.

If provisioning stops after registration, rerun the same script. It selects the
policy-bound resume path from the protected journal and keeps the Runner paused
until all local and GitLab attestations pass.
