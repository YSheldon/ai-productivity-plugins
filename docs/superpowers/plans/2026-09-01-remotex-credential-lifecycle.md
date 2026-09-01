# RemoteX Credential Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver RemoteX 0.5.0 with secret-free asynchronous task IPC, reusable `credential_ref` aliases, batch missing-reference diagnostics, and native secure setup, rotation, and deletion workflows.

**Architecture:** Keep protocol adapters dependent on one normalized credential resolver. Move asynchronous secrets over an anonymous one-shot pipe and protect non-secret task state with verified local permissions. Keep all password entry inside a visible local Windows secure prompt; MCP tools accept only configured profile or alias selectors and confirmations.

**Tech Stack:** Python 3 standard library, Windows Credential Manager Win32 APIs, Windows PowerShell 5.1, OpenSSH, MCP JSON-RPC, `unittest`.

**Spec:** `docs/superpowers/specs/2026-09-01-remotex-credential-lifecycle-design.md`

## Global Constraints

- Never place a password, token, private-key body, or injected secret in MCP arguments, process arguments, configuration, logs, audit records, receipts, or persistent files.
- Version 1 inline credential references remain readable and are never rewritten automatically.
- Credential setup, rotation, deletion, configuration migration, and legacy sensitive-artifact cleanup require explicit confirmation.
- Credential presence and remote authentication are independent states.
- Existing host-key, public-key-only SSH, queue, VM identity, audit, timeout, output, and process-tree behavior must remain intact.
- No new third-party runtime dependency is allowed.

---

### Task 1: Secret-free asynchronous task IPC and private task state

**Files:**
- Create: `plugins/remotex/src/secure_paths.py`
- Create: `plugins/remotex/tests/test_task_secret_ipc.py`
- Modify: `plugins/remotex/src/task_manager.py`
- Modify: `plugins/remotex/src/task_worker.py`
- Modify: `plugins/remotex/tests/test_remotex_vnext.py`

**Interfaces:**
- Produces: `secure_paths.ensure_private_directory(path: Path) -> dict[str, Any]`
- Produces: `secure_paths.private_path_status(path: Path) -> dict[str, Any]`
- Produces: `task_manager._encode_worker_payload(input_bytes: bytes, secrets: list[str]) -> bytes`
- Produces: `task_worker._read_worker_payload(stream: BinaryIO) -> tuple[bytes, list[str]]`
- Produces: `task_manager.cleanup_sensitive_artifacts(args: dict[str, Any]) -> dict[str, Any]`
- Produces MCP tool: `remotex_ssh_task_cleanup_sensitive_artifacts`
- Preserves: `remotex_ssh_task_start/status/collect/cancel` MCP contracts except `RemoteXTaskSpec/v2` and removal of sensitive files.

- [x] **Step 1: Write failing IPC tests**

  Add tests that start a mocked worker with a secret injection and assert:
  `stdin.bin` and `secrets.json` never exist, the child receives a bounded framed
  payload over stdin, no secret enters `argv` or `env`, and the manager returns
  only after a `running` acknowledgment.

- [x] **Step 2: Run the focused tests and observe failure**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_task_secret_ipc.py' -v`

  Expected: imports or assertions fail because pipe framing and private-path APIs do not exist.

- [x] **Step 3: Implement cross-platform private-path enforcement**

  Implement POSIX `0700`/`0600` verification and Windows effective ACL setup/readback. Windows grants only the current user SID, SYSTEM, and Built-in Administrators, rejects reparse/network paths, and fails closed when effective read access remains broader.

- [x] **Step 4: Replace task secret files with a one-shot pipe**

  Change task startup to create only non-secret spec/state files, spawn the worker with `stdin=PIPE`, send a versioned length-bounded payload, close stdin, and wait up to five seconds for the atomic `running` state. On any write, acknowledgment, ACL, or worker failure, terminate the process tree and remove the task directory.

- [x] **Step 5: Update the worker and legacy detection**

  Read exactly one framed payload from `sys.stdin.buffer`, reject trailing or oversized bytes, write the non-secret running state, and drop in-memory references in `finally`. Status reports counts of inactive legacy `stdin.bin` or `secrets.json` files without reading them. Add `remotex_ssh_task_cleanup_sensitive_artifacts` with `confirm=true`; it validates the task UUID and inactive worker, deletes only those two exact filenames, and reports task/path hashes without contents.

- [x] **Step 6: Run focused and existing task tests**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_task_secret_ipc.py' -v`
  and
  `python -m unittest discover -s plugins/remotex/tests -p 'test_remotex_vnext.py' -v`

  Expected: all tests pass and no task fixture leaves a sensitive file.

- [x] **Step 7: Commit the IPC security change**

  Commit message: `fix(remotex): keep asynchronous secrets off disk`

---

### Task 2: Version 2 credential aliases and normalized resolver

**Files:**
- Create: `plugins/remotex/src/credential_store.py`
- Create: `plugins/remotex/tests/test_credential_store.py`
- Modify: `plugins/remotex/src/remotex_core.py`
- Modify: `plugins/remotex/src/ssh_adapter.py`
- Modify: `plugins/remotex/src/ssh_vnext.py`
- Modify: `plugins/remotex/src/rdp_adapter.py`
- Modify: `plugins/remotex/src/windows_guest.py`
- Modify: `plugins/remotex/src/vsphere_adapter.py`
- Modify: `plugins/remotex/tests/test_remotex_core.py`
- Modify: `plugins/remotex/tests/test_adapters.py`

**Interfaces:**
- Produces: `credential_store.resolve_profile_reference(bundle: ConfigBundle, profile_name: str, profile: dict[str, Any], kind: str) -> ResolvedCredential`
- Produces: `ResolvedCredential.public() -> dict[str, Any]`
- Produces: `ResolvedCredential.presence() -> dict[str, Any]`
- Consumes: existing `remotex_core.read_windows_generic_credential()` until native functions move into the store.

- [x] **Step 1: Write failing version 2 resolver tests**

  Cover alias resolution for every provider, v1 inline compatibility, missing aliases, inline-plus-reference conflicts, unknown provider fields, provider/kind incompatibility, token/PEM/userinfo rejection, and alias output that excludes credential values.

- [x] **Step 2: Run resolver tests and observe failure**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_credential_store.py' -v`

  Expected: module or resolver imports fail.

- [x] **Step 3: Implement strict config versions and alias schemas**

  Accept configuration versions 1 and 2. Version 2 validates the exact top-level `credentials` object and exact fields for `identity-file`, `ssh-agent`, `windows-credential-manager`, `windows-integrated`, and `environment`. Profiles accept exactly one of inline `credential` and `credential_ref`.

- [x] **Step 4: Implement normalized credential resolution**

  Resolve inline and alias records into an immutable object containing alias, source, safe references, and provider-specific local readiness methods. Enforce SSH/RDP/Windows guest/vSphere/VMware compatibility before any client process starts.

- [x] **Step 5: Route all adapters through the resolver**

  Preserve current v1 result fields while adding `credentialAlias` and `configurationVersion`. Ensure SSH arguments, RDP launch, WinRM stdin, and govc child environment remain value-compatible and never include secrets in result data.

- [x] **Step 6: Run resolver, adapter, and core tests**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_credential_store.py' -v`
  followed by the complete RemoteX test discovery command.

- [x] **Step 7: Commit alias support**

  Commit message: `feat(remotex): add reusable credential aliases`

---

### Task 3: Batch missing-reference doctor and authentication-state separation

**Files:**
- Create: `plugins/remotex/src/credential_tools.py`
- Create: `plugins/remotex/tests/test_credential_tools.py`
- Modify: `plugins/remotex/src/remotex_mcp.py`
- Modify: `plugins/remotex/src/audit_log.py`
- Modify: `plugins/remotex/tests/test_mcp_protocol.py`
- Modify: `plugins/remotex/tests/test_plugin_contract.py`

**Interfaces:**
- Produces: `credential_tools.doctor(args: dict[str, Any]) -> dict[str, Any]`
- Produces MCP tool: `remotex_credential_doctor`
- Consumes: `credential_store.ResolvedCredential`
- Consumes: `secure_paths.private_path_status`

- [x] **Step 1: Write failing doctor and schema tests**

  Assert collection-wide counts by provider and kind, unique missing aliases and targets, consumer counts, profile/alias filters, v1 migration advice, environment-provider warnings, local protection state, and `authenticationVerified=null` when no protocol evidence exists. Assert no username, password, blob, private-key contents, or environment values appear.

- [x] **Step 2: Run doctor tests and observe failure**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_credential_tools.py' -v`

- [x] **Step 3: Implement batch diagnostics**

  Return `configured`, `present`, `missing`, `incompatible`, and `uniqueMissing` totals plus sanitized per-reference results. Deduplicate shared aliases/targets so one missing reference has one setup action even when several profiles consume it.

- [x] **Step 4: Add independent authentication evidence fields**

  Add a bounded local evidence cache containing only profile, provider, endpoint digest, verified state, and timestamp. Existing SSH, Windows guest, and vSphere authentication tools update it after positive readback; RDP remains `authenticationVerified=null`.

- [x] **Step 5: Register the MCP tool and audit metadata**

  The tool schema accepts optional `profile` and `credential_ref` selectors only. Audit records store alias/provider/target digest and never raw references when a digest suffices.

- [x] **Step 6: Run doctor, MCP, audit, and status tests**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_credential_tools.py' -v`
  followed by the complete RemoteX test discovery command.

- [x] **Step 7: Commit batch diagnostics**

  Commit message: `feat(remotex): diagnose missing credentials in batches`

---

### Task 4: Native secure setup, rotation, and deletion

**Files:**
- Create: `plugins/remotex/scripts/manage_windows_credential.ps1`
- Create: `plugins/remotex/tests/test_credential_lifecycle.py`
- Modify: `plugins/remotex/src/credential_store.py`
- Modify: `plugins/remotex/src/credential_tools.py`
- Modify: `plugins/remotex/src/remotex_mcp.py`
- Modify: `plugins/remotex/tests/test_mcp_protocol.py`

**Interfaces:**
- Produces MCP tool: `remotex_credential_setup`
- Produces MCP tool: `remotex_credential_delete`
- Produces: `credential_store.launch_secure_setup(reference: ResolvedCredential, timeout: int) -> dict[str, Any]`
- Produces: `credential_store.delete_windows_credential(reference: ResolvedCredential) -> dict[str, Any]`

- [x] **Step 1: Write failing lifecycle and schema tests**

  Assert setup/delete schemas contain only `profile`, `credential_ref`, `confirm`, and bounded timeout fields. Reject arbitrary targets and every password/token/secret/username field. Mock helper launch to verify argv contains only the fixed script path, operation, configured target, receipt path, and no credential value.

- [x] **Step 2: Run lifecycle tests and observe failure**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_credential_lifecycle.py' -v`

- [x] **Step 3: Implement the visible secure helper**

  Use `Get-Credential` for local interaction and embedded C# P/Invoke for `CredWriteW`. Pass `SecureString` into native code, use `SecureStringToCoTaskMemUnicode`, and call `ZeroFreeCoTaskMemUnicode` in `finally`. The helper accepts fixed operations and configured target input only, writes a sanitized JSON receipt atomically, and never prints credential values.

- [x] **Step 4: Implement setup and rotation**

  Require Windows, explicit confirmation, a Windows Credential Manager provider, and a protected receipt directory. Launch a visible new console, wait with a bounded timeout, read and delete the receipt, then perform presence readback. Existing entries are rotated by the same secure prompt; cancellation preserves the old entry.

- [x] **Step 5: Implement deletion with consumer safeguards**

  Require explicit confirmation and a configured alias/profile. Reject arbitrary targets. Report consumers before deletion, call `CredDeleteW`, verify absence, and return only alias, consumer count, provider, and target digest.

- [x] **Step 6: Run lifecycle, protocol, and redaction tests**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_credential_lifecycle.py' -v`
  followed by the complete RemoteX test discovery command.

- [x] **Step 7: Commit lifecycle tools**

  Commit message: `feat(remotex): add secure credential lifecycle tools`

---

### Task 5: Version 1 migration preview and explicit version 2 write

**Files:**
- Create: `plugins/remotex/scripts/migrate_remotex_config.py`
- Create: `plugins/remotex/tests/test_config_migration.py`
- Modify: `plugins/remotex/src/credential_store.py`
- Modify: `plugins/remotex/config/config.example.json`

**Interfaces:**
- Produces: `credential_store.migrate_v1_config(data: dict[str, Any]) -> dict[str, Any]`
- Produces CLI: `migrate_remotex_config.py --config PATH --check`
- Produces CLI: `migrate_remotex_config.py --config PATH --write --confirm`

- [ ] **Step 1: Write failing migration tests**

  Cover deterministic alias names, deduplication of identical inline references, semantic profile equivalence, no credential-value reads, preview without writes, required confirmation, adjacent backup, atomic replace, private protection, and reload/readback rollback on failure.

- [ ] **Step 2: Run migration tests and observe failure**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_config_migration.py' -v`

- [ ] **Step 3: Implement deterministic migration**

  Generate aliases from profile names with collision-safe numeric suffixes, deduplicate byte-for-byte identical normalized references, replace inline objects with `credential_ref`, set version 2, and preserve defaults and every non-credential profile field.

- [ ] **Step 4: Implement preview and confirmed write**

  `--check` prints only a sanitized structural summary and the candidate JSON without secret values. `--write --confirm` creates a protected backup, atomically replaces the config, reloads through RemoteX validation, compares semantic normalized profiles, and restores the backup on failure.

- [ ] **Step 5: Update the example config to version 2**

  Demonstrate separate SSH, RDP, Windows guest, and vSphere aliases without any literal value or product-specific endpoint.

- [ ] **Step 6: Run migration and contract tests**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_config_migration.py' -v`
  followed by the complete RemoteX test discovery command.

- [ ] **Step 7: Commit migration support**

  Commit message: `feat(remotex): add explicit credential config migration`

---

### Task 6: Documentation, skill, version, and complete verification

**Files:**
- Modify: `plugins/remotex/README.md`
- Modify: `plugins/remotex/skills/remotex/SKILL.md`
- Create: `plugins/remotex/docs/credential-lifecycle.md`
- Modify: `plugins/remotex/.codex-plugin/plugin.json`
- Modify: `plugins/remotex/src/remotex_mcp.py`
- Modify: `plugins/remotex/tests/test_plugin_contract.py`
- Modify: `plugins/remotex/tests/test_plugin_contract.py` for marketplace/version assertions.

**Interfaces:**
- Produces: RemoteX 0.5.0 manifest and server version.
- Documents: secure prompt, aliases, doctor, migration, setup/rotation/delete, no-disk IPC, and authentication boundaries.

- [ ] **Step 1: Write failing version and documentation contract tests**

  Assert manifest/server/marketplace version `0.5.0`, new MCP tools, example version 2, required documentation sections, and absence of password-like tool fields.

- [ ] **Step 2: Run contract tests and observe failure**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_plugin_contract.py' -v`
  and
  `python -m unittest discover -s plugins/remotex/tests -p 'test_mcp_protocol.py' -v`

- [ ] **Step 3: Update docs, skill, manifest, and version**

  Explain that setup is local interactive, presence is not authentication, RDP has no login receipt, version 1 remains supported, environment references are ephemeral-only, and installed-plugin update is a separate gate.

- [ ] **Step 4: Run RemoteX tests**

  Run:
  `python -m unittest discover -s plugins/remotex/tests -p 'test_*.py' -v`

- [ ] **Step 5: Run plugin and skill validation**

  Run the bundled `validate_plugin.py` against `plugins/remotex` and `quick_validate.py` against `plugins/remotex/skills/remotex`.

- [ ] **Step 6: Run repository-wide configured tests**

  Run the repository `pytest.ini` test set with the bundled Python runtime and temporary dependencies. Remove test caches and dependencies before staging.

- [ ] **Step 7: Scan and review the final diff**

  Run Python compilation, `git diff --check`, known-secret-pattern scanning, MCP schema scanning for forbidden secret fields, and explicit staged-file review.

- [ ] **Step 8: Commit the release update**

  Commit message: `docs(remotex): document credential lifecycle workflows`

- [ ] **Step 9: Push and create a pull request**

  Fetch `origin/main`, confirm the topic branch base, push only
  `codex/remotex-credential-lifecycle`, create a PR describing security and
  compatibility boundaries, and wait for required GitHub checks. Do not merge.

- [ ] **Step 10: Install only after source acceptance**

  After merge or explicit approval of a branch build, use the plugin creator
  cachebuster/reinstall workflow, run `remotex_status`, and report installation,
  credential setup, reference presence, and remote authentication separately.
