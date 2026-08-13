# Configuration

- `gate_mail_account` points to the mailbox account used for IMAP scan and SMTP replies.
- `submission_group_address` receives PASS notices.
- `blocked_notice_address` receives block notices when the sender cannot be safely inferred.
- `mandatory_checks_by_module` defines the non-disableable checks. An empty effective set is `GATE_POLICY_INVALID`.
- `gitlab_gate_adapter_config` points to the setup-managed credential-free adapter config.
- The adapter config requires `base_url`, numeric `project_id`, protected
  `ref`, exact `job_name`, and the environment-variable name containing the
  GitLab token. The result path is fixed to
  `artifacts/<pipeline-id>-<job-id>-submission-gate/result.json` and cannot be
  configured by a user.
- The pipeline must execute the exact protected-ref head commit observed by
  preflight. Job ref, commit, pipeline ID, and GitLab HTTPS origin are verified
  before the result artifact is accepted. HTTP redirects are rejected.
- `gate_adapter.command` and `gate_adapter.preflight_command` are setup-managed argv arrays. The entrypoint path/SHA-256 and every setup-generated `integrity_files` entry must match before either command runs.
- `PMG_GITLAB_TOKEN` is the default token variable. The token value must exist only in the process environment or an external secret manager.
- CLEAN gate results must include a full canonical Manifest-S and a nonempty `rollback_ref`; missing or malformed evidence blocks before mail forwarding.
- `dependency_lock` and `dependency_lock_sha256` are setup-managed and must not be hand-edited.
