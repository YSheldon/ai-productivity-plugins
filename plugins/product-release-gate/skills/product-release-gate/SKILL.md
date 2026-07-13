---
name: product-release-gate
description: Create and execute fail-closed product material submission and release gates through the local Product Release Gate MCP server.
---

# Product Release Gate

Use this plugin for product material submission, submission gates, automated test evidence, final release material production, release gates, and durable gate reports.

## Required Workflow

1. Call `release_gate_preflight` before creating a new event. Do not treat missing signature, cloud-scan, or test adapters as a pass.
2. Call `release_gate_create_submission` with real local artifact paths. The tool computes the frozen Manifest-S SHA1 values itself.
3. Call `release_gate_run_submission_gate`. Any non-PASS result blocks the event. Correct the source material and create a new round; never overwrite a frozen manifest.
4. Call `release_gate_run_tests`, or ingest a trusted external callback through `release_gate_record_test_result`.
5. Standard risk can move automatically when policy allows. High or emergency risk stops at `TEST_APPROVAL_REQUIRED` until `release_gate_record_test_approval` receives an auditable approval reference.
6. Call `release_gate_build_final_release` only after the event reaches `RELEASE_PREPARING`. The target output directory must be empty.
7. Call `release_gate_run_release_gate`. `RELEASE_READY` proves the material passed the gate; it is not a claim that production deployment already happened.
8. Call `release_gate_generate_report` for the durable event summary.

## Safety Boundaries

- The plugin fails closed when a configured required adapter is absent, returns invalid JSON, or reports a non-clean/non-pass result.
- Artifact paths, logical names, source mappings, SHA1 values, signature checks, and cloud-scan results are evidence. Do not replace them with narrative summaries.
- Final material drift, a missing submission file, an extra final file, or a SHA1 mismatch requires a new submission round.
- The plugin intentionally does not hold production deployment credentials and does not mark an event as deployed.

## Adapter Contracts

- `cloud_scan.command` runs without a shell and must write JSON such as `{"verdict":"CLEAN","evidence_ref":"scan-123"}` to stdout.
- `test.command` runs without a shell and must write JSON such as `{"result":"PASS","report_ref":"test-run-123","summary":"..."}` to stdout.
- Use `config/config.example.json` as the configuration starting point. Set `PRODUCT_RELEASE_GATE_CONFIG` or pass `config_path` to each tool.
