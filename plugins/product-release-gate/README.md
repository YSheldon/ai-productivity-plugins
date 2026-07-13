# Product Release Gate

This local Codex plugin creates a durable, fail-closed product material gate:

```text
N0 submission -> N1 submission gate -> N2 test evidence -> N3 policy approval
-> N4 final material / Manifest-R -> N5 release gate -> RELEASE_READY -> report
```

It is intentionally an evidence and gate controller, not a deployment controller. `RELEASE_READY` means the frozen material passed the configured checks. It does not claim that an environment was deployed.

## Configuration

Copy `config/config.example.json` to a protected local location and customize the adapter commands:

```powershell
$env:PRODUCT_RELEASE_GATE_CONFIG = "C:\path\to\product-release-gate.json"
```

The plugin calls adapters with argument arrays rather than a shell.

- Cloud scan adapter stdout: `{"verdict":"CLEAN","evidence_ref":"scan-123"}`
- Test adapter stdout: `{"result":"PASS","report_ref":"test-run-123","summary":"..."}`

Required checks fail closed when their adapter is absent, errors, or returns a non-pass verdict.

## Normal Flow

1. `release_gate_preflight`
2. `release_gate_create_submission`
3. `release_gate_run_submission_gate`
4. `release_gate_run_tests` or `release_gate_record_test_result`
5. `release_gate_record_test_approval` only when the configured risk policy requires it
6. `release_gate_build_final_release`
7. `release_gate_run_release_gate`
8. `release_gate_generate_report`

The event store retains `event.json`, `manifest-s.json`, `manifest-r.json`, execution receipts, and `report.md` under `storage_dir`.

## Security Model

- SHA1 is computed from the artifact file and later re-verified from final material.
- On Windows, required product signing uses `Get-AuthenticodeSignature` and can require a signer-subject substring.
- Cloud scan and test orchestration are explicit adapter contracts, not LLM judgments.
- Any final-material mapping or SHA1 drift sends the event back to a new submission round.
- The plugin does not contain production deployment credentials or a release action.
