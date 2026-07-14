# Selecting the First Practice

## Selection Test

Choose one real case that is representative, observable, reversible, meaningful, and small enough to close before platform work begins. Reject toy demos, synthetic-only fixtures, documentation-only launches, and cases that cannot reach the intended production boundary.

| Work type | First-practice shape |
| --- | --- |
| New requirement | One real user-visible path plus regression coverage in the existing product. |
| New project | One end-to-end vertical slice with a real caller, operational owner, and deploy target. |
| New task/automation | One real event processed from authoritative input through external delivery and readback. |

## Self-Bootstrap Pattern

Meta-capabilities such as release controllers, CI builders, or policy engines should dogfood themselves, but their first production release needs an external trust root:

1. Freeze the candidate input and acceptance contract.
2. Use the previous trusted version or an independent verifier to produce gate evidence.
3. Bind human authorization to candidate, policy, deployment, and rollback hashes.
4. Deploy through isolated stages and read actual state back.
5. Only after production observation may the new version execute later events.

The candidate may generate diagnostics, but it cannot be the sole source of its own first PASS.

If the first practice exposes a missing dependency, build only the missing contract and resume the original event. Broader abstractions are harvested after the observed case proves them.
