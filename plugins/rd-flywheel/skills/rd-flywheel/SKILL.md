---
name: rd-flywheel
description: Use when starting or materially changing a new requirement, project, automation, or engineering task (新需求、新项目、新任务) that must become a reusable, production-proven capability rather than a one-off delivery.
---

# R&D Flywheel

## Principle

Use the real task as both delivery and first practice. Close its business loop before harvesting reusable experience. Evidence, not AI narrative, advances state.

## Runtime Contract

Use the same controller and the same versioned config on every surface.

1. Use MCP first: `rd_flywheel_setup`, `rd_flywheel_preflight`, `rd_flywheel_run_once`, `rd_flywheel_status`, `rd_flywheel_doctor`, `rd_flywheel_list_events`, `rd_flywheel_get_event`, `rd_flywheel_retry_event`, `rd_flywheel_verify_audit`, and `rd_flywheel_scheduler`.
2. If MCP is unavailable, use the explicit CLI fallback: `py -3 src/rd_flywheel_cli.py <command>`. Do not recreate business logic in the Skill.
3. Standard installation is `py -3 src/rd_flywheel_cli.py setup`; use `setup --non-interactive` for managed deployment. Do not manually duplicate config for another surface. Standard setup requires zero manual JSON editing, and an existing valid configuration makes setup reruns use zero prompts.
4. The unattended entry is `rd_flywheel_cli.py run-once`. OS scheduling must use `scheduler install`, a non-expiring kernel lock, `RUN_ALREADY_ACTIVE` overlap semantics, and skip all missed intervals.
5. Use `verify-audit` before accepting state evidence. Codex is optional and is never a production runtime dependency.

If there is no approved agent adapter, a required tool profile is absent, or an independent verifier cannot prove its evidence, preserve the originating checkpoint and return `CAPABILITY_BLOCKED`. Do not downgrade the detector or fabricate construction.

## Hard Invariants

- **Visual decision:** read Visual Companion `state/events`; bind choice and timestamp to the displayed HTML SHA-256. No event means `VISUAL_DECISION_PENDING`. This is design consent only, never production authorization.
- **Capability gap:** record `UNSUPPORTED -> CAPABILITY_BLOCKED` and preserve the originating checkpoint before construction. A required detector must not be waived, even for emergency delivery.
- **Authority:** AI and tools return evidence, never authority. They cannot grant credentials, privileges, allowlist membership, protected-branch merge, publication, deployment, or production scope.
- **Completion:** tests, independent review, protected-branch merge, package publication, installation, first practice, rollback, and original-checkpoint replay remain separately verified evidence.

## Required Loop

1. **Establish truth.** Locate the authoritative repository, request, runtime, assets, authority boundary, and freshest evidence. Separate “exists” from “proved”; classify assets as reuse, adapt, reference-only, or unavailable.
2. **Contract the outcome.** Define one user-visible vertical slice, non-goals, failure semantics, production meaning, and evidence-based acceptance criteria.
3. **Select the first practice.** Use the actual request, not a toy. Prefer a representative, observable, reversible case. Meta-tooling needs a previous trusted path or independent verifier as its bootstrap trust root for its first production release; it cannot approve itself.
4. **Design before code.** **REQUIRED SUB-SKILL:** use `superpowers:brainstorming`. Use its accepted Visual Companion for architecture, state machines, spatial flows, and visual comparisons. Use terminal text for conceptual decisions and accessibility fallback. Silence is never approval.
5. **Plan and build.** After approval, use `superpowers:writing-plans`, then `superpowers:test-driven-development`. Preserve immutable inputs, deterministic outputs, idempotency, rollback hooks, and observable transitions.
6. **Build missing capability.** Contract, build, test, merge, and register the smallest missing capability; replay the original immutable input at the preserved checkpoint. AI may generate a candidate patch but cannot self-grant credentials, privileges, merge authority, or production scope.
7. **Gate, deploy, observe.** Fail closed with deterministic evidence. Use risk-appropriate test, pre-production, production canary, and production-full stages. Read actual state after side effects; verify recovery and rollback.
8. **Harvest.** After production observation, extract only proved lessons into skills, scripts, templates, policies, or regression scenarios. Remove private identities and secrets; label unproved ideas as hypotheses.
9. **Close.** Require the real outcome, production evidence, rollback proof, separate external readbacks, risk audit, and reusable delta.

Lifecycle: `DISCOVERED -> CONTRACTED -> FIRST_PRACTICE -> BUILT -> VERIFIED -> AUTHORIZED -> DEPLOYED -> OBSERVED -> HARVESTED -> CLOSED`.

Read [visual-decision-gates.md](references/visual-decision-gates.md) for browser evidence, [first-practice.md](references/first-practice.md) for self-bootstrap, [evidence-and-completion.md](references/evidence-and-completion.md) for proof, [tool-routing.md](references/tool-routing.md) for tool authority, and [pressure-scenarios.md](references/pressure-scenarios.md) for regression tests.

## Stop Conditions

- Do not build a platform before one vertical slice closes.
- Do not replace missing evidence with approval or prose.
- Do not implement a missing capability without preserving and resuming the original event.
- Local runs, dry-runs, documents, merges, and notifications do not prove production.
- A policy `BLOCK` is not a runtime failure; follow its evidence and transition.
- Do not harvest “success” before `OBSERVED`.
