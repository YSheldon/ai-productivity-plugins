---
name: rd-flywheel
description: Use when starting or materially changing a new requirement, project, automation, or engineering task (新需求、新项目、新任务) that must become a reusable, production-proven capability rather than a one-off delivery.
---

# R&D Flywheel

## Principle

Use the real task as both delivery and first practice. Close its business loop before harvesting reusable experience. Evidence, not AI narrative, advances state.

## Hard Invariants

- **Visual decision:** read Visual Companion `state/events`; bind choice and timestamp to the displayed HTML SHA-256. No event means `VISUAL_DECISION_PENDING`. This is design consent only, never production authorization.
- **Capability gap:** record `UNSUPPORTED -> CAPABILITY_BLOCKED` and preserve the originating checkpoint before construction. A required detector must not be waived, even for emergency delivery.

## Required Loop

1. **Establish truth.** Locate the authoritative repository, request, runtime, assets, authority boundary, and freshest evidence. Separate “exists” from “proved”; classify assets as reuse, adapt, reference-only, or unavailable.
2. **Contract the outcome.** Define one user-visible vertical slice, non-goals, failure semantics, production meaning, and evidence-based acceptance criteria.
3. **Select the first practice.** Use the actual request, not a toy. Prefer a representative, observable, reversible case. Meta-tooling needs a previous trusted path or independent verifier as its bootstrap trust root for its first production release; it cannot approve itself.
4. **Design before code.** **REQUIRED SUB-SKILL:** use `superpowers:brainstorming`. Use its accepted Visual Companion for architecture, state machines, spatial flows, and visual comparisons. Use terminal text for conceptual decisions and accessibility fallback. Silence is never approval.
5. **Plan and build.** After approval, use `superpowers:writing-plans`, then `superpowers:test-driven-development`. Preserve immutable inputs, deterministic outputs, idempotency, rollback hooks, and observable transitions.
6. **Build missing capability.** Contract, build, test, merge, and register the smallest missing capability; replay the original immutable input at the preserved checkpoint. AI may auto-merge policy-compliant code but cannot self-grant credentials, privileges, or production scope.
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
