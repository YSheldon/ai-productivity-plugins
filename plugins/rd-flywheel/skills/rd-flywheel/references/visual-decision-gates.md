# Visual Decision Gates

Use this mechanism for choices whose meaning is clearer when seen: architecture boundaries, state machines, dependency relationships, UI layouts, rollout topology, and acceptance matrices. Keep requirements, trade-offs, and conceptual choices in the terminal.

## Consent and Session

1. Offer the Visual Companion once and wait for consent.
2. Start a persistent local session under the project, and retain `screen_dir`, `state_dir`, and URL.
3. Before every screen, verify `state/server-info` exists and the server is alive.
4. Use a fresh semantic HTML filename. Never overwrite a prior decision screen.

## Gate Protocol

1. Define one decision with two to four options, or one explicit confirmation action.
2. Render the real architecture, flow, or acceptance content. Do not use decorative mockups that conceal missing detail.
3. Tell the user what is shown, repeat the local URL, and end the turn.
4. On the next turn, read `state/events`. The terminal message is primary feedback; click events add structured evidence.
5. Compute the SHA-256 of the displayed HTML and record the decision envelope:

```json
{
  "decision_id": "architecture-v1",
  "screen_file": "architecture-v1.html",
  "screen_sha256": "...",
  "choice": "c",
  "event_timestamp": 0,
  "terminal_confirmation": null,
  "status": "APPROVED"
}
```

6. Advance only after an explicit click or unambiguous terminal approval. No event means `VISUAL_DECISION_PENDING`, not implicit consent.
7. If feedback changes the design, create a new versioned screen and invalidate the prior decision for that section.
8. When returning to non-visual discussion, push a waiting screen so stale choices are not mistaken for active ones.

State model:

`PRESENTED -> USER_SELECTED -> DECISION_RECORDED -> APPROVED`

Alternative paths:

- `PRESENTED -> REVISE_REQUESTED -> PRESENTED(new version)`
- `PRESENTED -> TERMINAL_FALLBACK -> DECISION_RECORDED -> APPROVED`
- `PRESENTED -> VISUAL_DECISION_PENDING` when no response exists

## Authority Boundary

A Visual Companion decision proves design consent only. It may authorize writing a specification or implementation plan when the applicable design workflow allows it. It must never replace Feishu approval, GitLab protected-branch policy, production credential authority, release authorization, or a deterministic gate result.

Persist the decision envelope with the design spec or event evidence. Do not store private browser data, cookies, credentials, or unrelated UI state.
