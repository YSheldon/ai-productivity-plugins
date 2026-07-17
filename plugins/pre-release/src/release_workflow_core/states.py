from __future__ import annotations

from dataclasses import dataclass


SUBMISSION_CREATED = "SUBMISSION_CREATED"
SUBMITTED = "SUBMITTED"
SEND_BLOCKED = "SEND_BLOCKED"
SUBMISSION_GATE_PASSED = "SUBMISSION_GATE_PASSED"
SUBMISSION_GATE_BLOCKED = "SUBMISSION_GATE_BLOCKED"
PENDING_TEST_RESULT = "PENDING_TEST_RESULT"
TEST_FAILED = "TEST_FAILED"
PRERELEASE_REQUESTED = "PRERELEASE_REQUESTED"
RELEASE_READY = "RELEASE_READY"
RELEASE_READY_NOTIFIED = "RELEASE_READY_NOTIFIED"
RELEASE_BLOCKED = "RELEASE_BLOCKED"
CAPABILITY_BLOCKED = "CAPABILITY_BLOCKED"

SUCCESSOR_STATES: dict[str, frozenset[str]] = {
    SUBMISSION_CREATED: frozenset((SUBMITTED, SEND_BLOCKED, CAPABILITY_BLOCKED)),
    SUBMITTED: frozenset((SUBMISSION_GATE_PASSED, SUBMISSION_GATE_BLOCKED, SEND_BLOCKED, CAPABILITY_BLOCKED)),
    SEND_BLOCKED: frozenset((SUBMITTED, CAPABILITY_BLOCKED)),
    SUBMISSION_GATE_PASSED: frozenset((PENDING_TEST_RESULT, CAPABILITY_BLOCKED)),
    PENDING_TEST_RESULT: frozenset((PRERELEASE_REQUESTED, TEST_FAILED, CAPABILITY_BLOCKED)),
    PRERELEASE_REQUESTED: frozenset((RELEASE_READY, RELEASE_BLOCKED, CAPABILITY_BLOCKED)),
    RELEASE_READY: frozenset((RELEASE_READY_NOTIFIED, CAPABILITY_BLOCKED)),
    RELEASE_READY_NOTIFIED: frozenset(),
    SUBMISSION_GATE_BLOCKED: frozenset(),
    TEST_FAILED: frozenset(),
    RELEASE_BLOCKED: frozenset(),
    CAPABILITY_BLOCKED: frozenset(),
}

CHECKPOINT_STATES = frozenset(
    (SUBMISSION_CREATED, SUBMITTED, SUBMISSION_GATE_PASSED, PENDING_TEST_RESULT, PRERELEASE_REQUESTED, RELEASE_READY)
)
FAILURE_STATES = frozenset(
    (SEND_BLOCKED, SUBMISSION_GATE_BLOCKED, TEST_FAILED, RELEASE_BLOCKED, CAPABILITY_BLOCKED)
)


class WorkflowTransitionError(ValueError):
    """Raised when a workflow state advance violates the accepted state graph."""


def can_transition(current_state: str, next_state: str) -> bool:
    return next_state in SUCCESSOR_STATES.get(current_state, frozenset())


def require_transition(current_state: str, next_state: str) -> None:
    if not can_transition(current_state, next_state):
        raise WorkflowTransitionError(
            f"workflow transition is invalid: {current_state} -> {next_state}."
        )


@dataclass(frozen=True)
class CapabilityBlockedCheckpoint:
    state: str
    reason: str
    replayable: bool = True


def freeze_capability_blocked(checkpoint_state: str, reason: str, *, replayable: bool = True) -> CapabilityBlockedCheckpoint:
    if checkpoint_state not in CHECKPOINT_STATES:
        raise WorkflowTransitionError(
            f"capability blocks must freeze one prior checkpoint, got: {checkpoint_state}."
        )
    text = str(reason or "").strip()
    if not text:
        raise WorkflowTransitionError("capability blocked checkpoints require a reason.")
    return CapabilityBlockedCheckpoint(state=checkpoint_state, reason=text, replayable=replayable)
