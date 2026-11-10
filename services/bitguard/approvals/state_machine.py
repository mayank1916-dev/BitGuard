"""State machine logic and transition validation for Quarantine Hold Tickets (Milestone S14).

Invariants & Rules:
- Enforce valid state transitions in code and database triggers.
- Terminal states (DENIED, EXPIRED, CANCELLED, RELEASED) cannot change.
- Cancelling only tightens policy (PENDING/APPROVED -> CANCELLED).
- Single-use release (PENDING/APPROVED -> RELEASED).
"""

from services.bitguard.approvals.exceptions import InvalidHoldStateTransitionError
from services.bitguard.models import HoldState

TERMINAL_STATES: frozenset[str] = frozenset({
    HoldState.DENIED.value,
    HoldState.EXPIRED.value,
    HoldState.CANCELLED.value,
    HoldState.RELEASED.value,
})

VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    HoldState.PENDING.value: frozenset({
        HoldState.PENDING_RELEASE.value,
        HoldState.APPROVED.value,
        HoldState.DENIED.value,
        HoldState.EXPIRED.value,
        HoldState.CANCELLED.value,
        HoldState.RELEASED.value,
    }),
    HoldState.PENDING_RELEASE.value: frozenset({
        HoldState.RELEASED.value,
        HoldState.CANCELLED.value,
        HoldState.DENIED.value,
        HoldState.EXPIRED.value,
    }),
    HoldState.APPROVED.value: frozenset({
        HoldState.PENDING_RELEASE.value,
        HoldState.RELEASED.value,
        HoldState.CANCELLED.value,
    }),
    HoldState.DENIED.value: frozenset(),
    HoldState.EXPIRED.value: frozenset(),
    HoldState.CANCELLED.value: frozenset(),
    HoldState.RELEASED.value: frozenset(),
}


def validate_transition(current_state: str, new_state: str, ticket_id: str = "") -> None:
    """Validates state transitions according to S14 state machine rules.

    Raises:
        InvalidHoldStateTransitionError: If moving from a terminal state or an invalid transition.
    """
    curr = current_state.upper()
    nxt = new_state.upper()
    if curr == nxt:
        return

    if curr in TERMINAL_STATES:
        raise InvalidHoldStateTransitionError(
            f"Terminal state '{curr}' cannot change to '{nxt}' for ticket '{ticket_id}'",
            current_state=curr,
            target_state=nxt,
        )

    allowed = VALID_TRANSITIONS.get(curr, frozenset())
    if nxt not in allowed:
        raise InvalidHoldStateTransitionError(
            f"Invalid transition from '{curr}' to '{nxt}' for ticket '{ticket_id}'. Allowed transitions: {sorted(allowed)}",
            current_state=curr,
            target_state=nxt,
        )
