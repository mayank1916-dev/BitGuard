"""Exceptions for quarantine hold ticket state transitions and approvals (Milestone S14)."""


class QuarantineError(Exception):
    """Base exception for quarantine and hold errors."""


class InvalidHoldStateTransitionError(QuarantineError):
    """Raised when an invalid state transition or terminal state modification is attempted."""

    def __init__(self, message: str, current_state: str | None = None, target_state: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.current_state = current_state
        self.target_state = target_state


class TicketAlreadyReleasedError(QuarantineError):
    """Raised when a ticket is already released or produces a duplicate approval token."""

    def __init__(self, message: str, ticket_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.ticket_id = ticket_id


class HoldTicketNotFoundError(QuarantineError):
    """Raised when a requested hold ticket does not exist."""

    def __init__(self, message: str, ticket_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.ticket_id = ticket_id


class HoldTicketExpiredError(QuarantineError):
    """Raised when an operation is attempted on an expired hold ticket."""

    def __init__(self, message: str, ticket_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.ticket_id = ticket_id
