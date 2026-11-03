"""BitGuard Quorum Approvals and Quarantine Holds module (Milestone S16 / F10)."""

from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.approvals.models import (
    ApproveHoldRequest,
    ApproveHoldResponse,
    DenyHoldRequest,
    DenyHoldResponse,
    HoldViewResponse,
    WebAuthnAssertion,
)
from services.bitguard.approvals.notifiers import (
    CompositeNotifier,
    PagerDutyNotifier,
    SlackNotifier,
    TelegramNotifier,
    notifier,
)
from services.bitguard.approvals.router import router
from services.bitguard.approvals.service import approval_service
from services.bitguard.approvals.webauthn import (
    ApproverKeyRegistry,
    WebAuthnVerificationError,
    WebAuthnVerifier,
    approver_registry,
    create_test_webauthn_assertion,
    webauthn_verifier,
)

__all__ = [
    "ApproveHoldRequest",
    "ApproveHoldResponse",
    "ApproverKeyRegistry",
    "CompositeNotifier",
    "DenyHoldRequest",
    "DenyHoldResponse",
    "HoldViewResponse",
    "PagerDutyNotifier",
    "SlackNotifier",
    "TelegramNotifier",
    "WebAuthnAssertion",
    "WebAuthnVerificationError",
    "WebAuthnVerifier",
    "approval_service",
    "approver_registry",
    "create_test_webauthn_assertion",
    "hold_store",
    "notifier",
    "router",
    "webauthn_verifier",
]
