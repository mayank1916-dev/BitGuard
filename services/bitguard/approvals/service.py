"""Quorum approval service orchestrating WebAuthn assertions, quorum enforcement, and signer release (Milestone S16 / F10).

Invariants:
- Invariant #1: Key Isolation (BitGuard never holds signing keys; calls signer shim).
- Invariant #2: Approval Binding & Verification (one-time Ed25519 token bound to digest).
- Invariant #3: Fail-Closed Default (unknown, expired, or invalid assertion fails closed).
- Invariant #4: Raw Byte Source of Truth (recomputes decoded tx from raw transaction bytes).
- Invariant #5: WebAuthn Hardware Approvals (approvals are WebAuthn signatures over tx digest).
- Invariant #6: Asymmetric Policy Evolution (deny = 1 approver instant; approval = quorum of 2 distinct approvers).
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

import logging
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, status

from services.bitguard.approvals.exceptions import TicketAlreadyReleasedError
from services.bitguard.approvals.hold_store import hold_store
from services.bitguard.approvals.models import (
    ApproveHoldResponse,
    DenyHoldResponse,
    HoldViewResponse,
    WebAuthnAssertion,
)
from services.bitguard.approvals.state_machine import TERMINAL_STATES
from services.bitguard.approvals.webauthn import (
    WebAuthnVerificationError,
    webauthn_verifier,
)
from services.bitguard.audit_service import audit_service
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.gateway.client_shim import SignerShimClient, signer_shim_client
from services.bitguard.limits.store import limit_store
from services.bitguard.models import (
    Approval,
    CancelHoldResponse,
    DecodedTx,
    HoldTicket,
    UserResponse,
)
from services.bitguard.stream.broadcaster import stream_broadcaster
from services.bitguard.tokens.manager import token_manager

logger = logging.getLogger("bitguard.approvals.service")


class QuorumApprovalService:
    """Core domain service managing quarantine hold tickets and WebAuthn quorum approvals."""

    def __init__(
        self,
        shim_client: SignerShimClient | None = None,
        required_quorum: int = 2,
    ) -> None:
        self.shim_client = shim_client or signer_shim_client
        self.required_quorum = required_quorum

    def view_hold(self, hold_id: str) -> HoldViewResponse:
        """Retrieves hold ticket and re-decodes ground truth directly from raw bytes."""
        ticket = hold_store.get(hold_id)
        if ticket is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Hold ticket '{hold_id}' not found",
            )

        now = datetime.now(UTC)
        seconds_remaining = max(0, int((ticket.expires_at - now).total_seconds()))
        is_expired = seconds_remaining <= 0

        if is_expired and ticket.status == "PENDING":
            hold_store.update_status(ticket.id, "EXPIRED")
            ticket.status = "EXPIRED"

        # Invariant #4: Recompute decoded transaction from raw bytes
        decoded_tx: DecodedTx | None = None
        if ticket.raw_tx:
            try:
                raw_bytes = bytes.fromhex(ticket.raw_tx.removeprefix("0x"))
                decoded_tx = evm_decoder.decode(raw_bytes)
            except Exception as exc:
                logger.warning("failed_decoding_raw_tx_bytes_in_view: %s", exc)

        return HoldViewResponse(
            hold_id=ticket.id,
            request_id=ticket.request_id,
            status=ticket.status,
            tx_digest=ticket.tx_digest,
            raw_tx=ticket.raw_tx or "",
            chain=ticket.chain,
            wallet=ticket.wallet,
            amount_usd=ticket.amount_usd,
            requester_id=ticket.requester_id,
            risk_score=ticket.risk_score,
            reasons=ticket.reasons,
            decoded_tx=decoded_tx,
            seconds_remaining=seconds_remaining,
            is_expired=is_expired,
            approvals=ticket.approvals,
            signed_result=ticket.signed_result,
            data_label=ticket.data_label,
        )

    async def approve_hold(
        self,
        hold_id: str,
        approver_user: UserResponse,
        assertion: WebAuthnAssertion,
    ) -> ApproveHoldResponse:
        """Processes an approver's WebAuthn assertion; releases when quorum is reached."""
        ticket = hold_store.get(hold_id)
        if ticket is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Hold ticket '{hold_id}' not found",
            )

        now = datetime.now(UTC)

        # 1. State validation
        if ticket.status != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Hold ticket '{hold_id}' cannot be approved: current status is {ticket.status}",
            )

        # 2. Expiration validation
        if now >= ticket.expires_at:
            hold_store.update_status(ticket.id, "EXPIRED")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="HOLD_EXPIRED: Hold ticket expiration window has elapsed and cannot be approved",
            )

        # 3. Separation of duties: requester cannot approve own request
        if ticket.requester_id and approver_user.id == ticket.requester_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="REQUESTER_CANNOT_APPROVE: Requester cannot approve their own quarantine hold request",
            )

        # 4. Quorum validation: same approver cannot approve twice
        if any(a.approver_id == approver_user.id for a in ticket.approvals):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"DUPLICATE_APPROVER: Approver '{approver_user.id}' has already approved this ticket",
            )

        # 5. Invariant #5: WebAuthn cryptographic verification over tx digest
        try:
            webauthn_verifier.verify_assertion(
                assertion=assertion,
                expected_digest=ticket.tx_digest,
                approver_id=approver_user.id,
            )
        except WebAuthnVerificationError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{exc.code}: {exc.detail}",
            ) from exc

        # 6. Record approval
        approval_id = f"appr-{uuid.uuid4().hex[:12]}"
        role_str = (
            approver_user.role.value
            if hasattr(approver_user.role, "value")
            else str(approver_user.role)
        )
        approval = Approval(
            id=approval_id,
            hold_ticket_id=ticket.id,
            approver_id=approver_user.id,
            approver_role=role_str,
            tx_digest=ticket.tx_digest,
            webauthn_signature=assertion.signature,
            assertion_data=assertion.model_dump(),
            created_at=now,
        )
        ticket = hold_store.add_approval(ticket.id, approval) or ticket

        # 7. Check Quorum (Invariant #6: Quorum of 2 distinct approvers)
        if len(ticket.approvals) >= self.required_quorum:
            # QUORUM REACHED: Release transaction through signer shim
            return await self._release_approved_transaction(ticket)

        # Pending Quorum (e.g. 1 of 2 recorded)
        audit_service.append_entry(
            event_type="APPROVAL_RECORDED",
            request_id=ticket.request_id,
            verdict="HOLD",
            data_label=ticket.data_label,
        )
        return ApproveHoldResponse(
            status="PENDING_QUORUM",
            hold_id=ticket.id,
            request_id=ticket.request_id,
            approvals_count=len(ticket.approvals),
            required_approvals=self.required_quorum,
            signature=None,
            tx_hash=None,
            message=f"{len(ticket.approvals)} of {self.required_quorum} approvals recorded. Quorum pending.",
            data_label=ticket.data_label,
        )

    async def _release_approved_transaction(self, ticket: HoldTicket) -> ApproveHoldResponse:
        """Re-decodes, issues one-time approval token, signs via shim, and commits limit."""
        if not ticket.raw_tx:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Missing raw transaction bytes on quarantined ticket",
            )

        # Invariant #4: Re-decode directly from raw bytes
        raw_bytes = bytes.fromhex(ticket.raw_tx.removeprefix("0x"))
        decoded_tx = evm_decoder.decode(raw_bytes)

        # Invariant #2: Issue one-time Ed25519 approval token (60 s TTL)
        token_str = token_manager.issue(
            decoded_tx=decoded_tx,
            wallet=ticket.wallet or decoded_tx.from_address,
            chain=ticket.chain,
        )

        # Call Signer Shim enforcement point (Invariant #1: Key Isolation)
        try:
            shim_res = await self.shim_client.sign(
                raw_tx_bytes=ticket.raw_tx,
                token=token_str,
                wallet=ticket.wallet,
                chain=ticket.chain,
            )
        except Exception as exc:
            logger.error("signer_shim_release_failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Signer shim rejected or failed signing: {exc}",
            ) from exc

        # Commit limit reservation if present
        if ticket.reservation_id:
            try:
                limit_store.commit(ticket.reservation_id)
            except Exception as exc:
                logger.warning("failed_committing_limit_reservation: %s", exc)

        # Mark ticket RELEASED with single-use guarantee (SELECT ... FOR UPDATE)
        try:
            hold_store.atomic_release(ticket.id, actor="system", signed_result=shim_res)
            ticket.state = "RELEASED"
            ticket.status = "RELEASED"
            ticket.signed_result = shim_res
        except TicketAlreadyReleasedError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"TICKET_ALREADY_RELEASED: {exc.message}",
            ) from exc

        # Invariant #7: Audit log entries
        audit_service.append_entry(
            event_type="APPROVAL_QUORUM_REACHED",
            request_id=ticket.request_id,
            verdict="ALLOW",
            data_label=ticket.data_label,
        )
        audit_service.append_entry(
            event_type="TRANSACTION_SIGNED",
            request_id=ticket.request_id,
            verdict="ALLOW",
            data_label=ticket.data_label,
        )

        return ApproveHoldResponse(
            status="RELEASED",
            hold_id=ticket.id,
            request_id=ticket.request_id,
            approvals_count=len(ticket.approvals),
            required_approvals=self.required_quorum,
            signature=shim_res.get("signature"),
            tx_hash=shim_res.get("tx_hash"),
            message="Quorum reached (2 of 2). One-time token issued and transaction signed by shim.",
            data_label=ticket.data_label,
        )

    def deny_hold(
        self,
        hold_id: str,
        approver_user: UserResponse,
        reason: str,
    ) -> DenyHoldResponse:
        """Invariant #6: Any single approver tightens immediately by denying the hold."""
        ticket = hold_store.get(hold_id)
        if ticket is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Hold ticket '{hold_id}' not found",
            )

        if ticket.status in ("APPROVED", "DENIED"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Ticket '{hold_id}' cannot be denied: already in status {ticket.status}",
            )

        # Release limit reservation
        if ticket.reservation_id:
            try:
                limit_store.release(ticket.reservation_id)
            except Exception as exc:
                logger.warning("failed_releasing_limit_reservation: %s", exc)

        hold_store.update_status(ticket.id, "DENIED")
        ticket.status = "DENIED"

        audit_service.append_entry(
            event_type="HOLD_DENIED",
            request_id=ticket.request_id,
            verdict="DENY",
            data_label=ticket.data_label,
        )

        data_label_val = (
            ticket.data_label.value
            if hasattr(ticket.data_label, "value")
            else str(ticket.data_label)
        )
        stream_broadcaster.publish_event(
            event_type="HOLD_DENIED",
            payload={
                "hold_id": ticket.id,
                "request_id": ticket.request_id,
                "denied_by": approver_user.id,
                "reason": reason,
            },
            data_label=data_label_val,
        )

        return DenyHoldResponse(
            status="DENIED",
            hold_id=ticket.id,
            reason=reason,
            data_label=ticket.data_label,
        )


    def cancel_hold(
        self,
        hold_id: str,
        cancelled_by_user: UserResponse,
        reason: str = "Cancelled by authorized operator",
    ) -> CancelHoldResponse:
        """Invariant #6: Operator or SecOps cancels and tightens immediately."""
        ticket = hold_store.get(hold_id)
        if ticket is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Hold ticket '{hold_id}' not found",
            )

        if ticket.state in TERMINAL_STATES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Hold ticket '{hold_id}' cannot be cancelled: already in terminal state {ticket.state}",
            )

        # Release limit reservation if present
        if ticket.reservation_id:
            try:
                limit_store.release(ticket.reservation_id)
            except Exception as exc:
                logger.warning("failed_releasing_limit_reservation_on_cancel: %s", exc)

        hold_store.transition_state(
            ticket_id=ticket.id,
            new_state="CANCELLED",
            actor=cancelled_by_user.id,
            reason=reason,
        )

        return CancelHoldResponse(
            status="CANCELLED",
            state="CANCELLED",
            hold_id=ticket.id,
            cancelled_by=cancelled_by_user.id,
            reason=reason,
            data_label=ticket.data_label,
        )


approval_service = QuorumApprovalService()
