"""Centralized separation-of-duties enforcement engine (Milestone S15 / F9 / Invariant #6).

Invariants:
- Invariant #6: Asymmetric Policy Evolution & Quorum. A requester cannot approve their own
  request; a policy author cannot approve their own change; quorum approvals require
  two distinct human approvers with distinct identities and, where configured, distinct roles.
"""

import logging
from typing import Any

from fastapi import HTTPException, status

logger = logging.getLogger("bitguard.auth.separation")


class SeparationOfDutiesError(HTTPException):
    """Raised when a dual-control or self-approval invariant is violated."""

    def __init__(self, detail: str, status_code: int = status.HTTP_403_FORBIDDEN) -> None:
        super().__init__(
            status_code=status_code,
            detail=detail,
        )


class SeparationOfDutiesService:
    """Centralized enforcement of dual-control, maker-checker, and quorum separation rules."""

    @staticmethod
    def enforce_requester_cannot_approve(
        requester_id: str | None,
        approver_id: str | None,
    ) -> None:
        """Enforces that a transaction requester cannot approve their own hold ticket."""
        if requester_id and approver_id and requester_id.strip() == approver_id.strip():
            logger.warning(
                "Separation of duties violation: requester %s attempted to approve own request",
                requester_id,
            )
            raise SeparationOfDutiesError(
                "REQUESTER_CANNOT_APPROVE: Requester cannot approve their own quarantine hold request",
                status_code=status.HTTP_403_FORBIDDEN,
            )

    @staticmethod
    def enforce_policy_author_cannot_approve(
        author_id: str | None,
        approver_id: str | None,
    ) -> None:
        """Enforces that a policy author cannot approve or loosen their own policy manifest."""
        if author_id and approver_id and author_id.strip() == approver_id.strip():
            logger.warning(
                "Separation of duties violation: policy author %s attempted to approve own change",
                author_id,
            )
            raise SeparationOfDutiesError(
                "POLICY_AUTHOR_CANNOT_APPROVE: Policy author cannot approve their own policy change",
                status_code=status.HTTP_403_FORBIDDEN,
            )

    @staticmethod
    def enforce_quorum_approvers_distinct(
        approver1_id: str,
        approver2_id: str,
        approver1_role: str | None = None,
        approver2_role: str | None = None,
        require_different_roles: bool = False,
    ) -> None:
        """Enforces that two approvers in a quorum have distinct user IDs and (if configured) distinct roles."""
        if approver1_id.strip() == approver2_id.strip():
            logger.warning(
                "Separation of duties violation: duplicate approver ID %s in quorum",
                approver1_id,
            )
            raise SeparationOfDutiesError(
                f"DUPLICATE_APPROVER: Approver '{approver1_id}' has already approved this ticket",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        if require_different_roles and approver1_role and approver2_role:
            if approver1_role.strip().lower() == approver2_role.strip().lower():
                logger.warning(
                    "Separation of duties violation: quorum requires distinct roles, but both approvers hold '%s'",
                    approver1_role,
                )
                raise SeparationOfDutiesError(
                    f"DIFFERENT_ROLES_REQUIRED: Quorum approvers must have different roles, but both hold role '{approver1_role}'",
                    status_code=status.HTTP_403_FORBIDDEN,
                )

    @staticmethod
    def validate_hold_ticket_approvals(
        requester_id: str | None,
        new_approver_id: str,
        existing_approvals: list[Any],
        new_approver_role: str | None = None,
        require_different_roles: bool = False,
    ) -> None:
        """Validates hold approval against requester self-approval and existing approvals in ticket."""
        # 1. Requester cannot approve
        SeparationOfDutiesService.enforce_requester_cannot_approve(
            requester_id=requester_id,
            approver_id=new_approver_id,
        )

        # 2. Cannot approve twice
        for existing in existing_approvals:
            raw_id = (
                existing.approver_id
                if hasattr(existing, "approver_id")
                else (existing.get("approver_id") if isinstance(existing, dict) else str(existing))
            )
            existing_id = str(raw_id or "")
            existing_role = (
                existing.approver_role
                if hasattr(existing, "approver_role")
                else (existing.get("approver_role") if isinstance(existing, dict) else None)
            )

            SeparationOfDutiesService.enforce_quorum_approvers_distinct(
                approver1_id=existing_id,
                approver2_id=new_approver_id,
                approver1_role=existing_role,
                approver2_role=new_approver_role,
                require_different_roles=require_different_roles,
            )


separation_of_duties = SeparationOfDutiesService()
