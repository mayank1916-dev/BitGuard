"""Tamper-evident hash-chained audit ledger service for BitGuard (Invariant #7).

Canonical implementation is located in services.bitguard.audit.
This module re-exports the canonical audit service for backwards compatibility.
"""

from services.bitguard.audit.service import (
    AuditChainService,
    audit_service,
)
from services.bitguard.audit.service import (
    AuditChainService as AuditService,
)

__all__ = ["AuditChainService", "AuditService", "audit_service"]
