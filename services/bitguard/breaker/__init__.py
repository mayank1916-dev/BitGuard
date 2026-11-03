"""Circuit Breaker subsystem for BitGuard Firewall (Milestone S18 / F9, F14)."""

from services.bitguard.breaker.epoch_store import TokenEpochStore, token_epoch_store
from services.bitguard.breaker.key_hook import (
    KeyUsePolicyHook,
    MockKeyUsePolicyHook,
    key_policy_hook,
)
from services.bitguard.breaker.models import (
    BREAKER_STATE_RANKS,
    BreakerStateEnum,
    BreakerStatusResponse,
    DeescalateApprovalResult,
    DeescalateApproveRequest,
    DeescalateRequestCreate,
    DeescalationRequestModel,
    EscalateRequest,
)
from services.bitguard.breaker.router import router as breaker_router
from services.bitguard.breaker.store import (
    DistributedBreakerStore,
    distributed_breaker_store,
)
from services.bitguard.breaker.triggers import (
    BreakerTriggerManager,
    breaker_triggers,
)

__all__ = [
    "BREAKER_STATE_RANKS",
    "BreakerStateEnum",
    "BreakerStatusResponse",
    "BreakerTriggerManager",
    "DeescalateApprovalResult",
    "DeescalateApproveRequest",
    "DeescalateRequestCreate",
    "DeescalationRequestModel",
    "DistributedBreakerStore",
    "EscalateRequest",
    "KeyUsePolicyHook",
    "MockKeyUsePolicyHook",
    "TokenEpochStore",
    "breaker_router",
    "breaker_triggers",
    "distributed_breaker_store",
    "key_policy_hook",
    "token_epoch_store",
]
