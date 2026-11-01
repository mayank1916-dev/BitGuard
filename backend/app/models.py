from typing import Optional, Any
from pydantic import BaseModel, Field


class SigningRequest(BaseModel):
    """
    Represents an incoming transaction signing request to be evaluated
    by the BitGuard firewall before an exchange hot wallet signs it.
    """
    id: str
    ts: float
    chain: str
    wallet: str
    kind: str  # 'transfer' | 'contract_call' | 'authorization_7702'
    asset: str
    amount_usd: float
    to: Optional[str] = None
    delegate: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    """
    Evaluation decision returned by BitGuard.
    """
    request_id: str
    action: str  # 'allow' | 'hold' | 'deny'
    risk: int = Field(ge=0, le=100)
    reasons: list[dict[str, Any]] = Field(default_factory=list)
    breaker_state: str
