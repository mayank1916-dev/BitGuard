"""Demo Custody Workload Service (Milestone S23 / F19).

Represents an automated exchange custody backend or withdrawal orchestration
workload communicating with the BitGuard Signing Gateway via mTLS JSON-RPC 2.0.
"""

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from lab.demo_custody.client import CustodyClientRpcError, DemoCustodyClient

app = FastAPI(
    title="BitGuard Demo Custody Workload",
    version="1.0.0",
    description="Simulated exchange custody withdrawal daemon",
)

BITGUARD_URL = os.getenv("DEMO_CUSTODY_BITGUARD_URL", "http://localhost:8000")
CUSTODY_SAN = os.getenv("DEMO_CUSTODY_SAN", "spiffe://exchange.internal/workload/custody")

client = DemoCustodyClient(
    base_url=BITGUARD_URL,
    san=CUSTODY_SAN,
)


class WithdrawalRequest(BaseModel):
    chain: str = Field(default="ethereum")
    raw_tx: str = Field(description="Hex-encoded unsigned transaction payload")
    intent_id: str | None = Field(default=None, description="Pre-approved ledger intent ID")
    amount_usd: float | None = Field(default=None, description="USD equivalent for rate limits")
    wallet_group: str | None = Field(default=None, description="Target wallet group")
    metadata: dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz")
def health_check() -> dict[str, str]:
    """Liveness probe for docker-compose and monitoring."""
    return {"status": "ok", "service": "demo_custody"}


@app.post("/submit-withdrawal")
def submit_withdrawal(req: WithdrawalRequest) -> dict[str, Any]:
    """Submits a withdrawal transaction through BitGuard JSON-RPC gateway."""
    try:
        result = client.sign_transaction(
            chain=req.chain,
            raw_tx=req.raw_tx,
            intent_id=req.intent_id,
            amount_usd=req.amount_usd,
            wallet_group=req.wallet_group,
            metadata=req.metadata,
        )
        return {"status": "SUCCESS", "result": result}
    except CustodyClientRpcError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": exc.code,
                "message": exc.message,
                "data": exc.data,
            },
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
