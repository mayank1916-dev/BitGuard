"""Ledger Mock Service.

Provides withdrawal intent reconciliation records against core exchange databases.
Endpoints for creating, approving, consuming, and inspecting intents (test use only).
"""

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from services.ledger_mock.config import settings
from services.ledger_mock.database import get_db, init_db
from services.ledger_mock.models import (
    IntentStatus,
    WithdrawalIntentCreate,
    WithdrawalIntentDB,
    WithdrawalIntentResponse,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup lifespan hook to initialize database tables."""
    init_db()
    yield


app = FastAPI(
    title="BitGuard Ledger Mock",
    description="Mock custodial database for withdrawal intent reconciliation (test use only)",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/healthz", tags=["Health"])
def healthz() -> dict[str, str]:
    """Health check endpoint for the ledger mock service."""
    return {
        "status": "ok",
        "service": "ledger_mock",
        "environment": settings.environment,
    }


@app.post(
    "/intents",
    response_model=WithdrawalIntentResponse,
    status_code=201,
    tags=["Withdrawal Intents"],
    summary="Create withdrawal intent",
)
def create_intent(
    payload: WithdrawalIntentCreate,
    db: Session = Depends(get_db),
) -> WithdrawalIntentResponse:
    """Creates a new withdrawal intent in the mock ledger."""
    intent_id = payload.id or f"intent-{uuid.uuid4().hex[:12]}"
    existing = db.get(WithdrawalIntentDB, intent_id)
    if existing:
        raise HTTPException(status_code=409, detail=f"Intent '{intent_id}' already exists")

    intent = WithdrawalIntentDB(
        id=intent_id,
        status=payload.status.value,
        chain=payload.chain,
        asset=payload.asset,
        amount=payload.amount,
        destination=payload.destination,
        created_at=datetime.now(UTC),
    )
    db.add(intent)
    db.commit()
    db.refresh(intent)
    return WithdrawalIntentResponse.model_validate(intent)


@app.post(
    "/intents/{intent_id}/approve",
    response_model=WithdrawalIntentResponse,
    tags=["Withdrawal Intents"],
    summary="Approve withdrawal intent",
)
def approve_intent(
    intent_id: str,
    db: Session = Depends(get_db),
) -> WithdrawalIntentResponse:
    """Transitions a withdrawal intent to APPROVED status."""
    intent = db.get(WithdrawalIntentDB, intent_id)
    if not intent:
        raise HTTPException(status_code=404, detail=f"Intent '{intent_id}' not found")
    if intent.status == IntentStatus.PAID.value:
        raise HTTPException(status_code=400, detail="Cannot approve an already paid intent")
    if intent.status == IntentStatus.CANCELLED.value:
        raise HTTPException(status_code=400, detail="Cannot approve a cancelled intent")

    intent.status = IntentStatus.APPROVED.value
    db.commit()
    db.refresh(intent)
    return WithdrawalIntentResponse.model_validate(intent)


@app.post(
    "/intents/{intent_id}/consume",
    response_model=WithdrawalIntentResponse,
    tags=["Withdrawal Intents"],
    summary="Mark withdrawal intent consumed (PAID)",
)
def consume_intent(
    intent_id: str,
    db: Session = Depends(get_db),
) -> WithdrawalIntentResponse:
    """Marks an intent as consumed and transitions status to PAID."""
    intent = db.get(WithdrawalIntentDB, intent_id)
    if not intent:
        raise HTTPException(status_code=404, detail=f"Intent '{intent_id}' not found")
    if intent.status == IntentStatus.PAID.value:
        raise HTTPException(status_code=409, detail="Intent has already been consumed / paid")

    intent.status = IntentStatus.PAID.value
    intent.consumed_at = datetime.now(UTC)
    db.commit()
    db.refresh(intent)
    return WithdrawalIntentResponse.model_validate(intent)


@app.get(
    "/intents/{intent_id}",
    response_model=WithdrawalIntentResponse,
    tags=["Withdrawal Intents"],
    summary="Get withdrawal intent by ID (read-only)",
)
def get_intent(
    intent_id: str,
    db: Session = Depends(get_db),
) -> WithdrawalIntentResponse:
    """Retrieves an intent by identifier (read-only)."""
    intent = db.get(WithdrawalIntentDB, intent_id)
    if not intent:
        raise HTTPException(status_code=404, detail=f"Intent '{intent_id}' not found")
    return WithdrawalIntentResponse.model_validate(intent)


@app.get(
    "/intents",
    response_model=list[WithdrawalIntentResponse],
    tags=["Withdrawal Intents"],
    summary="List withdrawal intents",
)
def list_intents(
    status: str | None = Query(default=None),
    chain: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[WithdrawalIntentResponse]:
    """Lists withdrawal intents with optional status and chain filters."""
    query = select(WithdrawalIntentDB)
    if status:
        query = query.where(WithdrawalIntentDB.status == status)
    if chain:
        query = query.where(WithdrawalIntentDB.chain == chain)
    query = query.offset(offset).limit(limit)

    results = db.execute(query).scalars().all()
    return [WithdrawalIntentResponse.model_validate(item) for item in results]


@app.delete(
    "/intents",
    status_code=204,
    tags=["Withdrawal Intents"],
    summary="Reset / clear all intents (test use only)",
)
def reset_intents(db: Session = Depends(get_db)) -> None:
    """Clears all intents from mock database."""
    db.query(WithdrawalIntentDB).delete()
    db.commit()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.ledger_mock.main:app",
        host=settings.host,
        port=settings.port,
        reload=(settings.environment == "development"),
    )
