"""API Router for Backtest operations (Milestone S22 / U3)."""

from typing import Any

from fastapi import APIRouter, HTTPException

from services.bitguard.backtest.models import BacktestMeta, BacktestRunResponse
from services.bitguard.backtest.service import backtest_service

router = APIRouter(prefix="/backtests", tags=["Policy Backtesting & Replay Logs"])


@router.get("", response_model=list[BacktestMeta], summary="List available backtest datasets")
async def list_backtests() -> list[BacktestMeta]:
    """Returns metadata for all available historical and synthetic backtest datasets."""
    return backtest_service.list_backtests()


@router.get("/{backtest_id}/events", summary="Get raw events for a backtest dataset")
async def get_backtest_events(backtest_id: str) -> list[dict[str, Any]]:
    """Returns the raw signing request events from the specified backtest dataset."""
    events = backtest_service.get_backtest_events(backtest_id)
    result = []
    for e in events:
        d = e.model_dump(mode="json")
        if "metadata" in d and isinstance(d["metadata"], dict):
            for k, v in d["metadata"].items():
                if k not in d:
                    d[k] = v
        result.append(d)
    return result


@router.post("/{backtest_id}/run", response_model=BacktestRunResponse, summary="Stream backtest through real engine")
async def run_backtest(backtest_id: str) -> BacktestRunResponse:
    """Streams a backtest dataset through the real policy engine, returning real decisions and replay steps."""
    valid_ids = [b.id for b in backtest_service.list_backtests()]
    if backtest_id not in valid_ids:
        raise HTTPException(status_code=404, detail=f"Backtest dataset '{backtest_id}' not found")

    return backtest_service.run_backtest(backtest_id)
