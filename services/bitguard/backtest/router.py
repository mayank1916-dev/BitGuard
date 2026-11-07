"""API Router for Backtest operations (Milestone S22 / F8)."""

from typing import Any

from fastapi import APIRouter, HTTPException

from services.bitguard.backtest.models import (
    BacktestImportRequest,
    BacktestMeta,
    BacktestReport,
    BacktestRunResponse,
)
from services.bitguard.backtest.service import backtest_service

router = APIRouter(prefix="/backtests", tags=["Policy Backtesting & Replay Logs"])


@router.get("", response_model=list[BacktestMeta], summary="List available backtest datasets")
async def list_backtests() -> list[BacktestMeta]:
    """Returns metadata for all available historical and synthetic backtest datasets."""
    return backtest_service.list_backtests()


@router.post("", response_model=BacktestReport, summary="Import and execute historical backtest")
async def import_and_run_backtest(req: BacktestImportRequest) -> BacktestReport:
    """Imports historical signing requests (JSONL or CSV), overlays scenario patterns, runs isolated replay, and returns backtest report."""
    try:
        report = backtest_service.create_and_run_backtest(req)
        return report
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Backtest execution failed: {exc}") from exc


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


@router.get("/{id}", response_model=BacktestReport, summary="Get stored backtest report by ID")
async def get_backtest_report(id: str) -> BacktestReport:
    """Retrieves an existing backtest report by report ID."""
    report = backtest_service.get_report(id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Backtest report '{id}' not found")
    return report
