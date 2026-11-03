"""Ledger Mock Service.

Provides withdrawal intent reconciliation records against core exchange databases.
For now, exposes /healthz endpoint.
"""

from fastapi import FastAPI

from services.ledger_mock.config import settings

app = FastAPI(
    title="BitGuard Ledger Mock",
    description="Mock database for withdrawal intent reconciliation",
    version="0.1.0",
)


@app.get("/healthz", tags=["Health"])
def healthz() -> dict[str, str]:
    """Health check endpoint for the ledger mock service."""
    return {
        "status": "ok",
        "service": "ledger_mock",
        "environment": settings.environment,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.ledger_mock.main:app",
        host=settings.host,
        port=settings.port,
        reload=(settings.environment == "development"),
    )
