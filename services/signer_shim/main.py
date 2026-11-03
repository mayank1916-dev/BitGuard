"""Signer Shim Service (Enforcement Point).

Invariants:
- Holds the disposable testnet private key.
- Never directly accessible from host networks; deployed strictly on 'signer_internal'.
- Only signs when presented with valid, verified BitGuard approval tokens.
"""

from fastapi import FastAPI

from services.signer_shim.config import settings

app = FastAPI(
    title="BitGuard Signer Shim",
    description="Isolated signing enforcement point with testnet key custody",
    version="0.1.0",
)


@app.get("/healthz", tags=["Health"])
def healthz() -> dict[str, str]:
    """Health check endpoint for the signer shim service."""
    return {
        "status": "ok",
        "service": "signer_shim",
        "environment": settings.environment,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.signer_shim.main:app",
        host=settings.host,
        port=settings.port,
        reload=(settings.environment == "development"),
    )
