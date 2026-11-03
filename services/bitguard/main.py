"""BitGuard Firewall Service entrypoint."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.main import create_app as create_legacy_api_app
from services.bitguard.config import settings
from services.bitguard.logging import setup_json_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context for startup and shutdown events."""
    setup_json_logging(
        service_name=settings.service_name,
        log_level=settings.log_level,
    )
    logger.info(
        "BitGuard Firewall service starting up",
        extra={
            "environment": settings.environment,
            "port": settings.port,
            "signer_shim_url": settings.signer_shim_url,
        },
    )
    yield
    logger.info("BitGuard Firewall service shutting down")


def create_app() -> FastAPI:
    """Factory creating the BitGuard FastAPI application."""
    app = FastAPI(
        title="BitGuard Defensive Signing Firewall",
        description="Policy Decision Point for exchange hot wallets and custodial signing requests",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/healthz", tags=["Health"])
    def healthz() -> dict[str, str]:
        """Kubernetes / Docker health check probe."""
        return {
            "status": "ok",
            "service": "bitguard",
            "environment": settings.environment,
        }

    # Mount/include legacy lab & simulation routes for complete UI backwards compatibility
    legacy_app = create_legacy_api_app()
    app.mount("", legacy_app)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.bitguard.main:app",
        host=settings.host,
        port=settings.port,
        reload=(settings.environment == "development"),
    )
