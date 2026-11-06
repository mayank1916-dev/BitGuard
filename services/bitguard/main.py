"""BitGuard Firewall Service entrypoint."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel

from backend.app.main import create_app as create_legacy_api_app
from services.bitguard.approvals.models import (
    ApproveHoldRequest,
    ApproveHoldResponse,
    DenyHoldRequest,
    DenyHoldResponse,
    HoldViewResponse,
    WebAuthnAssertion,
)
from services.bitguard.approvals.worker import hold_expiry_worker
from services.bitguard.audit.models import (
    AnchorRecordModel,
    AuditEntryModel,
    AuditVerifyResponse,
    ManualAnchorResponse,
)
from services.bitguard.auth.models import (
    OIDCLoginRequest,
    OIDCLoginResponse,
    WebAuthnAuthenticateOptionsRequest,
    WebAuthnAuthenticateOptionsResponse,
    WebAuthnAuthenticateVerifyRequest,
    WebAuthnAuthenticateVerifyResponse,
    WebAuthnCredentialSummary,
    WebAuthnRegisterOptionsResponse,
    WebAuthnRegisterVerifyRequest,
    WebAuthnRegisterVerifyResponse,
)
from services.bitguard.breaker.models import (
    BreakerStatusResponse,
    DeescalateApprovalResult,
    DeescalateApproveRequest,
    DeescalateRequestCreate,
    DeescalationRequestModel,
    EscalateRequest,
)
from services.bitguard.config import settings
from services.bitguard.gateway.models import (
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    SignTransactionParams,
    SignTransactionResult,
)
from services.bitguard.gateway.router import router as gateway_router
from services.bitguard.incidents.models import (
    AcknowledgeIncidentRequest,
    ApproveIncidentStepRequest,
    ChecklistItem,
    Incident,
    IncidentApproval,
    Runbook,
    RunbookStep,
    TickChecklistRequest,
    TimelineEvent,
    TriggerRunbookRequest,
)
from services.bitguard.logging import setup_json_logging
from services.bitguard.models import (
    Approval,
    AuditEntry,
    CancelHoldRequest,
    CancelHoldResponse,
    CreateWatchedAddressRequest,
    DailyGroupMetrics,
    DecodedTx,
    DevLoginRequest,
    DevLoginResponse,
    FalsePositiveRequest,
    HoldTicket,
    PolicyConfig,
    PolicyVersion,
    PromotionCheckItem,
    PromotionChecklistResponse,
    UpdateWatchedAddressRequest,
    UserResponse,
    WalletGroupConfig,
    WalletGroupModeUpdate,
    WatchedAddress,
    WatcherAlert,
)
from services.bitguard.policy.models import (
    ActivatePolicyRequest,
    ApprovePolicyRequest,
    LimitsPolicy,
    PolicyApproval,
    PolicyDocument,
    PolicyIntegrityResponse,
    ProposePolicyRequest,
    RollbackPolicyRequest,
    ThresholdsPolicy,
    TimeLockPolicy,
    WalletGroupPolicy,
)
from services.bitguard.stream.broadcaster import stream_broadcaster
from services.bitguard.timelock.store import TimelockItem
from services.bitguard.v1.router import CancelTimelockRequest
from services.bitguard.v1.router import router as v1_router

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
    stream_broadcaster.start_ticker()
    hold_expiry_worker.start()
    yield
    hold_expiry_worker.stop()
    stream_broadcaster.stop_ticker()
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

    # Include V1 canonical API routes
    app.include_router(v1_router, prefix="/v1")
    app.include_router(v1_router, prefix="/api/v1")

    # Include JSON-RPC 2.0 Gateway routes (Milestone S12)
    app.include_router(gateway_router)

    # Custom OpenAPI schema hook guaranteeing all canonical data models are documented
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schemas = openapi_schema.setdefault("components", {}).setdefault("schemas", {})
        canonical_models: list[type[BaseModel]] = [
            Approval,
            ApproveHoldRequest,
            ApproveHoldResponse,
            AuditEntry,
            BreakerStatusResponse,
            CancelHoldRequest,
            CancelHoldResponse,
            CreateWatchedAddressRequest,
            DailyGroupMetrics,
            DecodedTx,
            DeescalateApprovalResult,
            DeescalateApproveRequest,
            DeescalateRequestCreate,
            DeescalationRequestModel,
            DenyHoldRequest,
            DenyHoldResponse,
            DevLoginRequest,
            DevLoginResponse,
            EscalateRequest,
            AnchorRecordModel,
            AuditEntryModel,
            AuditVerifyResponse,
            ManualAnchorResponse,
            FalsePositiveRequest,
            HoldTicket,
            HoldViewResponse,
            PolicyConfig,
            PolicyVersion,
            PromotionCheckItem,
            PromotionChecklistResponse,
            UpdateWatchedAddressRequest,
            UserResponse,
            WalletGroupConfig,
            WalletGroupModeUpdate,
            WatchedAddress,
            WatcherAlert,
            WebAuthnAssertion,
            JsonRpcRequest,
            JsonRpcResponse,
            JsonRpcError,
            SignTransactionParams,
            SignTransactionResult,
            TimelockItem,
            CancelTimelockRequest,
            OIDCLoginRequest,
            OIDCLoginResponse,
            WebAuthnAuthenticateOptionsRequest,
            WebAuthnAuthenticateOptionsResponse,
            WebAuthnAuthenticateVerifyRequest,
            WebAuthnAuthenticateVerifyResponse,
            WebAuthnCredentialSummary,
            WebAuthnRegisterOptionsResponse,
            WebAuthnRegisterVerifyRequest,
            WebAuthnRegisterVerifyResponse,
            Incident,
            Runbook,
            RunbookStep,
            TimelineEvent,
            ChecklistItem,
            IncidentApproval,
            TickChecklistRequest,
            AcknowledgeIncidentRequest,
            TriggerRunbookRequest,
            ApproveIncidentStepRequest,
            PolicyDocument,
            LimitsPolicy,
            ThresholdsPolicy,
            WalletGroupPolicy,
            TimeLockPolicy,
            PolicyApproval,
            ProposePolicyRequest,
            ApprovePolicyRequest,
            ActivatePolicyRequest,
            RollbackPolicyRequest,
            PolicyIntegrityResponse,
        ]
        for model_cls in canonical_models:
            model_schema = model_cls.model_json_schema(ref_template="#/components/schemas/{model}")
            defs = model_schema.pop("$defs", {})
            for def_name, def_schema in defs.items():
                schemas[def_name] = def_schema
            schemas[model_cls.__name__] = model_schema

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi  # type: ignore[method-assign]

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
