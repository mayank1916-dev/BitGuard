"""API router for hot wallet balance tracking and exposure reduction (Milestone S29 / F11).

Invariants:
- Invariant #8: Explicit Data Provenance. Values returned are explicitly labelled REAL or REPORTED.
- Invariant #11: Strict Wording & Claims: 'reduces and contains unauthorized transaction signing'.
"""

from fastapi import APIRouter, Depends, Query

from services.bitguard.exposure.models import ExposureSummaryResponse
from services.bitguard.exposure.poller import exposure_service
from services.bitguard.models import DataLabel, Permission, UserResponse
from services.bitguard.rbac import require_permission

router = APIRouter(tags=["Exposure Reduction (F11)"])


@router.get(
    "/exposure",
    response_model=ExposureSummaryResponse,
    summary="Get hot wallet exposure, caps, headroom, and exposure at risk",
    description=(
        "Returns per-wallet on-chain balances, balance caps, headroom, and aggregate exposure at risk. "
        "Every numeric metric is explicitly labelled REAL or REPORTED per Invariant #8."
    ),
)
def get_exposure(
    data_label: DataLabel = Query(
        default=DataLabel.REAL,
        description="Explicit data provenance label (REAL or REPORTED)",
    ),
    current_user: UserResponse = Depends(require_permission(Permission.READ_METRICS)),
) -> ExposureSummaryResponse:
    """Returns the comprehensive hot wallet exposure telemetry snapshot."""
    return exposure_service.get_exposure_summary(data_label=data_label)
