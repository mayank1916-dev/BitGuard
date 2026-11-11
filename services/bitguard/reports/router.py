"""FastAPI Router for Compliance and Audit Reports (Milestone S35 / F20).

Enforces Compliance role access via RBAC (Permission.READ_REPORTS) and serves:
1. /v1/reports/incident/{incident_id} (PDF, CSV, JSON)
2. /v1/reports/monthly (PDF, CSV, JSON)
3. /v1/reports/policy-history (PDF, CSV, JSON)
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from services.bitguard.database import get_db
from services.bitguard.models import Permission, UserResponse
from services.bitguard.rbac import require_permission
from services.bitguard.reports.generator import report_generator
from services.bitguard.reports.models import (
    IncidentPostMortemData,
    MonthlyControlReportData,
    PolicyChangeHistoryData,
    ReportFormat,
)

router = APIRouter(prefix="/reports", tags=["Compliance Reports"])


@router.get(
    "/incident/{incident_id}",
    summary="Export Incident Post-Mortem Report",
    description="Generates an executive post-mortem report (PDF or CSV) with timeline, containment metrics, and audit-chain stamp.",
    responses={
        200: {
            "content": {
                "application/pdf": {},
                "text/csv": {},
                "application/json": {},
            },
            "description": "Generated incident post-mortem report.",
        },
        403: {"description": "Access denied: Compliance role permission required."},
        404: {"description": "Incident not found."},
    },
)
def get_incident_post_mortem_report(
    incident_id: str,
    format: ReportFormat = Query(default=ReportFormat.PDF, description="Report output format: pdf, csv, or json"),
    session: Session = Depends(get_db),
    _user: UserResponse = Depends(require_permission(Permission.READ_REPORTS)),
) -> Any:
    """Exports an incident post-mortem report stamped with audit chain verification."""
    try:
        data: IncidentPostMortemData = report_generator.get_incident_post_mortem_data(
            incident_id=incident_id,
            session=session,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    if format == ReportFormat.CSV:
        csv_content = report_generator.render_incident_post_mortem_csv(data)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}-postmortem.csv"'},
        )
    elif format == ReportFormat.PDF:
        pdf_content = report_generator.render_incident_post_mortem_pdf(data)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}-postmortem.pdf"'},
        )
    else:
        return data.model_dump()


@router.get(
    "/monthly",
    summary="Export Monthly Control and Decision Report",
    description="Generates monthly control report with decision counts by verdict, holds, false-positive rate, and breaker history.",
    responses={
        200: {
            "content": {
                "application/pdf": {},
                "text/csv": {},
                "application/json": {},
            },
            "description": "Generated monthly control report.",
        },
        403: {"description": "Access denied: Compliance role permission required."},
    },
)
def get_monthly_control_report(
    year: int = Query(default=2026, description="Report calendar year"),
    month: int = Query(default=11, ge=1, le=12, description="Report calendar month (1-12)"),
    format: ReportFormat = Query(default=ReportFormat.PDF, description="Report output format: pdf, csv, or json"),
    session: Session = Depends(get_db),
    _user: UserResponse = Depends(require_permission(Permission.READ_REPORTS)),
) -> Any:
    """Exports monthly control report stamped with cryptographic audit chain verification."""
    data: MonthlyControlReportData = report_generator.get_monthly_control_data(
        year=year,
        month=month,
        session=session,
    )

    if format == ReportFormat.CSV:
        csv_content = report_generator.render_monthly_control_csv(data)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="control-report-{year:04d}-{month:02d}.csv"'},
        )
    elif format == ReportFormat.PDF:
        pdf_content = report_generator.render_monthly_control_pdf(data)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="control-report-{year:04d}-{month:02d}.pdf"'},
        )
    else:
        return data.model_dump()


@router.get(
    "/policy-history",
    summary="Export Policy Change and Approval History",
    description="Generates policy change history report with version diffs, approvers, cool-down, and backtest reports.",
    responses={
        200: {
            "content": {
                "application/pdf": {},
                "text/csv": {},
                "application/json": {},
            },
            "description": "Generated policy change history report.",
        },
        403: {"description": "Access denied: Compliance role permission required."},
    },
)
def get_policy_change_history_report(
    version: str | None = Query(default=None, description="Optional policy version filter"),
    format: ReportFormat = Query(default=ReportFormat.PDF, description="Report output format: pdf, csv, or json"),
    session: Session = Depends(get_db),
    _user: UserResponse = Depends(require_permission(Permission.READ_REPORTS)),
) -> Any:
    """Exports policy version change history and dual-control approval records."""
    data: PolicyChangeHistoryData = report_generator.get_policy_change_history_data(
        session=session,
        version=version,
    )

    if format == ReportFormat.CSV:
        csv_content = report_generator.render_policy_change_history_csv(data)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="policy-change-history.csv"'},
        )
    elif format == ReportFormat.PDF:
        pdf_content = report_generator.render_policy_change_history_pdf(data)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="policy-change-history.pdf"'},
        )
    else:
        return data.model_dump()
