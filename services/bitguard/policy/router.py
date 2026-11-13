"""FastAPI router for Versioned Policy Management (Milestone S20 / Section D).

Invariants:
- Invariant #6: Asymmetric Policy Evolution (tightening = single operator, instant; loosening = 2 WebAuthn approvers + cool-down + backtest report).
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

import difflib
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from services.bitguard.backtest.models import BacktestImportRequest, BacktestReport
from services.bitguard.config import settings
from services.bitguard.models import DataLabel, Role, UserResponse
from services.bitguard.policy.classifier import classify_change
from services.bitguard.policy.crypto import compute_content_hash
from services.bitguard.policy.models import (
    ActivatePolicyRequest,
    ApprovePolicyRequest,
    ChangeClassification,
    ClassifyPolicyRequest,
    ClassifyPolicyResponse,
    DraftBacktestRequest,
    PolicyDocument,
    PolicyIntegrityResponse,
    PolicyRequirements,
    PolicyStatus,
    PolicyVersion,
    ProposePolicyRequest,
    RollbackPolicyRequest,
)
from services.bitguard.policy.service import policy_service
from services.bitguard.policy.store import policy_store
from services.bitguard.rbac import get_current_user, require_role

logger = logging.getLogger("bitguard.policy.router")

router = APIRouter(tags=["Policy Management"])


def _normalize_draft_to_document(
    draft_input: dict[str, Any] | PolicyDocument,
    baseline_doc: PolicyDocument,
) -> PolicyDocument:
    """Normalizes raw slider values or dictionary overrides into a canonical PolicyDocument."""
    if isinstance(draft_input, PolicyDocument):
        return draft_input
    if isinstance(draft_input, dict):
        if "limits" in draft_input and "thresholds" in draft_input:
            try:
                return PolicyDocument.model_validate(draft_input)
            except Exception:
                pass

        base_dict = baseline_doc.model_dump(mode="json")
        if "single_tx_usd" in draft_input:
            val = float(draft_input["single_tx_usd"])
            base_dict["thresholds"]["single_tx_usd"] = val
            base_dict["limits"]["global_single_tx_usd"] = val
        if "wallet_limit_usd" in draft_input:
            val = float(draft_input["wallet_limit_usd"])
            base_dict["limits"]["global_velocity_limit_usd"] = val
        if "global_limit_usd" in draft_input:
            val = float(draft_input["global_limit_usd"])
            base_dict["limits"]["global_daily_usd"] = val
        if "new_recipient_usd" in draft_input:
            val = float(draft_input["new_recipient_usd"])
            base_dict["thresholds"]["new_recipient_usd"] = val
        if "spray_threshold" in draft_input:
            base_dict["thresholds"]["velocity_spike_multiplier"] = float(draft_input["spray_threshold"]) / 10.0

        if "limits" in draft_input and isinstance(draft_input["limits"], dict):
            base_dict["limits"].update(draft_input["limits"])
        if "thresholds" in draft_input and isinstance(draft_input["thresholds"], dict):
            base_dict["thresholds"].update(draft_input["thresholds"])
        if "delegate_allowlist" in draft_input:
            base_dict["delegate_allowlist"] = draft_input["delegate_allowlist"]
        if "owned_addresses" in draft_input:
            base_dict["owned_addresses"] = draft_input["owned_addresses"]

        base_dict["version"] = draft_input.get("version", f"{baseline_doc.version}-draft")
        return PolicyDocument.model_validate(base_dict)
    return baseline_doc


def _generate_diff(baseline: PolicyDocument, draft: PolicyDocument) -> tuple[dict[str, Any], str]:
    """Computes structured and textual diff between baseline and proposed draft policy."""
    b_dict = baseline.model_dump(mode="json")
    d_dict = draft.model_dump(mode="json")

    diff: dict[str, Any] = {}

    for k in ["global_daily_usd", "global_single_tx_usd", "global_velocity_limit_usd"]:
        bv = getattr(baseline.limits, k, None)
        dv = getattr(draft.limits, k, None)
        if bv != dv:
            direction = "LOOSEN" if (dv is not None and bv is not None and dv > bv) else "TIGHTEN"
            diff[k] = {"old": bv, "new": dv, "direction": direction}

    if baseline.thresholds.single_tx_usd != draft.thresholds.single_tx_usd:
        bv = baseline.thresholds.single_tx_usd
        dv = draft.thresholds.single_tx_usd
        direction = "LOOSEN" if dv > bv else "TIGHTEN"
        diff["single_tx_usd"] = {"old": bv, "new": dv, "direction": direction}

    if baseline.thresholds.hold_score != draft.thresholds.hold_score:
        bv = baseline.thresholds.hold_score
        dv = draft.thresholds.hold_score
        direction = "LOOSEN" if dv > bv else "TIGHTEN"
        diff["hold_score"] = {"old": bv, "new": dv, "direction": direction}

    b_json = json.dumps(b_dict, indent=2, sort_keys=True).splitlines(keepends=True)
    d_json = json.dumps(d_dict, indent=2, sort_keys=True).splitlines(keepends=True)
    unified = list(
        difflib.unified_diff(
            b_json,
            d_json,
            fromfile=f"active ({baseline.version})",
            tofile=f"draft ({draft.version})",
        )
    )
    text_diff = "".join(unified) if unified else "No differences detected."
    return diff, text_diff


@router.post(
    "/policies/classify",
    response_model=ClassifyPolicyResponse,
    summary="Classify draft policy against active baseline and compute diff",
    description="Compares draft policy against active version, producing a clear TIGHTENS, LOOSENS, or MIXED badge, structured diff, and governance requirements.",
)
def classify_policy_draft(
    payload: ClassifyPolicyRequest,
) -> ClassifyPolicyResponse:
    """Classifies a draft policy change."""
    active = None
    if payload.baseline_version_id:
        active = policy_store.get(payload.baseline_version_id) or policy_store.get_by_version(payload.baseline_version_id)
    if not active:
        active = policy_store.get_active() or policy_service.get_or_create_baseline()

    draft_doc = _normalize_draft_to_document(payload.draft, active.content)
    draft_hash = compute_content_hash(draft_doc)

    change_type = classify_change(active.content, draft_doc)
    diff, text_diff = _generate_diff(active.content, draft_doc)

    if change_type == ChangeClassification.TIGHTEN:
        badge = "TIGHTENS"
        requirements = PolicyRequirements(
            approvers_required=1,
            cooldown_seconds=0,
            backtest_required=False,
            can_instant_activate=True,
        )
    elif change_type == ChangeClassification.LOOSEN:
        badge = "LOOSENS"
        requirements = PolicyRequirements(
            approvers_required=2,
            cooldown_seconds=getattr(settings, "policy_cooldown_seconds", 60),
            backtest_required=True,
            can_instant_activate=False,
        )
    else:
        badge = "MIXED"
        requirements = PolicyRequirements(
            approvers_required=2,
            cooldown_seconds=getattr(settings, "policy_cooldown_seconds", 60),
            backtest_required=True,
            can_instant_activate=False,
        )

    return ClassifyPolicyResponse(
        classification=change_type,
        badge=badge,
        diff=diff,
        text_diff=text_diff,
        requirements=requirements,
        active_version=active.version,
        active_id=active.id,
        draft_hash=draft_hash,
        draft_doc=draft_doc.model_dump(mode="json"),
        data_label=DataLabel.REAL,
    )


@router.post(
    "/policies/draft/backtest",
    response_model=BacktestReport,
    summary="Execute backtest on a draft policy (Milestone S22 / F8)",
    description="Executes historical/synthetic replay with the draft policy, returning holds, false positives, and synthetic loss prevented.",
)
def backtest_draft_policy(
    payload: DraftBacktestRequest,
    current_user: UserResponse = Depends(get_current_user),
) -> BacktestReport:
    """Executes S22 backtesting on a draft policy."""
    active = policy_store.get_active() or policy_service.get_or_create_baseline()
    draft_doc = _normalize_draft_to_document(payload.draft_policy or {}, active.content)
    draft_hash = compute_content_hash(draft_doc)

    # Save draft policy version
    draft_id = payload.draft_policy_id or f"pv-draft-{draft_hash[:12]}"
    draft_ver = policy_store.get(draft_id) or policy_store.get_by_version(draft_doc.version)
    if not draft_ver:
        change_type = classify_change(active.content, draft_doc)
        draft_ver = PolicyVersion(
            id=draft_id,
            version=draft_doc.version if draft_doc.version != active.version else f"{active.version}-draft",
            author=current_user.id,
            status=PolicyStatus.DRAFT,
            content=draft_doc,
            content_hash=draft_hash,
            change_type=change_type,
            data_label=DataLabel.REAL,
        )
        policy_store.save(draft_ver)

    from services.bitguard.backtest.service import backtest_service

    report = backtest_service.create_and_run_backtest(
        BacktestImportRequest(
            draft_policy_id=draft_ver.id,
            scenarios=payload.scenarios,
        )
    )
    draft_ver.backtest_report_id = report.id
    policy_store.save(draft_ver)
    return report


@router.post(
    "/policies",
    response_model=PolicyVersion,
    status_code=status.HTTP_201_CREATED,
    summary="Propose new versioned policy manifest",
    description="Proposes a new declarative policy version. Automatically classifies change as TIGHTEN, LOOSEN, or MIXED, and schedules governance requirements.",
)
def propose_policy(
    payload: ProposePolicyRequest,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> PolicyVersion:
    """Proposes a new policy manifest."""
    try:
        return policy_service.propose_policy(request=payload, author_user=current_user)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/policies",
    response_model=list[PolicyVersion],
    summary="List all policy versions",
    description="Returns all versioned policy manifests sorted by creation time descending.",
)
def list_policies(
    limit: int = Query(default=50, ge=1, le=200, description="Max versions to return"),
    current_user: UserResponse = Depends(get_current_user),
) -> list[PolicyVersion]:
    """Lists policy manifests."""
    return policy_store.list_all(limit=limit)


@router.get(
    "/policies/active",
    response_model=PolicyVersion,
    summary="Get currently active policy version",
    description="Returns the currently active, verified policy version governing the decision engines.",
)
def get_active_policy(
    current_user: UserResponse = Depends(get_current_user),
) -> PolicyVersion:
    """Retrieves active policy version."""
    active = policy_store.get_active() or policy_service.get_or_create_baseline()
    return active


@router.get(
    "/policies/{version_id}",
    response_model=PolicyVersion,
    summary="Get policy version details by ID",
    description="Retrieves a specific policy version including content, hash, classification, approvals, and signatures.",
)
def get_policy(
    version_id: str,
    current_user: UserResponse = Depends(get_current_user),
) -> PolicyVersion:
    """Retrieves a policy version by ID."""
    pv = policy_store.get(version_id) or policy_store.get_by_version(version_id)
    if not pv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy version '{version_id}' not found",
        )
    return pv


@router.post(
    "/policies/{version_id}/approve",
    response_model=PolicyVersion,
    summary="Approve policy change with WebAuthn hardware key",
    description="Submits an authorized WebAuthn assertion over policy content hash. Enforces separation of duties (author cannot approve).",
)
def approve_policy(
    version_id: str,
    payload: ApprovePolicyRequest,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.APPROVER)),
) -> PolicyVersion:
    """Submits WebAuthn approval signature for a pending policy change."""
    try:
        return policy_service.approve_policy(
            version_id=version_id,
            approver_user=current_user,
            assertion=payload.assertion,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/policies/{version_id}/activate",
    response_model=PolicyVersion,
    summary="Activate policy change and hot-reload engines",
    description="Activates a policy version after verifying signature, content hash, approval quorum, and cool-down delay. Hot-reloads decision engine memory.",
)
def activate_policy(
    version_id: str,
    payload: ActivatePolicyRequest | None = None,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> PolicyVersion:
    """Activates a verified policy version."""
    sig_override = payload.ed25519_signature if payload else None
    try:
        return policy_service.activate_policy(
            version_id=version_id,
            activator_user=current_user,
            ed25519_sig_override=sig_override,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/policies/{version_id}/rollback",
    response_model=PolicyVersion,
    summary="Rollback active policy to previous version",
    description="Rolls back from an active policy version to the previous verified healthy version or specified target version.",
)
def rollback_policy(
    version_id: str,
    payload: RollbackPolicyRequest,
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN)),
) -> PolicyVersion:
    """Rolls back an active policy."""
    try:
        active = policy_store.get_active()
        target = policy_store.get(version_id) or policy_store.get_by_version(version_id)
        if target and active and target.id != active.id:
            return policy_service.rollback_to_version(
                target_version_id=target.id,
                reason=f"Operator rollback by {current_user.email}: {payload.reason}",
                actor_email=current_user.email,
            )
        return policy_service.auto_rollback(
            version_id=version_id,
            reason=f"Operator rollback by {current_user.email}: {payload.reason}",
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/policies/integrity-check",
    response_model=PolicyIntegrityResponse,
    summary="Execute policy integrity scan across engine memory and database",
    description="Compares engine memory loaded hash against database active record and cryptographic release signature. Direct DB tampering triggers fail-closed remediation.",
)
def check_policy_integrity(
    current_user: UserResponse = Depends(require_role(Role.SECOPS, Role.ADMIN, Role.OPERATOR)),
) -> PolicyIntegrityResponse:
    """Runs periodic policy integrity check."""
    return policy_service.run_integrity_check()
