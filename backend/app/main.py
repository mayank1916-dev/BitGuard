from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from backend.app.core.audit import AuditLog
from backend.app.core.policy import PolicyEngine
from backend.app.core.radar import (
    RadarScanner,
    RadarScanResult,
)
from backend.app.core.replay import (
    ReplayMetrics,
    ReplayReport,
    ReplayRunner,
    SensitivityPoint,
    StepEvent,
    run_sensitivity_matrix,
)
from backend.app.core.report import generate_post_mortem_pdf
from backend.app.models import Decision, SigningRequest


class ReplayBatchRequest(BaseModel):
    """
    Request payload for /api/replay.
    Supports supplying custom event batches and policy parameter overrides.
    If events is omitted, runs the default synthetic Binance attack timeline dataset.
    """
    events: list[SigningRequest] | None = None
    policy_overrides: dict[str, Any] | None = None


class EnhancedReplayResponse(BaseModel):
    """
    Replay response containing full step-by-step stream, aggregate summary metrics,
    and backwards-compatible summary counts.
    """
    summary: ReplayMetrics
    steps: list[StepEvent]
    # Backwards-compatible fields for Milestone 1 test suites
    results: list[Decision]
    breaker_state: str
    total_evaluated: int
    allowed_count: int
    held_count: int
    denied_count: int


class SensitivityRequest(BaseModel):
    base_limits: dict[str, Any] | None = None
    multipliers: list[float] | None = None
    # Direct custom base values supported for slider updates
    base_single_tx_usd: float | None = None
    base_wallet_limit_usd: float | None = None
    base_global_limit_usd: float | None = None
    base_new_recipient_usd: float | None = None
    single_tx_usd: float | None = None
    wallet_limit_usd: float | None = None
    global_limit_usd: float | None = None
    new_recipient_usd: float | None = None


class SensitivityResponse(BaseModel):
    matrix: list[SensitivityPoint]
    base_limits: dict[str, Any]


def create_app(engine: PolicyEngine | None = None) -> FastAPI:
    app = FastAPI(
        title="BitGuard Firewall, Replay & 7702 Radar",
        description="Autonomous signing-request firewall, incident-replay lab, and EIP-7702 live radar for exchange hot wallets",
        version="0.4.0",
    )

    app.state.engine = engine or PolicyEngine()
    app.state.radar_scanner = RadarScanner()
    app.state.audit_log = AuditLog()
    app.state.last_replay_report = None

    def ensure_audit_chain_seeded() -> None:
        if not app.state.audit_log.entries:
            runner = ReplayRunner()
            rep = runner.run()
            app.state.last_replay_report = rep
            for s in rep.steps:
                app.state.audit_log.append_decision(s.protected_decision, timestamp=s.ts)

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "service": "bitguard",
            "version": "0.4.0",
            "breaker_state": app.state.engine.breaker.state,
        }

    @app.get("/api/mode")
    def get_mode():
        return {"mode": "SIMULATION", "wallet_group": "default"}

    @app.get("/api/metrics/shadow")
    def get_shadow_metrics(wallet_group: str = "default"):
        return {
            "mode": "SIMULATION",
            "wallet_group": wallet_group,
            "would_have_allowed_count": 0,
            "would_have_allowed_value": 0.0,
            "would_have_blocked_count": 0,
            "would_have_blocked_value": 0.0,
        }

    @app.post("/api/evaluate", response_model=Decision)
    def evaluate(request: SigningRequest) -> Decision:
        decision = app.state.engine.evaluate(request)
        app.state.audit_log.append_decision(decision, timestamp=request.ts)
        return decision

    @app.post("/api/replay", response_model=EnhancedReplayResponse)
    def replay(
        payload: ReplayBatchRequest | list[SigningRequest] | None = None,
    ) -> EnhancedReplayResponse:
        events: list[SigningRequest] | None = None
        policy_overrides: dict[str, Any] | None = None

        if isinstance(payload, list):
            events = payload
        elif isinstance(payload, ReplayBatchRequest):
            events = payload.events
            policy_overrides = payload.policy_overrides

        # Instantiate ReplayRunner
        runner = ReplayRunner(
            requests=events,
            policy_overrides=policy_overrides,
        )
        report: ReplayReport = runner.run()
        app.state.last_replay_report = report

        # Ensure decisions are appended to audit chain
        for s in report.steps:
            app.state.audit_log.append_decision(s.protected_decision, timestamp=s.ts)

        results = [s.protected_decision for s in report.steps]
        allowed = sum(1 for r in results if r.action == "allow")
        held = sum(1 for r in results if r.action == "hold")
        denied = sum(1 for r in results if r.action == "deny")

        return EnhancedReplayResponse(
            summary=report.summary,
            steps=report.steps,
            results=results,
            breaker_state=report.summary.breaker_final_state,
            total_evaluated=len(results),
            allowed_count=allowed,
            held_count=held,
            denied_count=denied,
        )

    @app.get("/api/radar", response_model=RadarScanResult)
    def get_radar(
        n_blocks: int = Query(default=5, ge=1, le=20),
        force_cached: bool = Query(default=False),
    ) -> RadarScanResult:
        """
        Polls recent Ethereum blocks for Type-4 (EIP-7702) transactions,
        scoring authorization pattern heuristics.
        Seamlessly falls back to cached offline dataset if RPC is unreachable.
        """
        scanner: RadarScanner = app.state.radar_scanner
        return scanner.scan_recent_blocks(n_blocks=n_blocks, force_cached=force_cached)

    @app.post("/api/policy/sensitivity", response_model=SensitivityResponse)
    def get_sensitivity(payload: SensitivityRequest | None = None) -> SensitivityResponse:
        """
        Runs sensitivity analysis across limit multipliers, charting capital saved vs false positives.
        Accepts custom base limits dynamically from interactive sliders.
        """
        base: dict[str, float] = {
            "single_tx_usd": 50_000.0,
            "wallet_limit_usd": 100_000.0,
            "global_limit_usd": 500_000.0,
            "new_recipient_usd": 10_000.0,
        }

        if payload:
            if payload.base_limits:
                for k, v in payload.base_limits.items():
                    if v is not None:
                        clean_k = k.replace("base_", "")
                        base[clean_k] = float(v)

            if payload.base_single_tx_usd is not None:
                base["single_tx_usd"] = float(payload.base_single_tx_usd)
            elif payload.single_tx_usd is not None:
                base["single_tx_usd"] = float(payload.single_tx_usd)

            if payload.base_wallet_limit_usd is not None:
                base["wallet_limit_usd"] = float(payload.base_wallet_limit_usd)
            elif payload.wallet_limit_usd is not None:
                base["wallet_limit_usd"] = float(payload.wallet_limit_usd)

            if payload.base_global_limit_usd is not None:
                base["global_limit_usd"] = float(payload.base_global_limit_usd)
            elif payload.global_limit_usd is not None:
                base["global_limit_usd"] = float(payload.global_limit_usd)

            if payload.base_new_recipient_usd is not None:
                base["new_recipient_usd"] = float(payload.base_new_recipient_usd)
            elif payload.new_recipient_usd is not None:
                base["new_recipient_usd"] = float(payload.new_recipient_usd)

        base["base_single_tx_usd"] = base["single_tx_usd"]
        base["base_wallet_limit_usd"] = base["wallet_limit_usd"]
        base["base_global_limit_usd"] = base["global_limit_usd"]
        base["base_new_recipient_usd"] = base["new_recipient_usd"]

        multipliers = (
            payload.multipliers
            if (payload and payload.multipliers)
            else [0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0]
        )
        matrix = run_sensitivity_matrix(multipliers=multipliers, base_limits=base)
        return SensitivityResponse(matrix=matrix, base_limits=base)

    @app.get("/api/audit/records")
    def get_audit_records():
        """Returns recent tamper-evident append-only audit records and current root hash."""
        ensure_audit_chain_seeded()
        return {
            "root_hash": app.state.audit_log.get_root_hash(),
            "total_records": len(app.state.audit_log.entries),
            "records": [e.model_dump() for e in app.state.audit_log.entries],
        }

    @app.get("/api/audit/verify")
    def verify_audit():
        """Verifies cryptographic hash chain integrity."""
        ensure_audit_chain_seeded()
        valid, corrupted_idx = app.state.audit_log.verify_integrity()
        return {
            "valid": valid,
            "corrupted_index": corrupted_idx,
            "root_hash": app.state.audit_log.get_root_hash(),
            "total_records": len(app.state.audit_log.entries),
            "is_tampered": getattr(app.state.audit_log, "is_tampered", False),
        }

    @app.post("/api/audit/simulate-tamper")
    def simulate_tamper(index: int | None = Query(default=None)):
        """Modifies a stored record's payload to demonstrate live tamper detection."""
        ensure_audit_chain_seeded()
        if not app.state.audit_log.entries:
            raise HTTPException(status_code=400, detail="Audit chain is empty")
        target_idx = index if index is not None else (len(app.state.audit_log.entries) // 2)
        _ = app.state.audit_log.tamper_test_corrupt_entry(target_idx)
        valid, corrupted_idx = app.state.audit_log.verify_integrity()
        return {
            "status": "tampered",
            "tampered_index": target_idx,
            "is_chain_valid": valid,
            "detected_corrupted_index": corrupted_idx,
            "root_hash": app.state.audit_log.get_root_hash(),
            "is_tampered": getattr(app.state.audit_log, "is_tampered", True),
        }

    @app.post("/api/audit/reset")
    def reset_audit():
        """Restores the original untampered audit chain."""
        app.state.audit_log.reset_ledger()
        valid, corrupted_idx = app.state.audit_log.verify_integrity()
        return {
            "status": "restored",
            "valid": valid,
            "corrupted_index": corrupted_idx,
            "root_hash": app.state.audit_log.get_root_hash(),
            "total_records": len(app.state.audit_log.entries),
            "is_tampered": getattr(app.state.audit_log, "is_tampered", False),
        }

    @app.get("/api/report/download")
    def download_report():
        """Generates and streams the PDF post-mortem report directly to the browser."""
        ensure_audit_chain_seeded()
        report = getattr(app.state, "last_replay_report", None)
        if not report:
            runner = ReplayRunner()
            report = runner.run()
            app.state.last_replay_report = report

        summary_dict = report.summary.model_dump()
        recent_decisions = [
            {
                "chain": s.chain,
                "kind": s.kind,
                "wallet": s.wallet,
                "amount_usd": s.amount_usd,
                "action": s.protected_decision.action,
                "risk": s.protected_decision.risk,
                "rule_hits": [r.get("rule") for r in s.protected_decision.reasons if isinstance(r, dict)],
            }
            for s in report.steps
            if s.protected_decision.action in ("deny", "hold")
        ]
        root_hash = app.state.audit_log.get_root_hash()
        pdf_bytes = generate_post_mortem_pdf(
            replay_summary=summary_dict,
            recent_decisions=recent_decisions,
            audit_root_hash=root_hash,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": 'attachment; filename="bitguard_incident_report.pdf"'
            },
        )

    @app.post("/api/reset")
    def reset():
        app.state.engine.reset()
        return {
            "status": "reset",
            "breaker_state": app.state.engine.breaker.state,
        }

    return app


app = create_app()
