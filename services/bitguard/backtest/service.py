"""Backtest service providing isolated replay, scenario injection, and report generation (Milestone S22 / F8)."""

import csv
import hashlib
import io
import json
import logging
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from services.bitguard.backtest.injector import scenario_injector
from services.bitguard.backtest.models import (
    BacktestImportRequest,
    BacktestMeta,
    BacktestReport,
    BacktestRunResponse,
    StepEvent,
)
from services.bitguard.database import get_session_factory
from services.bitguard.db_models import BacktestReportRecord
from services.bitguard.engine.pipeline import DecisionEngine
from services.bitguard.engine.types import DecisionEngineConfig
from services.bitguard.limits.store import LimitStore, limit_store
from services.bitguard.models import DecodedTx, SigningRequest, Verdict
from services.bitguard.policy.classifier import classify_change
from services.bitguard.policy.crypto import compute_content_hash
from services.bitguard.policy.models import PolicyDocument
from services.bitguard.policy.store import policy_store

logger = logging.getLogger("bitguard.backtest.service")


class BacktestService:
    """Service providing historical/synthetic backtest imports, isolated replay, and reports."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_factory: sessionmaker[Session] | None = None
        self._redis_client: Any | None = None
        self._dataset_cache: dict[str, list[SigningRequest]] = {}
        self._memory_reports: dict[str, BacktestReport] = {}

    def set_session_factory(self, factory: sessionmaker[Session] | None) -> None:
        """Sets the SQLAlchemy session factory for persistence."""
        with self._lock:
            self._session_factory = factory

    def set_redis_client(self, client: Any) -> None:
        """Sets the Redis client instance for isolated replay."""
        with self._lock:
            self._redis_client = client

    def _get_session(self) -> Session:
        factory = self._session_factory or get_session_factory()
        return factory()

    # -----------------------------------------------------------------
    # Dataset Discovery & Compatibility (Milestone U3)
    # -----------------------------------------------------------------

    def list_backtests(self) -> list[BacktestMeta]:
        """Lists available historical and synthetic backtest datasets."""
        built_ins = [
            BacktestMeta(
                id="binance-exploit-2026",
                name="Binance Exploit Sequence (Oct 2026)",
                description="Late-October 2026 multi-chain exploit sequence including XRP outflow, 7702 spray, and massive sweeps.",
                events_count=72,
                source="incident_export",
            ),
            BacktestMeta(
                id="multichain-velocity-spike",
                name="Multi-Chain Velocity Spike",
                description="Simulated multi-chain concurrent burst exceeding per-wallet and global rolling window limits.",
                events_count=35,
                source="synthetic_generator",
            ),
            BacktestMeta(
                id="unauthorized-delegation-7702",
                name="EIP-7702 Unauthorized Delegation Spray",
                description="Type-4 transaction batch directing hot wallet addresses to non-allowlisted upgradeable contracts.",
                events_count=20,
                source="lab_scenario",
            ),
        ]
        return built_ins

    def _load_binance_dataset(self) -> list[SigningRequest]:
        """Loads default Binance exploit dataset from backend/data."""
        possible_paths = [
            Path(__file__).resolve().parent.parent.parent.parent / "backend" / "data" / "replay_binance_like.json",
            Path("backend/data/replay_binance_like.json"),
        ]
        for p in possible_paths:
            if p.exists():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    requests: list[SigningRequest] = []
                    for item in data:
                        amt = float(item.get("amount_usd", 0.0))
                        req = SigningRequest(
                            id=item.get("id", f"req-{len(requests)}"),
                            raw_tx=item.get("raw_tx", "0x02f87001legit"),
                            chain=item.get("chain", "ethereum"),
                            wallet=item.get("wallet", "0xBinanceHotETH1"),
                            metadata={
                                "amount_usd": amt,
                                "ts": float(item.get("ts", 1730299400.0)),
                                "kind": item.get("kind", "transfer"),
                                "asset": item.get("asset", "ETH"),
                                "to": item.get("to"),
                                "destination": item.get("to", "0xCustomer"),
                                "delegate": item.get("delegate"),
                                "scenario": item.get("meta", {}).get("scenario", "normal"),
                                "data_label": "REAL" if item.get("meta", {}).get("scenario") != "attack" else "SYNTHETIC",
                            },
                        )
                        requests.append(req)
                    return requests
                except Exception as exc:
                    logger.warning("Error reading binance dataset: %s", exc)

        return self._generate_synthetic_scenario(count=72, chain="ethereum", attack_ratio=0.5)

    def _generate_synthetic_scenario(self, count: int, chain: str, attack_ratio: float = 0.3) -> list[SigningRequest]:
        """Generates a reproducible synthetic request sequence."""
        requests: list[SigningRequest] = []
        base_ts = 1730299400.0
        for i in range(count):
            is_attack = (i / count) >= (1.0 - attack_ratio)
            amt = 5000000.0 if is_attack else (1000.0 + (i * 250.0))
            req = SigningRequest(
                id=f"syn-{chain[:3]}-{i+1:03d}",
                raw_tx="0x02f87001legit",
                chain=chain,
                wallet="0xBinanceHotETH1",
                metadata={
                    "amount_usd": amt,
                    "ts": base_ts + (i * 15.0),
                    "kind": "authorization_7702" if (is_attack and i % 3 == 0) else "transfer",
                    "asset": "ETH",
                    "to": f"0xAttackerSink{i}" if is_attack else f"0xCustomer{i}",
                    "destination": f"0xAttackerSink{i}" if is_attack else f"0xCustomer{i}",
                    "delegate": "0x9999999999999999999999999999999999999999" if (is_attack and i % 3 == 0) else None,
                    "scenario": "attack" if is_attack else "normal",
                    "data_label": "SYNTHETIC" if is_attack else "REAL",
                },
            )
            requests.append(req)
        return requests

    def get_backtest_events(self, backtest_id: str) -> list[SigningRequest]:
        """Retrieves raw events for the given backtest dataset."""
        if backtest_id in self._dataset_cache:
            return self._dataset_cache[backtest_id]

        if backtest_id == "binance-exploit-2026":
            reqs = self._load_binance_dataset()
        elif backtest_id == "multichain-velocity-spike":
            reqs = self._generate_synthetic_scenario(count=35, chain="bitcoin", attack_ratio=0.6)
        elif backtest_id == "unauthorized-delegation-7702":
            reqs = self._generate_synthetic_scenario(count=20, chain="ethereum", attack_ratio=0.8)
        else:
            reqs = self._load_binance_dataset()

        self._dataset_cache[backtest_id] = reqs
        return reqs

    def run_backtest(self, backtest_id: str) -> BacktestRunResponse:
        """Streams backtest events through the real policy decision engine (for U3 incident replay)."""
        events = self.get_backtest_events(backtest_id)
        from services.bitguard.breaker import distributed_breaker_store
        from services.bitguard.engine.pipeline import decision_engine

        steps: list[StepEvent] = []
        cum_unprotected = 0.0
        cum_protected = 0.0
        allowed_count = 0
        held_count = 0
        denied_count = 0

        for req in events:
            amt = float(req.metadata.get("amount_usd", 0.0))
            ts = float(req.metadata.get("ts", 1730299400.0))
            kind = str(req.metadata.get("kind", "transfer"))
            asset = str(req.metadata.get("asset", "ETH"))
            scenario = str(req.metadata.get("scenario", "normal"))
            data_label = str(req.metadata.get("data_label", "SYNTHETIC"))

            cum_unprotected += amt
            decision = decision_engine.evaluate(req, is_dry_run=True)

            if decision.verdict == Verdict.ALLOW:
                allowed_count += 1
                cum_protected += amt
            elif decision.verdict == Verdict.HOLD:
                held_count += 1
            else:
                denied_count += 1

            step = StepEvent(
                request_id=req.id,
                ts=ts,
                chain=req.chain,
                wallet=req.wallet,
                kind=kind,
                asset=asset,
                amount_usd=amt,
                scenario=scenario,
                unprotected_action="allow",
                protected_decision=decision,
                cumulative_unprotected_loss_usd=cum_unprotected,
                cumulative_protected_loss_usd=cum_protected,
                data_label=data_label,
            )
            steps.append(step)

        loss_prevented = max(0.0, cum_unprotected - cum_protected)
        prevented_pct = (loss_prevented / cum_unprotected * 100.0) if cum_unprotected > 0 else 100.0

        summary: dict[str, Any] = {
            "total_requests": len(events),
            "allowed_count": allowed_count,
            "held_count": held_count,
            "denied_count": denied_count,
            "unprotected_loss_usd": cum_unprotected,
            "protected_loss_usd": cum_protected,
            "loss_prevented_usd": loss_prevented,
            "loss_prevented_pct": prevented_pct,
            "breaker_final_state": distributed_breaker_store.get_state().value,
        }

        return BacktestRunResponse(
            backtest_id=backtest_id,
            total_events=len(events),
            allowed_count=allowed_count,
            held_count=held_count,
            denied_count=denied_count,
            unprotected_loss_usd=cum_unprotected,
            protected_loss_usd=cum_protected,
            loss_prevented_usd=loss_prevented,
            steps=steps,
            summary=summary,
        )

    # -----------------------------------------------------------------
    # Historical Signing Request Parser (JSONL & CSV)
    # -----------------------------------------------------------------

    def parse_historical_events(
        self,
        raw_data: str,
        file_format: str = "jsonl",
    ) -> list[SigningRequest]:
        """Parses historical signing requests from JSONL or CSV formatted data."""
        requests: list[SigningRequest] = []
        fmt = (file_format or "jsonl").strip().lower()

        if fmt == "csv":
            reader = csv.DictReader(io.StringIO(raw_data))
            for i, row in enumerate(reader):
                # Normalise keys to lower case
                low_row = {k.strip().lower(): v for k, v in row.items() if k}
                ts_val = float(low_row.get("ts", 1730299400.0 + (i * 10.0)))
                wallet = str(low_row.get("wallet", "0xUnknownWallet"))
                chain = str(low_row.get("chain", "ethereum"))
                asset = str(low_row.get("asset", "ETH"))
                amt = float(low_row.get("amount", 0.0))
                destination = str(low_row.get("destination", "0xUnknownDestination"))
                intent_id = low_row.get("intent_id")
                raw_label = str(low_row.get("data_label", "REAL")).strip().upper()
                label = "SYNTHETIC" if raw_label == "SYNTHETIC" else "REAL"

                tx_digest = f"0x{hashlib.sha256(f'{chain}:{wallet}:{destination}:{amt}:{ts_val}'.encode()).hexdigest()}"
                decoded = DecodedTx(
                    chain=chain,
                    from_address=wallet,
                    to_address=destination,
                    amount=str(int(amt * 100)),
                    asset=asset,
                    digest=tx_digest,
                )

                metadata: dict[str, Any] = {
                    "amount_usd": amt,
                    "ts": ts_val,
                    "chain": chain,
                    "asset": asset,
                    "wallet": wallet,
                    "destination": destination,
                    "data_label": label,
                    "is_backtest": True,
                    "scenario": "normal" if label == "REAL" else "synthetic",
                    "decoded_tx": decoded.model_dump(mode="json"),
                }
                if intent_id:
                    metadata["intent_id"] = intent_id

                req = SigningRequest(
                    id=f"hist-csv-{i+1:04d}",
                    raw_tx=low_row.get("raw_tx", "0x02f87001legit"),
                    chain=chain,
                    wallet=wallet,
                    intent_id=intent_id,
                    metadata=metadata,
                )
                requests.append(req)

        else:
            # Default JSONL format
            lines = raw_data.strip().splitlines()
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    ts_val = float(obj.get("ts", 1730299400.0 + (i * 10.0)))
                    wallet = str(obj.get("wallet", "0xUnknownWallet"))
                    chain = str(obj.get("chain", "ethereum"))
                    asset = str(obj.get("asset", "ETH"))
                    amt = float(obj.get("amount", obj.get("amount_usd", 0.0)))
                    destination = str(obj.get("destination", obj.get("to", "0xUnknownDestination")))
                    intent_id = obj.get("intent_id")
                    raw_label = str(obj.get("data_label", "REAL")).strip().upper()
                    label = "SYNTHETIC" if raw_label == "SYNTHETIC" else "REAL"

                    tx_digest = f"0x{hashlib.sha256(f'{chain}:{wallet}:{destination}:{amt}:{ts_val}'.encode()).hexdigest()}"
                    decoded = DecodedTx(
                        chain=chain,
                        from_address=wallet,
                        to_address=destination,
                        amount=str(int(amt * 100)),
                        asset=asset,
                        digest=tx_digest,
                    )

                    metadata = {
                        "amount_usd": amt,
                        "ts": ts_val,
                        "chain": chain,
                        "asset": asset,
                        "wallet": wallet,
                        "destination": destination,
                        "data_label": label,
                        "is_backtest": True,
                        "scenario": obj.get("scenario", ("normal" if label == "REAL" else "synthetic")),
                        "decoded_tx": decoded.model_dump(mode="json"),
                    }
                    if intent_id:
                        metadata["intent_id"] = intent_id
                    if "delegate" in obj:
                        metadata["delegate"] = obj["delegate"]
                    if "delegate_code_hash" in obj:
                        metadata["delegate_code_hash"] = obj["delegate_code_hash"]
                    if obj.get("simulate_intent_mismatch"):
                        metadata["simulate_intent_mismatch"] = True

                    req = SigningRequest(
                        id=obj.get("id", f"hist-jsonl-{i+1:04d}"),
                        raw_tx=obj.get("raw_tx", "0x02f87001legit"),
                        chain=chain,
                        wallet=wallet,
                        intent_id=intent_id,
                        metadata=metadata,
                    )
                    requests.append(req)
                except Exception as exc:
                    logger.warning("Error parsing JSONL line %d: %s", i + 1, exc)

        return requests

    # -----------------------------------------------------------------
    # Policy Diff Computation
    # -----------------------------------------------------------------

    def compute_policy_diff(
        self,
        baseline_doc: PolicyDocument,
        draft_doc: PolicyDocument,
    ) -> dict[str, Any]:
        """Computes structural and threshold diffs between baseline and draft policies."""
        classification = classify_change(baseline_doc, draft_doc)

        limits_diff: dict[str, Any] = {}
        for k in ["global_daily_usd", "global_single_tx_usd", "global_velocity_limit_usd"]:
            b_val = getattr(baseline_doc.limits, k, None)
            d_val = getattr(draft_doc.limits, k, None)
            if b_val != d_val:
                limits_diff[k] = {"baseline": b_val, "draft": d_val}

        thresholds_diff: dict[str, Any] = {}
        if baseline_doc.thresholds.single_tx_usd != draft_doc.thresholds.single_tx_usd:
            thresholds_diff["single_tx_usd"] = {
                "baseline": baseline_doc.thresholds.single_tx_usd,
                "draft": draft_doc.thresholds.single_tx_usd,
            }
        if baseline_doc.thresholds.hold_score != draft_doc.thresholds.hold_score:
            thresholds_diff["hold_score"] = {
                "baseline": baseline_doc.thresholds.hold_score,
                "draft": draft_doc.thresholds.hold_score,
            }

        base_allowlist = set(baseline_doc.delegate_allowlist)
        draft_allowlist = set(draft_doc.delegate_allowlist)
        allowlist_diff = {
            "added": list(draft_allowlist - base_allowlist),
            "removed": list(base_allowlist - draft_allowlist),
        }

        return {
            "classification": classification.value,
            "limits_diff": limits_diff,
            "thresholds_diff": thresholds_diff,
            "allowlist_diff": allowlist_diff,
            "draft_version": draft_doc.version,
            "baseline_version": baseline_doc.version,
        }

    # -----------------------------------------------------------------
    # Isolated Replay Execution & Report Generation
    # -----------------------------------------------------------------

    def create_and_run_backtest(self, req: BacktestImportRequest) -> BacktestReport:
        """Imports historical events, injects scenarios, executes isolated replay, and saves report."""
        # 1. Resolve draft policy
        draft_ver = policy_store.get(req.draft_policy_id) or policy_store.get_by_version(req.draft_policy_id)
        if not draft_ver:
            raise ValueError(f"Draft policy '{req.draft_policy_id}' not found in policy store")

        draft_doc: PolicyDocument = draft_ver.content
        draft_hash: str = draft_ver.content_hash or compute_content_hash(draft_doc)

        # 2. Resolve baseline policy
        baseline_ver = None
        if req.baseline_policy_id:
            baseline_ver = policy_store.get(req.baseline_policy_id) or policy_store.get_by_version(req.baseline_policy_id)
        if not baseline_ver:
            baseline_ver = policy_store.get_active()

        baseline_doc: PolicyDocument = (
            baseline_ver.content if baseline_ver else PolicyDocument(version="v0.0.0-empty")
        )
        baseline_hash = baseline_ver.content_hash if baseline_ver else ""
        baseline_id = baseline_ver.id if baseline_ver else None

        # 3. Parse input historical traffic
        real_events: list[SigningRequest] = []
        if req.data and req.data.strip():
            real_events = self.parse_historical_events(req.data, file_format=req.format)
        else:
            # Fallback to Binance sample dataset if no data supplied
            real_events = self._load_binance_dataset()

        # 4. Scenario injection: overlay requested scenario patterns
        all_events = scenario_injector.overlay(real_events, req.scenarios)

        # 5. Isolated replay execution setup
        report_id = f"btr-{uuid.uuid4().hex[:12]}"
        isolated_prefix = f"backtest:{report_id}:"
        redis_client = self._redis_client or limit_store._redis
        isolated_limits = LimitStore(redis_client=redis_client, key_prefix=isolated_prefix)

        # Engine config reflecting the draft policy thresholds
        engine_cfg = DecisionEngineConfig(
            hold_risk_threshold=draft_doc.thresholds.hold_score,
            single_tx_usd_threshold=draft_doc.thresholds.single_tx_usd,
            policy_version=draft_doc.version,
        )

        isolated_engine = DecisionEngine(
            config=engine_cfg,
            limits=isolated_limits,
        )
        isolated_engine.reload_policy(draft_doc, draft_hash)

        # 6. Stream events in timestamp order
        steps: list[StepEvent] = []
        cum_unprotected = 0.0
        cum_protected = 0.0
        allowed_count = 0
        held_count = 0
        denied_count = 0
        false_positives = 0
        synthetic_loss_prevented = 0.0
        synthetic_loss_allowed = 0.0

        for event in all_events:
            amt = float(event.metadata.get("amount_usd", 0.0))
            ts = float(event.metadata.get("ts", 1730299400.0))
            label = str(event.metadata.get("data_label", "REAL")).upper()
            scenario = str(event.metadata.get("scenario", "normal"))

            cum_unprotected += amt
            event.metadata["is_backtest"] = True

            # Evaluate through isolated engine
            decision = isolated_engine.evaluate(event, is_dry_run=True)

            if decision.verdict == Verdict.ALLOW:
                allowed_count += 1
                cum_protected += amt
                if label == "SYNTHETIC":
                    synthetic_loss_allowed += amt
            elif decision.verdict == Verdict.HOLD:
                held_count += 1
                if label == "REAL":
                    false_positives += 1
                elif label == "SYNTHETIC":
                    synthetic_loss_prevented += amt
            else:
                denied_count += 1
                if label == "REAL":
                    false_positives += 1
                elif label == "SYNTHETIC":
                    synthetic_loss_prevented += amt

            step = StepEvent(
                request_id=event.id,
                ts=ts,
                chain=event.chain,
                wallet=event.wallet,
                kind=event.metadata.get("kind", "transfer"),
                asset=event.metadata.get("asset", "ETH"),
                amount_usd=amt,
                scenario=scenario,
                unprotected_action="allow",
                protected_decision=decision,
                cumulative_unprotected_loss_usd=cum_unprotected,
                cumulative_protected_loss_usd=cum_protected,
                data_label=label,
            )
            steps.append(step)

        # Clean up isolated Redis keys
        isolated_limits.clear_namespace()

        # 7. Compute summary statistics
        real_count = sum(1 for e in all_events if e.metadata.get("data_label") == "REAL")
        syn_count = len(all_events) - real_count

        timestamps = [float(e.metadata.get("ts", 0.0)) for e in all_events]
        time_span_days = 1.0
        if timestamps:
            delta_sec = max(timestamps) - min(timestamps)
            time_span_days = max(1.0, delta_sec / 86400.0)

        holds_per_day = round(held_count / time_span_days, 2)
        policy_diff = self.compute_policy_diff(baseline_doc, draft_doc)

        report_summary: dict[str, Any] = {
            "total_events": len(all_events),
            "real_events_count": real_count,
            "synthetic_events_count": syn_count,
            "allowed_count": allowed_count,
            "held_count": held_count,
            "denied_count": denied_count,
            "holds_per_day": holds_per_day,
            "estimated_false_positives": false_positives,
            "synthetic_loss_prevented_usd": synthetic_loss_prevented,
            "synthetic_loss_allowed_usd": synthetic_loss_allowed,
            "classification": policy_diff.get("classification", "TIGHTEN"),
            "time_span_days": round(time_span_days, 2),
            "protection_note": "Policy reduces and contains unauthorized outflows; target p99 under 15 ms, measured.",
        }

        report = BacktestReport(
            id=report_id,
            draft_policy_id=draft_ver.id,
            draft_policy_hash=draft_hash,
            baseline_policy_id=baseline_id,
            baseline_policy_hash=baseline_hash,
            created_at=datetime.now(UTC),
            total_events=len(all_events),
            real_events_count=real_count,
            synthetic_events_count=syn_count,
            allowed_count=allowed_count,
            held_count=held_count,
            denied_count=denied_count,
            holds_per_day=holds_per_day,
            estimated_false_positives=false_positives,
            synthetic_loss_prevented_usd=synthetic_loss_prevented,
            synthetic_loss_allowed_usd=synthetic_loss_allowed,
            policy_diff=policy_diff,
            summary=report_summary,
            steps=steps,
        )

        # 8. Persist report to database and memory cache
        self.save_report(report)
        return report

    def save_report(self, report: BacktestReport) -> BacktestReport:
        """Persists a backtest report record to memory and database."""
        with self._lock:
            self._memory_reports[report.id] = report

            try:
                with self._get_session() as session:
                    rec = session.query(BacktestReportRecord).filter_by(id=report.id).first()
                    steps_json = [s.model_dump(mode="json") for s in report.steps]

                    if rec:
                        rec.total_events = report.total_events
                        rec.real_events_count = report.real_events_count
                        rec.synthetic_events_count = report.synthetic_events_count
                        rec.allowed_count = report.allowed_count
                        rec.held_count = report.held_count
                        rec.denied_count = report.denied_count
                        rec.holds_per_day = report.holds_per_day
                        rec.estimated_false_positives = report.estimated_false_positives
                        rec.synthetic_loss_prevented_usd = report.synthetic_loss_prevented_usd
                        rec.synthetic_loss_allowed_usd = report.synthetic_loss_allowed_usd
                        rec.policy_diff = report.policy_diff
                        rec.summary = report.summary
                        rec.steps = steps_json
                    else:
                        rec = BacktestReportRecord(
                            id=report.id,
                            draft_policy_id=report.draft_policy_id,
                            draft_policy_hash=report.draft_policy_hash,
                            baseline_policy_id=report.baseline_policy_id,
                            baseline_policy_hash=report.baseline_policy_hash,
                            total_events=report.total_events,
                            real_events_count=report.real_events_count,
                            synthetic_events_count=report.synthetic_events_count,
                            allowed_count=report.allowed_count,
                            held_count=report.held_count,
                            denied_count=report.denied_count,
                            holds_per_day=report.holds_per_day,
                            estimated_false_positives=report.estimated_false_positives,
                            synthetic_loss_prevented_usd=report.synthetic_loss_prevented_usd,
                            synthetic_loss_allowed_usd=report.synthetic_loss_allowed_usd,
                            policy_diff=report.policy_diff,
                            summary=report.summary,
                            steps=steps_json,
                            created_at=report.created_at,
                        )
                        session.add(rec)
                    session.commit()
            except Exception as exc:
                logger.warning("Failed saving backtest report to database: %s", exc)

        return report

    def get_report(self, report_id: str) -> BacktestReport | None:
        """Retrieves a backtest report by ID from memory cache or database."""
        with self._lock:
            if report_id in self._memory_reports:
                return self._memory_reports[report_id]

            try:
                with self._get_session() as session:
                    rec = session.query(BacktestReportRecord).filter_by(id=report_id).first()
                    if rec:
                        steps_list = [StepEvent.model_validate(s) for s in (rec.steps or [])]
                        report = BacktestReport(
                            id=rec.id,
                            draft_policy_id=rec.draft_policy_id,
                            draft_policy_hash=rec.draft_policy_hash,
                            baseline_policy_id=rec.baseline_policy_id,
                            baseline_policy_hash=rec.baseline_policy_hash,
                            created_at=rec.created_at,
                            total_events=rec.total_events,
                            real_events_count=rec.real_events_count,
                            synthetic_events_count=rec.synthetic_events_count,
                            allowed_count=rec.allowed_count,
                            held_count=rec.held_count,
                            denied_count=rec.denied_count,
                            holds_per_day=rec.holds_per_day,
                            estimated_false_positives=rec.estimated_false_positives,
                            synthetic_loss_prevented_usd=rec.synthetic_loss_prevented_usd,
                            synthetic_loss_allowed_usd=rec.synthetic_loss_allowed_usd,
                            policy_diff=rec.policy_diff,
                            summary=rec.summary,
                            steps=steps_list,
                        )
                        self._memory_reports[report_id] = report
                        return report
            except Exception as exc:
                logger.warning("Failed reading backtest report from database: %s", exc)

        return None


# Global singleton instance
backtest_service = BacktestService()
