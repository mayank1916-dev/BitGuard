"""Backtest loader and real engine evaluation streamer (Milestone S22 / F8 preview)."""

import json
from pathlib import Path
from typing import Any

from services.bitguard.backtest.models import BacktestMeta, BacktestRunResponse, StepEvent
from services.bitguard.breaker import distributed_breaker_store
from services.bitguard.engine.pipeline import decision_engine
from services.bitguard.models import SigningRequest, Verdict


class BacktestService:
    """Service providing backtest datasets and real engine replay execution."""

    def __init__(self) -> None:
        self._dataset_cache: dict[str, list[SigningRequest]] = {}

    def list_backtests(self) -> list[BacktestMeta]:
        """Lists available historical and synthetic backtest datasets."""
        return [
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
                                "delegate": item.get("delegate"),
                                "scenario": item.get("meta", {}).get("scenario", "normal"),
                            },
                        )
                        requests.append(req)
                    return requests
                except Exception:
                    pass

        # Fallback generated timeline if file unreadable
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
                    "delegate": "0x9999999999999999999999999999999999999999" if (is_attack and i % 3 == 0) else None,
                    "scenario": "attack" if is_attack else "normal",
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
        """Streams backtest events through the real policy decision engine."""
        events = self.get_backtest_events(backtest_id)
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

            # 1. Unprotected baseline blindly signs
            cum_unprotected += amt

            # 2. Evaluate through the real engine
            decision = decision_engine.evaluate(req, is_dry_run=True)

            # Map to step verdict counters
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
                data_label="SYNTHETIC",
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


backtest_service = BacktestService()
