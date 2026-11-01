from pathlib import Path
from typing import Optional, Any, Union
import json
from pydantic import BaseModel, Field

from backend.app.models import SigningRequest, Decision
from backend.app.core.policy import PolicyEngine
from backend.app.core.breaker import Breaker
from backend.app.core.delegation import DelegationGuard


class StepEvent(BaseModel):
    """Details of a single replayed transaction step in the simulation."""
    request_id: str
    ts: float
    chain: str
    wallet: str
    kind: str
    amount_usd: float
    scenario: str  # 'normal' | 'attack'
    unprotected_action: str  # always 'allow'
    protected_decision: Decision
    cumulative_unprotected_loss_usd: float
    cumulative_protected_loss_usd: float


class ReplayMetrics(BaseModel):
    """Aggregate comparative metrics between unprotected baseline and BitGuard protected."""
    total_requests: int
    normal_requests_count: int
    attack_requests_count: int
    unprotected_loss_usd: float
    protected_loss_usd: float
    loss_prevented_usd: float
    loss_prevented_pct: float
    time_to_contain_seconds: float
    seconds_to_first_block: float
    first_blocked_event: Optional[dict[str, Any]] = None
    breaker_lockdown_ts: Optional[float] = None
    breaker_lockdown_event_id: Optional[str] = None
    breaker_final_state: str
    false_positive_count: int


class ReplayReport(BaseModel):
    """Complete report produced by the ReplayRunner."""
    summary: ReplayMetrics
    steps: list[StepEvent]


class SensitivityPoint(BaseModel):
    """Result of sensitivity testing at a specific policy limit multiplier."""
    limit_multiplier: float
    single_tx_usd: float
    wallet_limit_usd: float
    global_limit_usd: float
    new_recipient_usd: float
    unprotected_loss_usd: float
    protected_loss_usd: float
    loss_prevented_usd: float
    loss_mitigated_pct: float
    false_positives_held: int
    time_to_contain_seconds: float
    breaker_final_state: str


def create_engine_with_overrides(overrides: Optional[dict[str, Any]] = None) -> PolicyEngine:
    """Helper to construct a PolicyEngine with optional parameter overrides."""
    if not overrides:
        return PolicyEngine()

    breaker_kwargs = {}
    if "multi_chain_lockdown_threshold" in overrides:
        breaker_kwargs["multi_chain_lockdown_threshold"] = overrides["multi_chain_lockdown_threshold"]
    if "multi_chain_elevate_threshold" in overrides:
        breaker_kwargs["multi_chain_elevate_threshold"] = overrides["multi_chain_elevate_threshold"]
    breaker = Breaker(**breaker_kwargs) if breaker_kwargs else None

    delegation_kwargs = {}
    if "delegate_allowlist" in overrides:
        delegation_kwargs["delegate_allowlist"] = overrides["delegate_allowlist"]
    if "spray_threshold" in overrides:
        delegation_kwargs["spray_threshold"] = overrides["spray_threshold"]
    delegation_guard = DelegationGuard(**delegation_kwargs) if delegation_kwargs else None

    engine_kwargs = {}
    for key in (
        "wallet_limit_usd",
        "global_limit_usd",
        "single_tx_usd",
        "new_recipient_usd",
        "window_seconds",
        "known_recipients",
    ):
        if key in overrides:
            engine_kwargs[key] = overrides[key]

    if breaker:
        engine_kwargs["breaker"] = breaker
    if delegation_guard:
        engine_kwargs["delegation_guard"] = delegation_guard

    return PolicyEngine(**engine_kwargs)


class ReplayRunner:
    """
    Incident Replay Engine & Timeline Simulator.
    Executes chronological requests through two parallel pipelines:
    1. Unprotected Baseline: Blindly signs all requests (action='allow')
    2. BitGuard Protected: Evaluates through PolicyEngine, Breaker, and DelegationGuard.
    """

    def __init__(
        self,
        dataset_path: Optional[Union[str, Path]] = None,
        requests: Optional[list[SigningRequest]] = None,
        policy_engine: Optional[PolicyEngine] = None,
        policy_overrides: Optional[dict[str, Any]] = None,
    ):
        self.default_dataset_path = (
            Path(__file__).resolve().parent.parent.parent / "data" / "replay_binance_like.json"
        )
        self.dataset_path = Path(dataset_path) if dataset_path else self.default_dataset_path

        if requests is not None:
            self.requests = requests
        else:
            self.requests = self.load_dataset(self.dataset_path)

        if policy_engine is not None:
            self.policy_engine = policy_engine
        else:
            self.policy_engine = create_engine_with_overrides(policy_overrides)

    @staticmethod
    def load_dataset(path: Path) -> list[SigningRequest]:
        """Loads and parses SigningRequest dataset from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        return [SigningRequest(**item) for item in raw_data]

    def run(self) -> ReplayReport:
        """
        Executes the timeline simulation and computes comparative metrics.
        """
        # Ensure requests are sorted chronologically by timestamp
        sorted_requests = sorted(self.requests, key=lambda r: r.ts)

        unprotected_loss_usd = 0.0
        protected_loss_usd = 0.0
        steps: list[StepEvent] = []

        first_blocked_event: Optional[dict[str, Any]] = None
        breaker_lockdown_ts: Optional[float] = None
        breaker_lockdown_event_id: Optional[str] = None
        false_positive_count = 0
        normal_count = 0
        attack_count = 0

        attack_start_ts: Optional[float] = None

        for req in sorted_requests:
            scenario = (req.meta or {}).get("scenario", "normal")
            is_attack = scenario == "attack"

            if is_attack:
                attack_count += 1
                if attack_start_ts is None:
                    attack_start_ts = req.ts
            else:
                normal_count += 1

            # 1. Unprotected Baseline: Blindly signs all requests
            if is_attack:
                unprotected_loss_usd += req.amount_usd

            # 2. BitGuard Protected Pipeline: Evaluated by PolicyEngine
            decision = self.policy_engine.evaluate(req)

            if is_attack and decision.action == "allow":
                protected_loss_usd += req.amount_usd

            # Check if this is the first blocked event
            if decision.action in ("hold", "deny") and first_blocked_event is None:
                first_blocked_event = {
                    "request_id": req.id,
                    "ts": req.ts,
                    "rule": decision.reasons[0].get("rule") if decision.reasons else "policy_violation",
                    "action": decision.action,
                    "amount_usd": req.amount_usd,
                    "chain": req.chain,
                    "wallet": req.wallet,
                    "scenario": scenario,
                    "message": decision.reasons[0].get("message") if decision.reasons else "",
                }

            # Check Breaker state transition to Lockdown
            if self.policy_engine.breaker.is_locked_down() and breaker_lockdown_ts is None:
                breaker_lockdown_ts = req.ts
                breaker_lockdown_event_id = req.id

            # Track false positives on legitimate background traffic
            if not is_attack and decision.action in ("hold", "deny"):
                false_positive_count += 1

            # Record step event
            steps.append(
                StepEvent(
                    request_id=req.id,
                    ts=req.ts,
                    chain=req.chain,
                    wallet=req.wallet,
                    kind=req.kind,
                    amount_usd=req.amount_usd,
                    scenario=scenario,
                    unprotected_action="allow",
                    protected_decision=decision,
                    cumulative_unprotected_loss_usd=unprotected_loss_usd,
                    cumulative_protected_loss_usd=protected_loss_usd,
                )
            )

        # Compute summary metrics
        loss_prevented_usd = max(0.0, unprotected_loss_usd - protected_loss_usd)
        loss_prevented_pct = (
            (loss_prevented_usd / unprotected_loss_usd * 100.0)
            if unprotected_loss_usd > 0
            else 0.0
        )

        if first_blocked_event and attack_start_ts is not None:
            seconds_to_first_block = max(0.0, first_blocked_event["ts"] - attack_start_ts)
            time_to_contain_seconds = seconds_to_first_block
        else:
            seconds_to_first_block = 0.0
            time_to_contain_seconds = 0.0

        metrics = ReplayMetrics(
            total_requests=len(sorted_requests),
            normal_requests_count=normal_count,
            attack_requests_count=attack_count,
            unprotected_loss_usd=unprotected_loss_usd,
            protected_loss_usd=protected_loss_usd,
            loss_prevented_usd=loss_prevented_usd,
            loss_prevented_pct=round(loss_prevented_pct, 4),
            time_to_contain_seconds=time_to_contain_seconds,
            seconds_to_first_block=seconds_to_first_block,
            first_blocked_event=first_blocked_event,
            breaker_lockdown_ts=breaker_lockdown_ts,
            breaker_lockdown_event_id=breaker_lockdown_event_id,
            breaker_final_state=self.policy_engine.breaker.state,
            false_positive_count=false_positive_count,
        )

        return ReplayReport(summary=metrics, steps=steps)


def run_sensitivity_matrix(
    multipliers: Optional[list[float]] = None,
    base_limits: Optional[dict[str, Any]] = None,
    dataset_path: Optional[Union[str, Path]] = None,
) -> list[SensitivityPoint]:
    """
    Evaluates the synthetic replay across multiple limit multipliers to produce
    a sensitivity matrix comparing capital saved ($) vs. false positives held.
    """
    mults = multipliers or [0.25, 0.5, 1.0, 1.5, 2.0]
    base = base_limits or {
        "single_tx_usd": 50_000.0,
        "wallet_limit_usd": 100_000.0,
        "global_limit_usd": 500_000.0,
        "new_recipient_usd": 10_000.0,
    }

    results: list[SensitivityPoint] = []

    for m in mults:
        scaled_overrides = {
            "single_tx_usd": base.get("single_tx_usd", 50_000.0) * m,
            "wallet_limit_usd": base.get("wallet_limit_usd", 100_000.0) * m,
            "global_limit_usd": base.get("global_limit_usd", 500_000.0) * m,
            "new_recipient_usd": base.get("new_recipient_usd", 10_000.0) * m,
        }
        runner = ReplayRunner(
            dataset_path=dataset_path,
            policy_overrides=scaled_overrides,
        )
        report = runner.run()
        summary = report.summary

        results.append(
            SensitivityPoint(
                limit_multiplier=m,
                single_tx_usd=scaled_overrides["single_tx_usd"],
                wallet_limit_usd=scaled_overrides["wallet_limit_usd"],
                global_limit_usd=scaled_overrides["global_limit_usd"],
                new_recipient_usd=scaled_overrides["new_recipient_usd"],
                unprotected_loss_usd=summary.unprotected_loss_usd,
                protected_loss_usd=summary.protected_loss_usd,
                loss_prevented_usd=summary.loss_prevented_usd,
                loss_mitigated_pct=summary.loss_prevented_pct,
                false_positives_held=summary.false_positive_count,
                time_to_contain_seconds=summary.time_to_contain_seconds,
                breaker_final_state=summary.breaker_final_state,
            )
        )

    return results
