from typing import Any

from backend.app.core.breaker import Breaker
from backend.app.core.delegation import DelegationGuard
from backend.app.models import Decision, SigningRequest


class PolicyEngine:
    """
    Core Policy Engine for BitGuard Firewall.
    Tracks independent rolling-window USD sums and evaluates signing requests
    against exchange risk thresholds.

    Critical rule: ONLY allowed transactions increment the rolling window sums
    (so attackers cannot exhaust limits with denied or held requests).
    """

    def __init__(
        self,
        wallet_limit_usd: float = 100_000.0,
        global_limit_usd: float = 500_000.0,
        single_tx_usd: float = 50_000.0,
        new_recipient_usd: float = 10_000.0,
        window_seconds: float = 3600.0,  # 1-hour rolling window
        known_recipients: set[str] | list[str] | None = None,
        breaker: Breaker | None = None,
        delegation_guard: DelegationGuard | None = None,
    ):
        self.wallet_limit_usd = float(wallet_limit_usd)
        self.global_limit_usd = float(global_limit_usd)
        self.single_tx_usd = float(single_tx_usd)
        self.new_recipient_usd = float(new_recipient_usd)
        self.window_seconds = float(window_seconds)

        self.known_recipients: set[str] = {
            r.lower() for r in (known_recipients or [])
        }
        self.breaker = breaker if breaker is not None else Breaker()
        self.delegation_guard = (
            delegation_guard if delegation_guard is not None else DelegationGuard()
        )

        # Rolling window history: wallet -> list of (ts, amount_usd)
        self.wallet_windows: dict[str, list[tuple[float, float]]] = {}
        # Global multi-chain rolling window: list of (ts, amount_usd)
        self.global_window: list[tuple[float, float]] = []

    def _prune_wallet_window(self, wallet: str, current_ts: float) -> list[tuple[float, float]]:
        cutoff = current_ts - self.window_seconds
        records = [
            rec for rec in self.wallet_windows.get(wallet.lower(), [])
            if rec[0] > cutoff
        ]
        self.wallet_windows[wallet.lower()] = records
        return records

    def _prune_global_window(self, current_ts: float) -> list[tuple[float, float]]:
        cutoff = current_ts - self.window_seconds
        self.global_window = [
            rec for rec in self.global_window
            if rec[0] > cutoff
        ]
        return self.global_window

    def get_wallet_rolling_sum(self, wallet: str, current_ts: float) -> float:
        records = self._prune_wallet_window(wallet, current_ts)
        return sum(amt for _, amt in records)

    def get_global_rolling_sum(self, current_ts: float) -> float:
        records = self._prune_global_window(current_ts)
        return sum(amt for _, amt in records)

    def record_allowed(self, req: SigningRequest) -> None:
        """
        Increment the rolling-window sums and register recipient.
        CRITICAL: ONLY allowed transactions increment the rolling window sums.
        """
        wallet_key = req.wallet.lower()
        if wallet_key not in self.wallet_windows:
            self.wallet_windows[wallet_key] = []
        self.wallet_windows[wallet_key].append((req.ts, req.amount_usd))
        self.global_window.append((req.ts, req.amount_usd))

        if req.to:
            self.known_recipients.add(req.to.lower())

    def evaluate(self, req: SigningRequest) -> Decision:
        """
        Evaluate a single signing request through all layers of BitGuard.
        """
        reasons: list[dict[str, Any]] = []

        # 1. Breaker Lockdown Check
        if self.breaker.is_locked_down():
            return Decision(
                request_id=req.id,
                action="deny",
                risk=100,
                reasons=[{
                    "rule": "circuit_breaker_lockdown",
                    "message": "Breaker is in Lockdown state. Automated signing is paused.",
                }],
                breaker_state=self.breaker.state,
            )

        # 2. Delegation & Nonce-Spray Security Layer
        delegation_violation = self.delegation_guard.evaluate_request(req)
        if delegation_violation:
            is_critical = delegation_violation.get("critical", False)
            self.breaker.record_anomaly(
                chain=req.chain,
                ts=req.ts,
                reason=delegation_violation["message"],
                is_critical=is_critical,
            )
            return Decision(
                request_id=req.id,
                action="deny",
                risk=100,
                reasons=[delegation_violation],
                breaker_state=self.breaker.state,
            )

        # 3. Policy Engine Limits
        action = "allow"
        risk = 0

        # Check Single Transaction Size Limit
        if req.amount_usd > self.single_tx_usd:
            action = "hold"
            risk = max(risk, 70)
            reasons.append({
                "rule": "single_tx_limit",
                "message": (
                    f"Transaction amount ${req.amount_usd:,.2f} exceeds single tx limit "
                    f"of ${self.single_tx_usd:,.2f}"
                ),
                "limit_usd": self.single_tx_usd,
                "amount_usd": req.amount_usd,
            })

        # Check Unseen Recipient Limit
        if req.to:
            norm_to = req.to.lower()
            if norm_to not in self.known_recipients:
                if req.amount_usd > self.new_recipient_usd:
                    action = "hold"
                    risk = max(risk, 60)
                    reasons.append({
                        "rule": "new_recipient_limit",
                        "message": (
                            f"Amount ${req.amount_usd:,.2f} to new/unseen recipient {req.to} "
                            f"exceeds limit of ${self.new_recipient_usd:,.2f}"
                        ),
                        "limit_usd": self.new_recipient_usd,
                        "amount_usd": req.amount_usd,
                        "recipient": req.to,
                    })

        # Check Wallet-Level Rolling-Window Limit
        current_wallet_sum = self.get_wallet_rolling_sum(req.wallet, req.ts)
        projected_wallet_sum = current_wallet_sum + req.amount_usd
        if projected_wallet_sum > self.wallet_limit_usd:
            action = "hold"
            risk = max(risk, 80)
            reasons.append({
                "rule": "wallet_limit",
                "message": (
                    f"Projected wallet volume ${projected_wallet_sum:,.2f} exceeds rolling limit "
                    f"of ${self.wallet_limit_usd:,.2f}"
                ),
                "limit_usd": self.wallet_limit_usd,
                "current_volume_usd": current_wallet_sum,
                "projected_volume_usd": projected_wallet_sum,
            })

        # Check Global Multi-Chain Rolling-Window Limit
        current_global_sum = self.get_global_rolling_sum(req.ts)
        projected_global_sum = current_global_sum + req.amount_usd
        if projected_global_sum > self.global_limit_usd:
            action = "hold"
            risk = max(risk, 85)
            reasons.append({
                "rule": "global_limit",
                "message": (
                    f"Projected global volume ${projected_global_sum:,.2f} exceeds rolling limit "
                    f"of ${self.global_limit_usd:,.2f}"
                ),
                "limit_usd": self.global_limit_usd,
                "current_volume_usd": current_global_sum,
                "projected_volume_usd": projected_global_sum,
            })

        # 4. Breaker State Hold Override
        if self.breaker.state == "Hold" and action == "allow":
            action = "hold"
            risk = max(risk, 50)
            reasons.append({
                "rule": "breaker_hold",
                "message": "Breaker is in Hold state. Signing request requires manual confirmation.",
            })
        elif self.breaker.state == "Elevated":
            risk = min(100, risk + 15)

        # 5. Apply Critical Rule:
        # ONLY allowed transactions increment the rolling window sums
        if action == "allow":
            self.record_allowed(req)
        else:
            # Denied or held requests do NOT increment sums.
            # Record an anomaly in breaker for cross-chain correlation.
            self.breaker.record_anomaly(
                chain=req.chain,
                ts=req.ts,
                reason=f"Policy hold on wallet {req.wallet}: {[r['rule'] for r in reasons]}",
                is_critical=False,
            )

        return Decision(
            request_id=req.id,
            action=action,
            risk=risk,
            reasons=reasons,
            breaker_state=self.breaker.state,
        )

    def replay(self, requests: list[SigningRequest]) -> list[Decision]:
        """
        Sequentially evaluate a batch of signing requests, recording state transitions.
        """
        return [self.evaluate(req) for req in requests]

    def reset(self) -> None:
        """Reset all windows, breaker, and delegation state."""
        self.wallet_windows.clear()
        self.global_window.clear()
        self.known_recipients.clear()
        self.breaker.reset()
        self.delegation_guard.reset()
