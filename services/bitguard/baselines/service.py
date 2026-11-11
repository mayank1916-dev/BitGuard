"""Behavioral Baselines Evaluation Service (Milestone S32 / F15).

Invariants:
- Invariant #3: Fail-Closed Default. Unconfigured or invalid policies safely default to strict weights.
- Invariant #4: Raw Byte Source of Truth. Base volumes and transaction values on decoded amounts.
- Invariant #8: Explicit Data Provenance. Baseline outcomes tagged with REAL or SYNTHETIC.
- Invariant #11: Strict Wording: 'reduces and contains', 'target p99 under 15 ms, measured'.
- Baselines contribute risk weight only and can NEVER alone cause DENY.
- Cold start (< 7 days of data) adds a small configurable 'LOW_HISTORY' weight and NO other baseline reasons.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from services.bitguard.baselines.models import BaselineEvaluationResult
from services.bitguard.baselines.store import BaselineStore, baseline_store
from services.bitguard.models import DecisionReason

if TYPE_CHECKING:
    from services.bitguard.policy.models import BaselinePolicy, PolicyDocument

logger = logging.getLogger("bitguard.baselines.service")


class BaselineService:
    """Evaluates transactions against wallet rolling behavioral baselines."""

    def __init__(self, store: BaselineStore | None = None) -> None:
        self.store: BaselineStore = store or baseline_store

    def evaluate_transaction(
        self,
        wallet: str,
        amount_usd: float,
        destination: str,
        timestamp: float | None = None,
        policy: BaselinePolicy | None = None,
        policy_document: PolicyDocument | None = None,
    ) -> BaselineEvaluationResult:
        """Evaluates a proposed transfer against behavioral baselines.

        Returns BaselineEvaluationResult containing any flagged reasons with additive weights.
        Baselines contribute weight only and never alone cause DENY (is_hard_deny is always False).
        """
        now_ts = timestamp if timestamp is not None else time.time()
        dt = datetime.fromtimestamp(now_ts, tz=UTC)
        hour = dt.hour
        clean_wallet = wallet.lower()
        clean_dest = destination.lower()

        from services.bitguard.policy.models import BaselinePolicy

        active_policy: BaselinePolicy = policy if policy is not None else BaselinePolicy()

        # Check if baselines are disabled
        if not active_policy.enabled:
            return BaselineEvaluationResult(
                wallet=clean_wallet,
                reasons=[],
                total_risk_weight=0,
                is_cold_start=False,
                details={"status": "disabled"},
            )

        # Retrieve risk weight overrides from policy document if provided
        risk_weights = policy_document.risk_weights if policy_document and policy_document.risk_weights else {}

        profile = self.store.get_profile(clean_wallet)

        # -------------------------------------------------------------
        # 1. Cold Start Check (< min_history_days)
        # -------------------------------------------------------------
        history_days = profile.history_days if profile else 0.0
        if profile is None or history_days < active_policy.min_history_days:
            low_hist_weight = risk_weights.get("LOW_HISTORY", active_policy.low_history_weight)
            cold_start_reasons: list[DecisionReason] = []
            if low_hist_weight > 0:
                cold_start_reasons.append(
                    DecisionReason(
                        code="LOW_HISTORY",
                        weight=low_hist_weight,
                        detail=(
                            f"Wallet has only {history_days:.1f} days of transaction history "
                            f"(< {active_policy.min_history_days} days required for behavioral baselines); "
                            f"low history weight applied."
                        ),
                    )
                )
            return BaselineEvaluationResult(
                wallet=clean_wallet,
                reasons=cold_start_reasons,
                total_risk_weight=low_hist_weight,
                is_cold_start=True,
                details={
                    "history_days": history_days,
                    "min_history_days": active_policy.min_history_days,
                },
            )

        reasons: list[DecisionReason] = []
        details: dict[str, Any] = {
            "history_days": history_days,
            "total_transactions": profile.total_transactions,
        }

        # -------------------------------------------------------------
        # 2. Check BASELINE_VOLUME_HIGH
        # -------------------------------------------------------------
        prior_hourly_volume = self.store.get_hourly_rolling_volume(clean_wallet, now_ts)
        current_hourly_volume = prior_hourly_volume + amount_usd
        hourly_stats = profile.hourly_volumes.get(hour)
        p50_hourly = hourly_stats.p50 if hourly_stats else 0.0

        if p50_hourly > 0:
            volume_multiplier = current_hourly_volume / p50_hourly
            if volume_multiplier >= active_policy.volume_multiplier_threshold:
                weight = risk_weights.get("BASELINE_VOLUME_HIGH", active_policy.volume_high_weight)
                reasons.append(
                    DecisionReason(
                        code="BASELINE_VOLUME_HIGH",
                        weight=weight,
                        detail=(
                            f"volume {volume_multiplier:.1f}x typical for this hour "
                            f"(${current_hourly_volume:,.2f} vs typical ${p50_hourly:,.2f})"
                        ),
                    )
                )
                details["volume_multiplier"] = round(volume_multiplier, 2)
        elif current_hourly_volume >= active_policy.off_hours_threshold_usd and profile.total_transactions >= 10:
            # Hour had zero typical volume historically, but current volume is significant
            weight = risk_weights.get("BASELINE_VOLUME_HIGH", active_policy.volume_high_weight)
            reasons.append(
                DecisionReason(
                    code="BASELINE_VOLUME_HIGH",
                    weight=weight,
                    detail=(
                        f"volume is atypical for this hour: "
                        f"current volume ${current_hourly_volume:,.2f} exceeds historical median of $0.00"
                    ),
                )
            )

        # -------------------------------------------------------------
        # 3. Check BASELINE_NEW_DESTINATION_BURST
        # -------------------------------------------------------------
        if clean_dest and not self.store.is_known_destination(clean_wallet, clean_dest):
            # Destination not in historical set
            prior_new_count = self.store.get_new_destinations_count_24h(clean_wallet, now_ts)
            new_dest_count = prior_new_count + 1
            if new_dest_count >= active_policy.new_destination_burst_threshold:
                weight = risk_weights.get(
                    "BASELINE_NEW_DESTINATION_BURST",
                    active_policy.new_destination_burst_weight,
                )
                reasons.append(
                    DecisionReason(
                        code="BASELINE_NEW_DESTINATION_BURST",
                        weight=weight,
                        detail=(
                            f"New destination burst: {new_dest_count} new destinations in 24h "
                            f"(threshold {active_policy.new_destination_burst_threshold})"
                        ),
                    )
                )
                details["new_destinations_24h"] = new_dest_count

        # -------------------------------------------------------------
        # 4. Check BASELINE_SIZE_OUTLIER
        # -------------------------------------------------------------
        p99_size = profile.size_percentiles.p99
        if p99_size > 0 and amount_usd > p99_size:
            weight = risk_weights.get("BASELINE_SIZE_OUTLIER", active_policy.size_outlier_weight)
            reasons.append(
                DecisionReason(
                    code="BASELINE_SIZE_OUTLIER",
                    weight=weight,
                    detail=(
                        f"Transaction size ${amount_usd:,.2f} is an outlier compared to "
                        f"historical p99 (${p99_size:,.2f})"
                    ),
                )
            )
            details["size_outlier"] = {
                "amount_usd": amount_usd,
                "p99_size": p99_size,
            }

        # -------------------------------------------------------------
        # 5. Check BASELINE_OFF_HOURS
        # -------------------------------------------------------------
        if hour in active_policy.off_hours and amount_usd >= active_policy.off_hours_threshold_usd:
            # Verify if this hour is genuinely low-volume in historical baseline
            typical_off_hour_volume = p50_hourly
            if typical_off_hour_volume < active_policy.off_hours_threshold_usd:
                weight = risk_weights.get("BASELINE_OFF_HOURS", active_policy.off_hours_weight)
                reasons.append(
                    DecisionReason(
                        code="BASELINE_OFF_HOURS",
                        weight=weight,
                        detail=(
                            f"Outflow of ${amount_usd:,.2f} during off-hours ({hour:02d}:00 UTC) "
                            f"deviates from historical activity profile "
                            f"(typical volume ${typical_off_hour_volume:,.2f})"
                        ),
                    )
                )
                details["off_hours"] = {
                    "hour": hour,
                    "typical_volume": typical_off_hour_volume,
                }

        total_weight = sum(r.weight for r in reasons)
        return BaselineEvaluationResult(
            wallet=clean_wallet,
            reasons=reasons,
            total_risk_weight=total_weight,
            is_cold_start=False,
            details=details,
        )


# Global singleton baseline service
baseline_service = BaselineService()
