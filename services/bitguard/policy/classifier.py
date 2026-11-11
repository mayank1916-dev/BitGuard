"""Policy diff classifier evaluating tightening vs loosening (Milestone S20 / Section D).

Invariants:
- Invariant #6: Asymmetric Policy Evolution:
  Tightening = one person, instant.
  Loosening = quorum (2 approvers) + cool-down delay + attached backtest report.
  MIXED is treated as LOOSEN.
"""

import logging

from services.bitguard.models import OperationMode
from services.bitguard.policy.models import ChangeClassification, PolicyDocument

logger = logging.getLogger("bitguard.policy.classifier")

MODE_SEVERITY = {
    OperationMode.SIMULATION: 0,
    OperationMode.SHADOW: 1,
    OperationMode.ENFORCE: 2,
}


def classify_change(old: PolicyDocument, new: PolicyDocument) -> ChangeClassification:
    """Classifies the transition between two policy versions.

    Rules:
    - Numeric limits: raising a limit is LOOSEN; lowering is TIGHTEN.
    - Allowlist additions: adding a delegate code hash allows more code => LOOSEN. Removing => TIGHTEN.
    - Owned addresses: adding a protected address => TIGHTEN. Removing => LOOSEN.
    - Mode changes: ENFORCE -> SHADOW or SHADOW -> SIMULATION is LOOSEN. Transitioning towards ENFORCE is TIGHTEN.
    - Hold thresholds: raising hold_score or single_tx threshold is LOOSEN (more permissive). Lowering is TIGHTEN.
    - Time-lock: shorter delay or higher min_amount threshold is LOOSEN. Longer delay or lower threshold is TIGHTEN.
    - Risk weights: lowering weight is LOOSEN. Raising weight is TIGHTEN.
    - If changes contain both loosening and tightening aspects => MIXED.
    """
    has_tighten = False
    has_loosen = False

    # 1. Compare global numeric limits
    if new.limits.global_daily_usd > old.limits.global_daily_usd:
        has_loosen = True
    elif new.limits.global_daily_usd < old.limits.global_daily_usd:
        has_tighten = True

    if new.limits.global_single_tx_usd > old.limits.global_single_tx_usd:
        has_loosen = True
    elif new.limits.global_single_tx_usd < old.limits.global_single_tx_usd:
        has_tighten = True

    if new.limits.global_velocity_limit_usd > old.limits.global_velocity_limit_usd:
        has_loosen = True
    elif new.limits.global_velocity_limit_usd < old.limits.global_velocity_limit_usd:
        has_tighten = True

    # 2. Compare per-wallet limits
    all_wallets = set(old.limits.wallet_daily_usd.keys()) | set(new.limits.wallet_daily_usd.keys())
    for w in all_wallets:
        old_val = old.limits.wallet_daily_usd.get(w, old.limits.global_daily_usd)
        new_val = new.limits.wallet_daily_usd.get(w, new.limits.global_daily_usd)
        if new_val > old_val:
            has_loosen = True
        elif new_val < old_val:
            has_tighten = True

    # 3. Compare asset & chain limits
    all_assets = set(old.limits.asset_daily_limits.keys()) | set(new.limits.asset_daily_limits.keys())
    for a in all_assets:
        old_val = old.limits.asset_daily_limits.get(a, float("inf"))
        new_val = new.limits.asset_daily_limits.get(a, float("inf"))
        if new_val > old_val:
            has_loosen = True
        elif new_val < old_val:
            has_tighten = True

    all_chains = set(old.limits.chain_daily_limits.keys()) | set(new.limits.chain_daily_limits.keys())
    for c in all_chains:
        old_val = old.limits.chain_daily_limits.get(c, float("inf"))
        new_val = new.limits.chain_daily_limits.get(c, float("inf"))
        if new_val > old_val:
            has_loosen = True
        elif new_val < old_val:
            has_tighten = True

    # 3b. Compare asset native unit limits (Milestone S31 / F13)
    all_unit_assets = set(old.limits.asset_unit_limits.keys()) | set(new.limits.asset_unit_limits.keys())
    for a in all_unit_assets:
        old_unit = old.limits.asset_unit_limits.get(a)
        new_unit = new.limits.asset_unit_limits.get(a)
        if old_unit is not None and new_unit is not None:
            if new_unit > old_unit:
                has_loosen = True
            elif new_unit < old_unit:
                has_tighten = True
        elif old_unit is not None and new_unit is None:
            has_loosen = True
        elif old_unit is None and new_unit is not None:
            has_tighten = True

    # 4. Compare hold thresholds
    # Raising single_tx_usd hold threshold means fewer transactions held -> LOOSEN
    if new.thresholds.single_tx_usd > old.thresholds.single_tx_usd:
        has_loosen = True
    elif new.thresholds.single_tx_usd < old.thresholds.single_tx_usd:
        has_tighten = True

    # Raising hold_score means higher risk tolerated before hold -> LOOSEN
    if new.thresholds.hold_score > old.thresholds.hold_score:
        has_loosen = True
    elif new.thresholds.hold_score < old.thresholds.hold_score:
        has_tighten = True

    # Raising velocity_spike_multiplier means larger spike tolerated -> LOOSEN
    if new.thresholds.velocity_spike_multiplier > old.thresholds.velocity_spike_multiplier:
        has_loosen = True
    elif new.thresholds.velocity_spike_multiplier < old.thresholds.velocity_spike_multiplier:
        has_tighten = True

    # 5. Compare delegate allowlist (bytecode hashes)
    old_allowlist = {h.lower() for h in old.delegate_allowlist}
    new_allowlist = {h.lower() for h in new.delegate_allowlist}
    added_delegates = new_allowlist - old_allowlist
    removed_delegates = old_allowlist - new_allowlist
    if added_delegates:
        # Allowing more code hashes is LOOSEN
        has_loosen = True
    if removed_delegates:
        # Removing allowed code hashes is TIGHTEN
        has_tighten = True

    # 6. Compare owned addresses (monitored hot wallets)
    old_owned = {a.lower() for a in old.owned_addresses}
    new_owned = {a.lower() for a in new.owned_addresses}
    added_owned = new_owned - old_owned
    removed_owned = old_owned - new_owned
    if added_owned:
        # Monitoring more addresses is TIGHTEN
        has_tighten = True
    if removed_owned:
        # Removing protection is LOOSEN
        has_loosen = True

    # 7. Compare wallet group operation modes
    all_groups = set(old.wallet_groups.keys()) | set(new.wallet_groups.keys())
    for g in all_groups:
        old_grp = old.wallet_groups.get(g)
        new_grp = new.wallet_groups.get(g)
        if old_grp and new_grp:
            old_rank = MODE_SEVERITY.get(old_grp.mode, 0)
            new_rank = MODE_SEVERITY.get(new_grp.mode, 0)
            if new_rank < old_rank:
                # E.g. ENFORCE -> SHADOW or SHADOW -> SIMULATION is LOOSEN
                has_loosen = True
            elif new_rank > old_rank:
                # E.g. SIMULATION -> ENFORCE is TIGHTEN
                has_tighten = True
        elif old_grp and not new_grp:
            # Group removed
            has_loosen = True
        elif not old_grp and new_grp:
            # Group added under protection
            has_tighten = True

    # 8. Compare time-lock policy
    if new.time_lock.timelock_minutes < old.time_lock.timelock_minutes:
        has_loosen = True
    elif new.time_lock.timelock_minutes > old.time_lock.timelock_minutes:
        has_tighten = True

    if new.time_lock.min_amount_usd > old.time_lock.min_amount_usd:
        has_loosen = True
    elif new.time_lock.min_amount_usd < old.time_lock.min_amount_usd:
        has_tighten = True

    if new.time_lock.delay_seconds < old.time_lock.delay_seconds:
        has_loosen = True
    elif new.time_lock.delay_seconds > old.time_lock.delay_seconds:
        has_tighten = True

    all_tl_assets = set(old.time_lock.timelock_threshold.keys()) | set(new.time_lock.timelock_threshold.keys())
    for a in all_tl_assets:
        old_th = old.time_lock.timelock_threshold.get(a)
        new_th = new.time_lock.timelock_threshold.get(a)
        if old_th is not None and new_th is not None:
            if new_th > old_th:
                has_loosen = True
            elif new_th < old_th:
                has_tighten = True
        elif old_th is not None and new_th is None:
            has_loosen = True
        elif old_th is None and new_th is not None:
            has_tighten = True

    # 9. Compare risk weights
    all_rules = set(old.risk_weights.keys()) | set(new.risk_weights.keys())
    for r in all_rules:
        old_w = old.risk_weights.get(r, 0)
        new_w = new.risk_weights.get(r, 0)
        if new_w < old_w:
            has_loosen = True
        elif new_w > old_w:
            has_tighten = True

    # 10. Compare wallet exposure balance thresholds (Milestone S29 / F11)
    all_exp_wallets = set(old.wallet_exposure.keys()) | set(new.wallet_exposure.keys())
    for w in all_exp_wallets:
        old_exp = old.wallet_exposure.get(w)
        new_exp = new.wallet_exposure.get(w)
        if old_exp and new_exp:
            # Raising max_hot_balance allows more funds in hot wallet => LOOSEN. Lowering => TIGHTEN.
            if new_exp.max_hot_balance > old_exp.max_hot_balance:
                has_loosen = True
            elif new_exp.max_hot_balance < old_exp.max_hot_balance:
                has_tighten = True

            # Raising top_up_threshold triggers earlier top-ups => LOOSEN. Lowering => TIGHTEN.
            if new_exp.top_up_threshold > old_exp.top_up_threshold:
                has_loosen = True
            elif new_exp.top_up_threshold < old_exp.top_up_threshold:
                has_tighten = True
        elif old_exp and not new_exp:
            has_loosen = True
        elif not old_exp and new_exp:
            has_tighten = True

    # 11. Compare pricing sanity policy (Milestone S31 / F13)
    if hasattr(old, "pricing") and hasattr(new, "pricing"):
        if new.pricing.max_price_deviation_pct > old.pricing.max_price_deviation_pct:
            has_loosen = True
        elif new.pricing.max_price_deviation_pct < old.pricing.max_price_deviation_pct:
            has_tighten = True

        if new.pricing.max_price_age_seconds > old.pricing.max_price_age_seconds:
            has_loosen = True
        elif new.pricing.max_price_age_seconds < old.pricing.max_price_age_seconds:
            has_tighten = True

        if old.pricing.unpriced_action != new.pricing.unpriced_action:
            if old.pricing.unpriced_action == "DENY" and new.pricing.unpriced_action == "HOLD":
                has_loosen = True
            elif old.pricing.unpriced_action == "HOLD" and new.pricing.unpriced_action == "DENY":
                has_tighten = True

    # 12. Compare behavioral baselines policy (Milestone S32 / F15)
    if hasattr(old, "baselines") and hasattr(new, "baselines"):
        if old.baselines.enabled and not new.baselines.enabled:
            has_loosen = True
        elif not old.baselines.enabled and new.baselines.enabled:
            has_tighten = True

        if new.baselines.min_history_days > old.baselines.min_history_days:
            has_loosen = True
        elif new.baselines.min_history_days < old.baselines.min_history_days:
            has_tighten = True

        if new.baselines.low_history_weight < old.baselines.low_history_weight:
            has_loosen = True
        elif new.baselines.low_history_weight > old.baselines.low_history_weight:
            has_tighten = True

        if new.baselines.volume_multiplier_threshold > old.baselines.volume_multiplier_threshold:
            has_loosen = True
        elif new.baselines.volume_multiplier_threshold < old.baselines.volume_multiplier_threshold:
            has_tighten = True

        if new.baselines.volume_high_weight < old.baselines.volume_high_weight:
            has_loosen = True
        elif new.baselines.volume_high_weight > old.baselines.volume_high_weight:
            has_tighten = True

        if new.baselines.new_destination_burst_threshold > old.baselines.new_destination_burst_threshold:
            has_loosen = True
        elif new.baselines.new_destination_burst_threshold < old.baselines.new_destination_burst_threshold:
            has_tighten = True

        if new.baselines.new_destination_burst_weight < old.baselines.new_destination_burst_weight:
            has_loosen = True
        elif new.baselines.new_destination_burst_weight > old.baselines.new_destination_burst_weight:
            has_tighten = True

        if new.baselines.size_outlier_weight < old.baselines.size_outlier_weight:
            has_loosen = True
        elif new.baselines.size_outlier_weight > old.baselines.size_outlier_weight:
            has_tighten = True

        if new.baselines.off_hours_threshold_usd > old.baselines.off_hours_threshold_usd:
            has_loosen = True
        elif new.baselines.off_hours_threshold_usd < old.baselines.off_hours_threshold_usd:
            has_tighten = True

        if new.baselines.off_hours_weight < old.baselines.off_hours_weight:
            has_loosen = True
        elif new.baselines.off_hours_weight > old.baselines.off_hours_weight:
            has_tighten = True

        old_oh = set(old.baselines.off_hours)
        new_oh = set(new.baselines.off_hours)
        if len(new_oh) < len(old_oh) or (old_oh - new_oh):
            has_loosen = True
        if len(new_oh) > len(old_oh) or (new_oh - old_oh):
            has_tighten = True

    if has_loosen and has_tighten:
        return ChangeClassification.MIXED
    if has_loosen:
        return ChangeClassification.LOOSEN
    if has_tighten:
        return ChangeClassification.TIGHTEN

    # If exactly identical, consider TIGHTEN (no approval quorum needed)
    return ChangeClassification.TIGHTEN
