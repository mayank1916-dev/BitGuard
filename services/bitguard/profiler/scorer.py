"""Risk scoring logic and diagnostic reason evaluation for address profiles (Milestone S27).

Invariants:
- Invariant #3: Fail-Closed Default. Unprofiled destinations add ELEVATED_RISK_UNPROFILED weight, never 'safe'.
- Direct local list matches can hard-deny if policy specifies.
- Age, first-time status, and taint are heuristics: they contribute weight, never hard-deny.
"""

import logging
from typing import Any

from services.bitguard.profiler.models import AddressProfile, ProfileScoreResult

logger = logging.getLogger("bitguard.profiler.scorer")

# Default heuristic weights (overridable in policy.risk_weights)
DEFAULT_RISK_WEIGHTS: dict[str, int] = {
    "LIST_MATCH": 100,
    "KNOWN_BAD_BYTECODE": 85,
    "NEW_CONTRACT": 30,
    "FIRST_TIME_DESTINATION": 20,
    "TAINT_EXPOSURE": 40,
    "ELEVATED_RISK_UNPROFILED": 25,
}


class ProfileScorer:
    """Evaluates an AddressProfile against configurable policy weights."""

    def __init__(self, default_weights: dict[str, int] | None = None) -> None:
        self.default_weights = dict(DEFAULT_RISK_WEIGHTS)
        if default_weights:
            self.default_weights.update(default_weights)

    def score_profile(
        self,
        profile: AddressProfile | None,
        is_first_time: bool = False,
        policy_weights: dict[str, int] | None = None,
        hard_deny_on_list_match: bool = True,
    ) -> ProfileScoreResult:
        """Calculates 0-100 risk score and generates diagnostic reasons."""
        weights = dict(self.default_weights)
        if policy_weights:
            weights.update(policy_weights)

        # -------------------------------------------------------------
        # Case A: Missing Profile (Cache Miss) -> ELEVATED_RISK_UNPROFILED
        # -------------------------------------------------------------
        if profile is None:
            unprofiled_weight = weights.get("ELEVATED_RISK_UNPROFILED", 25)
            reason = {
                "code": "ELEVATED_RISK_UNPROFILED",
                "weight": unprofiled_weight,
                "detail": "Address profile not found in cache; unprofiled destination adds elevated risk.",
            }
            return ProfileScoreResult(
                risk_score=min(100, unprofiled_weight),
                is_hard_deny=False,
                reasons=[reason],
                is_unprofiled=True,
            )

        # -------------------------------------------------------------
        # Case B: Profile Available -> Evaluate Heuristics & Lists
        # -------------------------------------------------------------
        reasons: list[dict[str, Any]] = []
        is_hard_deny = False

        # 1. Direct Sanctions / Blocklist match
        if profile.is_sanctioned or profile.is_blocked:
            list_name = "SANCTIONS" if profile.is_sanctioned else "BLOCKLIST"
            list_weight = weights.get("LIST_MATCH", 100)
            reasons.append({
                "code": "LIST_MATCH",
                "weight": list_weight,
                "detail": f"Destination address matches local {list_name} registry.",
            })
            if hard_deny_on_list_match or list_weight >= 90:
                is_hard_deny = True

        # 2. Known-bad bytecode match
        if profile.is_known_bad_code:
            code_weight = weights.get("KNOWN_BAD_BYTECODE", 85)
            reasons.append({
                "code": "KNOWN_BAD_BYTECODE",
                "weight": code_weight,
                "detail": f"Contract code hash '{profile.code_hash}' matched known malicious bytecode database.",
            })
            if code_weight >= 90:
                is_hard_deny = True

        # 3. Newly deployed contract heuristic (< 7 days or < 50,000 blocks)
        if profile.is_contract and profile.contract_age_days is not None:
            if profile.contract_age_days < 7.0:
                contract_weight = weights.get("NEW_CONTRACT", 30)
                reasons.append({
                    "code": "NEW_CONTRACT",
                    "weight": contract_weight,
                    "detail": (
                        f"Destination is a recently deployed contract "
                        f"(age: {profile.contract_age_days:.1f} days, {profile.contract_age_blocks or 0} blocks)."
                    ),
                })

        # 4. First-time destination for this hot-wallet
        if is_first_time:
            first_time_weight = weights.get("FIRST_TIME_DESTINATION", 20)
            reasons.append({
                "code": "FIRST_TIME_DESTINATION",
                "weight": first_time_weight,
                "detail": "Destination address has never been sent to previously by this wallet.",
            })

        # 5. Taint exposure score from AML provider
        if profile.taint_exposure_score > 20.0:
            taint_weight = weights.get("TAINT_EXPOSURE", 40)
            reasons.append({
                "code": "TAINT_EXPOSURE",
                "weight": taint_weight,
                "detail": (
                    f"Destination exhibits high AML taint exposure "
                    f"({profile.taint_exposure_score:.1f}/100 from {profile.taint_provider})."
                ),
            })

        # Calculate total combined risk score, capped at 100
        total_score = min(100, sum(int(r["weight"]) for r in reasons))

        return ProfileScoreResult(
            risk_score=total_score,
            is_hard_deny=is_hard_deny,
            reasons=reasons,
            is_unprofiled=False,
        )


# Global default scorer instance
profile_scorer = ProfileScorer()
