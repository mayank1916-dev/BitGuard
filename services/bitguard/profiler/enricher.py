"""Cached profiler enricher integrating with DecisionEngine Stage 5 (Milestone S27).

Invariants:
- Invariant #1: Cached lookups on the fast path (microsecond reads).
- Invariant #3: Fail-Closed Default. Unprofiled destinations add ELEVATED_RISK_UNPROFILED weight.
"""

import logging

from services.bitguard.engine.enrichment import EnrichmentResult, ProfilerEnricher
from services.bitguard.engine.types import PipelineContext
from services.bitguard.profiler.models import AddressProfile
from services.bitguard.profiler.scorer import ProfileScorer, profile_scorer
from services.bitguard.profiler.worker import ProfileWorker, profile_worker

logger = logging.getLogger("bitguard.profiler.enricher")


class CachedProfilerEnricher(ProfilerEnricher):
    """Enricher that reads pre-computed address profiles from cache on the fast path."""

    def __init__(
        self,
        worker: ProfileWorker | None = None,
        scorer: ProfileScorer | None = None,
    ) -> None:
        self.worker: ProfileWorker = worker or profile_worker
        self.scorer: ProfileScorer = scorer or profile_scorer

    def enrich(self, context: PipelineContext) -> EnrichmentResult:
        """Inspects recipient address profile on the fast path."""
        # 1. Resolve destination address
        destination: str = ""
        if context.decoded_tx:
            destination = context.decoded_tx.to_address or ""
            if not destination and context.decoded_tx.calls:
                destination = context.decoded_tx.calls[0].to or ""
        if not destination and hasattr(context.request, "destination"):
            dest_attr = getattr(context.request, "destination", None)
            destination = str(dest_attr) if dest_attr else ""
        if not destination and "destination" in context.request.metadata:
            destination = str(context.request.metadata["destination"])

        if not destination:
            # Contract creation / deployment or no destination
            return EnrichmentResult(
                configured=True,
                risk_weight=0,
                reason_code="NO_DESTINATION_SPECIFIED",
                detail="Transaction does not specify a destination address (e.g. contract deployment).",
            )

        # 2. Resolve wallet and chain
        wallet: str = ""
        if context.decoded_tx and context.decoded_tx.from_address:
            wallet = context.decoded_tx.from_address
        elif context.request.wallet:
            wallet = context.request.wallet

        chain = "ethereum"
        if context.decoded_tx and context.decoded_tx.chain:
            chain = context.decoded_tx.chain
        elif context.request.chain:
            chain = context.request.chain

        # 3. Read cached profile (fast path, non-blocking)
        profile: AddressProfile | None = self.worker.get_cached_profile(chain, destination)

        # 4. Check first-time destination heuristic
        is_first_time = self.worker.is_first_time_destination(wallet, destination)

        # 5. Extract active policy risk weights if configured
        policy_weights: dict[str, int] | None = None
        if "policy" in context.metadata and context.metadata["policy"] and hasattr(context.metadata["policy"], "risk_weights"):
            policy_weights = context.metadata["policy"].risk_weights
        elif hasattr(context, "policy") and context.policy and hasattr(context.policy, "risk_weights"):
            policy_weights = context.policy.risk_weights

        # 6. Score profile
        score_res = self.scorer.score_profile(
            profile=profile,
            is_first_time=is_first_time,
            policy_weights=policy_weights,
        )

        # Primary reason code and detail
        primary_code = score_res.reasons[0]["code"] if score_res.reasons else None
        primary_detail = score_res.reasons[0]["detail"] if score_res.reasons else None

        return EnrichmentResult(
            configured=True,
            risk_weight=score_res.risk_score,
            reason_code=primary_code,
            detail=primary_detail,
            data={
                "risk_score": score_res.risk_score,
                "is_hard_deny": score_res.is_hard_deny,
                "reasons": score_res.reasons,
                "is_unprofiled": score_res.is_unprofiled,
                "destination": destination,
                "profile": profile.model_dump() if profile else None,
            },
        )
