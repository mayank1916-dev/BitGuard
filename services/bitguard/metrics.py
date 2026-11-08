"""Prometheus metrics exporter for BitGuard operational observability (Milestone S24 / F17).

Provides Prometheus metrics for:
- Decision counts by verdict and chain
- Per-stage latency histograms (decode, policy_eval, reservation, token_issue)
- Reservation failures
- Unmatched intents
- Token issues and refusals
- Circuit breaker state
- Heartbeat age
"""

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.responses import Response

# Counters
DECISIONS_TOTAL = Counter(
    "bitguard_decisions_total",
    "Total policy decisions rendered by BitGuard",
    ["verdict", "chain"],
)

RESERVATION_FAILURES_TOTAL = Counter(
    "bitguard_reservation_failures_total",
    "Total balance limit reservation failures",
    ["asset", "chain"],
)

UNMATCHED_INTENTS_TOTAL = Counter(
    "bitguard_unmatched_intents_total",
    "Total signing requests with no matching ledger intent",
    ["chain"],
)

TOKEN_ISSUES_TOTAL = Counter(
    "bitguard_token_issues_total",
    "Total BitGuard approval tokens successfully issued",
    ["kid"],
)

TOKEN_REFUSALS_TOTAL = Counter(
    "bitguard_token_refusals_total",
    "Total approval token refusals (e.g. breaker lockdown, policy deny)",
    ["reason"],
)

# Latency Histograms
STAGE_DURATION_SECONDS = Histogram(
    "bitguard_stage_duration_seconds",
    "Duration of individual pipeline stages in seconds",
    ["stage"],
    buckets=(0.001, 0.002, 0.005, 0.010, 0.015, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0),
)

# Operational State Gauges
BREAKER_STATE = Gauge(
    "bitguard_breaker_state",
    "Current circuit breaker state (0=NORMAL, 1=ELEVATED, 2=HOLD, 3=LOCKDOWN)",
)

HEARTBEAT_AGE_SECONDS = Gauge(
    "bitguard_heartbeat_age_seconds",
    "Seconds elapsed since last successful heartbeat to Signer Shim",
)

BREAKER_STATE_MAP = {
    "NORMAL": 0,
    "ELEVATED": 1,
    "HOLD": 2,
    "LOCKDOWN": 3,
}


def record_decision(verdict: str, chain: str = "unknown") -> None:
    """Increments decision verdict counter."""
    DECISIONS_TOTAL.labels(verdict=verdict.upper(), chain=chain.lower()).inc()


def record_stage_duration(stage: str, duration_seconds: float) -> None:
    """Observes execution duration for a specific pipeline stage."""
    STAGE_DURATION_SECONDS.labels(stage=stage).observe(duration_seconds)


def record_reservation_failure(asset: str = "unknown", chain: str = "unknown") -> None:
    """Increments limit reservation failure counter."""
    RESERVATION_FAILURES_TOTAL.labels(asset=asset.upper(), chain=chain.lower()).inc()


def record_unmatched_intent(chain: str = "unknown") -> None:
    """Increments unmatched ledger intent counter."""
    UNMATCHED_INTENTS_TOTAL.labels(chain=chain.lower()).inc()


def record_token_issue(kid: str = "default") -> None:
    """Increments issued approval token counter."""
    TOKEN_ISSUES_TOTAL.labels(kid=kid).inc()


def record_token_refusal(reason: str = "denied") -> None:
    """Increments token refusal counter."""
    TOKEN_REFUSALS_TOTAL.labels(reason=reason).inc()


def update_breaker_state_metric(state: str) -> None:
    """Updates circuit breaker state gauge."""
    val = BREAKER_STATE_MAP.get(state.upper(), 0)
    BREAKER_STATE.set(val)


def update_heartbeat_age_metric(age_seconds: float) -> None:
    """Updates dead-man heartbeat age gauge."""
    HEARTBEAT_AGE_SECONDS.set(max(0.0, age_seconds))


def get_metrics_response() -> Response:
    """Generates Prometheus standard metrics text exposition."""
    # Ensure breaker gauge has an initial value
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
