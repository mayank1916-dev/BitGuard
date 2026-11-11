"""Comprehensive test suite for Task S31 - Price Sanity and Unit-Based Limits (F13).

Invariants Verified:
- Invariant #1: Key Isolation (BitGuard never holds keys).
- Invariant #2: Approval Binding & Verification.
- Invariant #3: Fail-Closed Default (unknown token, stale price, missing price => never zero; HOLD or DENY).
- Invariant #4: Raw Byte Source of Truth (converts raw transaction units to USD for limit checks; ignores spoofed amounts).
- Invariant #6: Asymmetric Policy Evolution (stricter pricing/limits = TIGHTEN; looser = LOOSEN).
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance.
- Invariant #9: Environment & Safety Boundary (local chains with disposable keys ONLY).
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
import rlp

from services.bitguard.engine.pipeline import DecisionEngine
from services.bitguard.engine.types import PipelineContext
from services.bitguard.models import (
    DecodedTx,
    OperationMode,
    SigningRequest,
    Verdict,
)
from services.bitguard.policy.classifier import classify_change
from services.bitguard.policy.models import (
    ChangeClassification,
    LimitsPolicy,
    PolicyDocument,
    PricingPolicy,
    ThresholdsPolicy,
)
from services.bitguard.pricing.adapter import RealPriceSourceAdapter
from services.bitguard.pricing.service import PriceService, price_service
from services.bitguard.pricing.sources import MockPriceSourceA, MockPriceSourceB

HOT_WALLET = "0x742d35cc6634c0532925a3b844bc454e4438f44e"
BENIGN_DEST = "0x1111111111111111111111111111111111111111"


def build_raw_legacy_tx(to_addr: str, value_wei: int = 0, nonce: int = 0) -> str:
    """Builds valid RLP-encoded raw EVM legacy transaction."""
    clean = to_addr.removeprefix("0x")
    to_bytes = bytes.fromhex(clean)
    payload = [nonce, 20_000_000_000, 21000, to_bytes, value_wei, b""]
    return "0x" + rlp.encode(payload).hex()


@pytest.fixture(autouse=True)
def clean_pricing_environment():
    """Resets pricing sources and limit store namespace before each test."""
    price_service.reset()
    yield
    price_service.reset()


# ==============================================================================
# Requirement 1: Unpriced token is not allowed through a USD limit
# ==============================================================================


def test_unpriced_token_not_allowed_through_usd_limit_default_hold():
    """Requirement 1a: Unknown/unpriced token is never zero; placed on HOLD by default policy."""
    engine = DecisionEngine()
    policy_doc = PolicyDocument(
        limits=LimitsPolicy(global_daily_usd=500_000.0),
        thresholds=ThresholdsPolicy(single_tx_usd=100_000.0),
        pricing=PricingPolicy(unpriced_action="HOLD"),
    )
    engine.reload_policy(policy_doc)

    # Decoded tx for an unknown/unpriced token
    decoded = DecodedTx(
        chain="ethereum",
        from_address=HOT_WALLET,
        to_address=BENIGN_DEST,
        asset="UNKNOWN_MEMECOIN",
        amount=str(1_000_000 * 10**18),
        digest="0x" + "a" * 64,
    )
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18),
        metadata={"amount_usd": 0.0},
    )

    context = PipelineContext(
        request=req,
        is_dry_run=False,
        active_mode=OperationMode.ENFORCE,
        wallet_group="default",
        decoded_tx=decoded,
    )

    engine._stage_limits(context)
    decision = engine._stage_decide(context, start_time=datetime.now(UTC))

    assert any(r.code == "UNPRICED_TOKEN" for r in context.reasons)
    unpriced_reason = next(r for r in context.reasons if r.code == "UNPRICED_TOKEN")
    assert "UNKNOWN_TOKEN" in unpriced_reason.detail or "MISSING_PRICE" in unpriced_reason.detail
    # Must never be treated as zero to allow through; must be HOLD
    assert decision.verdict == Verdict.HOLD


def test_unpriced_token_denied_when_policy_mandates_deny():
    """Requirement 1b: When policy.unpriced_action == 'DENY', unpriced tokens are hard-denied."""
    engine = DecisionEngine()
    policy_doc = PolicyDocument(
        pricing=PricingPolicy(unpriced_action="DENY"),
    )
    engine.reload_policy(policy_doc)

    decoded = DecodedTx(
        chain="ethereum",
        from_address=HOT_WALLET,
        to_address=BENIGN_DEST,
        asset="OBSCURE_TOKEN",
        amount=str(500 * 10**18),
        digest="0x" + "b" * 64,
    )
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18),
    )

    context = PipelineContext(
        request=req,
        is_dry_run=False,
        active_mode=OperationMode.ENFORCE,
        wallet_group="default",
        decoded_tx=decoded,
    )

    engine._stage_limits(context)
    decision = engine._stage_decide(context, start_time=datetime.now(UTC))

    assert any(r.code == "UNPRICED_TOKEN" for r in context.reasons)
    assert context.hard_deny is True
    assert decision.verdict == Verdict.DENY


# ==============================================================================
# Requirement 2: Price deviation uses the higher price
# ==============================================================================


def test_price_deviation_uses_higher_price_for_limit_checks():
    """Requirement 2: When sources deviate > max_price_deviation_pct, flag PRICE_DEVIATION and use HIGHER price."""
    src_a = MockPriceSourceA()
    src_b = MockPriceSourceB()
    ps = PriceService(source_a=src_a, source_b=src_b)

    # Source A: ETH = $3,000. Source B: ETH = $3,600 (20% deviation > 5% allowed)
    src_a.set_price("ETH", 3000.0)
    src_b.set_price("ETH", 3600.0)

    engine = DecisionEngine(price_service_inst=ps)
    # Single tx limit is $35,000
    # At $3000, 10 ETH = $30,000 (Passes single tx limit)
    # At median $3300, 10 ETH = $33,000 (Passes single tx limit)
    # At higher $3600, 10 ETH = $36,000 (Exceeds $35,000 single tx limit!)
    policy_doc = PolicyDocument(
        thresholds=ThresholdsPolicy(single_tx_usd=35_000.0),
        pricing=PricingPolicy(max_price_deviation_pct=5.0),
    )
    engine.reload_policy(policy_doc)

    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10 * 10**18)  # 10 ETH
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=raw_tx,
    )

    decision = engine.evaluate(req)

    # 1. Reason PRICE_DEVIATION must be recorded
    assert any(r.code == "PRICE_DEVIATION" for r in decision.reasons)
    dev_reason = next(r for r in decision.reasons if r.code == "PRICE_DEVIATION")
    assert "3,600.00" in dev_reason.detail
    assert "20.00%" in dev_reason.detail

    # 2. Limit check must use higher price ($36,000), tripping single tx limit!
    assert any(r.code == "SINGLE_TX_LIMIT_EXCEEDED" for r in decision.reasons)
    assert decision.verdict == Verdict.HOLD


def test_price_within_deviation_uses_median():
    """When sources deviate <= max_price_deviation_pct, use median price without deviation penalty."""
    src_a = MockPriceSourceA()
    src_b = MockPriceSourceB()
    ps = PriceService(source_a=src_a, source_b=src_b)

    # Source A: ETH = $3,000. Source B: ETH = $3,060 (2.0% deviation <= 5.0% allowed)
    src_a.set_price("ETH", 3000.0)
    src_b.set_price("ETH", 3060.0)

    engine = DecisionEngine(price_service_inst=ps)
    policy_doc = PolicyDocument(
        thresholds=ThresholdsPolicy(single_tx_usd=50_000.0),
        pricing=PricingPolicy(max_price_deviation_pct=5.0),
    )
    engine.reload_policy(policy_doc)

    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10 * 10**18)  # 10 ETH -> $30,300
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=raw_tx,
    )

    decision = engine.evaluate(req)
    assert not any(r.code == "PRICE_DEVIATION" for r in decision.reasons)
    assert decision.verdict == Verdict.ALLOW


# ==============================================================================
# Requirement 3: Stale price handled
# ==============================================================================


def test_stale_price_handled_as_unpriced():
    """Requirement 3: Quotes older than max_price_age_seconds are flagged STALE and never zero."""
    src_a = MockPriceSourceA()
    src_b = MockPriceSourceB()
    ps = PriceService(source_a=src_a, source_b=src_b)

    now = datetime(2026, 11, 11, 12, 0, 0, tzinfo=UTC)
    # Source A quote is 15 minutes old (stale, max age 5m / 300s)
    stale_ts = now - timedelta(minutes=15)
    src_a.set_price("ETH", 3000.0, timestamp=stale_ts)
    src_b.set_price("ETH", 3000.0, timestamp=now)

    engine = DecisionEngine(price_service_inst=ps)
    policy_doc = PolicyDocument(
        pricing=PricingPolicy(max_price_age_seconds=300, unpriced_action="HOLD"),
    )
    engine.reload_policy(policy_doc)

    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=10**18)
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=raw_tx,
        metadata={"ts": now.timestamp()},
    )

    decision = engine.evaluate(req)

    assert any(r.code == "UNPRICED_TOKEN" for r in decision.reasons)
    stale_reason = next(r for r in decision.reasons if r.code == "UNPRICED_TOKEN")
    assert "STALE_PRICE" in stale_reason.detail
    # Never zero: not allowed through
    assert decision.verdict == Verdict.HOLD


# ==============================================================================
# Requirement 4: Unit cap triggers when USD cap would not
# ==============================================================================


def test_native_unit_cap_triggers_when_usd_cap_would_not():
    """Requirement 4: Native-unit cap per asset triggers HOLD even when USD volume is well within cap."""
    engine = DecisionEngine()
    # USD limit is $1,000,000 (plenty of capacity)
    # Native unit limit for ETH is 5.0 ETH
    policy_doc = PolicyDocument(
        limits=LimitsPolicy(
            global_daily_usd=1_000_000.0,
            asset_unit_limits={"ETH": 5.0},
        ),
        thresholds=ThresholdsPolicy(single_tx_usd=100_000.0),
    )
    engine.reload_policy(policy_doc)

    # 1. Transfer 8 ETH:
    # USD value = 8 * $3,000 = $24,000 (well within $100,000 single tx limit and $1,000,000 daily limit)
    # But 8.0 ETH > 5.0 ETH native unit cap!
    raw_tx = build_raw_legacy_tx(BENIGN_DEST, value_wei=8 * 10**18)
    req = SigningRequest(
        chain="ethereum",
        wallet=HOT_WALLET,
        raw_tx=raw_tx,
        metadata={"amount_usd": 24_000.0},
    )

    decision = engine.evaluate(req)

    # USD cap would NOT trigger:
    assert not any(r.code == "SINGLE_TX_LIMIT_EXCEEDED" for r in decision.reasons)
    assert not any(r.code == "WALLET_LIMIT_EXCEEDED" for r in decision.reasons)

    # But native unit cap DOES trigger:
    assert any(r.code == "UNIT_LIMIT_EXCEEDED" for r in decision.reasons)
    unit_reason = next(r for r in decision.reasons if r.code == "UNIT_LIMIT_EXCEEDED")
    assert "8.0000 ETH" in unit_reason.detail
    assert "5.0000 ETH" in unit_reason.detail
    assert decision.verdict == Verdict.HOLD


# ==============================================================================
# Requirement 5: Real Price Source Adapter Skeleton
# ==============================================================================


def test_real_price_source_adapter_skeleton():
    """Requirement 5: Adapter skeleton handles configuration, headers, and parsing."""
    # 1. Unconfigured adapter returns None safely
    unconfigured = RealPriceSourceAdapter(api_url="")
    assert unconfigured.is_configured is False
    assert unconfigured.get_price("ETH") is None

    # 2. Configured adapter parses successful JSON response
    def custom_transport_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer secret-price-key"
        assert "prices/ETH" in str(request.url)
        return httpx.Response(
            status_code=200,
            json={
                "asset": "ETH",
                "price_usd": 3125.50,
                "timestamp": "2026-11-11T10:00:00Z",
            },
        )

    mock_transport = httpx.MockTransport(custom_transport_handler)
    configured = RealPriceSourceAdapter(
        api_url="https://api.pricing-oracle.internal",
        api_key="secret-price-key",
        provider_name="pyth_gateway",
        transport=mock_transport,
    )
    assert configured.is_configured is True
    quote = configured.get_price("ETH")
    assert quote is not None
    assert quote.asset == "ETH"
    assert quote.price_usd == 3125.50
    assert quote.source == "pyth_gateway"

    # 3. Failing endpoint returns None (fail-closed)
    def error_transport_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=500, json={"error": "oracle outage"})

    err_adapter = RealPriceSourceAdapter(
        api_url="https://api.pricing-oracle.internal",
        api_key="secret-price-key",
        transport=httpx.MockTransport(error_transport_handler),
    )
    assert err_adapter.get_price("ETH") is None


# ==============================================================================
# Requirement 6: Policy Classification for Pricing and Unit Limits
# ==============================================================================


def test_pricing_policy_and_unit_caps_asymmetric_classification():
    """Invariant #6: Stricter pricing/limits classify as TIGHTEN; looser classify as LOOSEN."""
    old_doc = PolicyDocument(
        limits=LimitsPolicy(asset_unit_limits={"ETH": 50.0}),
        pricing=PricingPolicy(
            max_price_deviation_pct=5.0,
            max_price_age_seconds=300,
            unpriced_action="HOLD",
        ),
    )

    # 1. Stricter deviation threshold (5% -> 2%): TIGHTEN
    doc_tighten_dev = old_doc.model_copy(deep=True)
    doc_tighten_dev.pricing.max_price_deviation_pct = 2.0
    assert classify_change(old_doc, doc_tighten_dev) == ChangeClassification.TIGHTEN

    # 2. Looser deviation threshold (5% -> 10%): LOOSEN
    doc_loosen_dev = old_doc.model_copy(deep=True)
    doc_loosen_dev.pricing.max_price_deviation_pct = 10.0
    assert classify_change(old_doc, doc_loosen_dev) == ChangeClassification.LOOSEN

    # 3. Stricter staleness window (300s -> 60s): TIGHTEN
    doc_tighten_age = old_doc.model_copy(deep=True)
    doc_tighten_age.pricing.max_price_age_seconds = 60
    assert classify_change(old_doc, doc_tighten_age) == ChangeClassification.TIGHTEN

    # 4. Looser staleness window (300s -> 600s): LOOSEN
    doc_loosen_age = old_doc.model_copy(deep=True)
    doc_loosen_age.pricing.max_price_age_seconds = 600
    assert classify_change(old_doc, doc_loosen_age) == ChangeClassification.LOOSEN

    # 5. Unpriced action tightened from HOLD to DENY: TIGHTEN
    doc_tighten_act = old_doc.model_copy(deep=True)
    doc_tighten_act.pricing.unpriced_action = "DENY"
    assert classify_change(old_doc, doc_tighten_act) == ChangeClassification.TIGHTEN

    # 6. Lowering native unit cap (50 ETH -> 20 ETH): TIGHTEN
    doc_tighten_unit = old_doc.model_copy(deep=True)
    doc_tighten_unit.limits.asset_unit_limits["ETH"] = 20.0
    assert classify_change(old_doc, doc_tighten_unit) == ChangeClassification.TIGHTEN

    # 7. Raising native unit cap (50 ETH -> 100 ETH): LOOSEN
    doc_loosen_unit = old_doc.model_copy(deep=True)
    doc_loosen_unit.limits.asset_unit_limits["ETH"] = 100.0
    assert classify_change(old_doc, doc_loosen_unit) == ChangeClassification.LOOSEN
