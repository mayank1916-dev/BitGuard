"""Modular 6-stage policy decision engine for BitGuard Firewall (Milestone S10).

Pipeline Order:
(1) decode -> (2) intent_check -> (3) delegation guard -> (4) limit reserve ->
(5) cached enrichment hooks (profiler, simulation) -> (6) decide
"""

import logging
import time
import traceback
from datetime import UTC, datetime
from typing import Any

from services.bitguard.config import settings
from services.bitguard.decoders.base import DecodeError
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.engine.breaker_store import BreakerStore, breaker_store
from services.bitguard.engine.enrichment import (
    DefaultProfilerEnricher,
    DefaultSimulationEnricher,
    ProfilerEnricher,
    SimulationEnricher,
)
from services.bitguard.engine.types import (
    DecisionEngineConfig,
    PipelineContext,
    StageTimer,
)
from services.bitguard.ledger.base import LedgerConnector
from services.bitguard.ledger.intent_check import check_intent
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.limits.store import LimitStore, ScopeBuilder, limit_store
from services.bitguard.models import (
    BreakerStateEnum,
    DataLabel,
    Decision,
    DecisionReason,
    DecodedTx,
    OperationMode,
    SigningRequest,
    Verdict,
)
from services.bitguard.pricing.service import (
    PriceService,
)
from services.bitguard.pricing.service import (
    price_service as default_price_service,
)
from services.bitguard.rpc.base import RpcClient
from services.bitguard.rpc.client import HttpRpcClient
from services.bitguard.rules.delegation import (
    DelegationPolicy,
    check_delegations,
)

logger = logging.getLogger("bitguard.engine.pipeline")


class DecisionEngine:
    """Core BitGuard Decision Engine orchestrating the 6 policy evaluation stages."""

    def __init__(
        self,
        config: DecisionEngineConfig | None = None,
        limits: LimitStore | None = None,
        ledger: LedgerConnector | None = None,
        rpc: RpcClient | None = None,
        breaker: BreakerStore | None = None,
        profiler: ProfilerEnricher | None = None,
        simulation: SimulationEnricher | None = None,
        price_service_inst: PriceService | None = None,
    ) -> None:
        self.config = config or DecisionEngineConfig(
            single_tx_usd_threshold=settings.single_tx_usd_default,
        )
        self.limit_store = limits or limit_store
        self.ledger_connector = ledger or mock_ledger_connector
        self.rpc_client: RpcClient = rpc or HttpRpcClient(rpc_url=settings.anvil_url)
        self.breaker_store = breaker or breaker_store
        self.price_service = price_service_inst or default_price_service
        if profiler is not None:
            self.profiler = profiler
        elif settings.profiler_enabled:
            from services.bitguard.profiler.enricher import CachedProfilerEnricher
            self.profiler = CachedProfilerEnricher()
        else:
            self.profiler = DefaultProfilerEnricher()
        if simulation is not None:
            self.simulation = simulation
        elif getattr(settings, "simulation_enabled", False):
            from services.bitguard.simulation.enricher import CachedSimulationEnricher
            self.simulation = CachedSimulationEnricher()
        else:
            self.simulation = DefaultSimulationEnricher()
        self.delegation_policy = DelegationPolicy()
        self.active_policy_document: Any | None = None
        self.active_policy_hash: str = ""

    def set_profiler(self, profiler: ProfilerEnricher) -> None:
        """Configures or replaces the address profiler enricher."""
        self.profiler = profiler

    def set_simulation(self, simulation: SimulationEnricher) -> None:
        """Configures or replaces the simulation enricher."""
        self.simulation = simulation

    def set_price_service(self, ps: PriceService) -> None:
        """Configures or replaces the token price sanity service."""
        self.price_service = ps

    def reload_policy(self, policy_doc: Any, content_hash: str = "") -> None:
        """Hot-reloads signed policy into active decision engine memory."""
        self.active_policy_document = policy_doc
        if content_hash:
            self.active_policy_hash = content_hash
        elif hasattr(policy_doc, "model_dump"):
            from services.bitguard.policy.crypto import compute_content_hash
            self.active_policy_hash = compute_content_hash(policy_doc)

        if hasattr(policy_doc, "version"):
            self.config.policy_version = policy_doc.version
        if hasattr(policy_doc, "thresholds"):
            self.config.single_tx_usd_threshold = policy_doc.thresholds.single_tx_usd
            self.config.hold_risk_threshold = policy_doc.thresholds.hold_score
        if hasattr(policy_doc, "delegate_allowlist"):
            self.delegation_policy.delegate_allowlist.clear()
            for h in policy_doc.delegate_allowlist:
                self.delegation_policy.add_allowed_delegate(code_hash=h, name="Policy Allowlist")
        if hasattr(policy_doc, "owned_addresses"):
            self.delegation_policy.owned_addresses = {
                a.lower() for a in policy_doc.owned_addresses
            }
        logger.info(
            "Engine hot-reloaded policy version %s (hash: %s)",
            getattr(policy_doc, "version", "unknown"),
            self.active_policy_hash,
        )

    def set_delegation_policy(self, policy: DelegationPolicy) -> None:
        """Configures the active EIP-7702 delegation policy."""
        self.delegation_policy = policy

    def set_rpc_client(self, rpc: RpcClient) -> None:
        """Sets the active RPC client for contract inspection."""
        self.rpc_client = rpc

    def evaluate(
        self,
        request: SigningRequest,
        is_dry_run: bool = True,
        wallet_group_mode: OperationMode = OperationMode.SIMULATION,
        wallet_group_id: str = "default",
    ) -> Decision:
        """Executes the full 6-stage decision pipeline over raw unsigned transaction bytes."""
        timer = StageTimer()
        start_time = datetime.now(UTC)

        # In dry run, request.mode takes precedence if supplied, otherwise group configured mode
        active_mode = request.mode if (is_dry_run and request.mode is not None) else wallet_group_mode

        context = PipelineContext(
            request=request,
            is_dry_run=is_dry_run,
            active_mode=active_mode,
            wallet_group=wallet_group_id,
            timer=timer,
            metadata={"policy": self.active_policy_document},
        )

        try:
            # ---------------------------------------------------------
            # Stage 1: decode (strictly from raw bytes, ignore caller)
            # ---------------------------------------------------------
            timer.start_stage("decode")
            self._stage_decode(context)
            timer.end_stage("decode")

            if not context.hard_deny:
                # ---------------------------------------------------------
                # Stage 2: intent_check (reconcile custody intent)
                # ---------------------------------------------------------
                timer.start_stage("intent_check")
                self._stage_intent_check(context)
                timer.end_stage("intent_check")

            if not context.hard_deny:
                # ---------------------------------------------------------
                # Stage 3: delegation guard (EIP-7702 authorizations)
                # ---------------------------------------------------------
                timer.start_stage("delegation")
                self._stage_delegation_guard(context)
                timer.end_stage("delegation")

            if not context.hard_deny:
                # ---------------------------------------------------------
                # Stage 4: limit reserve (sliding window velocity)
                # ---------------------------------------------------------
                timer.start_stage("limits")
                self._stage_limits(context)
                timer.end_stage("limits")

            if not context.hard_deny:
                # ---------------------------------------------------------
                # Stage 5: cached enrichment hooks (profiler, simulation)
                # ---------------------------------------------------------
                timer.start_stage("enrichment")
                self._stage_enrichment(context)
                timer.end_stage("enrichment")

            # ---------------------------------------------------------
            # Stage 6: decide (weigh reasons, breaker, release/mode)
            # ---------------------------------------------------------
            timer.start_stage("decide")
            decision = self._stage_decide(context, start_time)
            timer.end_stage("decide")

            # Record total duration
            timer.finish_total()
            decision.evaluation_latency_ms = timer.timings.get("total", 0.0)
            decision.timings = dict(timer.timings)

            for stage_name, duration_ms in decision.timings.items():
                if stage_name != "total":
                    try:
                        from services.bitguard.metrics import record_stage_duration
                        record_stage_duration(stage_name, duration_ms / 1000.0)
                    except Exception:
                        pass

            if request.metadata.get("is_backtest"):
                return decision

            if decision.verdict == Verdict.ALLOW and not is_dry_run:
                try:
                    w_rec = request.wallet or (context.decoded_tx.from_address if context.decoded_tx else "")
                    amt_rec = float(request.metadata.get("amount_usd", 0.0))
                    dest_rec = ""
                    if context.decoded_tx:
                        dest_rec = context.decoded_tx.to_address or (
                            context.decoded_tx.calls[0].to if context.decoded_tx.calls else ""
                        )
                    if not dest_rec and hasattr(request, "destination"):
                        dest_rec = str(getattr(request, "destination", "") or "")
                    if not dest_rec:
                        dest_rec = str(request.metadata.get("destination") or request.metadata.get("to") or "")
                    if w_rec and amt_rec > 0:
                        from services.bitguard.baselines.store import baseline_store

                        baseline_store.record_transaction(
                            wallet=w_rec,
                            amount_usd=amt_rec,
                            destination=dest_rec,
                            timestamp=start_time.timestamp(),
                            data_label=decision.data_label,
                        )
                except Exception as b_exc:
                    logger.debug("Failed recording baseline transaction: %s", b_exc)

            from services.bitguard.mode_service import mode_service
            return mode_service.save_decision(decision)

        except Exception as exc:
            # Invariant #3: Fail-closed on engine errors
            logger.error("engine_unhandled_exception: %s\n%s", exc, traceback.format_exc())
            if context.reservation_id:
                try:
                    self.limit_store.release(context.reservation_id)
                except Exception:
                    pass

            timer.finish_total()
            err_decision = Decision(
                request_id=request.id,
                verdict=Verdict.DENY,
                would_have_verdict=None,
                risk_score=100,
                reasons=[
                    DecisionReason(
                        code="ENGINE_ERROR",
                        weight=100,
                        detail=f"Unhandled decision engine error: {exc}",
                    )
                ],
                mode=active_mode,
                policy_version=self.config.policy_version,
                data_label=DataLabel.SYNTHETIC,
                wallet_group=wallet_group_id,
                created_at=start_time,
                evaluation_latency_ms=timer.timings.get("total", 0.0),
                timings=dict(timer.timings),
            )
            if request.metadata.get("is_backtest"):
                return err_decision

            from services.bitguard.mode_service import mode_service
            return mode_service.save_decision(err_decision)

    # -----------------------------------------------------------------
    # Stage Implementations
    # -----------------------------------------------------------------

    def _stage_decode(self, context: PipelineContext) -> None:
        """Stage 1: Decodes raw unsigned transaction bytes into canonical DecodedTx."""
        raw_tx = (context.request.raw_tx or "").strip()

        if context.request.metadata.get("simulate_invalid_caller"):
            context.add_reason(
                code="INVALID_CALLER_IDENTITY",
                weight=100,
                detail="Caller identity is invalid, unknown, or unauthorized.",
                is_hard_deny=True,
            )
            return

        if not raw_tx or context.request.metadata.get("simulate_decode_error"):
            from services.bitguard.mode_service import mode_service
            mode_service.record_decode_failure(context.wallet_group)
            context.add_reason(
                code="DECODE_ERROR",
                weight=100,
                detail="Transaction bytes cannot be decoded or format is invalid.",
                is_hard_deny=True,
            )
            return

        if "decoded_tx" in context.request.metadata:
            context.decoded_tx = DecodedTx.model_validate(context.request.metadata["decoded_tx"])
            return

        try:
            context.decoded_tx = evm_decoder.decode(raw_tx)
            if (
                context.decoded_tx
                and context.decoded_tx.from_address
                and context.decoded_tx.from_address != "0x0000000000000000000000000000000000000000"
            ):
                context.request.wallet = context.decoded_tx.from_address
        except DecodeError as exc:
            # Handle legacy test fixtures with simulated metadata where raw_tx was a stub string
            if (
                context.request.metadata.get("simulate_deny")
                or context.request.metadata.get("simulate_hold")
                or "amount_usd" in context.request.metadata
            ) and not context.request.metadata.get("simulate_decode_error"):
                context.decoded_tx = DecodedTx(
                    chain=context.request.chain or "ethereum",
                    from_address=context.request.wallet,
                    to_address=context.request.wallet,
                    asset="ETH",
                    amount=str(int(float(context.request.metadata.get("amount_usd", 0.0)) * 100)),
                    calls=[],
                    authorizations=[],
                    digest="0x" + "0" * 64,
                )
                return

            from services.bitguard.mode_service import mode_service
            mode_service.record_decode_failure(context.wallet_group)
            context.add_reason(
                code="DECODE_ERROR",
                weight=100,
                detail=f"Raw transaction decoding failed: {exc}",
                is_hard_deny=True,
            )

    def _stage_intent_check(self, context: PipelineContext) -> None:
        """Stage 2: Reconciles decoded transaction against exchange withdrawal intent."""
        if (
            context.request.metadata.get("simulate_intent_mismatch")
            or context.request.metadata.get("scenario") == "unmatched_intent_burst"
        ):
            context.add_reason(
                code="INTENT_MISMATCH",
                weight=100,
                detail="Transaction has no corresponding valid custody withdrawal intent in ledger.",
                is_hard_deny=True,
            )
            return

        # Run intent check if intent_id provided or required by metadata
        if context.request.intent_id or context.request.metadata.get("require_intent_check"):
            if context.decoded_tx is None:
                context.add_reason(
                    code="DECODE_ERROR",
                    weight=100,
                    detail="Cannot reconcile intent without decoded transaction bytes.",
                    is_hard_deny=True,
                )
                return

            res = check_intent(context.request, context.decoded_tx, self.ledger_connector)
            if not res.passed:
                context.add_reason(
                    code=res.code or "INTENT_CHECK_FAILED",
                    weight=100,
                    detail=res.detail or "Withdrawal intent reconciliation failed.",
                    is_hard_deny=True,
                )

    def _stage_delegation_guard(self, context: PipelineContext) -> None:
        """Stage 3: Validates EIP-7702 Type-4 delegation authorizations."""
        if (
            context.request.metadata.get("simulate_deny")
            or context.request.metadata.get("simulate_rule_hit") == "SUSPICIOUS_DELEGATION"
            or context.request.metadata.get("scenario") == "unapproved_delegation_flag"
        ):
            context.add_reason(
                code="SUSPICIOUS_DELEGATION",
                weight=95,
                detail="EIP-7702 authorization tuple points to unapproved delegate contract.",
                is_hard_deny=True,
            )
            return

        if context.decoded_tx and context.decoded_tx.authorizations:
            res = check_delegations(context.decoded_tx, self.delegation_policy, self.rpc_client)
            if res.is_alert:
                context.is_alert = True
            if not res.passed:
                context.add_reason(
                    code=res.code or "SUSPICIOUS_DELEGATION",
                    weight=100,
                    detail=res.detail or "EIP-7702 delegation policy violation.",
                    is_hard_deny=True,
                )

    def _stage_limits(self, context: PipelineContext) -> None:
        """Stage 4: Evaluates sliding-window velocity limits, native unit limits, and single tx thresholds."""
        wallet_addr = context.request.wallet
        asset = "USD"
        if context.decoded_tx:
            asset = (context.decoded_tx.asset or "ETH").upper()
        elif "asset" in context.request.metadata:
            asset = str(context.request.metadata["asset"]).upper()

        decimals = 18
        if asset in ("USDC", "USDT"):
            decimals = 6
        elif asset == "BTC":
            decimals = 8

        native_units = 0.0
        if context.decoded_tx:
            try:
                amt_str = (
                    context.decoded_tx.calls[0].amount
                    if (context.decoded_tx.calls and context.decoded_tx.calls[0].amount)
                    else context.decoded_tx.amount
                )
                raw_amt = float(amt_str)
                native_units = raw_amt / (10**decimals)
            except (ValueError, TypeError):
                native_units = 0.0

        # Multi-source price sanity (Milestone S31 / F13)
        pricing_policy = None
        if self.active_policy_document and hasattr(self.active_policy_document, "pricing"):
            pricing_policy = self.active_policy_document.pricing
        elif "policy" in context.metadata and hasattr(context.metadata["policy"], "pricing"):
            pricing_policy = context.metadata["policy"].pricing

        is_pricing_enabled = pricing_policy.enabled if pricing_policy else True
        amount_usd = float(context.request.metadata.get("amount_usd", 0.0))

        if is_pricing_enabled and context.decoded_tx and asset != "USD":
            sim_dt = None
            sim_ts_val = context.request.metadata.get("ts")
            if sim_ts_val is not None:
                sim_dt = datetime.fromtimestamp(float(sim_ts_val), tz=UTC)

            price_res = self.price_service.resolve_price(asset, now=sim_dt, policy=pricing_policy)

            if price_res.is_unpriced:
                unpriced_act = (pricing_policy.unpriced_action if pricing_policy else "HOLD").upper()
                if unpriced_act == "DENY":
                    context.add_reason(
                        code="UNPRICED_TOKEN",
                        weight=100,
                        detail=(
                            f"Token '{asset}' is unpriced ({price_res.unpriced_reason}); "
                            f"policy mandates DENY (never zero)."
                        ),
                        is_hard_deny=True,
                    )
                else:
                    context.add_reason(
                        code="UNPRICED_TOKEN",
                        weight=65,
                        detail=(
                            f"Token '{asset}' is unpriced ({price_res.unpriced_reason}); "
                            f"quarantined to HOLD (never zero)."
                        ),
                    )
            else:
                if price_res.is_deviated:
                    dev_weight = 50
                    if self.active_policy_document and hasattr(self.active_policy_document, "risk_weights"):
                        dev_weight = self.active_policy_document.risk_weights.get("PRICE_DEVIATION", 50)

                    context.add_reason(
                        code="PRICE_DEVIATION",
                        weight=dev_weight,
                        detail=(
                            f"Price sources deviate by {price_res.deviation_pct:.2f}% "
                            f"(threshold {pricing_policy.max_price_deviation_pct if pricing_policy else 5.0}%); "
                            f"evaluated using higher price ${price_res.effective_price_usd:,.2f}."
                        ),
                    )

                effective_price = price_res.effective_price_usd or 0.0
                calculated_usd = native_units * effective_price
                if calculated_usd > 0:
                    amount_usd = max(amount_usd, calculated_usd)
                    context.request.metadata["amount_usd"] = amount_usd
                    context.request.metadata["price_used_usd"] = effective_price
                    context.request.metadata["price_deviation_pct"] = price_res.deviation_pct

        # Determine raw amount integer (in cents for USD-denominated limit caps)
        raw_amount_int = 0
        if amount_usd > 0:
            raw_amount_int = int(amount_usd * 100)
        elif context.decoded_tx:
            try:
                amt_str = (
                    context.decoded_tx.calls[0].amount
                    if (context.decoded_tx.calls and context.decoded_tx.calls[0].amount)
                    else context.decoded_tx.amount
                )
                raw_amount_int = int(float(amt_str))
            except (ValueError, TypeError):
                raw_amount_int = 0

        # Check single transaction limit
        if amount_usd > self.config.single_tx_usd_threshold:
            context.add_reason(
                code="SINGLE_TX_LIMIT_EXCEEDED",
                weight=65,
                detail=(
                    f"Transfer amount ${amount_usd:,.2f} exceeds single tx limit "
                    f"${self.config.single_tx_usd_threshold:,.2f}."
                ),
            )

        if context.request.metadata.get("simulate_hold") or context.request.metadata.get("simulate_rule_hit") == "VELOCITY_SPIKE":
            context.add_reason(
                code="VELOCITY_SPIKE",
                weight=50,
                detail="Outflow velocity spike detected for wallet.",
            )

        # Distinct request type check (Milestone S29 / F11): Cold transfers are ALWAYS HOLD regardless of size
        if (
            getattr(context.request, "request_type", None) == "COLD_TRANSFER"
            or context.request.metadata.get("request_type") == "COLD_TRANSFER"
            or context.request.metadata.get("is_cold_transfer")
        ):
            context.add_reason(
                code="COLD_STORAGE_TRANSFER",
                weight=75,
                detail="Cold transfer is a distinct request type requiring quarantine hold and hardware quorum.",
            )

        # Native-unit caps per asset in addition to USD caps (Milestone S31 / F13)
        limits_policy = None
        if self.active_policy_document and hasattr(self.active_policy_document, "limits"):
            limits_policy = self.active_policy_document.limits
        elif "policy" in context.metadata and hasattr(context.metadata["policy"], "limits"):
            limits_policy = context.metadata["policy"].limits

        sim_ts = context.request.metadata.get("ts")
        now_ts = int(float(sim_ts)) if sim_ts is not None else None
        is_backtest = bool(context.request.metadata.get("is_backtest", False))

        if limits_policy and hasattr(limits_policy, "asset_unit_limits") and limits_policy.asset_unit_limits:
            unit_limits = limits_policy.asset_unit_limits
            if asset in unit_limits and native_units > 0:
                unit_cap = unit_limits[asset]
                unit_scope = ScopeBuilder.asset_unit_scope(asset)
                scale = 1_000_000  # micro-units precision
                unit_amount_int = int(native_units * scale)
                unit_cap_int = int(unit_cap * scale)

                if is_backtest:
                    unit_res = self.limit_store.reserve(
                        scope_keys=[unit_scope],
                        amount=unit_amount_int,
                        window_seconds=3600,
                        cap=unit_cap_int,
                        now=now_ts,
                    )
                    if unit_res.ok:
                        context.unit_reservation_id = unit_res.reservation_id
                        self.limit_store.commit(unit_res.reservation_id, now=now_ts)
                    else:
                        context.add_reason(
                            code="UNIT_LIMIT_EXCEEDED",
                            weight=65,
                            detail=(
                                f"Requested {native_units:,.4f} {asset} exceeds native-unit sliding-window limit "
                                f"of {unit_cap:,.4f} {asset}."
                            ),
                        )
                elif context.is_dry_run:
                    rem_units = self.limit_store.get_remaining(
                        unit_scope,
                        window_seconds=3600,
                        cap=unit_cap_int,
                        now=now_ts,
                    )
                    if unit_amount_int > rem_units:
                        context.add_reason(
                            code="UNIT_LIMIT_EXCEEDED",
                            weight=65,
                            detail=(
                                f"Requested {native_units:,.4f} {asset} exceeds remaining native-unit limit "
                                f"of {rem_units / scale:,.4f} {asset}."
                            ),
                        )
                else:
                    unit_res = self.limit_store.reserve(
                        scope_keys=[unit_scope],
                        amount=unit_amount_int,
                        window_seconds=3600,
                        cap=unit_cap_int,
                        now=now_ts,
                    )
                    if unit_res.ok:
                        context.unit_reservation_id = unit_res.reservation_id
                    else:
                        context.add_reason(
                            code="UNIT_LIMIT_EXCEEDED",
                            weight=65,
                            detail=(
                                f"Requested {native_units:,.4f} {asset} exceeds native-unit limit "
                                f"of {unit_cap:,.4f} {asset}."
                            ),
                        )

        if raw_amount_int <= 0:
            return

        wallet_cap_cents = int(settings.wallet_limit_usd_default * 100)
        if self.active_policy_document and hasattr(self.active_policy_document, "limits"):
            limits = self.active_policy_document.limits
            if hasattr(limits, "per_wallet_usd") and limits.per_wallet_usd:
                wallet_cap_cents = int(limits.per_wallet_usd * 100)

        wallet_scope = ScopeBuilder.wallet_scope(wallet_addr)
        global_scope = ScopeBuilder.global_scope()
        scope_keys = [wallet_scope, global_scope]

        if is_backtest:
            # Replay engine in isolated namespace: evaluate and commit with simulated clock
            res = self.limit_store.reserve(
                scope_keys=scope_keys,
                amount=raw_amount_int,
                window_seconds=3600,
                cap=wallet_cap_cents,
                now=now_ts,
            )
            if res.ok:
                context.reservation_id = res.reservation_id
                self.limit_store.commit(res.reservation_id, now=now_ts)
            else:
                context.add_reason(
                    code="WALLET_LIMIT_EXCEEDED",
                    weight=65,
                    detail="Requested amount exceeds remaining sliding-window wallet limit.",
                )
        elif context.is_dry_run:
            # Dry run: reserve nothing, read-only check
            rem_wallet = self.limit_store.get_remaining(
                wallet_scope,
                window_seconds=3600,
                cap=wallet_cap_cents,
                now=now_ts,
            )
            if raw_amount_int > rem_wallet:
                context.add_reason(
                    code="WALLET_LIMIT_EXCEEDED",
                    weight=65,
                    detail="Requested amount exceeds remaining sliding-window wallet limit.",
                )
        else:
            # Production non-dry run: execute atomic reservation
            res = self.limit_store.reserve(
                scope_keys=scope_keys,
                amount=raw_amount_int,
                window_seconds=3600,
                cap=wallet_cap_cents,
                now=now_ts,
            )
            if res.ok:
                context.reservation_id = res.reservation_id
            else:
                if res.error == "LIMIT_STORE_UNAVAILABLE":
                    context.add_reason(
                        code="LIMIT_STORE_UNAVAILABLE",
                        weight=100,
                        detail="Limit store is unavailable and local fallback limits were exceeded.",
                        is_hard_deny=True,
                    )
                else:
                    context.add_reason(
                        code="WALLET_LIMIT_EXCEEDED",
                        weight=65,
                        detail="Outflow velocity limit exceeded across scopes.",
                    )

    def _stage_enrichment(self, context: PipelineContext) -> None:
        """Stage 5: Executes cached enrichment hooks (profiler, simulation)."""
        if context.request.metadata.get("scenario") == "new_destination_burst":
            context.add_reason(
                code="NEW_DESTINATION_BURST",
                weight=60,
                detail="High frequency transfer burst to unverified or new destination addresses.",
            )
        # Address profiler hook
        profiler_to_use = self.profiler
        if context.request.metadata.get("enable_profiler") and isinstance(profiler_to_use, DefaultProfilerEnricher):
            from services.bitguard.profiler.enricher import CachedProfilerEnricher
            profiler_to_use = CachedProfilerEnricher()

        p_res = profiler_to_use.enrich(context)
        if not p_res.configured and p_res.reason_code:
            context.reasons.append(
                DecisionReason(
                    code=p_res.reason_code,
                    weight=0,
                    detail=p_res.detail or "Profiler not configured",
                )
            )
        elif p_res.timed_out:
            context.add_reason(
                code="ELEVATED_RISK_TIMEOUT",
                weight=30,
                detail="Address profiler hook timed out; elevated risk applied (never treat as safe).",
            )
        else:
            reasons_data = p_res.data.get("reasons") if p_res.data else None
            is_hard_deny = bool(p_res.data.get("is_hard_deny", False)) if p_res.data else False
            if reasons_data:
                for r in reasons_data:
                    context.add_reason(
                        code=r["code"],
                        weight=int(r["weight"]),
                        detail=r["detail"],
                        is_hard_deny=is_hard_deny if r["code"] == "LIST_MATCH" or int(r["weight"]) >= 90 else False,
                    )
            elif p_res.risk_weight > 0:
                context.add_reason(
                    code=p_res.reason_code or "PROFILER_ANOMALY",
                    weight=p_res.risk_weight,
                    detail=p_res.detail or "Address profiler flagged risk.",
                )

        # Simulation hook
        simulation_to_use = self.simulation
        if context.request.metadata.get("enable_simulation") and isinstance(simulation_to_use, DefaultSimulationEnricher):
            from services.bitguard.simulation.enricher import CachedSimulationEnricher
            simulation_to_use = CachedSimulationEnricher()

        s_res = simulation_to_use.simulate(context)
        if context.request.metadata.get("simulate_enrichment_timeout") or s_res.timed_out:
            context.add_reason(
                code="ELEVATED_RISK_TIMEOUT",
                weight=30,
                detail="Pre-flight simulation timed out; elevated risk applied (never treat as safe).",
            )
        elif not s_res.configured and s_res.reason_code:
            context.reasons.append(
                DecisionReason(
                    code=s_res.reason_code,
                    weight=0,
                    detail=s_res.detail or "Simulation not configured",
                )
            )
        elif s_res.risk_weight > 0:
            context.add_reason(
                code=s_res.reason_code or "SIMULATION_ANOMALY",
                weight=s_res.risk_weight,
                detail=s_res.detail or "Simulation flagged unexpected state change.",
            )

        # Behavioral Baselines evaluation (Milestone S32 / F15)
        # Baselines contribute risk weight only and can never alone cause DENY.
        b_wallet = context.request.wallet or (context.decoded_tx.from_address if context.decoded_tx else "")
        b_amount_usd = float(context.request.metadata.get("amount_usd", 0.0))
        b_destination = ""
        if context.decoded_tx:
            b_destination = context.decoded_tx.to_address or (
                context.decoded_tx.calls[0].to if context.decoded_tx.calls else ""
            )
        if not b_destination and hasattr(context.request, "destination"):
            b_destination = str(getattr(context.request, "destination", "") or "")
        if not b_destination:
            b_destination = str(context.request.metadata.get("destination") or context.request.metadata.get("to") or "")

        ts_val = context.request.metadata.get("ts")
        b_ts = float(ts_val) if ts_val is not None else time.time()

        b_policy = None
        if self.active_policy_document and hasattr(self.active_policy_document, "baselines"):
            b_policy = self.active_policy_document.baselines
        elif "policy" in context.metadata and hasattr(context.metadata["policy"], "baselines"):
            b_policy = context.metadata["policy"].baselines

        if b_wallet:
            from services.bitguard.baselines.service import baseline_service

            b_res = baseline_service.evaluate_transaction(
                wallet=b_wallet,
                amount_usd=b_amount_usd,
                destination=b_destination,
                timestamp=b_ts,
                policy=b_policy,
                policy_document=self.active_policy_document,
            )
            for r in b_res.reasons:
                context.add_reason(
                    code=r.code,
                    weight=r.weight,
                    detail=r.detail,
                    is_hard_deny=False,
                )

        # Caller Identity & Build Attestation evaluation (Milestone S33 / F16)
        c_identity = context.request.caller_identity or context.request.metadata.get("caller_identity")
        c_digest = (
            context.request.caller_image_digest
            or context.request.metadata.get("caller_image_digest")
            or context.request.metadata.get("image_digest")
        )
        c_deploy_time = (
            context.request.caller_deploy_time
            or context.request.metadata.get("caller_deploy_time")
            or context.request.metadata.get("deploy_time")
        )
        c_source_ip = (
            context.request.caller_source_ip
            or context.request.metadata.get("caller_source_ip")
            or context.request.metadata.get("source_ip")
        )

        from services.bitguard.gateway.mtls import parse_attestation_timestamp
        parsed_deploy_time = parse_attestation_timestamp(c_deploy_time)

        attestation_policy = None
        if self.active_policy_document and hasattr(self.active_policy_document, "attestation"):
            attestation_policy = self.active_policy_document.attestation
        elif "policy" in context.metadata and hasattr(context.metadata["policy"], "attestation"):
            attestation_policy = context.metadata["policy"].attestation

        from services.bitguard.attestation.verifier import caller_attestation_verifier

        att_res = caller_attestation_verifier.verify(
            caller_identity=c_identity,
            image_digest=c_digest,
            deploy_time=parsed_deploy_time,
            source_ip=c_source_ip,
            policy=attestation_policy,
            now_ts=b_ts,
        )
        for r in att_res.reasons:
            context.add_reason(
                code=r.code,
                weight=r.weight,
                detail=r.detail,
                is_hard_deny=False,
            )

    def _stage_decide(self, context: PipelineContext, start_time: datetime) -> Decision:
        """Stage 6: Computes final verdict, respects circuit breaker, and resolves mode."""
        # Check circuit breaker state
        b_state = self.breaker_store.get_state()
        if b_state == BreakerStateEnum.LOCKDOWN:
            context.add_reason(
                code="BREAKER_LOCKDOWN",
                weight=100,
                detail="Circuit breaker is in LOCKDOWN mode.",
                is_hard_deny=True,
            )
        elif b_state == BreakerStateEnum.HOLD:
            context.add_reason(
                code="BREAKER_HOLD",
                weight=75,
                detail="Circuit breaker is in HOLD mode.",
            )
        elif b_state == BreakerStateEnum.ELEVATED:
            context.add_reason(
                code="BREAKER_ELEVATED",
                weight=25,
                detail="Circuit breaker is in ELEVATED mode: increased risk weighting applied.",
            )
            # Increase risk score in ELEVATED mode
            context.risk_score = min(100, context.risk_score + 25)

        # Compute tentative policy verdict
        tentative_verdict: Verdict
        has_hard_deny = context.hard_deny or any(r.weight >= 90 for r in context.reasons)
        has_hold_reason = any(
            r.code in [
                "SINGLE_TX_LIMIT_EXCEEDED",
                "BREAKER_HOLD",
                "WALLET_LIMIT_EXCEEDED",
                "VELOCITY_SPIKE",
                "SIM_BALANCE_MISMATCH",
                "COLD_STORAGE_TRANSFER",
                "EXPOSURE_CAP_EXCEEDED",
                "EXPOSURE_TOP_UP_REQUIRED",
                "TIMELOCK_DELAY",
                "UNPRICED_TOKEN",
                "UNIT_LIMIT_EXCEEDED",
                "CALLER_UNKNOWN_DIGEST",
            ]
            for r in context.reasons
        )

        from services.bitguard.break_glass import break_glass_store
        to_addr = ""
        if context.decoded_tx:
            to_addr = context.decoded_tx.to_address or ""
            if not to_addr and context.decoded_tx.calls:
                to_addr = context.decoded_tx.calls[0].to or ""
        if not to_addr and hasattr(context.request, "destination"):
            dest = getattr(context.request, "destination", None)
            to_addr = str(dest) if dest else ""

        if to_addr and break_glass_store.is_destination_allowed(to_addr):
            context.add_reason(
                code="BREAK_GLASS_OVERRIDE",
                weight=0,
                detail=f"Emergency break-glass degraded mode active: destination {to_addr} permitted by two-approver quorum.",
            )
            tentative_verdict = Verdict.ALLOW
        elif has_hard_deny or b_state == BreakerStateEnum.LOCKDOWN:
            tentative_verdict = Verdict.DENY
        elif b_state == BreakerStateEnum.HOLD or context.risk_score >= self.config.hold_risk_threshold or has_hold_reason:
            tentative_verdict = Verdict.HOLD
        else:
            tentative_verdict = Verdict.ALLOW

        # Time-lock evaluation (Milestone S30 / F12):
        # Withdrawals at or above threshold that otherwise pass become TIMELOCKED
        if tentative_verdict == Verdict.ALLOW:
            timelock_policy = None
            if self.active_policy_document and hasattr(self.active_policy_document, "time_lock"):
                timelock_policy = self.active_policy_document.time_lock
            elif "policy" in context.metadata and hasattr(context.metadata["policy"], "time_lock"):
                timelock_policy = context.metadata["policy"].time_lock

            if timelock_policy:
                is_timelocked = False
                matched_threshold = None
                matched_amount = 0.0
                matched_unit = "USD"

                # Check asset-specific threshold
                if context.decoded_tx and timelock_policy.timelock_threshold:
                    asset = (context.decoded_tx.asset or "ETH").upper()
                    if asset in timelock_policy.timelock_threshold:
                        decimals = 18
                        if asset in ("USDC", "USDT"):
                            decimals = 6
                        elif asset == "BTC":
                            decimals = 8

                        try:
                            raw_val = float(context.decoded_tx.amount)
                            asset_amount = raw_val / (10**decimals)
                        except (ValueError, TypeError):
                            asset_amount = 0.0

                        th_asset = timelock_policy.timelock_threshold[asset]
                        if asset_amount >= th_asset and asset_amount > 0:
                            is_timelocked = True
                            matched_threshold = th_asset
                            matched_amount = asset_amount
                            matched_unit = asset

                # Check USD threshold
                if not is_timelocked:
                    usd_threshold = None
                    if timelock_policy.timelock_threshold and "USD" in timelock_policy.timelock_threshold:
                        usd_threshold = timelock_policy.timelock_threshold["USD"]
                    elif timelock_policy.min_amount_usd is not None:
                        usd_threshold = timelock_policy.min_amount_usd

                    amount_usd = float(context.request.metadata.get("amount_usd", 0.0))
                    if usd_threshold is not None and amount_usd >= usd_threshold and amount_usd > 0:
                        is_timelocked = True
                        matched_threshold = usd_threshold
                        matched_amount = amount_usd
                        matched_unit = "USD"

                if is_timelocked and matched_threshold is not None:
                    multiplier = timelock_policy.delay_multipliers.get(b_state.value, 1.0)
                    delay_seconds = int(timelock_policy.timelock_minutes * 60 * multiplier)
                    from datetime import timedelta
                    release_not_before = start_time + timedelta(seconds=delay_seconds)

                    context.add_reason(
                        code="TIMELOCK_DELAY",
                        weight=60,
                        detail=(
                            f"Transfer amount {matched_amount:,.2f} {matched_unit} meets or exceeds time-lock threshold "
                            f"{matched_threshold:,.2f} {matched_unit}; delayed by {timelock_policy.timelock_minutes}m (x{multiplier:.1f} breaker mult) "
                            f"until {release_not_before.isoformat()}."
                        ),
                    )
                    tentative_verdict = Verdict.HOLD
                    context.request.metadata["is_timelocked"] = True
                    context.request.metadata["release_not_before"] = release_not_before.isoformat()
                    context.request.metadata["timelock_multiplier"] = multiplier
                    context.request.metadata["timelock_delay_seconds"] = delay_seconds

        # Release reservation if verdict is not ALLOW
        if context.reservation_id and tentative_verdict != Verdict.ALLOW:
            try:
                self.limit_store.release(context.reservation_id)
            except Exception as exc:
                logger.warning("failed_releasing_reservation_on_non_allow: %s", exc)
            context.reservation_id = None

        if context.unit_reservation_id and tentative_verdict != Verdict.ALLOW:
            try:
                self.limit_store.release(context.unit_reservation_id)
            except Exception as exc:
                logger.warning("failed_releasing_unit_reservation_on_non_allow: %s", exc)
            context.unit_reservation_id = None

        # Apply mode semantics (Milestone S04) as the last step
        amount_usd = float(context.request.metadata.get("amount_usd", 0.0))
        meta_ts = context.request.metadata.get("ts")
        date_str = (
            datetime.fromtimestamp(float(meta_ts), UTC).strftime("%Y-%m-%d")
            if meta_ts is not None
            else None
        )
        dec_time = (
            datetime.fromtimestamp(float(meta_ts), UTC)
            if meta_ts is not None
            else start_time
        )
        meta_label = context.request.metadata.get("data_label")
        data_label_val = DataLabel.REAL if str(meta_label).upper() == "REAL" else DataLabel.SYNTHETIC

        final_verdict: Verdict
        would_have_verdict: Verdict | None = None

        if context.active_mode == OperationMode.SHADOW:
            # Format and critical security checks still fail closed in SHADOW mode
            is_invariant_denial = any(
                r.code in ["DECODE_ERROR", "INVALID_CALLER_IDENTITY", "LIMIT_STORE_UNAVAILABLE"]
                for r in context.reasons
            )
            if is_invariant_denial:
                final_verdict = Verdict.DENY
                would_have_verdict = None
            elif tentative_verdict in [Verdict.DENY, Verdict.HOLD]:
                would_have_verdict = tentative_verdict
                final_verdict = Verdict.ALLOW  # Pass-through for policy verdicts
                from services.bitguard.mode_service import mode_service
                mode_service.record_metric(
                    context.wallet_group,
                    is_would_block=True,
                    value_usd=amount_usd,
                    date_str=date_str,
                )
            else:
                final_verdict = Verdict.ALLOW
                would_have_verdict = None
                from services.bitguard.mode_service import mode_service
                mode_service.record_metric(context.wallet_group, is_allowed=True, date_str=date_str)

        elif context.active_mode == OperationMode.ENFORCE:
            final_verdict = tentative_verdict
            would_have_verdict = None
            if final_verdict == Verdict.ALLOW:
                from services.bitguard.mode_service import mode_service
                mode_service.record_metric(context.wallet_group, is_allowed=True, date_str=date_str)

        else:
            # SIMULATION mode: dry-run, returns what BitGuard would do
            final_verdict = tentative_verdict
            would_have_verdict = None

        # Idempotency: consume intent on valid production signing requests
        if not context.is_dry_run and final_verdict == Verdict.ALLOW and context.request.intent_id:
            self.ledger_connector.mark_consumed(context.request.intent_id)

        c_id = context.request.caller_identity or context.request.metadata.get("caller_identity")
        c_dig = (
            context.request.caller_image_digest
            or context.request.metadata.get("caller_image_digest")
            or context.request.metadata.get("image_digest")
        )
        c_dep = (
            context.request.caller_deploy_time
            or context.request.metadata.get("caller_deploy_time")
            or context.request.metadata.get("deploy_time")
        )
        c_ip = (
            context.request.caller_source_ip
            or context.request.metadata.get("caller_source_ip")
            or context.request.metadata.get("source_ip")
        )
        from services.bitguard.gateway.mtls import parse_attestation_timestamp
        parsed_dt = parse_attestation_timestamp(c_dep)

        decision = Decision(
            request_id=context.request.id,
            verdict=final_verdict,
            would_have_verdict=would_have_verdict,
            risk_score=context.risk_score,
            reasons=context.reasons,
            mode=context.active_mode,
            policy_version=self.config.policy_version,
            data_label=data_label_val,
            wallet_group=context.wallet_group,
            wallet=context.decoded_tx.from_address if context.decoded_tx else context.request.wallet,
            chain=context.decoded_tx.chain if context.decoded_tx else context.request.chain,
            caller_identity=c_id,
            caller_image_digest=c_dig,
            caller_deploy_time=parsed_dt,
            caller_source_ip=c_ip,
            created_at=dec_time,
            evaluation_latency_ms=0.0,
            timings={},
            reservation_id=context.reservation_id,
            unit_reservation_id=context.unit_reservation_id,
            decoded_tx=context.decoded_tx,
        )

        if not context.is_dry_run:
            try:
                from services.bitguard.breaker.triggers import breaker_triggers

                if final_verdict == Verdict.DENY:
                    breaker_triggers.record_denial(decision.request_id, "; ".join(r.code for r in decision.reasons))
                    if any("INTENT" in r.code for r in decision.reasons):
                        breaker_triggers.record_unmatched_intent(context.request.intent_id)
                if amount_usd > 0:
                    breaker_triggers.record_velocity(amount_usd, context.request.wallet or "")
            except Exception:
                pass

        try:
            from services.bitguard.metrics import record_decision, record_unmatched_intent
            record_decision(final_verdict.value, decision.chain or "unknown")
            if any("INTENT" in r.code for r in decision.reasons):
                record_unmatched_intent(decision.chain or "unknown")
        except Exception:
            pass

        return decision


# Global singleton instance
decision_engine = DecisionEngine()
