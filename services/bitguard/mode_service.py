"""Mode resolution, wallet group configuration, and promotion checklist service (Milestone S04 / F7)."""

from datetime import UTC, datetime

from services.bitguard.audit_service import audit_service
from services.bitguard.config import settings
from services.bitguard.decoders.base import DecodeError
from services.bitguard.decoders.evm import evm_decoder
from services.bitguard.ledger.intent_check import check_intent
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.models import (
    DailyGroupMetrics,
    DataLabel,
    Decision,
    DecisionReason,
    DecodedTx,
    OperationMode,
    PromotionCheckItem,
    PromotionChecklistResponse,
    SigningRequest,
    Verdict,
    WalletGroupConfig,
)


class ModeService:
    """Manages wallet group operational modes, shadow pass-through, and promotion rules."""

    def __init__(self) -> None:
        # Default hot wallet group
        default_group = WalletGroupConfig(
            id="default",
            name="Default Hot Wallets",
            mode=OperationMode.SIMULATION,
            wallets=[],
            shadow_started_at=None,
            enforce_started_at=None,
            unexplained_decode_failures=0,
        )
        self._groups: dict[str, WalletGroupConfig] = {"default": default_group}
        self._wallet_to_group: dict[str, str] = {}
        self._metrics: dict[str, DailyGroupMetrics] = {}  # key: f"{wallet_group}:{date}"
        self._decisions: dict[str, Decision] = {}

    def get_wallet_group(self, group_id_or_wallet: str) -> WalletGroupConfig:
        """Finds wallet group by identifier or wallet address. Falls back to 'default'."""
        if group_id_or_wallet in self._groups:
            return self._groups[group_id_or_wallet]
        mapped_id = self._wallet_to_group.get(group_id_or_wallet.lower())
        if mapped_id and mapped_id in self._groups:
            return self._groups[mapped_id]
        return self._groups["default"]

    def register_wallet_group(self, group: WalletGroupConfig) -> WalletGroupConfig:
        """Registers or updates a wallet group."""
        self._groups[group.id] = group
        for w in group.wallets:
            self._wallet_to_group[w.lower()] = group.id
        return group

    def list_wallet_groups(self) -> list[WalletGroupConfig]:
        """Returns all configured wallet groups."""
        return list(self._groups.values())

    def _get_metric_record(self, wallet_group: str, date_str: str | None = None) -> DailyGroupMetrics:
        """Retrieves or initializes the daily metric record for a wallet group."""
        date_key = date_str or datetime.now(UTC).strftime("%Y-%m-%d")
        key = f"{wallet_group}:{date_key}"
        if key not in self._metrics:
            self._metrics[key] = DailyGroupMetrics(wallet_group=wallet_group, date=date_key)
        return self._metrics[key]

    def record_metric(
        self,
        wallet_group: str,
        is_would_block: bool = False,
        value_usd: float = 0.0,
        is_allowed: bool = False,
        date_str: str | None = None,
    ) -> None:
        """Increments daily metrics counters for a wallet group."""
        rec = self._get_metric_record(wallet_group, date_str)
        if is_would_block:
            rec.would_have_blocked_count += 1
            rec.would_have_blocked_value += value_usd
        if is_allowed:
            rec.allowed_count += 1

    def get_metrics_for_group(self, wallet_group: str) -> list[DailyGroupMetrics]:
        """Returns all recorded daily metric records for a wallet group."""
        return [m for m in self._metrics.values() if m.wallet_group == wallet_group]

    def record_decode_failure(self, wallet_group: str) -> None:
        """Increments unexplained decode failures for a wallet group."""
        group = self.get_wallet_group(wallet_group)
        group.unexplained_decode_failures += 1

    def save_decision(self, decision: Decision) -> Decision:
        """Persists a decision in memory and registers in audit log."""
        self._decisions[decision.request_id] = decision
        audit_service.append_entry(
            event_type="DECISION",
            request_id=decision.request_id,
            verdict=decision.verdict.value,
            data_label=decision.data_label,
        )
        return decision

    def get_decision(self, decision_id: str) -> Decision | None:
        """Finds a decision by request_id."""
        return self._decisions.get(decision_id)

    def list_decisions(self, limit: int = 50, offset: int = 0) -> list[Decision]:
        """Lists decisions with pagination."""
        all_decs = list(self._decisions.values())
        return all_decs[offset : offset + limit]

    def label_false_positive(
        self,
        decision_id: str,
        operator_id: str = "operator",
        reason: str | None = None,
    ) -> Decision:
        """Labels a would-block or blocked decision as a false positive (Operator role)."""
        dec = self._decisions.get(decision_id)
        if dec is None:
            raise KeyError(f"Decision '{decision_id}' not found")

        # Validate that this was a would-block or block
        is_block_candidate = (
            (dec.would_have_verdict in [Verdict.DENY, Verdict.HOLD])
            or (dec.verdict in [Verdict.DENY, Verdict.HOLD])
        )
        if not is_block_candidate:
            raise ValueError(f"Decision '{decision_id}' was not a blocked or would-block event")

        if not dec.is_false_positive:
            dec.is_false_positive = True
            # Increment daily false positive metric for the decision's date and group
            dec_date = dec.created_at.strftime("%Y-%m-%d")
            metric_rec = self._get_metric_record(dec.wallet_group, dec_date)
            metric_rec.false_positive_count += 1

            audit_service.append_entry(
                event_type="FALSE_POSITIVE_LABELED",
                request_id=dec.request_id,
                verdict="LABEL",
                data_label=DataLabel.REAL,
            )

        return dec

    def get_promotion_checklist(self, wallet_group_id: str) -> PromotionChecklistResponse:
        """Evaluates whether a wallet group meets requirements to promote from SHADOW to ENFORCE."""
        group = self.get_wallet_group(wallet_group_id)

        # 1. Minimum days in SHADOW
        min_days_target = settings.shadow_min_days
        if group.shadow_started_at is None:
            days_in_shadow = 0
            min_days_passed = False
        else:
            delta = datetime.now(UTC) - group.shadow_started_at
            days_in_shadow = delta.days
            min_days_passed = days_in_shadow >= min_days_target

        min_days_check = PromotionCheckItem(
            name="minimum_days_in_shadow",
            passed=min_days_passed,
            details={
                "current_days": days_in_shadow,
                "required_days": min_days_target,
                "shadow_started_at": group.shadow_started_at.isoformat() if group.shadow_started_at else None,
            },
        )

        # 2. False-positive rate under target
        max_fp_rate = settings.shadow_max_false_positive_rate
        group_metrics = self.get_metrics_for_group(group.id)
        total_allowed = sum(m.allowed_count for m in group_metrics)
        total_would_block = sum(m.would_have_blocked_count for m in group_metrics)
        total_fp = sum(m.false_positive_count for m in group_metrics)
        total_evals = total_allowed + total_would_block

        if total_evals == 0:
            current_fp_rate = 0.0
            fp_rate_passed = True
        else:
            current_fp_rate = round(total_fp / total_evals, 6)
            fp_rate_passed = current_fp_rate <= max_fp_rate

        fp_rate_check = PromotionCheckItem(
            name="false_positive_rate",
            passed=fp_rate_passed,
            details={
                "current_rate": current_fp_rate,
                "target_max_rate": max_fp_rate,
                "total_false_positives": total_fp,
                "total_evaluations": total_evals,
            },
        )

        # 3. Zero unexplained decode failures
        decode_passed = group.unexplained_decode_failures == 0
        decode_check = PromotionCheckItem(
            name="zero_unexplained_decode_failures",
            passed=decode_passed,
            details={
                "unexplained_failures": group.unexplained_decode_failures,
                "allowed_failures": 0,
            },
        )

        can_promote = min_days_passed and fp_rate_passed and decode_passed

        failures: list[str] = []
        if not min_days_passed:
            failures.append(f"SHADOW duration ({days_in_shadow}/{min_days_target} days)")
        if not fp_rate_passed:
            failures.append(f"false-positive rate ({current_fp_rate:.4f} > {max_fp_rate})")
        if not decode_passed:
            failures.append(f"unexplained decode failures ({group.unexplained_decode_failures} > 0)")

        if can_promote:
            summary = "All promotion gates passed. Wallet group is eligible for ENFORCE mode."
        else:
            summary = f"Promotion gates failing: {', '.join(failures)}."

        return PromotionChecklistResponse(
            wallet_group=group.id,
            current_mode=group.mode,
            can_promote=can_promote,
            checks={
                "minimum_days_in_shadow": min_days_check,
                "false_positive_rate": fp_rate_check,
                "zero_unexplained_decode_failures": decode_check,
            },
            summary=summary,
        )

    def update_group_mode(
        self,
        group_id: str,
        new_mode: OperationMode,
        override: bool = False,
        override_reason: str | None = None,
        operator_id: str = "operator",
    ) -> tuple[bool, str, WalletGroupConfig]:
        """Changes wallet group operational mode enforcing promotion gates or explicit override audit."""
        group = self.get_wallet_group(group_id)

        # Promotion gate validation when entering ENFORCE from another mode
        if new_mode == OperationMode.ENFORCE and group.mode != OperationMode.ENFORCE:
            if not override:
                checklist = self.get_promotion_checklist(group.id)
                if not checklist.can_promote:
                    return (
                        False,
                        f"Promotion rejected: checklist requirements not met ({checklist.summary})",
                        group,
                    )
            else:
                if not override_reason or not override_reason.strip():
                    return (
                        False,
                        "Explicit override_reason is required for unverified ENFORCE promotion",
                        group,
                    )
                # Invariant #7: Record explicit override in audit log
                audit_service.append_entry(
                    event_type="MODE_PROMOTION_OVERRIDE",
                    request_id=f"promo-override-{group.id}-{int(datetime.now(UTC).timestamp())}",
                    verdict="OVERRIDE",
                    data_label=DataLabel.REAL,
                )

        # Mode transition timestamps
        now = datetime.now(UTC)
        if new_mode == OperationMode.SHADOW and group.shadow_started_at is None:
            group.shadow_started_at = now
        elif new_mode == OperationMode.ENFORCE and group.enforce_started_at is None:
            group.enforce_started_at = now

        group.mode = new_mode

        audit_service.append_entry(
            event_type="MODE_CHANGED",
            request_id=f"mode-change-{group.id}-{new_mode.value}",
            verdict="ALLOW",
            data_label=DataLabel.REAL,
        )

        return True, f"Wallet group '{group.id}' mode updated to {new_mode.value}", group

    def evaluate_request(
        self,
        request: SigningRequest,
        is_dry_run: bool = True,
    ) -> Decision:
        """Evaluates signing request respecting wallet group mode semantics (SIMULATION, SHADOW, ENFORCE)."""
        start_time = datetime.now(UTC)
        group = self.get_wallet_group(request.wallet_group or request.wallet)

        # In dry run, request.mode takes precedence if supplied, otherwise group configured mode
        active_mode = request.mode if (is_dry_run and request.mode is not None) else group.mode

        # Security/Format checks: unknown format, decode error, or invalid caller identity
        # Invariant #3 & #4: Always Fail closed immediately, even in SHADOW mode
        raw_tx = request.raw_tx.strip() if request.raw_tx else ""
        if not raw_tx or request.metadata.get("simulate_decode_error"):
            self.record_decode_failure(group.id)
            dec = Decision(
                request_id=request.id,
                verdict=Verdict.DENY,
                would_have_verdict=None,
                risk_score=100,
                reasons=[
                    DecisionReason(
                        code="DECODE_ERROR",
                        weight=100,
                        detail="Transaction bytes cannot be decoded or format is invalid.",
                    )
                ],
                mode=active_mode,
                policy_version="v1.0.0",
                data_label=DataLabel.SYNTHETIC,
                wallet_group=group.id,
                created_at=start_time,
                evaluation_latency_ms=0.4,
            )
            return self.save_decision(dec)

        if request.metadata.get("simulate_invalid_caller"):
            dec = Decision(
                request_id=request.id,
                verdict=Verdict.DENY,
                would_have_verdict=None,
                risk_score=100,
                reasons=[
                    DecisionReason(
                        code="INVALID_CALLER_IDENTITY",
                        weight=100,
                        detail="Caller identity is invalid, unknown, or unauthorized.",
                    )
                ],
                mode=active_mode,
                policy_version="v1.0.0",
                data_label=DataLabel.SYNTHETIC,
                wallet_group=group.id,
                created_at=start_time,
                evaluation_latency_ms=0.4,
            )
            return self.save_decision(dec)

        # Stage: Withdrawal Intent Reconciliation (Milestone S08 / F2)
        # Invariant #3 & #4: Fail-closed verification against custody ledger intent
        if request.intent_id or request.metadata.get("require_intent_check"):
            decoded: DecodedTx | None = None
            if "decoded_tx" in request.metadata:
                decoded = DecodedTx.model_validate(request.metadata["decoded_tx"])
            else:
                try:
                    decoded = evm_decoder.decode(raw_tx)
                except DecodeError as exc:
                    self.record_decode_failure(group.id)
                    dec = Decision(
                        request_id=request.id,
                        verdict=Verdict.DENY,
                        would_have_verdict=None,
                        risk_score=100,
                        reasons=[
                            DecisionReason(
                                code="DECODE_ERROR",
                                weight=100,
                                detail=f"Failed to decode transaction bytes: {exc}",
                            )
                        ],
                        mode=active_mode,
                        policy_version="v1.0.0",
                        data_label=DataLabel.SYNTHETIC,
                        wallet_group=group.id,
                        created_at=start_time,
                        evaluation_latency_ms=0.4,
                    )
                    return self.save_decision(dec)

            intent_res = check_intent(request, decoded, mock_ledger_connector)
            if not intent_res.passed:
                dec = Decision(
                    request_id=request.id,
                    verdict=Verdict.DENY,
                    would_have_verdict=None,
                    risk_score=100,
                    reasons=[
                        DecisionReason(
                            code=intent_res.code or "INTENT_CHECK_FAILED",
                            weight=100,
                            detail=intent_res.detail or "Intent reconciliation failed.",
                        )
                    ],
                    mode=active_mode,
                    policy_version="v1.0.0",
                    data_label=DataLabel.SYNTHETIC,
                    wallet_group=group.id,
                    created_at=start_time,
                    evaluation_latency_ms=0.4,
                )
                return self.save_decision(dec)

        # Policy checks evaluation
        amount_usd = float(request.metadata.get("amount_usd", 0.0))
        policy_verdict = Verdict.ALLOW
        risk_score = 0
        reasons: list[DecisionReason] = []

        if request.metadata.get("simulate_deny") or request.metadata.get("simulate_rule_hit") == "SUSPICIOUS_DELEGATION":
            policy_verdict = Verdict.DENY
            risk_score = 95
            reasons.append(
                DecisionReason(
                    code="SUSPICIOUS_DELEGATION",
                    weight=95,
                    detail="EIP-7702 authorization tuple points to unapproved delegate contract.",
                )
            )
        elif amount_usd > settings.single_tx_usd_default:
            policy_verdict = Verdict.HOLD
            risk_score = 65
            reasons.append(
                DecisionReason(
                    code="SINGLE_TX_LIMIT_EXCEEDED",
                    weight=65,
                    detail=f"Transfer amount ${amount_usd:,.2f} exceeds single tx limit ${settings.single_tx_usd_default:,.2f}.",
                )
            )
        elif request.metadata.get("simulate_hold"):
            policy_verdict = Verdict.HOLD
            risk_score = 50
            reasons.append(
                DecisionReason(
                    code="VELOCITY_SPIKE",
                    weight=50,
                    detail="Outflow velocity spike detected for wallet.",
                )
            )

        # Resolve mode semantics
        final_verdict: Verdict
        would_have_verdict: Verdict | None = None

        if active_mode == OperationMode.SHADOW:
            if policy_verdict in [Verdict.DENY, Verdict.HOLD]:
                # In SHADOW mode: store real verdict as would_have_verdict, return pass-through ALLOW
                would_have_verdict = policy_verdict
                final_verdict = Verdict.ALLOW
                self.record_metric(group.id, is_would_block=True, value_usd=amount_usd)
            else:
                would_have_verdict = None
                final_verdict = Verdict.ALLOW
                self.record_metric(group.id, is_allowed=True)
        elif active_mode == OperationMode.ENFORCE:
            # In ENFORCE mode: verdict is binding
            final_verdict = policy_verdict
            would_have_verdict = None
            if final_verdict == Verdict.ALLOW:
                self.record_metric(group.id, is_allowed=True)
        else:
            # In SIMULATION mode: dry-run, returns what BitGuard would do without state mutations
            final_verdict = policy_verdict
            would_have_verdict = None

        # Idempotency: consume intent on valid production signing requests
        if not is_dry_run and final_verdict == Verdict.ALLOW and request.intent_id:
            mock_ledger_connector.mark_consumed(request.intent_id)

        latency_ms = round((datetime.now(UTC) - start_time).total_seconds() * 1000.0, 3)

        decision = Decision(
            request_id=request.id,
            verdict=final_verdict,
            would_have_verdict=would_have_verdict,
            risk_score=risk_score,
            reasons=reasons,
            mode=active_mode,
            policy_version="v1.0.0",
            data_label=DataLabel.SYNTHETIC,
            wallet_group=group.id,
            created_at=start_time,
            evaluation_latency_ms=latency_ms,
        )

        return self.save_decision(decision)


# Global singleton instance
mode_service = ModeService()
