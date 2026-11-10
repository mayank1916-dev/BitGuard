"""Exposure reduction service and on-chain balance poller (Milestone S29 / F11).

Invariants:
- Invariant #1: Key Isolation (BitGuard never holds signing keys).
- Invariant #3: Fail-Closed Default (divergence or cap breaches quarantine/hold).
- Invariant #5: WebAuthn Hardware Approvals for Quorum Release.
- Invariant #6: Asymmetric Policy Evolution (proposals cannot be approved by requester).
- Invariant #8: Explicit Data Provenance (values labelled REAL or REPORTED).
- Invariant #11: Strict Wording: 'reduces and contains unauthorized transaction signing'.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

import rlp
from eth_utils import keccak

from services.bitguard.approvals.hold_store import HoldStore, hold_store
from services.bitguard.exposure.models import (
    BalanceRecord,
    ExposureAlert,
    ExposureStatus,
    ExposureSummaryResponse,
    WalletExposureItem,
)
from services.bitguard.limits.store import LimitStore, ScopeBuilder, limit_store
from services.bitguard.models import DataLabel, DecisionReason, HoldTicket
from services.bitguard.policy.models import WalletExposurePolicy
from services.bitguard.rpc.client import HttpRpcClient, RpcClient

logger = logging.getLogger("bitguard.exposure.poller")

DEFAULT_COLD_WALLET = "0x8888888888888888888888888888888888888888"


def build_raw_transfer_tx(to_addr: str, value_wei: int, nonce: int = 0) -> str:
    """Builds valid legacy EVM raw transaction hex for rebalancing transfers."""
    clean = to_addr.removeprefix("0x")
    to_bytes = bytes.fromhex(clean)
    payload = [nonce, 20_000_000_000, 21000, to_bytes, value_wei, b""]
    return "0x" + rlp.encode(payload).hex()


def compute_tx_digest(raw_tx_hex: str) -> str:
    """Computes keccak256 transaction digest over raw unsigned bytes."""
    raw_bytes = bytes.fromhex(raw_tx_hex.removeprefix("0x"))
    return "0x" + keccak(raw_bytes).hex()


class ExposureService:
    """Monitors hot wallet balances, reconciles limits, and generates sweep/top-up proposals."""

    def __init__(
        self,
        rpc_client: RpcClient | None = None,
        limit_store_inst: LimitStore | None = None,
        hold_store_inst: HoldStore | None = None,
        cold_storage_wallet: str = DEFAULT_COLD_WALLET,
        wei_per_unit: int = 10**18,
    ) -> None:
        self.rpc_client: RpcClient = rpc_client or HttpRpcClient(rpc_url="http://anvil:8545")
        self.limit_store: LimitStore = limit_store_inst or limit_store
        self.hold_store: HoldStore = hold_store_inst or hold_store
        self.cold_storage_wallet: str = cold_storage_wallet.lower()
        self.wei_per_unit: int = wei_per_unit

        self.wallet_policies: dict[str, WalletExposurePolicy] = {}
        self.wallet_baselines: dict[str, int] = {}  # wallet -> baseline balance in wei
        self.latest_balances: dict[str, BalanceRecord] = {}
        self.alerts: list[ExposureAlert] = []
        self.proposals: list[HoldTicket] = []
        self.divergence_tolerance_wei: int = 0

    def set_rpc_client(self, rpc_client: RpcClient) -> None:
        """Injects or updates the RPC client for on-chain state inspection."""
        self.rpc_client = rpc_client

    def configure_wallet(
        self,
        wallet: str,
        policy: WalletExposurePolicy,
        baseline_wei: int | None = None,
    ) -> None:
        """Configures balance caps and baseline for a monitored hot wallet."""
        w_lower = wallet.lower()
        self.wallet_policies[w_lower] = policy
        if baseline_wei is not None:
            self.wallet_baselines[w_lower] = baseline_wei

    def set_wallet_baseline(self, wallet: str, baseline_wei: int) -> None:
        """Sets the initial ground-truth baseline balance for a hot wallet."""
        self.wallet_baselines[wallet.lower()] = baseline_wei

    def poll_wallet(
        self,
        wallet: str,
        chain: str = "ethereum",
        block_number: int | None = None,
        requester_id: str = "system:exposure_poller",
        data_label: DataLabel = DataLabel.REAL,
    ) -> tuple[BalanceRecord, list[ExposureAlert], HoldTicket | None]:
        """Polls on-chain balance for a wallet, reconciles committed volume, and creates proposals if needed."""
        w_lower = wallet.lower()
        policy = self.wallet_policies.get(w_lower) or WalletExposurePolicy()

        # 1. Fetch on-chain balance from RPC client
        block_param = hex(block_number) if block_number is not None else "latest"
        on_chain_wei = self.rpc_client.get_balance(w_lower, block=block_param)
        on_chain_ether = on_chain_wei / self.wei_per_unit

        # 2. Reconcile committed limit volume from limit store (S07 reconciliation)
        wallet_scope = ScopeBuilder.wallet_scope(w_lower)
        committed_vol, reserved_vol, total_vol = self.limit_store.get_usage(wallet_scope)

        # Baseline reconciliation
        baseline_wei = self.wallet_baselines.get(w_lower, on_chain_wei)
        expected_wei = max(0, baseline_wei - committed_vol)
        divergence_wei = 0
        generated_alerts: list[ExposureAlert] = []

        if on_chain_wei < expected_wei:
            divergence_wei = expected_wei - on_chain_wei
            if divergence_wei > self.divergence_tolerance_wei:
                alert = ExposureAlert(
                    id=f"alert-div-{uuid.uuid4().hex[:12]}",
                    alert_code="BALANCE_DIVERGENCE",
                    severity="CRITICAL",
                    wallet=w_lower,
                    chain=chain,
                    on_chain_balance=on_chain_ether,
                    committed_volume=committed_vol / self.wei_per_unit,
                    divergence=divergence_wei / self.wei_per_unit,
                    threshold=float(self.divergence_tolerance_wei) / self.wei_per_unit,
                    detail=(
                        f"On-chain balance {on_chain_ether:.4f} diverges from expected balance "
                        f"{(expected_wei / self.wei_per_unit):.4f} by {(divergence_wei / self.wei_per_unit):.4f} "
                        f"beyond committed volume {(committed_vol / self.wei_per_unit):.4f}."
                    ),
                    data_label=data_label,
                )
                generated_alerts.append(alert)
                self.alerts.append(alert)
                logger.warning("BALANCE_DIVERGENCE detected for wallet %s: %s", w_lower, alert.detail)

        # Record balance snapshot
        balance_record = BalanceRecord(
            wallet=w_lower,
            chain=chain,
            balance_wei=on_chain_wei,
            balance_ether=on_chain_ether,
            committed_limit_volume=committed_vol,
            divergence_wei=divergence_wei,
            block_number=block_number,
            data_label=data_label,
        )
        self.latest_balances[w_lower] = balance_record

        # 3. Check exposure caps and create rebalancing proposals
        proposal_ticket: HoldTicket | None = None

        if on_chain_ether > policy.max_hot_balance:
            # Balance above cap: create SWEEP proposal (hot -> cold)
            excess_ether = on_chain_ether - policy.target_hot_balance
            excess_wei = int(excess_ether * self.wei_per_unit)
            raw_tx = build_raw_transfer_tx(to_addr=self.cold_storage_wallet, value_wei=excess_wei)
            digest = compute_tx_digest(raw_tx)

            ticket_id = f"ht-sweep-{uuid.uuid4().hex[:12]}"
            proposal_ticket = HoldTicket(
                id=ticket_id,
                request_id=f"req-sweep-{uuid.uuid4().hex[:12]}",
                tx_digest=digest,
                raw_tx=raw_tx,
                chain=chain,
                wallet=w_lower,
                amount_usd=excess_ether,
                requester_id=requester_id,
                risk_score=75,
                reasons=[
                    DecisionReason(
                        code="EXPOSURE_CAP_EXCEEDED",
                        weight=75,
                        detail=(
                            f"Hot wallet balance ({on_chain_ether:,.2f}) exceeds max_hot_balance "
                            f"({policy.max_hot_balance:,.2f}). Sweep of {excess_ether:,.2f} to cold storage proposed."
                        ),
                    )
                ],
                state="PENDING",
                status="PENDING",
                expires_at=datetime.now(UTC) + timedelta(hours=24),
                data_label=data_label,
            )
            self.hold_store.create(proposal_ticket)
            self.proposals.append(proposal_ticket)
            logger.info("Created sweep proposal %s for wallet %s", ticket_id, w_lower)

        elif on_chain_ether < policy.top_up_threshold:
            # Balance below threshold: create TOP-UP proposal (cold -> hot)
            top_up_ether = policy.target_hot_balance - on_chain_ether
            top_up_wei = int(top_up_ether * self.wei_per_unit)
            raw_tx = build_raw_transfer_tx(to_addr=w_lower, value_wei=top_up_wei)
            digest = compute_tx_digest(raw_tx)

            ticket_id = f"ht-topup-{uuid.uuid4().hex[:12]}"
            proposal_ticket = HoldTicket(
                id=ticket_id,
                request_id=f"req-topup-{uuid.uuid4().hex[:12]}",
                tx_digest=digest,
                raw_tx=raw_tx,
                chain=chain,
                wallet=w_lower,
                amount_usd=top_up_ether,
                requester_id=requester_id,
                risk_score=50,
                reasons=[
                    DecisionReason(
                        code="EXPOSURE_TOP_UP_REQUIRED",
                        weight=50,
                        detail=(
                            f"Hot wallet balance ({on_chain_ether:,.2f}) fell below top_up_threshold "
                            f"({policy.top_up_threshold:,.2f}). Top-up of {top_up_ether:,.2f} from cold storage proposed."
                        ),
                    )
                ],
                state="PENDING",
                status="PENDING",
                expires_at=datetime.now(UTC) + timedelta(hours=24),
                data_label=data_label,
            )
            self.hold_store.create(proposal_ticket)
            self.proposals.append(proposal_ticket)
            logger.info("Created top-up proposal %s for wallet %s", ticket_id, w_lower)

        return balance_record, generated_alerts, proposal_ticket

    def poll_all(
        self,
        chain: str = "ethereum",
        block_number: int | None = None,
        requester_id: str = "system:exposure_poller",
        data_label: DataLabel = DataLabel.REAL,
    ) -> list[ExposureAlert]:
        """Polls on-chain balances across all configured monitored hot wallets."""
        all_alerts: list[ExposureAlert] = []
        for wallet in list(self.wallet_policies.keys()):
            _, alerts, _ = self.poll_wallet(
                wallet=wallet,
                chain=chain,
                block_number=block_number,
                requester_id=requester_id,
                data_label=data_label,
            )
            all_alerts.extend(alerts)
        return all_alerts

    def get_exposure_summary(
        self,
        data_label: DataLabel = DataLabel.REAL,
    ) -> ExposureSummaryResponse:
        """Builds the comprehensive exposure summary for GET /v1/exposure."""
        items: list[WalletExposureItem] = []
        total_at_risk = 0.0
        total_headroom = 0.0

        now = datetime.now(UTC)

        for wallet, policy in self.wallet_policies.items():
            record = self.latest_balances.get(wallet)
            balance = record.balance_ether if record else 0.0
            last_polled = record.polled_at if record else now

            headroom = max(0.0, policy.max_hot_balance - balance)
            total_at_risk += balance
            total_headroom += headroom

            # Determine status
            status = ExposureStatus.NORMAL
            if any(a.wallet == wallet and a.alert_code == "BALANCE_DIVERGENCE" for a in self.alerts[-10:]):
                status = ExposureStatus.DIVERGENCE_ALERT
            elif balance > policy.max_hot_balance:
                status = ExposureStatus.CAP_EXCEEDED
            elif balance < policy.top_up_threshold:
                status = ExposureStatus.TOP_UP_NEEDED

            items.append(
                WalletExposureItem(
                    wallet=wallet,
                    chain=record.chain if record else "ethereum",
                    balance=balance,
                    cap=policy.max_hot_balance,
                    target_balance=policy.target_hot_balance,
                    top_up_threshold=policy.top_up_threshold,
                    headroom=headroom,
                    exposure_at_risk=balance,
                    status=status,
                    last_polled_at=last_polled,
                    data_label=data_label,
                )
            )

        active_proposals = len(
            [t for t in self.proposals if t.status == "PENDING" and t.state == "PENDING"]
        )

        return ExposureSummaryResponse(
            total_exposure_at_risk=total_at_risk,
            total_headroom=total_headroom,
            wallets_monitored=len(self.wallet_policies),
            proposals_pending=active_proposals,
            data_label=data_label,
            wallets=items,
            divergence_alerts=self.alerts[-50:],
            timestamp=now,
        )


# Global singleton instance
exposure_service = ExposureService()
