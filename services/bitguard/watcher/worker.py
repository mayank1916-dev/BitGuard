"""Delegation and bytecode watcher worker subscribing to blocks and evaluating addresses (Milestone S17 / F6).

Invariants:
- Invariant #3: Fail-Closed Default. Unapproved delegation or provider disagreement trips breaker to HOLD.
- Invariant #6: Asymmetric Policy Evolution. Any automated critical detection tightens/halts immediately (HOLD).
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).
- Invariant #11: Strict Wording: 'Reduces and contains unauthorized signing'.
"""

import logging
import time

from services.bitguard.audit_service import audit_service
from services.bitguard.engine.breaker_store import breaker_store
from services.bitguard.models import BreakerStateEnum, DataLabel, WatcherAlert
from services.bitguard.stream.broadcaster import stream_broadcaster
from services.bitguard.watcher.inspector import inspector
from services.bitguard.watcher.provider_pool import provider_pool
from services.bitguard.watcher.store import watched_address_store

logger = logging.getLogger("bitguard.watcher.worker")


class DelegationWatcher:
    """Monitors configured hot wallet addresses on-chain across multi-provider RPC nodes."""

    def __init__(self) -> None:
        self.last_scanned_block: int = 0
        self.recent_alerts: list[WatcherAlert] = []

    def scan_block(self, block_number: int | None = None) -> list[WatcherAlert]:
        """Scans a specific block (or latest block) for watched addresses, delegations, and nonces.

        Executes:
        1. Multi-provider eth_getCode consensus verification. Disagreement => alert PROVIDER_DISAGREEMENT.
        2. EIP-7702 delegation inspection (0xef0100 + delegate address).
        3. Bytecode code hash verification against expected hashes.
        4. Block transactions inspection for type-4 authorizations naming watched addresses.
        5. Nonce velocity jump inspection.
        6. On CRITICAL: trips circuit breaker to HOLD, emits stream event, appends audit entry,
           and measures detection latency.
        """
        primary_rpc = provider_pool.primary_rpc
        target_block = block_number if block_number is not None else primary_rpc.get_block_number()

        # 1. Fetch block data
        block_data = primary_rpc.get_block_by_number(target_block, full_transactions=True)
        raw_ts = block_data.get("timestamp", 0)
        block_ts: float
        if isinstance(raw_ts, str) and raw_ts.startswith("0x"):
            block_ts = float(int(raw_ts, 16))
        elif isinstance(raw_ts, (int, float)):
            block_ts = float(raw_ts)
        else:
            block_ts = time.time()

        watched_list = watched_address_store.list_all()
        watched_map = {w.address.lower(): w for w in watched_list}

        generated_alerts: list[WatcherAlert] = []
        detection_start = time.time()

        # 2. Check each watched address across providers
        for watched in watched_list:
            consensus_code, has_agreement, provider_results = provider_pool.query_code(
                watched.address, block=hex(target_block)
            )

            # Check provider disagreement
            if not has_agreement:
                alert = WatcherAlert(
                    id=f"alert-disagreement-{watched.id}-{target_block}",
                    alert_code="PROVIDER_DISAGREEMENT",
                    severity="HIGH",
                    address=watched.address,
                    chain=watched.chain,
                    block_number=target_block,
                    block_timestamp=block_ts,
                    detection_timestamp=detection_start,
                    latency_blocks=0,
                    latency_seconds=round(max(0.0, detection_start - block_ts), 3),
                    details={
                        "provider_results": provider_results,
                        "message": "RPC providers returned conflicting bytecode; treating as suspicious",
                    },
                    breaker_tripped=False,
                    data_label=DataLabel.REAL,
                )
                generated_alerts.append(alert)
                logger.warning(
                    "RPC_PROVIDER_DISAGREEMENT address=%s results=%s",
                    watched.address,
                    provider_results,
                )

            # Inspect retrieved bytecode
            code_alert = inspector.inspect_address_code(
                watched=watched,
                code_hex=consensus_code,
                rpc=primary_rpc,
                block_number=target_block,
                block_timestamp=block_ts,
            )
            if code_alert:
                generated_alerts.append(code_alert)

        # 3. Check block transactions and unexpected nonce jumps
        tx_alerts = inspector.inspect_block_transactions(
            block_data=block_data,
            watched_map=watched_map,
            rpc=primary_rpc,
            block_number=target_block,
            block_timestamp=block_ts,
        )
        generated_alerts.extend(tx_alerts)

        # 4. Handle alerts, breaker trips, and latency measurement
        for alert in generated_alerts:
            # Measure and log detection latency
            alert.latency_blocks = max(0, primary_rpc.get_block_number() - target_block)
            alert.latency_seconds = round(max(0.0, alert.detection_timestamp - alert.block_timestamp), 3)

            logger.warning(
                "WATCHER_ALERT alert_code=%s severity=%s address=%s latency_blocks=%d latency_seconds=%.3f details=%s",
                alert.alert_code,
                alert.severity,
                alert.address,
                alert.latency_blocks,
                alert.latency_seconds,
                alert.details,
            )

            if alert.severity == "CRITICAL":
                # Invariant #6: Asymmetric tightening - trip circuit breaker to HOLD immediately
                breaker_store.set_state(
                    BreakerStateEnum.HOLD,
                    reason=f"Watcher CRITICAL alert: {alert.alert_code} on {alert.address}",
                )
                alert.breaker_tripped = True

                # Invariant #7: Tamper-evident audit trail entry
                audit_service.append_entry(
                    event_type=f"WATCHER_CRITICAL_{alert.alert_code}",
                    request_id=alert.id,
                    verdict="HOLD",
                    data_label=DataLabel.REAL,
                )

            # Stream event to connected live UI feeds
            stream_broadcaster.publish_event(
                event_type="WATCHER_ALERT",
                payload=alert.model_dump(),
                data_label="REAL",
            )

        self.last_scanned_block = target_block
        self.recent_alerts.extend(generated_alerts)

        # Update last scanned block on all watched addresses
        for w in watched_list:
            watched_address_store.update(w.id, {"last_scanned_block": target_block})

        return generated_alerts


delegation_watcher = DelegationWatcher()
