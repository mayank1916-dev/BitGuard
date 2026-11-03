"""WebSocket event stream broadcaster with queue-based backpressure (Milestone S13).

Invariants:
- Invariant #8: Explicit Data Provenance. All stream events include data_label (REAL, SYNTHETIC, REPORTED).
- Backpressure: Drops slow clients rather than blocking the signing gateway.
- Complete isolation: Killing the stream never affects decision engine or signing.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from services.bitguard.models import Decision

logger = logging.getLogger("bitguard.stream.broadcaster")


@dataclass
class StreamClient:
    """Connected WebSocket client with bounded incoming event queue."""

    id: str
    websocket: Any
    queue: asyncio.Queue[dict[str, Any]]
    connected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_alive: bool = True


class StreamBroadcaster:
    """Manages active WebSocket subscribers, queues, and non-blocking broadcasts."""

    def __init__(self, max_queue_size: int = 100) -> None:
        self.max_queue_size = max_queue_size
        self._clients: dict[str, StreamClient] = {}
        self._lock = asyncio.Lock()
        self._chain_outflows: dict[str, float] = {}
        self._ticker_task: asyncio.Task[None] | None = None

    def record_chain_outflow(self, chain: str, amount_usd: float) -> None:
        """Records an approved outflow for per-chain volume aggregation."""
        chain_key = chain.lower()
        self._chain_outflows[chain_key] = round(self._chain_outflows.get(chain_key, 0.0) + amount_usd, 2)

    def get_chain_outflows(self) -> dict[str, float]:
        """Returns snapshot of per-chain cumulative outflow aggregates."""
        return dict(self._chain_outflows)

    def register_client(self, websocket: Any, client_id: str | None = None) -> StreamClient:
        """Registers a new WebSocket subscriber with a bounded event queue."""
        cid = client_id or f"ws-{uuid.uuid4().hex[:8]}"
        client = StreamClient(
            id=cid,
            websocket=websocket,
            queue=asyncio.Queue(maxsize=self.max_queue_size),
        )
        self._clients[cid] = client
        logger.info("stream_client_registered: id=%s active=%d", cid, len(self._clients))
        return client

    def unregister_client(self, client_id: str) -> None:
        """Removes a subscriber and cleans up resources."""
        if client_id in self._clients:
            client = self._clients.pop(client_id)
            client.is_alive = False
            logger.info("stream_client_unregistered: id=%s active=%d", client_id, len(self._clients))

    def publish_event(self, event_type: str, payload: dict[str, Any], data_label: str = "REAL") -> None:
        """Publishes an event to all connected clients.

        Enforces backpressure: if a client queue is full, the client is dropped immediately
        to prevent blocking the gateway or event producer.
        """
        event = {
            "type": event_type,
            "payload": payload,
            "data_label": data_label,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        dropped_clients: list[str] = []
        for cid, client in list(self._clients.items()):
            if not client.is_alive:
                dropped_clients.append(cid)
                continue
            try:
                client.queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(
                    "stream_backpressure_drop: client %s queue full (%d items); dropping slow client",
                    cid,
                    self.max_queue_size,
                )
                client.is_alive = False
                dropped_clients.append(cid)
                # Attempt to close the slow socket asynchronously without blocking
                try:
                    asyncio.create_task(client.websocket.close(code=1008, reason="Backpressure: slow client dropped"))
                except Exception:
                    pass

        for cid in dropped_clients:
            self.unregister_client(cid)

    # Convenience alias
    broadcast = publish_event

    def publish_decision(self, decision: Decision) -> None:
        """Broadcasts a newly issued policy decision."""
        # Record chain outflow if decision allowed the transfer
        if decision.verdict.value == "ALLOW" and decision.chain:
            amount_usd = float(decision.timings.get("amount_usd", 0.0))
            if amount_usd > 0:
                self.record_chain_outflow(decision.chain, amount_usd)

        data_label_val = decision.data_label.value if hasattr(decision.data_label, "value") else str(decision.data_label)
        self.publish_event(
            event_type="decision",
            payload=decision.model_dump(mode="json"),
            data_label=data_label_val,
        )

    def publish_breaker_state(self, state: Any, reason: str = "") -> None:
        """Broadcasts a circuit breaker state transition."""
        state_val = getattr(state, "state", state)
        state_str = state_val.value if hasattr(state_val, "value") else str(state_val)
        data_label_val = getattr(state, "data_label", "REAL")
        if hasattr(data_label_val, "value"):
            data_label_val = data_label_val.value

        self.publish_event(
            event_type="breaker_state",
            payload={
                "state": state_str,
                "reason": reason or getattr(state, "reason", "Circuit breaker state updated"),
                "updated_at": datetime.now(UTC).isoformat(),
            },
            data_label=str(data_label_val),
        )

    def publish_outflows(self) -> None:
        """Broadcasts per-chain outflow aggregates."""
        self.publish_event(
            event_type="chain_outflow_aggregate",
            payload={
                "outflows": self.get_chain_outflows(),
                "timestamp": datetime.now(UTC).isoformat(),
            },
            data_label="REAL",
        )

    async def _outflow_ticker_loop(self) -> None:
        """Background loop broadcasting per-chain outflow aggregates every 5 seconds."""
        try:
            while True:
                await asyncio.sleep(5)
                if self._clients:
                    self.publish_outflows()
        except asyncio.CancelledError:
            pass

    def start_ticker(self) -> None:
        """Starts the periodic 5-second outflow aggregation ticker."""
        if self._ticker_task is None or self._ticker_task.done():
            self._ticker_task = asyncio.create_task(self._outflow_ticker_loop())
            logger.info("Started 5-second per-chain outflow aggregation ticker")

    def stop_ticker(self) -> None:
        """Stops the outflow ticker loop."""
        if self._ticker_task and not self._ticker_task.done():
            self._ticker_task.cancel()
            self._ticker_task = None
            logger.info("Stopped outflow aggregation ticker")


# Global singleton instance
stream_broadcaster = StreamBroadcaster()
