"""WebSocket event stream broadcaster with queue-based backpressure and Redis Pub/Sub fan-out (Milestone S13 & S24).

Invariants:
- Invariant #8: Explicit Data Provenance. All stream events include data_label (REAL, SYNTHETIC, REPORTED).
- Backpressure: Drops slow clients rather than blocking the signing gateway.
- Multi-replica fan-out: Broadcasts events across all BitGuard instances via Redis Pub/Sub.
- Complete isolation: Killing the stream never affects decision engine or signing.
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from services.bitguard.config import settings
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
    """Manages active WebSocket subscribers, queues, and non-blocking broadcasts with Redis pub/sub fan-out."""

    def __init__(self, max_queue_size: int = 100, instance_id: str | None = None) -> None:
        self.max_queue_size = max_queue_size
        self.instance_id: str = str(instance_id or getattr(settings, 'instance_id', 'bitguard-1'))
        self._clients: dict[str, StreamClient] = {}
        self._lock = asyncio.Lock()
        self._chain_outflows: dict[str, float] = {}
        self._ticker_task: asyncio.Task[None] | None = None
        self._pubsub_task: asyncio.Task[None] | None = None
        self._sync_redis: Any | None = None

    def set_sync_redis(self, client: Any) -> None:
        """Injects custom sync Redis client for testing."""
        self._sync_redis = client

    def _get_sync_redis(self) -> Any:
        """Lazily retrieves synchronous Redis client for publishing."""
        if self._sync_redis is None:
            try:
                import redis
                self._sync_redis = redis.Redis.from_url(
                    settings.redis_url,
                    socket_connect_timeout=1.0,
                    socket_timeout=1.0,
                    decode_responses=True,
                )
            except Exception as exc:
                logger.debug("sync_redis_init_error: %s", exc)
                return None
        return self._sync_redis

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

    def _deliver_to_local_clients(self, event: dict[str, Any]) -> None:
        """Delivers event to locally connected clients with backpressure drop."""
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
                try:
                    asyncio.create_task(client.websocket.close(code=1008, reason="Backpressure: slow client dropped"))
                except Exception:
                    pass

        for cid in dropped_clients:
            self.unregister_client(cid)

    def _publish_to_redis(self, event: dict[str, Any]) -> None:
        """Publishes event to Redis channel for multi-replica fan-out."""
        try:
            r = self._get_sync_redis()
            if r is not None:
                envelope = json.dumps({"origin": self.instance_id, "event": event})
                r.publish("bitguard:stream:events", envelope)
        except Exception as exc:
            logger.debug("redis_pubsub_publish_bypassed: %s", exc)

    def publish_event(self, event_type: str, payload: dict[str, Any], data_label: str = "REAL") -> None:
        """Publishes an event to all connected clients and fans out to other replicas.

        Enforces backpressure: if a client queue is full, the client is dropped immediately
        to prevent blocking the gateway or event producer.
        """
        event = {
            "type": event_type,
            "payload": payload,
            "data_label": data_label,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        # Deliver to locally connected clients
        self._deliver_to_local_clients(event)

        # Fan out across replicas via Redis Pub/Sub
        self._publish_to_redis(event)

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

    async def _redis_pubsub_loop(self) -> None:
        """Background loop listening for stream events from other replicas via Redis Pub/Sub."""
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(settings.redis_url, decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.subscribe("bitguard:stream:events")
            logger.info("Subscribed to Redis Pub/Sub channel 'bitguard:stream:events'")
            while True:
                try:
                    msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if msg and msg.get("type") == "message":
                        raw_data = msg.get("data")
                        if raw_data and isinstance(raw_data, str):
                            parsed = json.loads(raw_data)
                            origin = parsed.get("origin")
                            event = parsed.get("event")
                            # Ignore self-published events since they were already delivered locally
                            if origin != self.instance_id and event:
                                self._deliver_to_local_clients(event)
                except Exception as exc:
                    logger.debug("pubsub_message_processing_error: %s", exc)
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("redis_pubsub_listener_init_error: %s", exc)

    def start_ticker(self) -> None:
        """Starts the periodic outflow ticker and Redis Pub/Sub subscriber."""
        if self._ticker_task is None or self._ticker_task.done():
            self._ticker_task = asyncio.create_task(self._outflow_ticker_loop())
            logger.info("Started 5-second per-chain outflow aggregation ticker")
        if self._pubsub_task is None or self._pubsub_task.done():
            self._pubsub_task = asyncio.create_task(self._redis_pubsub_loop())

    def stop_ticker(self) -> None:
        """Stops the outflow ticker loop and pubsub listener."""
        if self._ticker_task and not self._ticker_task.done():
            self._ticker_task.cancel()
            self._ticker_task = None
            logger.info("Stopped outflow aggregation ticker")
        if self._pubsub_task and not self._pubsub_task.done():
            self._pubsub_task.cancel()
            self._pubsub_task = None


# Global singleton instance
stream_broadcaster = StreamBroadcaster()
