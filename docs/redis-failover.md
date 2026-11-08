# Redis Replication, Persistence, and Failover Architecture

## Overview

BitGuard relies on Redis 7 for high-performance distributed state coordination:
- Sliding-window outflow velocity aggregation and limit reservation (Milestone S07 / F3).
- Circuit breaker state caching and token epoch increments (Milestone S18 / F14).
- WebSocket event stream fan-out via Redis Pub/Sub (Milestone S13 & S24).
- Distributed rate limiting counters (Milestone S24 / F17).
- Break-glass active override synchronization (Milestone S24 / F17).

This document outlines the high-availability replication design, persistence guarantees, failover procedures, and the strict fail-closed safety semantics enforced when Redis experiences degradation or failure.

---

## Architecture Topology

```
                  +---------------------------+
                  |    Nginx Load Balancer    |
                  |        (Port 8000)        |
                  +-------------+-------------+
                                |
               +----------------+----------------+
               |                                 |
        +------v------+                   +------v------+
        | BitGuard - 1|                   | BitGuard - 2|
        +------+------+                   +------+------+
               |                                 |
               +----------------+----------------+
                                |
                 +--------------+--------------+
                 |                             |
          +------v------+               +------v------+
          | Redis Primary| ------------> | Redis Replica|
          |  (Port 6379) |  async repl  |  (Port 6380) |
          |   AOF Sync  |               |   AOF Sync  |
          +-------------+               +-------------+
```

### Persistence Guarantees
Both the primary and replica Redis instances run with Append-Only File (AOF) persistence enabled:
```bash
redis-server --appendonly yes
```
Every write operation (sliding-window reservation, breaker transition, token epoch) is appended to disk, providing durable state recovery upon restart.

---

## Failover & Outage Semantics (S07 Fail-Closed Rules)

Under Invariant #3 (**Fail-Closed Default**), BitGuard never fails open when state stores become unavailable.

### Scenario A: Transient Primary Disconnection / Network Partition
1. **Sliding-Window Limits (S07):**
   - If Redis connection times out or drops during reservation (`reserve` script), BitGuard activates **local fallback caps** (`local_fallback_cap` = 10,000 units, `local_fallback_wallet_cap` = 5,000 units).
   - Any transaction exceeding the conservative local caps immediately receives verdict `HOLD` or `DENY`.
   - Incurred limits fall back to in-memory tracking until Redis reconnects.
2. **Circuit Breaker:**
   - If Redis cache reads fail, BitGuard immediately falls back to PostgreSQL `breaker_state` record.
   - If PostgreSQL is also unreachable, BitGuard enforces the strictest known state in memory (`HOLD` or `LOCKDOWN`).
3. **Approval Token Epochs:**
   - Increments local epoch counter, rejecting tokens issued under older epochs.
4. **WebSocket Fan-Out:**
   - Local client delivery continues unaffected via bounded in-memory subscriber queues; multi-replica fan-out degrades gracefully without interrupting the gateway.

### Scenario B: Primary Redis Catastrophic Failure & Replica Promotion

When the primary Redis node fails catastrophically:

#### 1. Promote Redis Replica to Primary
Execute the promotion command on `redis-replica`:
```bash
docker exec -it bitguard-redis-replica redis-cli replicaof no one
```
The replica immediately detaches and begins operating as an independent, fully writable primary instance containing all persisted AOF state.

#### 2. Re-point Service Traffic
Update the `BITGUARD_REDIS_URL` in environment configuration to point to the promoted replica, or update Docker network alias:
```bash
docker network disconnect public bitguard-redis-replica
docker network connect --alias redis public bitguard-redis-replica
```

#### 3. Re-attach New Replica
Once a new standby node is provisioned:
```bash
redis-server --replicaof redis-promoted 6379 --appendonly yes
```

---

## Verification & Observability

- **Prometheus Metrics:**
  - `bitguard_reservation_failures_total`: Increments on store partition or cap breach.
  - `bitguard_breaker_state`: Monitored gauge reflecting distributed breaker status.
- **Health Probes:**
  - `GET /healthz`: Verifies BitGuard instance status.
  - Performance target: target p99 under 15 ms, measured, maintained across all healthy and degraded modes.
- **Production Status:**
  - Production-ready architecture; pilot after audit and shadow-mode validation.
