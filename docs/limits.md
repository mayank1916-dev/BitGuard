# BitGuard Limit Store & Sliding Window Key Schema

## 1. Overview
BitGuard enforces outflow velocity limits using an atomic, distributed sliding-window limit store (`LimitStore`). The system supports multiple concurrent scopes (per wallet, per asset, per chain, and global) with all amounts represented strictly as **integers in smallest units** (e.g., satoshis, wei, or micro-units).

All operations are executed atomically using pre-compiled Redis Lua scripts loaded once at initialization.

---

## 2. Redis Key Schema

All keys use canonical namespace prefixes:

| Key Pattern | Type | Description | Score Format | Member Format |
| :--- | :--- | :--- | :--- | :--- |
| `limit:scope:wallet:{wallet}:{window_s}:c` | Sorted Set (`ZSET`) | Committed outflow transactions for a wallet | Timestamp (epoch seconds) | `{amount}:{reservation_id}` |
| `limit:scope:wallet:{wallet}:{window_s}:r` | Sorted Set (`ZSET`) | Active, uncommitted reservations for a wallet | Expiration timestamp (`now + ttl`) | `{amount}:{reservation_id}` |
| `limit:scope:asset:{asset}:{window_s}:c` | Sorted Set (`ZSET`) | Committed volume for an asset (e.g. `USDC`, `ETH`) | Timestamp (epoch seconds) | `{amount}:{reservation_id}` |
| `limit:scope:asset:{asset}:{window_s}:r` | Sorted Set (`ZSET`) | Active reservations for an asset | Expiration timestamp (`now + ttl`) | `{amount}:{reservation_id}` |
| `limit:scope:chain:{chain}:{window_s}:c` | Sorted Set (`ZSET`) | Committed volume for a blockchain network | Timestamp (epoch seconds) | `{amount}:{reservation_id}` |
| `limit:scope:chain:{chain}:{window_s}:r` | Sorted Set (`ZSET`) | Active reservations for a blockchain network | Expiration timestamp (`now + ttl`) | `{amount}:{reservation_id}` |
| `limit:scope:global:{window_s}:c` | Sorted Set (`ZSET`) | Committed global firewall outflow volume | Timestamp (epoch seconds) | `{amount}:{reservation_id}` |
| `limit:scope:global:{window_s}:r` | Sorted Set (`ZSET`) | Active global firewall outflow reservations | Expiration timestamp (`now + ttl`) | `{amount}:{reservation_id}` |
| `limit:res:{reservation_id}` | Hash (`HSET`) | Reservation state metadata | N/A | Fields: `amount`, `status`, `created_at`, `expires_at`, `window`, `scopes` |

---

## 3. Sliding Window Mechanism & Sorted Sets

For any scope key $K$, BitGuard tracks two sorted sets:
1. **Committed Set ($K:c$):** Holds transactions that were signed and broadcast.
   - Entries older than `(now - window_seconds)` are evicted on every check:
     $$\text{ZREMRANGEBYSCORE}(K:c, -\infty, \text{now} - \text{window})$$
2. **Reserved Set ($K:r$):** Holds uncommitted approvals that are in-flight.
   - The score is set to the reservation's expiration time ($\text{now} + \text{TTL}$, default 120 s).
   - Expired reservations are automatically evicted on every check:
     $$\text{ZREMRANGEBYSCORE}(K:r, -\infty, \text{now})$$

Total used volume for scope $K$ is computed as:
$$\text{used} = \sum_{m \in K:c} \text{amount}(m) + \sum_{m \in K:r} \text{amount}(m)$$

---

## 4. Atomic Lua Operations

### `reserve(scope_keys[], amount, window_seconds, cap)`
- **Atomicity:** Executed in a single Redis Lua script (`LUA_RESERVE`).
- **Phase 1 (Verification):** Checks all provided scope keys. If adding `amount` would cause $\text{used} + \text{amount} > \text{cap}_i$ on *any* scope, the script immediately aborts with `{0, remaining, ""}`.
- **Phase 2 (Reservation):** If all scopes pass, the member `"{amount}:{res_id}"` is atomically added to all $K:r$ sets with score $\text{now} + \text{TTL}$.
- Returns `{1, min_remaining, reservation_id}`.

### `commit(reservation_id)`
- Executed atomically via `LUA_COMMIT`.
- Verifies reservation exists and status is `RESERVED` and not expired.
- Removes `"{amount}:{res_id}"` from $K:r$ across all associated scopes.
- Adds `"{amount}:{res_id}"` to $K:c$ with score = $\text{now}$.
- Updates reservation status to `COMMITTED`.

### `release(reservation_id)`
- Executed atomically via `LUA_RELEASE`.
- Verifies reservation is `RESERVED`.
- Removes `"{amount}:{res_id}"` from $K:r$ across all associated scopes.
- Marks status as `RELEASED`.

### TTL Expiry & Automatic Reclamation
- If neither `commit` nor `release` is called within the TTL window (default 120 s), the score ($\text{now} + \text{TTL}$) falls behind current time.
- The next call to `reserve` or `get_usage` prunes it via $\text{ZREMRANGEBYSCORE}(K:r, -\infty, \text{now})$, automatically freeing reserved budget without background workers.

---

## 5. Fail-Closed Resilience & Conservative Local Caps

In conformance with **Invariant #3** (*Fail-Closed Default*):
- If Redis is disconnected, unreachable, or returns a script error, BitGuard **never** allows unmetered transactions.
- Instead, BitGuard activates `LocalFallbackStore`, which applies strict, conservative per-process limits (`BITGUARD_LOCAL_FALLBACK_CAP`).
- If a transaction exceeds the conservative local fallback cap, or if local fallback is exhausted or disabled, BitGuard rejects the reservation and the policy decision point issues a `DENY` with reason `LIMIT_STORE_UNAVAILABLE`.
