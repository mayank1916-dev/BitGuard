# BitGuard Integration Lab (Milestone S23 / F19)

## Overview & Architecture

The **BitGuard Integration Lab** is an automated integration test environment designed to validate policy enforcement, hardware-bound quorum approvals, circuit breaker actions, delegation monitoring, and failure containment across the full containerized stack:

- **BitGuard Firewall (`bitguard:8000`)**: Policy decision point (JSON-RPC 2.0).
- **Signer Shim (`signer_shim:8001`)**: Policy enforcement point; holds disposable testnet keys on isolated network.
- **Ledger Mock (`ledger_mock:8002`)**: Custodial ledger source of truth for withdrawal intent reconciliation.
- **Demo Custody Client (`demo_custody:8003`)**: Workload client simulating exchange withdrawal systems.
- **Foundry Anvil (`anvil:8545`)**: Local EVM test chain (`chain_id: 31337`).
- **Postgres 16 (`postgres:5432`)**: Persistent state store for decisions, hold tickets, and hash-chained audit logs.
- **Redis 7 (`redis:6379`)**: Sliding window limit storage and atomic single-use nonce consumption.
- **MinIO S3 (`minio:9000`)**: WORM object-lock storage for external audit chain anchoring.

---

## Operating Invariants & Safety Boundaries (AGENTS.md)

1. **Environment & Safety Boundary (Invariant #9):**
   - **Mainnet Strictly Forbidden:** The runner asserts `assert_non_mainnet(chain_id)` before execution and terminates immediately with `MainnetForbiddenError` if configured with any known mainnet chain ID (e.g., 1, 10, 56, 137, 8453, 42161, 43114).
   - **Disposable Test Keys Only:** BitGuard and the signer shim operate with disposable keys generated in the lab. Real keys or real funds are never utilized.
   - **Data-Driven Attack Scenarios:** All scenario files (`lab/scenarios/*.yaml`) describe attack patterns and structural tests purely as declarative data. No exploit code or offensive tooling exists in the repository.

2. **Core Policy & Decision Invariants:**
   - **Key Isolation (Invariant #1):** BitGuard never handles or stores private keys. The signer shim alone holds a disposable key.
   - **Approval Binding (Invariant #2):** Signatures require a single-use Ed25519 token cryptographically bound to transaction digest, wallet, chain, nonce, and expiry.
   - **Fail-Closed Default (Invariant #3):** Missing intents, RPC timeouts, store outages, or unallowlisted delegates fail closed to `DENY`.
   - **Raw Byte Source of Truth (Invariant #4):** Evaluates transactions from raw bytes independently decoded; caller-supplied JSON fields are ignored.
   - **Dual-Control WebAuthn (Invariant #5 & #6):** Quarantine releases and de-escalations require dual-custody hardware WebAuthn assertions over the digest/challenge.

3. **Strict Wording & Claims (Invariant #11):**
   - BitGuard **reduces and contains** unauthorized transaction signing (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection).
   - Performance benchmark: **target p99 under 15 ms for the local fast path, measured under load** (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)).
   - Deployment status: **production-ready architecture; pilot after audit and shadow-mode validation**. System boundaries cataloged in [docs/LIMITS.md](LIMITS.md).

---

## Scenario Catalog (`lab/scenarios/`)

| # | Scenario ID | Pattern / Action | Expected Outcome | Assertions Checked |
|---|---|---|---|---|
| **01** | `scenario_01_normal_withdrawal` | Pre-approved intent, under limits, valid mTLS SAN | `ALLOW` | Status `SIGNED`, 65-byte ECDSA signature, intent consumed |
| **02** | `scenario_02_over_limit_hold_then_quorum_release` | Amount ($75k) > single tx limit ($50k) -> 2 WebAuthn approvals | `HOLD_THEN_APPROVED` | Error `-32004` (HOLD), approver 1 leaves `PENDING_QUORUM`, approver 2 releases signature |
| **03** | `scenario_03_hold_expires_to_deny` | Quarantined ticket TTL elapses before quorum | `HOLD_EXPIRES_DENY` | Approval post-expiry fails `400 Bad Request` (`HOLD_EXPIRED`) |
| **04** | `scenario_04_delegation_attempt_denied` | EIP-7702 type-4 authorization naming owned hot wallet with unapproved delegate | `DENY` | Error `-32003`, reason `DELEGATION_OWNED_ADDRESS`, zero signatures |
| **05** | `scenario_05_watcher_detects_unapproved_delegation_and_breaker_trips` | Watcher identifies unallowlisted EIP-7702 bytecode on hot wallet | `BREAKER_TRIPPED` | Breaker trips to `HOLD`, critical alert emitted, time-to-contain measured (<5000 ms) |
| **06** | `scenario_06_split_under_limit_triggers_velocity_or_baseline_reason` | Structuring: 4 x $30k transfers exceed $100k hourly rolling limit | `VELOCITY_HOLD` | First 3 transfers succeed, 4th transfer quarantined on `HOLD` (`HOURLY_LIMIT_EXCEEDED`) |
| **07** | `scenario_07_redis_outage_fails_closed` | Redis outage simulated during rate limit check | `FAIL_CLOSED` | Error `-32003` (`ENGINE_ERROR` / `LIMIT_STORE_UNAVAILABLE`), fail closed |
| **08** | `scenario_08_direct_signer_call_refused` | Direct call to `signer_shim:8001/sign` without BitGuard internal auth | `REFUSED` | `403 Forbidden` / `400 Bad Request`, no keys accessible |
| **09** | `scenario_09_token_replay_refused` | Valid approval token presented a second time | `REFUSED` | First call `200 OK`, second call rejected `400 Bad Request` (`NONCE_ALREADY_CONSUMED`) |
| **10** | `scenario_10_unmatched_intent_denied` | Transaction submitted with nonexistent or forged intent ID | `DENY` | Error `-32003` (`INTENT_MISSING`), zero signatures |
| **11** | `scenario_11_lockdown_then_two_person_unlock` | Escalation to `LOCKDOWN` halts all signing; 2 approvers unlock | `LOCKDOWN_UNLOCKED` | In lockdown tx DENIED; 1 approver cannot unlock; 2 approvers restore `NORMAL` |

---

## Execution Guide

### 1. Direct Runner Execution
Run all scenarios and generate benchmark results:
```bash
python -m lab.runner.main
```

Options:
- `--chain-id <id>`: Target chain ID (default `31337`; mainnet IDs strictly rejected).
- `--scenarios-dir <path>`: Directory containing scenario YAML files.
- `--output <path>`: JSON benchmark report destination (default `lab/results/latest.json`).
- `--summary <path>`: Text summary report destination (default `lab/results/latest_summary.txt`).

### 2. Pytest Integration Test Suite
Verify safety guards and scenario execution through pytest:
```bash
python -m pytest tests/test_integration_lab.py -v
```

### 3. Docker Compose Stack
To run the full multi-container deployment:
```bash
docker-compose up --build
```

---

## Provenance & Reporting

Every execution produces `lab/results/latest.json` tagged with explicit data provenance:
- **`data_label: "SYNTHETIC"`**: Indicates simulated lab benchmark data.
- **Safety Metadata**: Details mainnet guards, disposable key isolation, and fail-closed validation.
- **Latency & Timings**: Millisecond-resolution execution metrics per scenario, with measured containment times.
