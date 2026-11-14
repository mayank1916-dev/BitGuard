# BitGuard: Autonomous Hot Wallet Signing Firewall

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-5.0-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev/)
[![Redis](https://img.shields.io/badge/Redis-7.0%20Lua-DC382D.svg?logo=redis&logoColor=white)](https://redis.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Foundry](https://img.shields.io/badge/Foundry-Anvil-black.svg)](https://getfoundry.sh/)
[![Security: FIDO2](https://img.shields.io/badge/Quorum-WebAuthn%20Hardware%20Keys-orange.svg)](https://fidoalliance.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**BitGuard** is an autonomous signing-request firewall and pre-signing policy gatekeeper for cryptocurrency exchange hot wallets and institutional custody systems.

Modeled on modern hot wallet compromise vectors (including the late-October 2026 multi-billion-dollar automated pipeline drains and EIP-7702 delegation sweeps), BitGuard sits between untrusted custody applications and automated signing nodes. It enforces independent raw transaction decoding, atomic distributed velocity limits, EIP-7702 set-code delegation guards, multi-party hardware quorums, and cryptographic tamper-evident audit logging.

> **Defensive Scope & Target:** Production-ready architecture; pilot after audit and shadow-mode validation. Tested on local forks (Foundry Anvil) and testnets using disposable keys. Reduces and contains exploit blast radius (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection); never holds or uses long-term private signing keys. Latency benchmark: target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](docs/PERF.md)). System boundaries and compensating controls documented in [docs/LIMITS.md](docs/LIMITS.md).

## 🏛️ Core Architecture: Separation of Policy & Signing

The core security principle of BitGuard is strict separation of concerns: **BitGuard is the Decision Point; a separate Signer Shim is the Enforcement Point.**

---

```text
┌──────────────────────────────────────┐
│  Untrusted Custody / Withdrawal App  │
└──────────────────┬───────────────────┘
                   │ 1. mTLS Client Cert + JSON-RPC (raw_tx, intent_id)
                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        BITGUARD FIREWALL GATEWAY                       │
│                                                                        │
│  [ Raw Byte Decoder ] ──► [ Intent Reconciliation ] ──► [ 7702 Guard ] │
│  (RLP, Legacy, 1559, 7702) (Checks approved ledger entry) (Code Hash)  │
│                                                                        │
│  [ Atomic Velocity Store ] ─────────────────────────► [ Multi-State ]  │
│  (Redis Lua Sliding Windows)                          [   Breaker   ]  │
│                                                                        │
│  Decision: ALLOW ──────► Issues 60s Ed25519 Token (digest bound)       │
│            HOLD  ──────► Durable Quarantine (WebAuthn Quorum)          │
│            DENY  ──────► Revert & Fail-Closed                          │
└──────────────────┬─────────────────────────────────────────────────────┘
                   │ 2. Isolated Network Call: POST /sign (raw_tx, token)
                   ▼
┌──────────────────────────────────────┐
│       SIGNER SHIM (Enforcement)      │
│  - Verifies Ed25519 Token            │
│  - Recomputes Digest from Raw Bytes  │
│  - Atomically Consumes Single Nonce  │
│  - Signs via Disposable Testnet Key  │
└──────────────────┬───────────────────┘
                   │ 3. Signed Transaction Broadcast
                   ▼
┌──────────────────────────────────────┐
│       BLOCKCHAIN (Anvil / EVM)       │
└──────────────────────────────────────┘
                   ▲
                   │ On-Chain Block Scanner (Every Block)
┌──────────────────┴───────────────────────────────────────────────────┐
│              EIP-7702 DELEGATION & CODE WATCHER (F6)                 │
│  Monitors owned addresses; trips Breaker on unapproved delegations   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Implemented Milestone Features

### 1. Enforcement Core & Non-Bypassable Signer Shim (F1, F4, S06, S11, S12)
* **Zero Key Custody:** BitGuard never stores or touches blockchain private keys. It issues compact, short-lived (60s) Ed25519 tokens containing `digest`, `wallet`, `chain`, `exp`, and `nonce`.
* **Hardware/Shim Enforcement:** The Signer Shim sits on an isolated network (`signer_internal`). It independently parses raw transaction bytes, recalculates the cryptographic digest (`keccak256`), consumes the nonce atomically via Redis `SET NX`, and refuses any direct or tokenless signing request.
* **Canonical EVM Decoder:** Parses raw hex payloads directly (Legacy, EIP-2930, EIP-1559, and EIP-7702 Type-4). Never trusts caller-supplied metadata.

### 2. Atomic Distributed Velocity Limits (F3, S07)
* **Reserve-Then-Commit Pattern:** Powered by Redis Lua scripts over sorted sets. Concurrently reserves outflow capacity across single-tx, wallet-level, and global multi-chain sliding windows.
* **Non-Exhaustive Allocation:** Denied and expired requests release reservations automatically so attackers cannot manipulate rate limits with malformed transactions.
* **Fail-Closed Guarantee:** If Redis goes down or times out, the system defaults to strict local caps or immediate `DENY`.

### 3. Ledger Intent Reconciliation (F2, S08)
* Validates every signing request against an internal ledger record (`withdrawal_intents`).
* The payload destination, asset, and value must match an approved, unpaid intent. Any manufactured or replayed intent ID is denied instantly (`INTENT_MISMATCH` / `INTENT_REPLAY`).

### 4. EIP-7702 Delegation Guard & Live Watcher (F6, S09, S17, U7)
* **Deny-by-Default:** Blocks any Type-4 set-code transaction targeting owned hot wallets unless the delegate contract's code hash is explicitly pre-approved on an allowlist.
* **Proxy-Sweeper Detection:** Detects and denies unreviewed upgradeable proxy patterns (`DELEGATECALL` opcodes or EIP-1967 implementation slots).
* **On-Chain Watcher:** Scans every block across multiple RPC nodes. If an owned address carries an unauthorized delegation designator (`0xef0100...`), the watcher immediately trips the circuit breaker to `HOLD` or `LOCKDOWN`.

### 5. Multi-Party Hardware Quorum Console (F9, F10, S14, S16, U5)
* **Durable Quarantine:** Requests exceeding hold thresholds enter a persistent SQLite/Postgres quarantine queue (`HOLD`).
* **WebAuthn Over Digest:** Approvers authenticate using FIDO2 hardware keys (WebAuthn). The challenge signed by the hardware key is the exact transaction digest.
* **Separation of Duties:** Requires 2 distinct approvers. Requesters cannot approve their own transactions, and approvals cannot be executed via chat webhooks (Slack/Telegram are notification-only).

### 6. Asymmetric Circuit Breaker (F14, S18, U6)
* **Four States:** `NORMAL` $\rightarrow$ `ELEVATED` $\rightarrow$ `HOLD` $\rightarrow$ `LOCKDOWN`.
* **Asymmetric Security:** A single Operator or SecOps user can escalate to `LOCKDOWN` instantly. De-escalating or unlocking requires two-person quorum authorization.
* **Live Token Invalidation:** Transitioning to `LOCKDOWN` increments a global token epoch, instantly invalidating any in-flight tokens before the shim can sign them.

### 7. Cryptographic SHA-256 Audit Chain (F18, S21)
* Every firewall decision, quorum approval, and breaker transition is written to an append-only hash chain:
  $$\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{Timestamp} \parallel \text{RequestID} \parallel \text{Action} \parallel \text{Risk} \parallel \text{RuleHits})$$
* Includes live database tampering detection via `/api/audit/verify`.

### 8. Full UI Control Center (U1–U7)
* **Dark Cybersecurity SOC Design:** Built with React, Vite, and Tailwind CSS.
* **Seam Architecture (`web/api.js`):** Supports seamless toggling between real backend API streaming and legacy offline demo datasets without code disruption.
* **Live WebSocket Streams:** Subscribes to `/v1/stream` pushing real decisions, outflow metrics, and breaker states.

---

## 📂 Repository Directory Layout
```text
BitGuard/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── audit.py          # SHA-256 hash-chained tamper-evident audit log
│   │   │   ├── breaker.py        # Asymmetric state machine (Normal -> Lockdown)
│   │   │   ├── delegation.py     # EIP-7702 deny-by-default & code hash pinning
│   │   │   ├── policy.py         # Rolling-window limits & rule engine pipeline
│   │   │   ├── radar.py          # Type-4 transaction scanner & spray detector
│   │   │   ├── replay.py         # Synthetic timeline incident replay runner
│   │   │   └── report.py         # Automated post-mortem PDF generator
│   │   ├── decoders/
│   │   │   └── evm.py            # Canonical raw EVM byte decoder (F4)
│   │   ├── limits/
│   │   │   └── store.py          # Atomic Redis Lua sliding window store (F3)
│   │   ├── gateway/
│   │   │   └── rpc.py            # JSON-RPC endpoint & mTLS authentication (S12)
│   │   ├── approvals/
│   │   │   └── quorum.py         # WebAuthn hardware-key quorum verification (F10)
│   │   ├── watcher/
│   │   │   └── watcher.py        # Live multi-RPC block watcher for owned addresses (F6)
│   │   ├── models.py             # Canonical Pydantic schemas
│   │   └── main.py               # FastAPI application routing & WebSockets
│   ├── tests/
│   │   ├── test_audit.py         # Hash integrity, tampering, and verification tests
│   │   ├── test_delegation.py    # 7702 spray & unapproved delegate tests
│   │   ├── test_policy.py        # Single-tx, velocity, and zero-leak limit tests
│   │   ├── test_radar.py         # Type-4 block evaluation heuristics
│   │   └── test_replay.py        # Replay runner & containment assertions
│   └── requirements.txt
├── services/
│   ├── signer_shim/              # Isolated signing service verifying approval tokens (F1)
│   └── ledger_mock/              # Stand-in mock withdrawal ledger (F2)
├── lab/
│   ├── scenarios/                # Automated integration test scenarios (F19)
│   │   ├── 01_normal_transfer.yaml
│   │   ├── 02_over_limit_hold.yaml
│   │   ├── 04_delegation_denied.yaml
│   │   └── 07_redis_outage_fail_closed.yaml
│   └── runner.py                 # End-to-end integration scenario test harness
├── frontend/
│   ├── src/
│   │   ├── components/           # Navigation, modal popups, badges, breaker controls
│   │   ├── pages/
│   │   │   ├── IncidentReplay.tsx # Split-screen baseline vs. protected evaluation
│   │   │   ├── LiveFeed.tsx       # Live WebSocket feed & WebAuthn HOLD queue
│   │   │   ├── RadarView.tsx      # EIP-7702 scanner & "My Addresses" watcher panel
│   │   │   ├── SensitivityLab.tsx # Trade-off curves & backtest matrix
│   │   │   └── ReportsView.tsx    # Tamper detection console & PDF generation
│   │   ├── api.ts                # API client with dual demo/api data-source seam
│   │   └── App.tsx
│   └── package.json
├── docker-compose.yml            # Multi-network lab setup (Postgres, Redis, Anvil, BitGuard, Shim)
└── Makefile                      # Build, test, and container orchestration
```
---

## ⚡ Quickstart & Local Installation

### Prerequisites
* **Python 3.12+**
* **Node.js 18+** & **npm**
* **Docker Desktop** (with Compose)
* **Foundry** (for local `anvil` EVM testing)

### 1. Start Lab Environment via Docker Compose

BitGuard isolates signing infrastructure across two Docker networks: `public` and `signer_internal` (the Signer Shim is physically unreachable from outside containers).
```bash
# Clone the repository
git clone [https://github.com/mayank1916-dev/BitGuard.git](https://github.com/mayank1916-dev/BitGuard.git)
cd BitGuard

# Launch Postgres, Redis, Anvil EVM, BitGuard Gateway, and Signer Shim
docker compose up -d
```
---
2. Run the Full Test Suite
The repository includes comprehensive unit tests and automated integration lab scenarios:
```bash
# Set up Python virtual environment
python -m venv venv
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Run pytest unit test suite
pytest backend/tests/ -v

# Run the S23 integration lab scenarios
python lab/runner.py
```
---
3. Launch the Frontend SOC Console
In a separate terminal:
```bash
  cd frontend

# Install UI dependencies
npm install

# Start Vite development server
npm run dev
```

Navigate to http://localhost:3000.

---

## 🔬 Interactive Feature Verification Guide

| Tab / Capability | Procedure | Expected Forensic Outcome |
| :--- | :--- | :--- |
| **Custom TX Sandbox** | Click **"Submit Custom Payload"** in the top bar. Enter a `$500,000` transfer to an unseen address. | Evaluates raw calldata; trips velocity rules; returns `HOLD` ticket with cryptographic reason codes. |
| **Quorum Release** | Navigate to **Live Feed** $\rightarrow$ locate the held transaction in the **HOLD Queue** $\rightarrow$ Click **Approve**. | Prompts WebAuthn FIDO2 ceremony (or virtual authenticator). Reaching 2-person quorum releases the transaction to the shim. |
| **EIP-7702 Detection** | In **7702 Radar**, observe the **"My Addresses"** panel while a test script executes an unapproved delegation on Anvil. | Watcher detects the delegation designator (`0xef0100`) within 1 block, raises `CRITICAL`, and transitions Breaker to `HOLD`. |
| **Circuit Breaker** | Click **BREAKER LOCKDOWN** in the navigation bar. | Prompts for confirmation. Entering Lockdown stops token issuance and invalidates all active token epochs across the shim. |
| **Tamper Detection** | Open **Reports & Audit** $\rightarrow$ Click **"Simulate DB Tampering"**. | The cryptographic seal flips to red: `CHAIN COMPROMISED AT RECORD #X - SHA-256 MISMATCH`. Clicking **Restore** rebuilds verified state. |
---

## 📊 Honest Scope & Limitations
---
To maintain institutional security rigor, BitGuard operates under explicitly stated boundaries:

Signing Boundary: BitGuard reduces and contains risks on the automated signing path against pipeline compromise, replay, and unauthorized delegation (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). It does not replace internal HSM key ceremonies or protect against compromised developer endpoints directly.

Velocity Evasion: An attacker who stays strictly below configured thresholds can move capital up to that limit. BitGuard relies on Intent Reconciliation (F2) and EIP-7702 Allowlisting (S09) to reduce and contain unauthorized withdrawals regardless of size (the goal is to shrink and slow loss and force detection). Detailed boundaries and compensating controls are cataloged in [docs/LIMITS.md](docs/LIMITS.md).

Fail-Closed Stance: If the atomic limit store (Redis) or ledger database becomes unreachable, the firewall defaults to DENY to reduce and contain race-condition drains. Performance target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](docs/PERF.md)). Classification: production-ready architecture; pilot after audit and shadow-mode validation.

## 📜 License
---
This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
