# BitGuard Repository Wording Pass & Claim Audit Log (TASK W1)

## Executive Summary

This document catalogs all text and claim revisions applied during **TASK W1 (Wording Pass)** across the BitGuard repository (UI components, README, architectural documentation, report generators, and user-facing code strings). 

All changes strictly enforce **Invariant #11 (Strict Wording & Claims)** and eliminate unhedged security guarantees, flat latency statements, and unlabelled figures.

---

## 1. Operating Wording Principles (Invariant #11)

1. **Attack Containment vs. Absolute Prevention:**
   - **Old Phrasing:** "prevents" or "stops" attacks.
   - **Mandated Formulation:** **"reduces and contains"** paired with the contextual clarification: *(a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection)*.
   - **Rationale:** A limit-aware adversary who stays strictly under single-transaction caps or velocity ceilings can move capital up to that configured limit. BitGuard shrinks and slows blast radiuses, forces human quorum escalation, and buys SecOps containment time; it cannot offer mathematical impossibility of fund movement below limits without paired controls.

2. **Latency Claims Grounded in Empirical Measurement:**
   - **Old Phrasing:** Flat assertions of "<15 ms" or "under 15 ms".
   - **Mandated Formulation:** **"target p99 under 15 ms for the local fast path, measured under load"** accompanied by the verified benchmark values from `docs/PERF.md` (*measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency*).

3. **Production Maturity Classification:**
   - **Old Phrasing:** "production-grade".
   - **Mandated Formulation:** **"production-ready architecture; pilot after audit and shadow-mode validation"**.

4. **Explicit Data Provenance (Invariant #8):**
   - Every metric, figure, or counter displayed in user-facing consoles must carry an explicit **REAL**, **SYNTHETIC**, or **REPORTED** data provenance label.

5. **Defensive Boundaries & System Limits Note:**
   - The Reports & Audit tab provides a prominent informational banner directly linking to [`docs/LIMITS.md`](file:///c:/Users/pursh/bitguard/docs/LIMITS.md) cataloging external Cloud HSM risks, compromised approver laptops, slow drains, and decoder bytecode gaps with paired compensating controls.

---

## 2. Comprehensive Inventory of Revisions

### A. Root & Architectural Overview
#### `README.md`
- **Location:** Line 17 (Header Callout)
  - **Before:** `> **Defensive Scope & Target:** Production-ready architecture tested on local forks (Foundry Anvil) and testnets using disposable keys. Reduces and contains exploit blast radius; never holds or uses long-term private signing keys.`
  - **After:** `> **Defensive Scope & Target:** Production-ready architecture; pilot after audit and shadow-mode validation. Tested on local forks (Foundry Anvil) and testnets using disposable keys. Reduces and contains exploit blast radius (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection); never holds or uses long-term private signing keys. Latency benchmark: target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](docs/PERF.md)). System boundaries and compensating controls documented in [docs/LIMITS.md](docs/LIMITS.md).`
- **Location:** Lines 237–246 (`## 📊 Honest Scope & Limitations`)
  - **Before:** `Signing Boundary: BitGuard protects the automated signing path against pipeline compromise... Velocity Evasion: ...BitGuard relies on Intent Reconciliation (F2) and EIP-7702 Allowlisting (S09) to stop unauthorized withdrawals regardless of size. Fail-Closed Stance: ...the firewall defaults to DENY to prevent race-condition drains.`
  - **After:** `Signing Boundary: BitGuard reduces and contains risks on the automated signing path against pipeline compromise, replay, and unauthorized delegation (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). It does not replace internal HSM key ceremonies or protect against compromised developer endpoints directly. Velocity Evasion: An attacker who stays strictly below configured thresholds can move capital up to that limit. BitGuard relies on Intent Reconciliation (F2) and EIP-7702 Allowlisting (S09) to reduce and contain unauthorized withdrawals regardless of size (the goal is to shrink and slow loss and force detection). Detailed boundaries and compensating controls are cataloged in [docs/LIMITS.md](docs/LIMITS.md). Fail-Closed Stance: If the atomic limit store (Redis) or ledger database becomes unreachable, the firewall defaults to DENY to reduce and contain race-condition drains. Performance target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](docs/PERF.md)). Classification: production-ready architecture; pilot after audit and shadow-mode validation.`

---

### B. Documentation Suite (`docs/`)

#### `docs/compliance-mapping.md`
- **Location:** Section 1 (Architectural Invariants & Scope)
  - **Before:** `Operating performance is target p99 under 15 ms, measured.`
  - **After:** `Operating performance is target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)).`
- **Location:** Section 3, Table CC6.6
  - **Before:** `Protects system boundaries and prevents unauthorized network traversal.`
  - **After:** `Protects system boundaries, reduces and contains unauthorized network traversal (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection).`
- **Location:** Section 3, Table CC6.8
  - **Before:** `Prevents unauthorized code execution or smart contract exploits.`
  - **After:** `Reduces and contains unauthorized code execution and smart contract exploits (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection).`
- **Location:** Section 3, Table CC7.3
  - **Before:** `Measured time to contain (target under 15 ms, measured).`
  - **After:** `Measured time to contain (target p99 under 15 ms for the local fast path, measured under load; measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)).`

#### `docs/PENTEST_BRIEF.md`
- **Location:** Section 1 (Claim Standard)
  - **Before:** `Claim standard (Invariant #11): BitGuard reduces and contains unauthorized transaction signing; production-ready architecture; pilot after audit and shadow-mode validation; target p99 under 15 ms, measured.`
  - **After:** `Claim standard (Invariant #11): BitGuard reduces and contains unauthorized transaction signing (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection); production-ready architecture; pilot after audit and shadow-mode validation; target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)).`

#### `docs/SHADOW_REPORT.md`
- **Location:** Section 1 (Technical Claims & Verifications)
  - **Before:** `Achieves target p99 under 15 ms, measured for the local fast path.`
  - **After:** `Achieves target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)).`
- **Location:** Section 8, Item 2
  - **Before:** `The promotion checklist successfully prevented premature promotion of an uncalibrated policy...`
  - **After:** `The promotion checklist successfully reduced risk by containing premature promotion of an uncalibrated policy...`

#### `docs/THREAT_MODEL.md`
- **Location:** Header Scope Callout
  - **Before:** `Target p99 under 15 ms, measured on synthetic and testnet traffic.`
  - **After:** `Target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)). Compensating controls cataloged in [docs/LIMITS.md](LIMITS.md).`

#### `docs/api-errors.md`
- **Location:** Section 1 Note Callout
  - **Before:** `BitGuard reduces and contains blast radius from compromised credentials or rogue callers. Target latency: target p99 under 15 ms, measured.`
  - **After:** `BitGuard reduces and contains blast radius from compromised credentials or rogue callers (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). Target latency: target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)). Production-ready architecture; pilot after audit and shadow-mode validation. Compensating controls in [docs/LIMITS.md](LIMITS.md).`

#### `docs/break-glass.md`
- **Location:** Section 1 & Section 4
  - **Before:** `The Break-Glass Emergency Protocol provides a production-ready architecture; pilot after audit and shadow-mode validation. This mechanism reduces and contains risk during catastrophic events by establishing a time-boxed, two-person quorum override that permits transactions only to pre-approved destination allowlists... Performance targets remain intact: target p99 under 15 ms, measured, across all evaluations.`
  - **After:** `The Break-Glass Emergency Protocol provides a production-ready architecture; pilot after audit and shadow-mode validation. This mechanism reduces and contains risk during catastrophic events by establishing a time-boxed, two-person quorum override that permits transactions only to pre-approved destination allowlists (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). Performance target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)). System boundaries detailed in [docs/LIMITS.md](LIMITS.md)... Performance targets remain intact: target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)), across all evaluations.`

#### `docs/lab.md`
- **Location:** Section 2, Item 3
  - **Before:** `BitGuard reduces and contains unauthorized transaction signing. Performance benchmark: target p99 under 15 ms, measured. Deployment status: production-ready architecture; pilot after audit and shadow-mode validation.`
  - **After:** `BitGuard reduces and contains unauthorized transaction signing (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). Performance benchmark: target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)). Deployment status: production-ready architecture; pilot after audit and shadow-mode validation. System boundaries cataloged in [docs/LIMITS.md](LIMITS.md).`

#### `docs/limits.md`
- **Location:** Header Callout
  - **Before:** `Latency benchmark: target p99 under 15 ms, measured.`
  - **After:** `Latency benchmark: target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)).`

#### `docs/redis-failover.md`
- **Location:** Section 4 (Observability)
  - **Before:** `Performance target: target p99 under 15 ms, measured, maintained across all healthy and degraded modes.`
  - **After:** `Performance target: target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)), maintained across all healthy and degraded modes.`

#### `docs/spiffe.md`
- **Location:** Section 1 (Overview)
  - **Before:** `This architecture reduces and contains unauthorized signing exposure by binding each incoming signing request to... Local fast-path local policy decision has a target p99 under 15 ms, measured.`
  - **After:** `This architecture reduces and contains unauthorized signing exposure (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection) by binding each incoming signing request to... Local fast-path local policy decision has a target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)). System boundaries detailed in [docs/LIMITS.md](LIMITS.md).`

---

### C. Services & Report Generators

#### `services/bitguard/reports/generator.py`
- **Location:** Line 53 (`INVARIANT_CLAIM_TEXT`)
  - **Before:** `"BitGuard reduces and contains unauthorized transaction signing. Operating performance target p99 under 15 ms, measured. Production-ready architecture; pilot after audit and shadow-mode validation."`
  - **After:** `"BitGuard reduces and contains unauthorized transaction signing (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). Operating performance target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per docs/PERF.md). Production-ready architecture; pilot after audit and shadow-mode validation."`
- **Location:** Line 778 (Monthly Control Report PDF KPI Table)
  - **Before:** `Paragraph("target p99 under 15 ms, measured [REAL]", self.body_style)`
  - **After:** `Paragraph("target p99 under 15 ms for the local fast path, measured under load (pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per docs/PERF.md) [REAL]", self.body_style)`

#### `services/bitguard/backtest/service.py`
- **Location:** Line 580 (`protection_note`)
  - **Before:** `"protection_note": "Policy reduces and contains unauthorized outflows; target p99 under 15 ms, measured."`
  - **After:** `"protection_note": "Policy reduces and contains unauthorized outflows (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection); target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per docs/PERF.md). Production-ready architecture; pilot after audit and shadow-mode validation."`

---

### D. User Interface Components (`frontend/src/pages/`)

#### `frontend/src/pages/ReportsView.tsx`
1. **Header Description:**
   - **Before:** `BitGuard reduces and contains unauthorized transaction signing with verified audit non-repudiation.`
   - **After:** `BitGuard reduces and contains unauthorized transaction signing with verified audit non-repudiation (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). Operating performance target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per docs/PERF.md). Production-ready architecture; pilot after audit and shadow-mode validation.`
2. **Defensive Boundary & LIMITS.md Callout:**
   - Added dedicated informational banner below the header linking to [`docs/LIMITS.md`](file:///c:/Users/pursh/bitguard/docs/LIMITS.md) with an overview of paired compensating controls for Cloud HSM root access, compromised approver laptops, slow drains, and bytecode decoder gaps.
3. **Data Provenance Labels on Unlabelled Figures:**
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Root Hash / Ledger Head**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Chained Audit Blocks**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Incident Record(s) Logged**.
   - Added `[REAL]` badge to **Time to Contain** in the security incident list rows.

#### `frontend/src/pages/RadarView.tsx`
1. **Multi-RPC Consensus Guard Information Banner (Line 428):**
   - **Before:** `...containing unauthorized key actions within target p99 under 15 ms, measured.`
   - **After:** `...reducing and containing unauthorized key actions within target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per docs/PERF.md; a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection).`
2. **Data Provenance Badges Added to Stat Cards:**
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Total Hot Wallets**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Allowlisted Delegates**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Unapproved Delegations**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Provider Consensus**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Latest Block**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Type-4 Txs Discovered**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Anomalies Detected**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Blocks Analyzed**.

#### `frontend/src/pages/LiveFeed.tsx`
1. **Data Provenance Badges Added to Top Metrics Row:**
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Total Streamed**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Allowed Signing**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Manual Holds**.
   - Added `[REAL]` / `[SYNTHETIC]` badge to **Firewall Denies**.

#### `frontend/src/pages/ApprovalView.tsx`
1. **Top Banner Claim Description:**
   - **Before:** `Reduces and contains unauthorized signing. Target p99 under 15 ms, measured.`
   - **After:** `Reduces and contains unauthorized signing (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection). Target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per docs/PERF.md). Production-ready architecture; pilot after audit and shadow-mode validation.`

#### `frontend/src/pages/SensitivityLab.tsx`
1. **Backtest Result Summary Callout:**
   - Added `[REPORTED]` / `[SYNTHETIC]` data provenance tag to the summary callout header.
   - Inserted contextual clarification: `(a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection)`.

---

## 3. Verification & Compliance Sign-Off

- **Linter & Code Quality:** Verified 0 errors across `services/` and `tests/` using `ruff check`.
- **Static Type Safety:** Verified 0 issues across 165 source files using `mypy`.
- **Frontend Build:** Clean compilation with Vite (`npm --prefix frontend run build`).
- **Test Integrity:** All regression suites passed (`test_ui_reports.py`, `test_reports.py`, `test_ui_radar.py`, `test_ui_sensitivity_lab.py`).
- **Invariant #10 (Visual Stability):** No CSS files (`index.css`, `App.css`), layout grids, or design tokens were modified.
- **Invariant #11 (Strict Wording):** All occurrences of forbidden unhedged claims have been eliminated repository-wide.
