# BitGuard System Audit & Architectural Specification

> **Document Classification:** Architecture & Simulation Audit  
> **Target System:** BitGuard — Autonomous Signing-Request Firewall & Incident-Replay Lab  
> **Status:** Read-Only Audit (Task S00)  
> **Scope:** Full-stack inspection across Backend (`backend/`), Frontend (`frontend/`), Data Datasets (`backend/data/`), and Test Suites (`backend/tests/`).

---

## 1. Tech Stack, File Tree & Execution Model

### 1.1 Tech Stack Inventory

| Layer | Technology | Version / Specification | Purpose |
| :--- | :--- | :--- | :--- |
| **Backend Runtime** | Python | `>= 3.10` (Tested on `3.14.6`) | Core execution environment |
| **Web Framework** | FastAPI | `>= 0.110.0` | High-performance async REST API framework |
| **ASGI Web Server** | Uvicorn | `>= 0.28.0` | Production ASGI server implementation |
| **Validation / Schema** | Pydantic (v2) | `>= 2.6.0` | Request validation, data serialization, type models |
| **HTTP & RPC Client** | HTTPX | `>= 0.27.0` | Async/sync JSON-RPC polling for Ethereum node communication |
| **PDF Generation** | ReportLab | `platypus`, `reportlab.lib` | Dynamic cybersecurity post-mortem PDF rendering |
| **Cryptography** | Python `hashlib` | SHA-256 (Standard Library) | Cryptographic block chaining for audit trail |
| **Test Suite** | Pytest | `>= 8.0.0`, AnyIO | Automated unit & integration testing (25 test cases) |
| **Frontend Runtime** | Node.js | `>= 18.0.0` (npm 10+) | Frontend build and runtime tooling |
| **UI Framework** | React | `^18.3.1` (TypeScript `~5.6.2`) | Component-driven reactive user interface |
| **Build Tooling** | Vite | `^5.4.10` | Fast HMR dev server & Rollup production bundler |
| **CSS & Design Engine**| Tailwind CSS | `^3.4.17` (PostCSS `8.5.32`) | Utility-first cybersecurity dark-mode design system |
| **Data Visualization** | Recharts | `^3.10.1` | SVG Composed Charts (Area + Line) for policy sensitivity |
| **Iconography** | Lucide React | `^1.66.0` | Consistent vector iconography |
| **Class Utilities** | `clsx` + `tailwind-merge` | `clsx ^2.1.1`, `twMerge ^3.7.0` | Conflict-free conditional CSS class merging |

---

### 1.2 Repository File Tree

```text
bitguard/
├── README.md
├── docs/
│   └── AUDIT.md                             # [This Document] System Architecture & Simulation Audit
├── backend/
│   ├── requirements.txt                     # Backend dependencies (fastapi, uvicorn, pydantic, httpx, etc.)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                          # FastAPI application factory, API routes & state seeding
│   │   ├── models.py                        # Pydantic core models (SigningRequest, Decision)
│   │   └── core/
│   │       ├── __init__.py
│   │       ├── audit.py                     # Tamper-evident append-only SHA-256 audit ledger
│   │       ├── breaker.py                   # CircuitBreaker state machine (Normal, Elevated, Hold, Lockdown)
│   │       ├── delegation.py                # EIP-7702 delegation allowlist & nonce-spray detection
│   │       ├── policy.py                    # PolicyEngine rolling-window velocity limit evaluation
│   │       ├── radar.py                     # EIP-7702 Type-4 transaction Ethereum RPC scanner & heuristic scorer
│   │       ├── replay.py                    # ReplayRunner simulation engine & sensitivity matrix runner
│   │       └── report.py                    # ReportLab automated incident post-mortem PDF generator
│   ├── data/
│   │   ├── cached_type4_blocks.json         # Static pre-recorded EIP-7702 Type-4 Ethereum transactions
│   │   └── replay_binance_like.json         # 75-event synthetic attack dataset (Oct 2026 Binance exploit replay)
│   └── tests/
│       ├── __init__.py
│       ├── test_audit.py                    # Cryptographic audit hash chain & tamper detection tests
│       ├── test_policy.py                   # Velocity rules, limits, and breaker escalation tests
│       ├── test_radar.py                    # Type-4 transaction heuristic pattern and RPC fallback tests
│       └── test_replay.py                   # Full 75-event timeline simulation & sensitivity tests
└── frontend/
    ├── package.json                         # Frontend dependencies & scripts
    ├── package-lock.json
    ├── tsconfig.json                        # Project TypeScript configuration references
    ├── tsconfig.app.json                    # Application TypeScript compiler settings
    ├── tsconfig.node.json                   # Node runtime TypeScript settings
    ├── vite.config.ts                       # Vite configuration (port 3000, /api reverse proxy to 8000)
    ├── tailwind.config.js                   # Custom cybersecurity palette, tokens & fonts
    ├── postcss.config.js                    # PostCSS configuration with Tailwind and Autoprefixer
    ├── eslint.config.js                     # ESLint 9 configuration
    ├── index.html                           # Single-page HTML shell
    ├── public/
    │   └── vite.svg
    └── src/
        ├── main.tsx                         # React entrypoint (StrictMode mount into #root)
        ├── App.tsx                          # Root container, top-level state, global simulation loaders & tab routing
        ├── App.css
        ├── index.css                        # Global CSS variables, body styles, custom slim scrollbar
        ├── api.ts                           # Client-side API functions, TypeScript interfaces, fetch wrappers
        ├── utils.ts                         # Formatting (currency, addresses), chain badge style dictionary, cn helper
        ├── vite-env.d.ts
        ├── assets/
        │   └── react.svg
        ├── components/
        │   ├── Navbar.tsx                   # Top navigation bar, circuit breaker badge, defensive simulation tag
        │   └── PolicySliders.tsx            # Interactive threshold tuning controls (single, wallet, global limits)
        └── pages/
            ├── ReplayView.tsx               # Split-screen incident replay hero, dynamic clock, custom TX sandbox modal
            ├── LiveFeed.tsx                 # Live transaction stream, search/filters, idle micro-withdrawal ticker
            ├── RadarView.tsx                # EIP-7702 Type-4 live scanner radar, heuristic risk scores, raw payload modal
            ├── PolicyLabView.tsx            # Policy sensitivity tab wrapper
            ├── SensitivityLab.tsx           # Sensitivity matrix curve (Recharts ComposedChart + multiplier table)
            └── ReportsView.tsx              # Tamper-evident ledger viewer, live tamper injection & PDF generator
```

---

### 1.3 How the Application is Started

#### 1. Backend Service (FastAPI / Uvicorn)
The backend runs as a standard ASGI server on port `8000`.
- **Command:**
  ```powershell
  uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
  ```
- **Alternative:**
  ```powershell
  python -m uvicorn backend.app.main:app --port 8000 --reload
  ```
- **Health Verification:** `GET http://localhost:8000/api/health` returns `{"status":"ok","service":"bitguard","version":"0.4.0","breaker_state":"Normal"}`.

#### 2. Frontend Development Server (Vite)
The frontend runs on port `3000` and automatically proxies all `/api/*` traffic to `http://localhost:8000`.
- **Command:**
  ```powershell
  cd frontend
  npm run dev
  ```
- **Dev URL:** `http://localhost:3000`
- **Reverse Proxy Specification (`frontend/vite.config.ts`):**
  ```typescript
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  }
  ```

#### 3. Verification Commands
- **Backend Tests (25/25 passing):**
  ```powershell
  python -m pytest backend/tests/ -v
  ```
- **Frontend Production Build (TypeScript compilation + Vite bundler):**
  ```powershell
  cd frontend
  npm run build
  ```

---

## 2. Tab & Screen Audit: Exact Data Sources

| Tab / Screen | Component File | Primary Data Source | Underlying Mechanism & Endpoints |
| :--- | :--- | :--- | :--- |
| **Incident Replay** | `frontend/src/pages/ReplayView.tsx` | Static JSON Dataset + Browser Timers | • Initial Load: `POST /api/replay` returning evaluation of `backend/data/replay_binance_like.json` (75 synthetic transactions).<br>• Playback: Browser `setInterval` (400ms @ 1x, 80ms @ 5x, 30ms @ 10x) advancing `currentIndex`.<br>• Standby Placeholder: Client-side condition `currentIndex === 0 && !isPlaying`.<br>• Dynamic Clock: Browser UTC `setInterval(..., 1000)` when idle; event timestamp `events[currentIndex]?.ts` when stepped/playing.<br>• Custom TX Sandbox: Form modal dispatching `POST /api/evaluate` and locally appending `StepEvent` to component state. |
| **Live Feed** | `frontend/src/pages/LiveFeed.tsx` | Prop Stream Slice + Local Synthetic Interval | • Active Replay Mode: Slices `steps.slice(0, currentStep + 1)` passed as props from `App.tsx`.<br>• Idle Background Generator: Browser `setInterval(..., 3000)` creating randomized synthetic micro-withdrawals ($120–$4,620) from hardcoded chain and wallet arrays.<br>• Fallback: Static 75 events from `App.tsx` if replay finished. |
| **7702 Radar** | `frontend/src/pages/RadarView.tsx` | Public Ethereum JSON-RPC + Offline JSON Fallback | • Endpoint: `GET /api/radar?n_blocks=5&force_cached=false&_t=...`<br>• Backend Engine: `RadarScanner.scan_recent_blocks()`.<br>• Live Path: HTTPX JSON-RPC calls (`eth_blockNumber`, `eth_getBlockByNumber`) to `https://eth.llamarpc.com`.<br>• Fallback / Cached Path: Loads `backend/data/cached_type4_blocks.json` from disk PLUS generates a simulated finding (`_generate_simulated_finding`) with incrementing `simulated_block_counter` (starts at `21,890,124`). |
| **Sensitivity Lab** | `frontend/src/pages/SensitivityLab.tsx`<br>(via `PolicyLabView.tsx`) | Computed Replay Grid | • Endpoint: `POST /api/policy/sensitivity`.<br>• Input: Debounced (200ms) slider values (`base_single_tx_usd`, `base_wallet_limit_usd`, `base_global_limit_usd`, `base_new_recipient_usd`).<br>• Backend Engine: `run_sensitivity_matrix()` runs `ReplayRunner` 9 times across multipliers `[0.1x, 0.25x, 0.5x, 0.75x, 1.0x, 1.5x, 2.0x, 3.0x, 5.0x]` on the 75-event synthetic timeline dataset.<br>• Rendered into Recharts `<ComposedChart>` and HTML evaluation table. |
| **Reports & Audit** | `frontend/src/pages/ReportsView.tsx` | In-Memory Cryptographic Hash Chain + ReportLab | • Record List: `GET /api/audit/records` (reads in-memory `AuditLog.entries`).<br>• Hash Verification: `GET /api/audit/verify` (recomputes SHA-256 chain from genesis block `0*64`).<br>• Tamper Simulation: `POST /api/audit/simulate-tamper` (mutates stored entry in-memory).<br>• Restore Ledger: `POST /api/audit/reset` (restores pristine backup and recomputes hashes).<br>• PDF Report Download: `GET /api/report/download` (ReportLab generates binary PDF buffer streamed to client). |

---

## 3. Enumeration of Faked & Simulated Behaviors

Every component in BitGuard balances defensive security logic with deterministic simulation behavior. Below is the comprehensive list of simulated behaviors, timers, and synthetic mock mechanics:

### 3.1 Replay Timer Loop (`ReplayView.tsx: lines 55–75`)
- **Faked Behavior:** Simulates real-time blockchain execution using browser `setInterval` steps rather than waiting for live network block propagation.
- **Calibration Intervals:**
  - `1x` speed: `400ms` per event.
  - `5x` speed: `80ms` per event.
  - `10x` speed: `30ms` per event.
- **State Advance:** Sequentially increments `currentIndex` from `0` to `events.length - 1`.

### 3.2 Dynamic Clock Emulation (`ReplayView.tsx: lines 111–135`)
- **Faked Behavior:** 
  - When idle/reset (`!isPlaying && currentIndex === 0`): Runs a `1000ms` `setInterval` reading browser UTC time:
    ```typescript
    new Date().toUTCString().slice(17, 25) + " UTC"
    ```
  - When playing or stepped (`isPlaying || currentIndex > 0`): Derives clock time from the synthetic dataset timestamp (based around October 30, 2026):
    ```typescript
    new Date((events[currentIndex]?.ts ?? 1730299400) * 1000).toISOString().substr(11, 8) + " UTC"
    ```

### 3.3 75-Event Synthetic Attack Scenario (`backend/data/replay_binance_like.json`)
- **Faked Behavior:** All 75 transactions are synthetically constructed to replicate the telemetry and progression of the late-October 2026 Binance hot wallet exploit sequence:
  1. **Events 0–9:** Baseline normal retail withdrawals across Ethereum, Solana, Bitcoin, Tron, Arbitrum, Base, Optimism (`$1,500` to `$14,200`).
  2. **Events 10–14 (T=0s):** XRP Ledger outflow — 5 hot wallets drained of 233.46M XRP (`$120.2M`).
  3. **Events 15–24 (T+35s):** Multi-chain cascade across Solana (970k SOL), Optimism, Base, Bitcoin (18,270 BTC), and Tron (612.7M USDT).
  4. **Events 25–44 (T+110s):** EIP-7702 Nonce Spray — 50 consecutive nonces for hot wallet `Binance 14` targeting unapproved sweeper contract `0x7702de1e9a4d86b72186be34f5dfbb653112c2a0`.
  5. **Events 45–64 (T+180s):** Massive sweeper drain — 167,464 ETH + 63 ERC-20 tokens (`$2.18B+`).
  6. **Events 65–74 (T+35m–T+55m):** Secondary automated sweeps.

### 3.4 Unprotected Baseline vs. BitGuard Protected Simulation (`backend/app/core/replay.py`)
- **Faked Behavior:**
  - **Unprotected Pipeline:** Blind-signs every transaction, always returning `action: "allow"` and accumulating cumulative loss up to `$2,912,660,000.00`.
  - **BitGuard Pipeline:** Evaluates each request sequentially against `PolicyEngine`. Once limits breach or unauthorized 7702 delegations are encountered, subsequent transactions are held or denied, freezing protected losses at `$120,200,000.00` and saving `$2,792,460,000.00` (`95.9%`).

### 3.5 Circuit-Breaker State Machine & Anomaly Scoring (`backend/app/core/breaker.py`)
- **Faked Behavior:** An in-memory sliding window heuristic:
  - Tracks anomalous events in `self.anomalies` within a `300.0s` (5-minute) rolling window.
  - Multi-chain escalation thresholds:
    - $\ge 2$ unique chains with anomalies $\rightarrow$ Transition to `Elevated`.
    - $\ge 3$ unique chains with anomalies $\rightarrow$ Transition to `Lockdown`.
  - Critical flags (`is_critical=True`, e.g., unauthorized 7702 delegate or $\ge 50$ nonce spray) trigger immediate `trip_lockdown()` bypassing the multi-chain counter.
  - In `ReplayView.tsx`, containment time is hardcoded to display `CONTAINMENT: 0.0s` as containment is immediate upon first denial.

### 3.6 Loss & Metric Gauges (`frontend/src/pages/ReplayView.tsx: lines 137–150`)
- **Faked Behavior:** When in reset state (`currentIndex === 0 && !isPlaying`), loss counters are artificially clamped to `$0.00` and breaker state to `NORMAL`, overriding the dataset's initial event values. During playback, values reflect cumulative synthetic loss sums from the active step.

### 3.7 Custom Transaction Evaluation & Injection Sandbox (`ReplayView.tsx: lines 188–236`)
- **Faked Behavior:**
  - Evaluates arbitrary custom transactions against the backend via `POST /api/evaluate`.
  - When "Inject into Timeline Stream" is clicked, it synthesizes a local `StepEvent` object with mock cumulative losses (`prevUnprotected + reqAmount`), prepending or appending it into React component state (`injectedEvents`), faking live pipeline insertion.

### 3.8 Live Feed Idle Micro-Withdrawal Generator (`frontend/src/pages/LiveFeed.tsx: lines 38–72`)
- **Faked Behavior:** When idle (`!isPlaying`), a 3-second background `setInterval` generates fake retail transactions:
  - Random chain chosen from: `['ethereum', 'bitcoin', 'solana', 'tron', 'arbitrum', 'base', 'optimism']`.
  - Random wallet chosen from: `['0xBinanceHotETH1', 'bc1qBinanceHotBTC1', 'SolBinanceHot1', 'TBinanceHotTRX1', '0xBinanceHotArb1', '0xBinanceHotBase1']`.
  - Random amount: `$120` to `$4,620` (`Math.floor(Math.random() * 4500) + 120`).
  - Synthesized `Decision`: `{ action: 'allow', risk: 0, reasons: [], breaker_state: 'Normal' }`.
  - Unshifted to the top of `liveStream` state, capped at 100 entries.

### 3.9 7702 Radar Dynamic Simulation (`backend/app/core/radar.py: lines 96–125, 234–249`)
- **Faked Behavior:**
  - Increments `self.simulated_block_counter` by `1` per scan (starting from `#21,890,124`).
  - If live Ethereum RPC fails, rate-limits, or contains 0 Type-4 transactions, `_generate_simulated_finding()` cycles through a 4-pattern heuristic pool:
    1. Consecutive nonces spray (`risk: 60`, `auths: 12`, `nonces: 12`).
    2. High volume authorizations + single delegate concentration (`risk: 70`, `auths: 25`).
    3. Benign single auth (`risk: 15`, `auths: 1`).
    4. Single delegate concentration (`risk: 35`, `auths: 3`).
  - Combines the newly generated finding with the disk cache (`cached_type4_blocks.json`) so the UI visibly refreshes with each scan.

### 3.10 Cryptographic Audit Tamper Mutation (`backend/app/core/audit.py: lines 134–164`)
- **Faked Behavior:**
  - `tamper_test_corrupt_entry(index)` deliberately mutates a record's `action` (e.g. `deny` $\rightarrow$ `allow`) and `risk` (`100` $\rightarrow$ `0`) in memory *without* recalculating `entry_hash`.
  - `verify_integrity()` detects the hash mismatch and points to `corrupted_index`.
  - `reset_ledger()` restores the in-memory array from `_backup_entries` and recalculates deterministic SHA-256 hashes from genesis block `0*64`.
  - Startup auto-seeding (`backend/app/main.py: ensure_audit_chain_seeded`): Runs `ReplayRunner().run()` on the first audit call to populate the in-memory ledger with the 75 synthetic replay decisions.

---

## 4. UI Design System Tokens, CSS Classes & Colors (Must Stay Unchanged)

To preserve visual continuity, all existing tokens, color classes, font declarations, and layouts must remain strictly intact:

### 4.1 Tailwind Config Color Palette (`frontend/tailwind.config.js`)

```javascript
colors: {
  cyber: {
    bg: "#0B0F17",       // Deep cybersecurity slate background
    card: "#111827",     // Secondary container background
    border: "#1F2937",   // Slate border
    subtle: "#1E293B",   // Input / inactive surface
    accent: "#38BDF8",   // Electric cyan accent
  },
  healthy: {
    DEFAULT: "#10B981",  // Emerald-500 (Allowed / Healthy)
    bg: "rgba(16, 185, 129, 0.12)",
    border: "rgba(16, 185, 129, 0.3)",
  },
  elevated: {
    DEFAULT: "#F59E0B",  // Amber-500 (Elevated scrutiny / Hold)
    bg: "rgba(245, 158, 11, 0.12)",
    border: "rgba(245, 158, 11, 0.3)",
  },
  lockdown: {
    DEFAULT: "#F43F5E",  // Rose-500 (Circuit Breaker Lockdown / Denied)
    bg: "rgba(244, 63, 94, 0.15)",
    border: "rgba(244, 63, 94, 0.4)",
  },
}
```

### 4.2 Typography & Fonts
- **Monospace Telemetry:** `"JetBrains Mono", Menlo, Monaco, "Courier New", monospace` (Tailwind class: `font-mono`). Applied to all timestamps, hashes, amounts, nonces, addresses, and counters.
- **Body / Sans:** `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto...` (Tailwind class: `font-sans`). Applied to headings, labels, tooltips, and badges.

### 4.3 Action & Breaker Status Styling Tokens

| State / Action | Badge Classes | Background / Border | Glow / Animation |
| :--- | :--- | :--- | :--- |
| **Normal / Allow** | `bg-emerald-500/20 text-emerald-300 border-emerald-500/40` | `bg-emerald-950/60 border-emerald-900/40` | Static green dot `bg-emerald-400` |
| **Elevated** | `bg-amber-500/10 border-amber-500/30 text-amber-400` | `bg-amber-950/20 border-amber-900/40` | Pulsing amber dot `animate-pulse` |
| **Hold** | `bg-amber-500/20 text-amber-300 border-amber-500/40 font-bold` | `bg-amber-950/30 border-amber-900/50` | Amber indicator `bg-amber-500` |
| **Lockdown / Deny** | `bg-rose-500/20 text-rose-300 border-rose-500/50 font-black` | `bg-rose-950/60 border-rose-900/40` | Pulsing/bouncing red dot `animate-ping`, `animate-bounce` |
| **Active Milestone Marker** | `text-cyan-200 font-semibold` | `bg-cyan-400` | Radial cyan glow `shadow-[0_0_8px_#22d3ee]` |

### 4.4 Chain Badge Color Registry (`frontend/src/utils.ts: getChainBadgeStyle`)

```typescript
switch (chain.toLowerCase()) {
  case 'ethereum': case 'eth':
    return { bg: 'bg-indigo-500/10', text: 'text-indigo-400', border: 'border-indigo-500/30' };
  case 'bitcoin': case 'btc':
    return { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' };
  case 'solana': case 'sol':
    return { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' };
  case 'tron': case 'trx':
    return { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' };
  case 'xrp': case 'ripple':
    return { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' };
  case 'optimism': case 'op':
    return { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30' };
  case 'base':
    return { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' };
  case 'polygon':
    return { bg: 'bg-violet-500/10', text: 'text-violet-400', border: 'border-violet-500/30' };
  case 'bsc': case 'bnb':
    return { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' };
  default:
    return { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/30' };
}
```

### 4.5 Layout Tokens
- **Global Body:** `bg-[#0B0F17] text-slate-100 min-h-screen flex flex-col font-sans`.
- **Max Width Container:** `max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6`.
- **Navbar Shell:** `h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-50`.
- **Card Panels:** `bg-slate-900/90 border border-slate-800 rounded-xl p-4 sm:p-6 shadow-xl backdrop-blur`.
- **Split-Screen Height:** `h-[620px]` fixed height with internal `overflow-y-auto`.
- **Custom Scrollbar (`index.css`):**
  - Width/Height: `6px`.
  - Track: `#0f172a`.
  - Thumb: `#334155` with `border-radius: 3px`.
  - Thumb Hover: `#475569`.

---

## 5. API Client Seam Architecture

### 5.1 Current Seam Assessment
The frontend codebase already isolates all external network communication into a single module:
```text
frontend/src/api.ts
```
Every page component and layout view consumes network operations exclusively by importing named functions and types from `frontend/src/api.ts`. **Not a single component invokes `window.fetch()` or `axios` directly.**

```text
[ React UI Components ]
  ├── App.tsx             --> imports { runReplay, resetSystem }
  ├── ReplayView.tsx      --> imports { evaluateSigningRequest }
  ├── RadarView.tsx       --> imports { fetchRadar }
  ├── SensitivityLab.tsx  --> imports { fetchSensitivityMatrix }
  └── ReportsView.tsx     --> imports { fetchAuditRecords, verifyAuditIntegrity, simulateAuditTamper, resetAuditChain, getReportDownloadUrl }
            │
            ▼
┌────────────────────────────────────────────────────────┐
│               frontend/src/api.ts                      │  <-- THE EXACT SEAM
│  (Typed Interfaces, REST Endpoints & Fetch Wrappers)   │
└────────────────────────────────────────────────────────┘
            │
            ▼  HTTP / JSON-RPC
┌────────────────────────────────────────────────────────┐
│               FastAPI Backend (Port 8000)              │
└────────────────────────────────────────────────────────┘
```

### 5.2 Seam Inventory (`frontend/src/api.ts`)

| Exported Function in `api.ts` | HTTP Method & Route | Consumer Components | Return Type |
| :--- | :--- | :--- | :--- |
| `fetchHealth()` | `GET /api/health` | Health checks / Utility | `Promise<HealthResponse>` |
| `evaluateSigningRequest(request)` | `POST /api/evaluate` | `ReplayView.tsx` (Sandbox) | `Promise<Decision>` |
| `runReplay(params?)` | `POST /api/replay` | `App.tsx` (Root Simulator) | `Promise<ReplayResponse>` |
| `fetchRadar(params?)` | `GET /api/radar` | `RadarView.tsx` | `Promise<RadarScanResult>` |
| `fetchSensitivityMatrix(params?)` | `POST /api/policy/sensitivity` | `SensitivityLab.tsx` | `Promise<SensitivityResponse>` |
| `resetSystem()` | `POST /api/reset` | `App.tsx` (Navbar Reset) | `Promise<{ status, breaker_state }>` |
| `fetchAuditRecords()` | `GET /api/audit/records` | `ReportsView.tsx` | `Promise<AuditChainResponse>` |
| `verifyAuditIntegrity()` | `GET /api/audit/verify` | `ReportsView.tsx` | `Promise<AuditVerifyResponse>` |
| `simulateAuditTamper(index?)` | `POST /api/audit/simulate-tamper` | `ReportsView.tsx` | `Promise<any>` |
| `resetAuditChain()` | `POST /api/audit/reset` | `ReportsView.tsx` | `Promise<AuditVerifyResponse>` |
| `getReportDownloadUrl()` | String: `/api/report/download` | `ReportsView.tsx` (Download Link) | `string` |

### 5.3 Optimal Injection Strategy (Minimal UI Change)
Because the consumer components only interact with the function signatures exported by `frontend/src/api.ts`, the optimal architecture for introducing an enterprise API client (e.g., Axios client, authentication headers, environment-driven base URLs, retry logic, or mock adapters) is:

1. **Retain Function Signatures & Types in `frontend/src/api.ts`:**
   Keep all exported interfaces (`SigningRequest`, `Decision`, `StepEvent`, `ReplayMetrics`, `ReplayResponse`, `RadarScanResult`, etc.) and all exported function names unchanged.
2. **Implement Underlying Client Engine:**
   Inside `frontend/src/api.ts` (or an adjacent `frontend/src/client/` helper), replace the repeated raw `fetch()` calls with a centralized client instance:
   - Configurable `baseURL` (e.g. `import.meta.env.VITE_API_BASE_URL || '/api'`).
   - Unified request/response error handling and interceptors.
   - Centralized timeout handling and JSON parsing.
3. **Zero UI Disruption:**
   With this approach:
   - `App.tsx`: **0 lines changed**.
   - `ReplayView.tsx`: **0 lines changed**.
   - `LiveFeed.tsx`: **0 lines changed**.
   - `RadarView.tsx`: **0 lines changed**.
   - `SensitivityLab.tsx`: **0 lines changed**.
   - `ReportsView.tsx`: **0 lines changed**.
   - `Navbar.tsx` & `PolicySliders.tsx`: **0 lines changed**.

---

## 6. Audit Conclusion & Readiness

- **Current Repository State:** Clean, fully functional, verified with 25 passing unit and integration tests (`python -m pytest backend/tests/ -v`) and 0 TypeScript build errors (`npm run build`).
- **Safety Guarantee:** No application code was altered, created, or deleted during this audit. Only this specification file (`docs/AUDIT.md`) has been created.
- **Architectural Seam:** Verified and documented. Future enhancements to API connectivity or data polling should hook exclusively into `frontend/src/api.ts`.
