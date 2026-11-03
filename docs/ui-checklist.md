# BitGuard UI Visual Stability Checklist (Milestone U1 & U2)

## Purpose & Strict Invariants

Under **AGENTS.md Invariant #10 (Visual Stability)**:
> *"The existing UI look stays unchanged: do not edit existing CSS tokens, colours, fonts or layout. New UI elements must reuse existing classes."*

Under **AGENTS.md Invariant #8 (Explicit Data Provenance)**:
> *"Every number shown in the UI is labelled REAL, SYNTHETIC or REPORTED."*

When adding or updating the API client layer (`web/api.js` / `frontend/src/api.ts` / `DATA_SOURCE`), mode indicator, and data provenance chips:
- When `DATA_SOURCE='demo'`, existing demo simulation behavior must remain **100% identical**.
- Zero visual drift across layout, typography, palette, borders, shadows, or existing class names.
- New provenance tags and state badges must strictly reuse existing classes (`bg-emerald-500/20`, `bg-purple-500/20`, `bg-cyan-500/20`, etc.).

---

## Data Source & Mode Toggle

The client layer selects between demo simulation and live API via:
- **Demo Mode (default):** `http://localhost:3000/?datasource=demo` (or default without query param)
- **Live API Mode:** `http://localhost:3000/?datasource=api`
- **Mode Selector:** `http://localhost:3000/?datasource=api&mode=SHADOW` or `?mode=ENFORCE`
- **Config Storage:** `localStorage.setItem('DATA_SOURCE', 'demo' | 'api')`

---

## Visual Verification Checklist by Tab

| View / Component | Key Visual Elements | Expected Classes & Styling | Pass / Fail |
| :--- | :--- | :--- | :--- |
| **Top Navigation Bar & Breaker Controls** (Task U6) | Breaker Pill displaying real state (`NORMAL OPERATION`, `ELEVATED SCRUTINY`, `MANUAL HOLD ACTIVE`, `BREAKER LOCKDOWN`) using canonical colors (emerald-500/10, amber-500/10, amber-500/15, rose-500/20); clicking opens Breaker Controls modal with last transition telemetry (`updated_by`, `reason` code, timestamp), role switcher for testing, instant EMERGENCY LOCKDOWN action with confirmation (SecOps/Admin only), and UNLOCK REQUEST workflow (visible only when > NORMAL) requiring 2-approver WebAuthn hardware signatures with separation of duties enforcement. In `demo` mode: simulation breaker states preserved. | `border-slate-800 bg-slate-950/80 backdrop-blur`, `font-sans`, exact padding, blue badge `bg-blue-950/60`, zero new CSS tokens | [x] Pass |
| **Tab 1: Incident Replay** (`replay`) | Split-screen loss cards: Unprotected loss / allowed value, BitGuard protected loss / blocked value; provenance tag (`REAL`, `SYNTHETIC`, `REPORTED`) on counter headers and every event card; interactive step slider; playback controls (`Run Simulation`, `Next Step`); Policy Sliders at footer | `bg-slate-900/60 border-slate-800`, monospace numbers `font-mono`, unchanged colors | [x] Pass |
| **Simulate Custom TX Modal** (Task U4) | Triggered via `Simulate Custom TX` button in Incident Replay. In `demo` mode: typed transaction inputs (`chain`, `kind`, `wallet`, `asset`, `amount`, `recipient`). In `api` mode: accepts raw transaction hex (`raw_tx`) and optional `intent_id`, invokes `POST /v1/evaluate`, displays card in feed style: verdict badge, risk score 0-100, each reason with weight, decoded fields (`chain`, `from`, `to`, `asset`, `amount`, `calls`, `authorizations`, `fee`), per-stage timings, and clear banner `"dry run - nothing signed or reserved"` | `bg-slate-950 border-slate-800 p-4 font-mono text-xs`, `bg-cyan-950/40 border-cyan-800/50`, zero new CSS tokens | [x] Pass |
| **Shadow Mode Counters** (`replay` in SHADOW) | Left counter reads `WOULD HAVE BEEN ALLOWED` (allowed value), right counter reads `BLOCKED VALUE` (blocked value) using S04 `would_have_*` counters | `bg-black/50 border-rose-900/50` / `border-emerald-900/50`, exact font and padding tokens | [x] Pass |
| **Tab 2: Live Decision Stream & Queues** (`feed` - Task U5) | In `api` mode: real-time WebSocket connection to `/v1/stream` with reconnect deduplication; Pending HOLD quarantine queue showing decoded tx (`from`, `to`, `asset`, `amount`, `digest`), risk reasons, live countdown to expiry, hardware WebAuthn Approve (`navigator.credentials.get`) and Deny button with disabled reason explanations (requester separation of duties & duplicate approver); Active Time-lock queue with release countdown and Cancel button; 5-second per-chain outflow velocity aggregate progress bars across 7 chains; `REAL`/`SYNTHETIC` provenance tags. In `demo` mode: simulated background micro-withdrawal feed preserved. | Dark slate card background (`bg-slate-900/60`, `border-slate-800`), colored verdict badges (`bg-emerald-500/20`, `bg-rose-500/20`), provenance chips, zero new CSS tokens | [x] Pass |
| **Tab 3: 7702 Radar & 'My addresses'** (`radar` - Task U7) | In `api` mode: connects to `/v1/watched-addresses` and `/v1/watcher/alerts`. Retains public block scanner with Live RPC / Cached Feed toggle and suspicious pattern filter. Adds sub-navigation to 'My addresses' panel featuring: summary telemetry cards (total monitored, allowlisted delegates, unapproved count, provider consensus status); watched addresses table showing wallet/label, delegation state badge (`none`, `allowed delegate`, `UNAPPROVED`), delegate address & code hash, last block checked, provider consensus (`all agree` / `disagree`), recent alerts with detection latency (e.g. `3.32 ms`), and SecOps-only Add/Remove address controls with confirmation modal and RBAC role switcher (`usr-secops-01`, `usr-operator-01`, `usr-admin-01`). In `demo` mode: realistic offline sample watched addresses preserved without network calls. | Reused existing table/card classes (`bg-slate-900/90 border border-slate-800 rounded-xl`, `font-mono text-xs`), standard status badge classes (`bg-emerald-500/20`, `bg-rose-500/20`, `bg-indigo-500/20`), zero new CSS tokens | [x] Pass |
| **Tab 4: Policy Sensitivity Lab** (`lab`) | Multiplier sliders, 2D sensitivity table, loss mitigated percentage curves, false positives count | Recharts SVG graphs without layout shift, slate table borders | [x] Pass |
| **Tab 5: Cryptographic Audit** (`reports`) | Chain integrity badge (`INTEGRITY VERIFIED`), root hash box, simulate tamper buttons, audit entry timeline, export buttons | Monospace hash text, green/red verified badges, download action links | [x] Pass |
| **Tab 6: Quorum Approvals** (`approvals`) | Quarantined tickets list, ticket inspector, raw tx decoding breakdown, dual-approver role selector, WebAuthn approve button | Amber quarantine badges, 2-approver progress step dots, monospace hex bytes | [x] Pass |

---

## Screenshot Comparison Protocol

To ensure zero visual regression:

1. **Environment Setup:**
   - Launch backend: `uvicorn services.bitguard.main:app --host 0.0.0.0 --port 8000`
   - Launch frontend: `npm run dev --prefix frontend` (accessible at `http://localhost:3000`)
   - Browser Viewport: Set browser window size to **1440 x 900** (standard desktop benchmark).

2. **Capture Baseline (Before):**
   - Take full-page screenshots for each tab in `DATA_SOURCE=demo` mode:
     - `screenshots/baseline/01_navbar_and_replay.png`
     - `screenshots/baseline/02_live_feed.png`
     - `screenshots/baseline/03_radar.png`
     - `screenshots/baseline/04_sensitivity_lab.png`
     - `screenshots/baseline/05_audit_reports.png`
     - `screenshots/baseline/06_approvals.png`

3. **Capture Comparison (After):**
   - Take matching screenshots with updated client module at identical viewport.

4. **Automated Image Diff:**
   - Compare before and after screenshots using an image comparison tool or perceptual diff (e.g. `pixelmatch` or `compare -metric AE`).
   - **Acceptance Criterion:** 0 pixels changed on layout, containers, typography, or styling tokens.

---

## Build & Test Quality Gate

Run frontend build to verify zero compile or bundle warnings:
```bash
npm run build --prefix frontend
```
Verify that `dist/assets/index-*.css` remains unchanged in size and classes.
