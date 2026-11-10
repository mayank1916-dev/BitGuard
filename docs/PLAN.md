# BitGuard Implementation Plan

## Architecture Summary

```text
┌─────────────────┐       Raw Tx Bytes        ┌─────────────────────────┐
│ Custody Service │ ────────────────────────> │ BitGuard Decision Point │
└─────────────────┘                           └─────────────────────────┘
                                                           │
                                                           │ (Evaluates Policy, Limits,
                                                           │  Delegation & Ledger Intent)
                                                           ▼
                                              ┌─────────────────────────┐
                                              │   One-Time Bound        │
                                              │   Approval Token        │
                                              └─────────────────────────┘
                                                           │
                                                           │ (Token bound to tx digest,
                                                           │  wallet, chain, expiry ~60s,
                                                           │  and nonce)
                                                           ▼
┌──────────────────┐    Tx Digest Signature   ┌─────────────────────────┐       Signed Tx       ┌─────────────────┐
│ Human Approvers  │ ───────────────────────> │       Signer Shim       │ ────────────────────> │ Blockchain /    │
│ (Hardware Keys / │  (For QUARANTINE / HOLD) │   (ENFORCEMENT POINT    │                       │ Local Anvil     │
│  WebAuthn)       │                          │  Holds Disposable Key)  │                       │ Testnet Node    │
└──────────────────┘                          └─────────────────────────┘                       └─────────────────┘
```

### Core Architecture Flow
1. **Custody Service $\rightarrow$ BitGuard Decision Point:**
   The upstream custody service dispatches raw transaction payload bytes to BitGuard. BitGuard acts strictly as a **policy decision point**; it decodes the raw transaction bytes independently (ignoring any caller-supplied unverified metadata) and cross-checks with intent reconciliation, distributed velocity limit counters, and delegation guards.
2. **BitGuard Decision Point $\rightarrow$ Approval Token:**
   If all policy checks pass, BitGuard issues a cryptographically signed, single-use approval token bound to the specific `tx_digest`, `wallet`, `chain`, `nonce`, and a tight expiration window (~60 seconds).
3. **Approval Token + Raw Bytes $\rightarrow$ Signer Shim (Enforcement Point):**
   The separate signer shim operates as the **enforcement point**. It holds a disposable testnet private key (or interacts with an HSM/KMS interface). It independently recomputes the transaction digest from the raw transaction bytes, verifies the BitGuard approval token, validates that the token matches the computed digest, checks the expiration and nonce, and only then signs and broadcasts the transaction.
4. **Hardware-Bound Human Approvals:**
   When an anomalous or high-risk transaction is flagged into a `HOLD` / quarantine state, approvers sign the computed transaction digest using WebAuthn hardware security keys. Notification channels (Slack, Telegram, PagerDuty) provide deep links for authentication and never contain inline approval actions.

---

## Master Checklist of Steps

- [x] S02 Scaffold the backend, signer shim and lab environment
- [x] S03 Canonical data model, API contract and dry-run evaluate endpoint
- [x] S04 Mode flag: SIMULATION / SHADOW / ENFORCE (F7)
- [x] S05 Basic roles and permission checks (F9 basic)
- [x] S06 EVM transaction decoder with canonical record (F4)
- [x] S07 Atomic distributed limit store (F3)
- [x] S08 Mock ledger and withdrawal intent reconciliation (F2)
- [x] S09 EIP-7702 delegation guard in the engine
- [x] S10 Decision engine: pipeline, risk score, reasons, fail-closed
- [x] S11 Approval token and signer shim (F1) with bypass protection
- [x] S12 Signing gateway: mTLS identity and JSON-RPC interface
- [x] S13 Decision persistence and live WebSocket stream
- [x] S14 Durable quarantine and HOLD state machine
- [x] S15 Full authentication: OIDC SSO and WebAuthn hardware keys (F9)
- [x] S16 Quorum approval with WebAuthn over the tx digest (F10)
- [x] S17 Delegation and code watcher for your own addresses (F6)
- [x] S18 Circuit breaker and asymmetric lockdown / unlock (F9, F14)
- [x] S19 Incident runbook automation and escalation (F14)
- [x] S20 Signed, versioned policy with hot reload and asymmetric changes (D)
- [x] S21 Hash-chained audit log with external anchoring and SIEM export (F18)
- [x] S22 Policy backtesting on real or exported history (F8)
- [x] S23 Testnet and local-fork integration lab with automated scenarios (F19)
- [x] S24 High availability, health, dead-man heartbeat and metrics (F17)
- [x] S25 Load test and honest latency measurement
- [x] S26 Shadow-mode pilot on recorded traffic and evidence report
- [x] S27 Contract and address risk profiler with local sanctions lists (C)
- [x] S28 Pre-sign transaction simulation (F5)
- [ ] S29 Balance caps, top-up proposals and sweep (F11)
- [ ] S30 Time-locked large withdrawals (F12)
- [ ] S31 Price sanity and unit-based limits (F13)
- [ ] S32 Behavioural baselines per wallet (F15)
- [ ] S33 Caller identity and build attestation (F16)
- [ ] S34 Additional chain adapters (BTC PSBT, Tron, XRP, Solana)
- [ ] S35 Reporting and compliance exports (F20)
- [ ] S36 Hardening pack: KMS/HSM adapter interface, fuzzing, security tooling, pen-test brief
- [x] U1 Add an API client layer without changing the look
- [x] U2 Mode badge and REAL / SYNTHETIC / REPORTED tags
- [x] U3 Incident Replay: source selector and real-engine replay
- [x] U4 Simulate Custom TX calls the real dry-run endpoint
- [x] U5 Live Feed: WebSocket stream, HOLD queue and chain outflow bars
- [x] U6 Circuit breaker pill and BREAKER LOCKDOWN with real effect
- [x] U7 7702 Radar: multi-provider scan and 'My addresses' panel
- [ ] U8 Sensitivity Lab: backtests, signed policy editor, diff and RBAC
- [ ] U9 Reports and Audit tab: chain verification, anchors, timeline, exports
- [ ] W1 Reword over-claims across UI and docs
- [ ] V1 Final verification against the success metrics
