# BitGuard Threat Model & Defensive Control Matrix

> [!IMPORTANT]
> **System Scope & Defensive Boundary:**
> BitGuard is an autonomous policy **decision point** (firewall) paired with an isolated signer shim **enforcement point**.
> BitGuard reduces and contains unauthorized transaction signing risks for exchange hot wallets (a limit-aware attacker can still move value; the goal is to shrink and slow loss and force detection).
> Architecture target: production-ready architecture; pilot after audit and shadow-mode validation.
> Target p99 under 15 ms for the local fast path, measured under load (measured pipeline p99: 2.398 ms at 50 concurrency, 2.814 ms at 200 concurrency, and 2.633 ms at 500 concurrency per [docs/PERF.md](PERF.md)). Compensating controls cataloged in [docs/LIMITS.md](LIMITS.md).

---

## 1. BitGuard-Itself Threat Table

The table below catalogs attacks targeted directly against the BitGuard firewall architecture, the implemented technical mitigations, the governing architectural invariants, and the automated tests proving control efficacy.

| # | Threat Vector | Description & Potential Impact | Implemented Mitigation | Invariant | Test Proving Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Token Key Theft** | Attacker extracts BitGuard Ed25519 approval signing key to forge approval tokens. | **Key Isolation & Asymmetric Cryptography:** Signer Shim holds only public keys; Ed25519 approval keys never leave the decision point. Tokens are bound to a 60-second TTL, wallet, chain, and tx digest. Circuit breaker trips immediately increment the token epoch, revoking all outstanding tokens in Redis and rejecting them at the shim. | Invariant #1, #2 | `tests/test_circuit_breaker.py::test_revoked_tokens_refused_by_shim_on_epoch_increment`<br>`tests/test_signer_shim.py::test_expired_token_refused_by_shim` |
| **2** | **Token Replay** | Attacker intercepts a valid approval token over the network and re-submits it to the Signer Shim. | **Atomic Nonce Tracking & Digest Recomputation:** Every token includes a single-use UUID nonce consumed atomically in Redis via `SET nonce "1" EX 120 NX`. The Shim independently decodes raw transaction bytes, recomputes the 32-byte digest, and verifies exact match against the token claims. Replayed tokens or altered bytes fail closed. | Invariant #2, #3, #4 | `tests/test_signer_shim.py::test_token_replay_refused`<br>`tests/test_signer_shim.py::test_recomputed_digest_mismatch_refused`<br>`lab/scenarios/scenario_09_token_replay_refused.py` |
| **3** | **Policy Tampering** | Attacker or rogue insider modifies policy files (e.g., raises limits or removes address restrictions) to allow unauthorized transfers. | **Asymmetric Policy Evolution & Cryptographic Signatures:** Policy tightening (lockdown, lower caps) takes effect instantly with a single operator. Loosening (higher limits, removing deny rules) strictly requires dual-control human quorum, a cool-down period, and an attached deterministic backtest report. All policy revisions are signed, hashed, and tracked on an immutable audit ledger. | Invariant #6, #7 | `tests/test_policy.py::test_loosening_requires_quorum_and_cooldown`<br>`tests/test_backtesting.py::test_s20_loosening_hook_requires_matching_backtest_report` |
| **4** | **DoS to Force Fail-Open** | Attacker floods Redis, RPC nodes, or internal services with traffic or causes an outage, hoping the firewall will fail open and pass transactions. | **Fail-Closed Default Everywhere:** If Redis is down, BitGuard fails closed to conservative local in-memory caps (`BITGUARD_LOCAL_FALLBACK_CAP`) or rejects with `LIMIT_STORE_UNAVAILABLE`. If RPC or simulation fails, the decision engine adds risk weight or flags `SIM_TIMEOUT`/`SIM_REVERT`, never declaring transactions 'safe'. Signer Shim rejects if heartbeat expires. | Invariant #3 | `tests/test_limits_store.py::test_redis_outage_fails_closed`<br>`tests/test_api_contract.py::test_post_evaluate_endpoint_fails_closed`<br>`tests/test_signer_shim.py::test_deadman_heartbeat_timeout_refuses_signing` |
| **5** | **Compromised Approver** | An attacker compromises credentials of a human operator to approve fraudulent transactions or release quarantined funds. | **Separation of Duties & Hardware WebAuthn Quorum:** The original transaction requester cannot approve their own request. High-value releases and breaker de-escalations mandate a 2-person quorum (`n-of-m`) authenticated via FIDO2/WebAuthn hardware tokens (YubiKey) signing the exact transaction digest. Slack/Telegram notifications are read-only alerts containing links, never approve buttons. | Invariant #2, #5 | `tests/test_approvals.py::test_separation_of_duties_requester_cannot_approve`<br>`tests/test_approvals.py::test_two_person_webauthn_quorum`<br>`tests/test_circuit_breaker.py::test_deescalation_requires_two_approvers_with_webauthn` |
| **6** | **Poisoned Feeds** | Attacker compromises a price oracle, RPC node, or external provider to report zero USD value or spoof simulation outcomes. | **Multi-Source Price Sanity & Consensus Radar:** USD conversions use the median of independent price sources only if they deviate < `max_price_deviation_pct`; otherwise the HIGHER price is used and `PRICE_DEVIATION` weight is added. Unpriced or stale tokens trigger `HOLD` or `DENY` (never zero). EIP-7702 addresses use multi-provider consensus (Infura + Alchemy) and flag provider disagreement. | Invariant #3, #8 | `tests/test_pricing.py::test_pricing_deviation_uses_higher_price`<br>`tests/test_pricing.py::test_unpriced_token_holds_or_denies`<br>`tests/test_ui_radar.py::test_provider_disagreement_alert_sets_status` |
| **7** | **Malicious Admin** | System administrator with database or host shell access attempts to silently alter decisions, bypass limits, or forge approvals. | **Key Isolation & Hash-Chained Audit Ledger:** Signing keys reside only on the Signer Shim / Cloud KMS with no human IAM access. Every decision, approval, and breaker transition is recorded on an immutable, sequentially linked SHA-256 hash-chain with external S3 object-lock anchors. Any row alteration or deletion is cryptographically detected at verification. | Invariant #1, #7, #8 | `tests/test_audit_chain.py::test_modify_row_directly_in_db_reports_exact_first_bad_seq`<br>`tests/test_audit_chain.py::test_delete_row_directly_in_db_fails_closed`<br>`tests/test_fuzz_and_mutation.py::test_signer_backend_factory_and_types` |

---

## 2. Invariant Mapping & Enforcement Points

```mermaid
graph TD
    subgraph Client Application / Core Banking
        Req["Raw Transaction Bytes + Intent"]
    end

    subgraph BitGuard Decision Point (Firewall)
        D1["Stage 1: Raw Bytes Decoder (Invariants #3, #4)"]
        D2["Stage 2: Intent Reconciliation (Invariant #3)"]
        D3["Stage 3: Delegation Guard & Radar"]
        D4["Stage 4: Limits Store & Price Sanity (Invariants #3, #8)"]
        D5["Stage 5: Profiler & Anvil Fork Simulation"]
        D6["Stage 6: Policy Decision & Breaker State (Invariants #6, #11)"]
        Audit["Immutable Hash-Chained Audit Ledger (Invariant #7)"]
        TokenGen["Approval Token Generator (Ed25519) (Invariant #2)"]
    end

    subgraph Signer Shim Enforcement Point
        VerifyTok["Verify Token & Epoch (Invariant #2)"]
        NonceCheck["Atomic Nonce Consumption (SET NX)"]
        Recompute["Recompute Digest from Raw Bytes (Invariant #4)"]
        SignKMS["Execute SECP256K1 Signing (AWS KMS / Disposable) (Invariant #1)"]
    end

    Req --> D1 --> D2 --> D3 --> D4 --> D5 --> D6
    D6 --> Audit
    D6 -- "ALLOW" --> TokenGen
    TokenGen -- "One-Time Approval Token (TTL 60s)" --> VerifyTok
    Req -- "Raw Bytes" --> Recompute
    VerifyTok --> NonceCheck --> Recompute --> SignKMS
```

---

## 3. Defense-in-Depth Summary

1. **No Shared Authority:** The policy firewall makes decisions; the signer shim enforces them. Even if an attacker compromises the firewall container, they cannot extract signing keys. Even if an attacker directly invokes the signer shim, requests are rejected without a cryptographically valid approval token bound to an unspent nonce.
2. **Deterministic Auditing:** All operational events are committed to a monotonically increasing sequence with forward-secure hash chaining. Any retrospective tampering by database administrators breaks the cryptographic chain and triggers immediate security alerts.
3. **Hardware-Anchored Human Decisions:** Dual-control workflows require FIDO2 WebAuthn hardware tokens, neutralizing credential theft and phishing attacks against individual administrators.
