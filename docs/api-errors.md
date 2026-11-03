# BitGuard API Error Codes & Diagnostics Reference

This document provides a comprehensive reference of JSON-RPC 2.0 error codes, HTTP status mappings, and deterministic reason codes issued by the BitGuard Defensive Signing Firewall.

> [!NOTE]
> **Defensive Architecture Invariant:** BitGuard is a policy **DECISION point**. A separate signer shim is the **ENFORCEMENT point**. BitGuard never stores or uses private signing keys. BitGuard **reduces and contains** blast radius from compromised credentials or rogue callers. Target latency: **target p99 under 15 ms, measured**.

---

## 1. JSON-RPC 2.0 Error Envelopes

All external signing requests via `POST /rpc` conform strictly to JSON-RPC 2.0 specification. Error responses maintain standard top-level error structures, enriched with structured data payloads.

### Error Envelope Schema

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32003,
    "message": "Signing request DENIED by policy firewall",
    "data": {
      "decision_id": "req-9b87df31a0e1",
      "hold_id": null,
      "reasons": [
        {
          "code": "INTENT_MISSING",
          "weight": 100,
          "detail": "Required withdrawal intent ID omitted from request."
        }
      ],
      "risk_score": 100
    }
  },
  "id": 1
}
```

---

## 2. Standard & Application RPC Codes

| RPC Code | Name | Description | Policy Implication |
|---|---|---|---|
| **`-32700`** | `Parse error` | Invalid JSON received by the server. | Request rejected before evaluation. |
| **`-32600`** | `Invalid Request` | The JSON sent is not a valid JSON-RPC 2.0 object. | Request rejected before evaluation. |
| **`-32601`** | `Method not found` | Method is not `bitguard_signTransaction`. | Request rejected before evaluation. |
| **`-32602`** | `Invalid params` | Missing mandatory `chain` or `raw_tx` parameters. | Request rejected before evaluation. |
| **`-32003`** | `DENIED` | Firewall policy DENIED signing, caller unauthenticated, or internal error. | Fail closed. Reservations released. No token issued. |
| **`-32004`** | `HOLD` | Quarantined awaiting multi-sig / WebAuthn hardware approval. | Hold ticket created (`ht-...`). Reservations released. |
| **`-32001`** | `SIGNING_REFUSED` | Isolated Signer Shim refused to sign the payload. | Enforced by shim. Nonce consumed or invalid token. |

---

## 3. Policy Engine Reason Codes

Reasons describe the deterministic checks evaluated across the 6-stage firewall pipeline:

### Authentication & Identification
- `INVALID_CALLER_IDENTITY` (Weight: 100, Hard DENY): Missing, invalid, or unauthorized mTLS client certificate workload identity. Invariant #3 fail closed.

### Stage 1: Raw EVM Decoding (F4 / Invariant #4)
- `DECODE_ERROR` (Weight: 100, Hard DENY): Raw transaction bytes could not be decoded, contain trailing garbage, or use an unsupported tx type. Caller fields are ignored; raw bytes are the sole source of truth.

### Stage 2: Intent Reconciliation (F2 / Invariant #3)
- `INTENT_MISSING` (Weight: 100, Hard DENY): Withdrawal intent ID missing or not registered in ledger connector.
- `INTENT_NOT_APPROVED` (Weight: 100, Hard DENY): Ledger intent status is `PENDING` or `CANCELLED`.
- `INTENT_ALREADY_PAID` (Weight: 100, Hard DENY): Ledger intent status is `PAID`.
- `INTENT_MISMATCH_DESTINATION` (Weight: 100, Hard DENY): Decoded recipient does not match authorized intent destination.
- `INTENT_MISMATCH_AMOUNT` (Weight: 100, Hard DENY): Decoded amount does not match authorized intent amount.
- `INTENT_MISMATCH_CHAIN` (Weight: 100, Hard DENY): Decoded target chain does not match intent chain.
- `INTENT_REPLAY` (Weight: 100, Hard DENY): Intent was already consumed in a prior signing cycle.

### Stage 3: EIP-7702 Delegation Guard (F4 / S09)
- `DELEGATION_OWNED_ADDRESS` (Weight: 95, Hard DENY): Owned wallet delegates to a contract whose code hash is not on `policy.delegate_allowlist`.
- `DELEGATION_UPGRADEABLE_PROXY` (Weight: 95, Hard DENY): Delegate code contains `DELEGATECALL` opcode or non-zero EIP-1967 implementation slot without explicit `reviewed_proxy_ok`.
- `DELEGATION_RPC_FAILURE` (Weight: 95, Hard DENY): Failed to resolve delegate bytecode via RPC. Fails closed.

### Stage 4: Atomic Limits & Velocity (F3 / S07)
- `SINGLE_TX_LIMIT_EXCEEDED` (Weight: 65, Triggers HOLD): Transfer amount exceeds configured single transaction threshold (default $50,000).
- `WALLET_LIMIT_EXCEEDED` (Weight: 65, Triggers HOLD): Sliding-window outflow volume exceeds wallet quota.
- `VELOCITY_SPIKE` (Weight: 50, Triggers HOLD): Velocity anomaly detected for originating wallet.
- `LIMIT_STORE_UNAVAILABLE` (Weight: 100, Hard DENY): Distributed limit store unreachable and local fallback quota exhausted. Never allows all.

### Stage 5: Cached Enrichment Hooks (S10)
- `ELEVATED_RISK_TIMEOUT` (Weight: 30): Address profiler or pre-flight simulation timed out. Elevated risk applied; never treated as safe.
- `PROFILER_ANOMALY` (Weight: 10–50): Destination address flagged with anomaly or sanctions alert.
- `SIMULATION_ANOMALY` (Weight: 10–50): Pre-flight simulation returned reverted execution or unexpected state mutation.

### Circuit Breaker States
- `BREAKER_LOCKDOWN` (Weight: 100, Hard DENY): Emergency trip engaged. All transactions DENIED immediately.
- `BREAKER_HOLD` (Weight: 75, Triggers HOLD): Elevated risk mode. All non-exempt transactions quarantined.

### Internal Safety
- `ENGINE_ERROR` (Weight: 100, Hard DENY): Unexpected exception or crash within BitGuard decision pipeline. Fails closed with zero signature leakage.

---

## 4. Response Examples

### Example A: Successful Execution (ALLOW)
```json
{
  "jsonrpc": "2.0",
  "result": {
    "signature": "0x5a2...b41c",
    "tx_hash": "0x4fe...89ab",
    "decision_id": "req-a4e9102c011f",
    "status": "SIGNED"
  },
  "id": 1
}
```

### Example B: Quarantine Quarantine (HOLD - Code `-32004`)
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32004,
    "message": "Transaction placed on quarantine HOLD",
    "data": {
      "hold_id": "ht-req-7c42a10e8891",
      "decision_id": "req-7c42a10e8891",
      "reasons": [
        {
          "code": "SINGLE_TX_LIMIT_EXCEEDED",
          "weight": 65,
          "detail": "Transfer amount $75,000.00 exceeds single tx limit $50,000.00."
        }
      ],
      "risk_score": 65
    }
  },
  "id": 2
}
```

### Example C: Policy Denial (DENY - Code `-32003`)
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32003,
    "message": "Signing request DENIED by policy firewall",
    "data": {
      "decision_id": "req-0182fe9a12c4",
      "reasons": [
        {
          "code": "INTENT_MISMATCH_DESTINATION",
          "weight": 100,
          "detail": "Decoded destination 0x1111... does not match intent destination 0x2222..."
        }
      ],
      "risk_score": 100
    }
  },
  "id": 3
}
```

### Example D: Unauthenticated Caller (DENY - Code `-32003`)
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32003,
    "message": "Signing request DENIED: unauthenticated caller",
    "data": {
      "decision_id": "unauth-71fa8290cc14",
      "reasons": [
        {
          "code": "INVALID_CALLER_IDENTITY",
          "weight": 100,
          "detail": "Missing, invalid, or unauthorized mTLS client certificate workload identity"
        }
      ],
      "risk_score": 100
    }
  },
  "id": 4
}
```

---

## 5. Deployment Recommendation

Production-ready architecture; pilot after audit and shadow-mode validation.
