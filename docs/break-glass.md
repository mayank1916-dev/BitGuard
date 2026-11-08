# Break-Glass Emergency Operational Procedure

## Overview

BitGuard is designed to operate under strict defensive policy constraints with fail-closed defaults. However, severe infrastructure anomalies—such as core custody system network partitions, upstream provider outages, or degraded operational modes—may require emergency fund migration (e.g. sweeping hot-wallet balances to cold storage multisig vaults).

The **Break-Glass Emergency Protocol** provides a production-ready architecture; pilot after audit and shadow-mode validation. This mechanism reduces and contains risk during catastrophic events by establishing a time-boxed, two-person quorum override that permits transactions **only** to pre-approved destination allowlists.

---

## Core Invariants & Safety Guarantees

1. **Two-Person Quorum (M-of-N):** A break-glass override cannot be activated by any single operator. It strictly requires two distinct authorized users holding `ADMIN` or `SECOPS` roles.
2. **Separation of Duties:** The initiator who proposes the break-glass request cannot approve it. Two independent pairs of eyes and credentials are mandatory.
3. **Hardware-Backed Step-Up (WebAuthn):** Approvers must authenticate using WebAuthn FIDO2 hardware authenticators over the override digest.
4. **Strict Scope Limitation (Allowlist Only):** Break-glass **never** grants blanket signing access. It strictly permits transactions to the pre-approved destination addresses specified in the approved manifest (e.g. cold storage sweep multisigs). Any transaction to an unlisted destination continues to fail closed.
5. **Strict Time-Boxing:** Overrides are strictly ephemeral. The time-to-live is configurable between 5 minutes and 4 hours (default: 3600 seconds). Upon expiry, BitGuard automatically reverts to standard enforcement without requiring operator intervention.
6. **Instant Revocation (Asymmetric Policy):** Any single `ADMIN` or `SECOPS` operator can instantly revoke an active break-glass override at any time. Revocation is instant and tightening; it does not require a quorum.
7. **Immutable Audit Trail:** All events (`BREAK_GLASS_PROPOSED`, `BREAK_GLASS_APPROVED`, `BREAK_GLASS_ACTIVATED`, `BREAK_GLASS_REVOKED`, and `BREAK_GLASS_EXPIRED`) are appended to the hash-chained audit ledger and anchored to immutable WORM object storage.

---

## Step-by-Step Emergency Execution Procedure

### Stage 1: Incident Assessment & Pre-Approval Verification
Before initiating a break-glass procedure:
1. Verify the incident meets degraded-mode criteria (e.g., active circuit breaker `HOLD` or `LOCKDOWN` due to an upstream failure preventing normal business flow).
2. Confirm the destination addresses are verified exchange cold reserve vaults or institutional multi-sig custody addresses.

### Stage 2: Proposal by Initiator (Operator / SecOps)
The initiator submits a proposal specifying the rationale, duration, and target allowlist:

```http
POST /v1/break-glass/propose
Authorization: Bearer <secops_jwt>
Content-Type: application/json

{
  "reason": "Custody RPC partition: emergency balance sweep to cold vault",
  "allowed_destinations": [
    "0x000000000000000000000000000000000000b001",
    "0x000000000000000000000000000000000000b002"
  ],
  "duration_seconds": 3600
}
```

*Response:*
```json
{
  "id": "bg-glass-a1b2c3d4e5f6",
  "reason": "Custody RPC partition: emergency balance sweep to cold vault",
  "proposed_by": "user:secops-lead",
  "allowed_destinations": [
    "0x000000000000000000000000000000000000b001",
    "0x000000000000000000000000000000000000b002"
  ],
  "duration_seconds": 3600,
  "state": "PENDING",
  "approvals": []
}
```

### Stage 3: Two-Person Quorum Approvals
Two distinct administrators/SecOps engineers (neither of whom is `proposed_by`) must independently review and approve the request.

#### Approver 1:
```http
POST /v1/break-glass/bg-glass-a1b2c3d4e5f6/approve
Authorization: Bearer <admin1_jwt>
Content-Type: application/json

{
  "webauthn_assertion": { ... }
}
```
*Result:* Request remains `PENDING` with 1 approval recorded.

#### Approver 2:
```http
POST /v1/break-glass/bg-glass-a1b2c3d4e5f6/approve
Authorization: Bearer <admin2_jwt>
Content-Type: application/json

{
  "webauthn_assertion": { ... }
}
```
*Result:* Quorum reached! State transitions immediately to `ACTIVE`. `activated_at` and `expires_at` are stamped. Redis active cache is updated across all BitGuard replicas.

### Stage 4: Degraded Mode Execution
During the active window:
- Signing requests destined for addresses in `allowed_destinations` receive verdict `ALLOW` with reason code `BREAK_GLASS_OVERRIDE`.
- Requests to any destination not in `allowed_destinations` are evaluated under standard rules (or held/denied if circuit breaker remains in `HOLD`/`LOCKDOWN`).
- Performance targets remain intact: target p99 under 15 ms, measured, across all evaluations.

### Stage 5: Emergency Termination / Revocation
When the incident is contained, or if suspicious activity is observed:
Any authorized administrator can instantly deactivate degraded mode:

```http
POST /v1/break-glass/bg-glass-a1b2c3d4e5f6/revoke
Authorization: Bearer <secops_oncall_jwt>
Content-Type: application/json

{
  "reason": "Cold sweep completed; normal policy enforcement restored"
}
```
*Result:* State immediately becomes `REVOKED`. The Redis override key is deleted, and all replicas return to standard enforcement instantaneously.

---

## Post-Incident Audit Review

Within 24 hours of any break-glass activation:
1. Export the audit chain head from `/v1/audit/head` and verify cryptographic hash chaining.
2. Confirm the tamper-proof S3/MinIO anchor record for the break-glass interval.
3. Conduct a post-incident review verifying all executed transactions matched legitimate cold sweep transactions.
