# BitGuard Authentication Architecture (F9)

BitGuard provides enterprise-grade authentication combining OpenID Connect (OIDC) Single Sign-On (SSO) with FIDO2 / WebAuthn Level 3 hardware security keys for dual-control signing decisions, administrative step-up verification, and quorum releases.

---

## 1. Core Authentication Flow & Invariants

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Keycloak OIDC SSO                              │
│                      (Realm: bitguard, Client: bitguard-api)                │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ 1. OIDC ID Token / Roles
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          BitGuard Session Layer                             │
│                  - Realm Roles mapped to RBAC Permissions                   │
│                  - Production Guard: DEV login disabled                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ 2. Sensitive Action Request
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      WebAuthn FIDO2 Hardware Step-Up                        │
│          - Monotonic sign-count tracking (anti-cloning / replay)            │
│          - Quorum separation of duties (maker-checker enforcement)          │
│          - Challenge = tx_digest (quarantined holds) or server nonce        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ 3. Verified Assertion
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   Tamper-Evident Hash-Chained Audit Ledger                  │
│       Appends record: {user, action, time, webauthn_assertion_ref}          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Governing Operating Invariants
1. **Invariant #1 (Key Isolation):** BitGuard never stores or uses signing keys.
2. **Invariant #3 (Fail-Closed Default):** Invalid credentials, replay tokens, decreased authenticator sign counts, or unverified origins fail closed immediately.
3. **Invariant #5 (WebAuthn Hardware Approvals):** Human approvals are WebAuthn hardware signatures over the transaction digest. Sensitive actions performed by `Admin`, `SecOps`, and `Approver` roles require a WebAuthn-verified session (step-up).
4. **Invariant #6 (Asymmetric Policy Evolution):** Tightening/lockdown = single authorized operator, instant. Loosening/unlocking = quorum with cool-down.
5. **Invariant #7 (Immutable Audit Trail):** Every admin action is recorded in the hash-chained audit ledger with its WebAuthn assertion reference.

---

## 2. Keycloak Lab Realm & Role Mapping

The lab environment provides an exported Keycloak realm (`deploy/keycloak/bitguard-realm.json`) running in `docker-compose.yml`.

### Realm Roles to BitGuard RBAC Matrix
| Keycloak Realm Role | BitGuard Role | Primary Responsibilities | WebAuthn Step-Up Required? |
| :--- | :--- | :--- | :--- |
| `Admin` | `Role.ADMIN` | User administration, policy loosening, system config | **YES** |
| `SecOps` | `Role.SECOPS` | Circuit breaker escalation, watched addresses, policy tighten | **YES** |
| `Approver` | `Role.APPROVER` | Quorum release of quarantined hold tickets | **YES** |
| `Operator` | `Role.OPERATOR` | Signing requests, false positive labeling | No (unless elevated) |
| `Compliance` | `Role.COMPLIANCE` | Audit log verification, compliance exports | No |
| `Viewer` | `Role.VIEWER` | Read-only inspection of decisions and telemetry | No |

### Pre-Seeded Lab Accounts
| Username | Email | Seeded Role | Initial Password | User ID |
| :--- | :--- | :--- | :--- | :--- |
| `admin` | `admin@bitguard.local` | `Admin` | `admin123` | `usr-admin-01` |
| `secops` | `secops@bitguard.local` | `SecOps` | `secops123` | `usr-secops-01` |
| `operator` | `operator@bitguard.local` | `Operator` | `operator123` | `usr-operator-01` |
| `compliance` | `compliance@bitguard.local` | `Compliance` | `compliance123` | `usr-compliance-01` |
| `approver1` | `approver@bitguard.local` | `Approver` | `approver123` | `usr-approver-01` |
| `approver2` | `approver2@bitguard.local` | `Approver` | `approver123` | `usr-approver-02` |
| `viewer` | `viewer@bitguard.local` | `Viewer` | `viewer123` | `usr-viewer-01` |

---

## 3. Centralized Separation of Duties

Separation of duties is enforced centrally in `services/bitguard/auth/separation.py`:
- **Requester Invariant (`REQUESTER_CANNOT_APPROVE`):** The identity that submitted a transaction signing request cannot approve its quarantine release.
- **Author Invariant (`POLICY_AUTHOR_CANNOT_APPROVE`):** The author of a policy manifest or loosening change cannot vote to approve or activate that change.
- **Quorum Invariant (`DUPLICATE_APPROVER`):** Multi-party quorum releases require at least two distinct user IDs and (where configured) distinct roles.

---

## 4. Production Safety Gate

When `BITGUARD_ENVIRONMENT=production`:
- The development token bypass endpoints (`POST /v1/auth/dev-token` and `POST /v1/auth/dev-login`) return `403 Forbidden`.
- The unauthenticated dev fallback is disabled; unauthenticated requests fail with `401 Unauthorized`.
- All requests must supply a valid OIDC bearer token or WebAuthn session.

---

## 5. Testing with Virtual Authenticator in Chrome DevTools

Chrome DevTools includes a built-in virtual authenticator environment that implements the W3C WebAuthn and FIDO2 CTAP2 protocols, allowing complete end-to-end testing of hardware security keys without physical YubiKeys.

### Step-by-Step Setup
1. **Open Chrome DevTools:**
   - Press `F12` or `Ctrl+Shift+I` (Windows/Linux) or `Cmd+Option+I` (macOS).
2. **Open the WebAuthn Tab:**
   - Click the three dots icon (`⋮`) in the top-right corner of DevTools $\rightarrow$ **More tools** $\rightarrow$ **WebAuthn**.
3. **Enable Virtual Authenticator:**
   - Check the box **"Enable virtual authenticator environment"**.
4. **Configure a Virtual Security Key:**
   - **Protocol:** `ctap2`
   - **Transport:** `internal` or `usb`
   - **Supports resident keys:** Checked
   - **Supports user verification:** Checked
   - Click **Add**.
5. **Register the Hardware Credential:**
   - In the BitGuard web console or API client, initiate registration:
     ```http
     POST /v1/auth/webauthn/register/options
     ```
   - Call `navigator.credentials.create({ publicKey: options })`.
   - Submit the resulting credential to `/v1/auth/webauthn/register/verify`.
   - The virtual authenticator will generate a credential that appears in the DevTools credential table.
6. **Authenticate & Step-Up:**
   - Request authentication options:
     ```http
     POST /v1/auth/webauthn/authenticate/options
     ```
   - Call `navigator.credentials.get({ publicKey: options })`.
   - Submit the assertion to `/v1/auth/webauthn/authenticate/verify`.
   - Observe in DevTools that the **Sign count** increments by 1 on each successful ceremony.
   - If an attacker attempts to replay a previous assertion or decrease the sign count, BitGuard rejects the request with `InvalidSignCountError`.

---

## 6. Endpoints Summary

| Endpoint | Method | Role / Dependency | Description |
| :--- | :--- | :--- | :--- |
| `/v1/auth/oidc-login` | `POST` | Public | Exchanges Keycloak OIDC ID token for BitGuard session token |
| `/v1/auth/webauthn/register/options` | `POST` | Authenticated | Generates challenge for hardware credential creation |
| `/v1/auth/webauthn/register/verify` | `POST` | Authenticated | Verifies registration response and persists public key |
| `/v1/auth/webauthn/authenticate/options` | `POST` | Public / Authenticated | Generates challenge for WebAuthn authentication ceremony |
| `/v1/auth/webauthn/authenticate/verify` | `POST` | Public / Authenticated | Verifies assertion signature, updates sign count, issues step-up token |
| `/v1/auth/webauthn/credentials` | `GET` | Authenticated | Lists registered credentials for active user |
| `/v1/auth/admin/action` | `POST` | `Admin`, `SecOps`, `Approver` | Executes sensitive action with step-up verification and audit logging |
| `/v1/auth/dev-token` | `POST` | DEV ONLY | Issues mock JWT (disabled when `ENV=production`) |
