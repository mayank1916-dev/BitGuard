# AGENTS.md — Permanent Rules & Operating Invariants

## Project Definition
**BitGuard** is a defensive signing firewall. BitGuard is a policy **DECISION point**. A separate signer shim is the **ENFORCEMENT point**.

---

## Invariants (Never violate, never weaken without explicit instruction)

1. **Key Isolation:** BitGuard never stores or uses signing keys. Only the signer shim holds a disposable TESTNET key.
2. **Approval Binding & Verification:** The signer signs only when given a one-time BitGuard approval token bound to tx digest, wallet, chain, expiry (about 60 s) and nonce. The shim recomputes the digest from the raw bytes itself.
3. **Fail-Closed Default:** Fail closed. Unknown format, parse error, missing ledger intent, store outage, unknown caller => DENY.
4. **Raw Byte Source of Truth:** Always decode from raw transaction bytes. Ignore caller-supplied fields.
5. **WebAuthn Hardware Approvals:** Human approvals are WebAuthn signatures over the tx digest. Slack/Telegram/PagerDuty are notifications only and carry a link, never an approve button.
6. **Asymmetric Policy Evolution:** Policy changes: tightening or lockdown = one authorised person, instant. Loosening or unlock = quorum plus cool-down plus attached backtest report.
7. **Immutable Audit Trail:** Every decision, approval and policy change is appended to a hash-chained audit log.
8. **Explicit Data Provenance:** Every number shown in the UI is labelled REAL, SYNTHETIC or REPORTED.
9. **Environment & Safety Boundary:** Local chains and public testnets with disposable keys ONLY. No mainnet. No real funds. No exploit tooling. Attack scenarios are data files describing patterns, not attack code.
10. **Visual Stability:** The existing UI look stays unchanged: do not edit existing CSS tokens, colours, fonts or layout. New UI elements must reuse existing classes.
11. **Strict Wording & Claims:** 
    - Say **"reduces and contains"**, never "prevents".
    - Say **"target p99 under 15 ms, measured"**, never a flat "<15 ms".
    - Say **"production-ready architecture; pilot after audit and shadow-mode validation"**.

---

## Engineering Standards

- **Core Stack:** Python 3.12, FastAPI, Postgres 16, Redis 7, pytest, ruff, mypy, Docker Compose, Foundry Anvil for the local chain.
- **Type Safety:** Type hints everywhere.
- **Coverage:** Every module has tests.
- **Configuration & Secrets:** No secrets in the repo; configuration strictly via environment variables.
- **Change Discipline:** Small, reviewable, well-scoped changes.

---

## Workflow Rules

- **Pre-execution Plan:** Make a short plan first and list the files you will touch.
- **Quality Gates:** Run tests and linters before you finish.
- **Completion Summary:** End with a summary of what changed, assumptions made and anything left undone.
- **Scope Boundary:** Do not start work belonging to another step.
