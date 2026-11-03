"""Lab utility generating disposable testnet signing keys (Milestone S11).

Invariants:
- Invariant #1: Only the signer shim holds a disposable TESTNET key.
- Invariant #9: Local chains and public testnets with disposable keys ONLY.
  No mainnet. No real funds. No exploit tooling.
"""

import json
import secrets

from eth_account import Account


def generate_disposable_testnet_key() -> dict[str, str]:
    """Generates a random disposable private key strictly for Anvil or testnet labs."""
    extra_entropy = secrets.token_hex(32)
    acc = Account.create(extra_entropy=extra_entropy)

    payload = {
        "disposable_address": acc.address,
        "private_key": acc.key.hex(),
        "environment": "lab_disposable_testnet",
        "safety_warning": (
            "SAFETY INVARIANT: DISPOSABLE TESTNET ONLY. "
            "NEVER STORE OR USE ON MAINNET. NEVER FUND WITH REAL ASSETS."
        ),
    }
    return payload


if __name__ == "__main__":
    result = generate_disposable_testnet_key()
    print(json.dumps(result, indent=2))
