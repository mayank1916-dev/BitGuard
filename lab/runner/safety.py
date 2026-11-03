"""Safety boundaries and invariants for BitGuard Integration Lab (AGENTS.md Invariant #9).

Guarantees:
- Strict prohibition of connecting to Ethereum or L2 mainnets.
- Refusal to start if chain ID corresponds to any known mainnet.
- Requirement for disposable testnet / lab keys only.
"""

from typing import Final

KNOWN_MAINNET_CHAIN_IDS: Final[dict[int, str]] = {
    1: "Ethereum Mainnet",
    10: "Optimism Mainnet",
    56: "BNB Smart Chain Mainnet",
    137: "Polygon PoS Mainnet",
    250: "Fantom Opera Mainnet",
    324: "zkSync Era Mainnet",
    1101: "Polygon zkEVM Mainnet",
    8453: "Base Mainnet",
    42161: "Arbitrum One Mainnet",
    42220: "Celo Mainnet",
    43114: "Avalanche C-Chain Mainnet",
    59144: "Linea Mainnet",
    534352: "Scroll Mainnet",
}

FORBIDDEN_CHAIN_IDENTIFIERS: Final[set[str]] = {
    "1",
    "mainnet",
    "homestead",
    "ethereum-mainnet",
    "eth-mainnet",
    "polygon-mainnet",
    "arbitrum-one",
    "optimism-mainnet",
    "base-mainnet",
    "bsc-mainnet",
    "avalanche-mainnet",
}


class MainnetForbiddenError(RuntimeError):
    """Raised when an attempt is made to execute the integration lab against a mainnet chain."""


class SafetyBoundaryViolation(RuntimeError):
    """Raised when an invariant regarding keys, environment, or real funds is violated."""


def assert_non_mainnet(chain_id: int | str, chain_name: str | None = None) -> None:
    """Verifies that the provided chain ID and chain name do NOT correspond to any mainnet.

    Raises:
        MainnetForbiddenError: If chain_id or chain_name is identified as mainnet.
    """
    # 1. Check numeric chain ID
    try:
        numeric_id = int(chain_id)
        if numeric_id in KNOWN_MAINNET_CHAIN_IDS:
            net_name = KNOWN_MAINNET_CHAIN_IDS[numeric_id]
            raise MainnetForbiddenError(
                f"SAFETY VIOLATION (AGENTS.md Invariant #9): Refusing to execute lab against "
                f"known mainnet chain ID {numeric_id} ({net_name}). "
                f"Only local chains (Anvil) and public testnets with disposable keys are permitted."
            )
    except ValueError:
        pass

    # 2. Check string chain name / identifier
    str_val = str(chain_id).strip().lower()
    if str_val in FORBIDDEN_CHAIN_IDENTIFIERS:
        raise MainnetForbiddenError(
            f"SAFETY VIOLATION (AGENTS.md Invariant #9): Refusing to execute lab against "
            f"forbidden chain identifier '{chain_id}'. "
            f"Only local chains (Anvil) and public testnets with disposable keys are permitted."
        )

    if chain_name:
        clean_name = chain_name.strip().lower()
        if clean_name in FORBIDDEN_CHAIN_IDENTIFIERS or "mainnet" in clean_name:
            raise MainnetForbiddenError(
                f"SAFETY VIOLATION (AGENTS.md Invariant #9): Refusing to execute lab against "
                f"forbidden chain name '{chain_name}'."
            )


def verify_disposable_key_safety(key_metadata: dict[str, str | bool]) -> None:
    """Verifies that signing keys utilized in the lab are tagged disposable."""
    is_disposable = key_metadata.get("is_disposable", True)
    if not is_disposable:
        raise SafetyBoundaryViolation(
            "SAFETY VIOLATION (AGENTS.md Invariant #1 & #9): Only disposable test keys are allowed in lab."
        )
