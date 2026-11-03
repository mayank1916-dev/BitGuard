"""Delegation guard policy enforcement for EIP-7702 Type-4 authorizations (Milestone S09)."""

import logging
from datetime import UTC, datetime
from typing import Any

from eth_utils import keccak
from pydantic import BaseModel, ConfigDict, Field

from services.bitguard.audit_service import audit_service
from services.bitguard.models import DataLabel, DecodedTx
from services.bitguard.rpc.base import RpcClient

logger = logging.getLogger("bitguard.rules.delegation")

# EIP-1967 implementation slot: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# EVM Opcode for DELEGATECALL
OPCODE_DELEGATECALL = 0xF4


def has_delegatecall_opcode(bytecode: bytes) -> bool:
    """Inspects EVM bytecode instructions to determine if executable DELEGATECALL (0xF4) is present.

    Correctly steps over PUSH1..PUSH32 immediate operands to prevent false positives.
    """
    i = 0
    n = len(bytecode)
    while i < n:
        op = bytecode[i]
        if op == OPCODE_DELEGATECALL:
            return True
        if 0x60 <= op <= 0x7F:  # PUSH1 through PUSH32
            push_bytes = op - 0x5F
            i += push_bytes + 1
        else:
            i += 1
    return False


def compute_code_hash(code_hex: str) -> str:
    """Computes Keccak-256 hash of raw contract bytecode."""
    clean = code_hex.strip()
    if clean.startswith("0x"):
        clean = clean[2:]
    code_bytes = bytes.fromhex(clean) if clean else b""
    return "0x" + keccak(code_bytes).hex().lower()


class DelegateAllowlistEntry(BaseModel):
    """Allowlist configuration for a reviewed delegate implementation contract."""

    model_config = ConfigDict(populate_by_name=True)

    code_hash: str = Field(description="Keccak-256 hash of the exact reviewed bytecode")
    name: str = Field(default="", description="Human-readable identifier of the contract")
    reviewed_proxy_ok: bool = Field(
        default=False,
        description="True if an upgradeable proxy pattern has been audited and approved",
    )
    added_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DelegationPolicy(BaseModel):
    """EIP-7702 delegation policy rules and allowlists."""

    model_config = ConfigDict(populate_by_name=True)

    owned_addresses: set[str] = Field(
        default_factory=set,
        description="Set of addresses owned or controlled by the custodian/exchange",
    )
    delegate_allowlist: dict[str, DelegateAllowlistEntry] = Field(
        default_factory=dict,
        description="Mapping from code_hash (lowercase) to DelegateAllowlistEntry",
    )

    def add_allowed_delegate(
        self,
        code_hash: str,
        name: str = "",
        reviewed_proxy_ok: bool = False,
    ) -> None:
        """Registers an approved delegate code hash."""
        clean_hash = code_hash.strip().lower()
        self.delegate_allowlist[clean_hash] = DelegateAllowlistEntry(
            code_hash=clean_hash,
            name=name,
            reviewed_proxy_ok=reviewed_proxy_ok,
        )


class DelegationCheckResult(BaseModel):
    """Outcome of EIP-7702 delegation validation."""

    passed: bool
    code: str | None = None
    detail: str | None = None
    is_alert: bool = False
    alert_severity: str | None = None
    alert_message: str | None = None
    inspected_delegates: list[dict[str, Any]] = Field(default_factory=list)


def check_delegations(
    decoded_tx: DecodedTx,
    policy: DelegationPolicy,
    rpc_client: RpcClient,
) -> DelegationCheckResult:
    """Evaluates EIP-7702 delegation authorizations against strict security policy.

    Rules:
    1. Authority in OWNED_ADDRESSES => DENY (DELEGATION_OWNED_ADDRESS) unless delegate's
       CODE HASH is in policy.delegate_allowlist.
    2. Resolve delegate's code through RpcClient, hash it, compare by hash, never address.
    3. Reject delegates that look like upgradeable proxies (EIP-1967 implementation slot non-zero,
       or DELEGATECALL opcode present) unless explicitly marked reviewed_proxy_ok in policy.
    4. Emit a high-severity alert event for any type-4 transaction naming an owned address,
       even if allowed.
    5. RPC failure while resolving code => DENY (fail closed).
    """
    if not decoded_tx.authorizations:
        return DelegationCheckResult(passed=True)

    owned = {addr.strip().lower() for addr in policy.owned_addresses}
    is_alert = False
    alert_message: str | None = None
    inspected: list[dict[str, Any]] = []

    # Rule 4: Check if ANY owned address is named in this Type-4 transaction
    named_owned_addrs: set[str] = set()
    from_addr = (decoded_tx.from_address or "").strip().lower()
    if from_addr in owned:
        named_owned_addrs.add(from_addr)

    for auth in decoded_tx.authorizations:
        if auth.authority and auth.authority.strip().lower() in owned:
            named_owned_addrs.add(auth.authority.strip().lower())
        if auth.address and auth.address.strip().lower() in owned:
            named_owned_addrs.add(auth.address.strip().lower())

    if named_owned_addrs:
        is_alert = True
        alert_message = (
            f"HIGH_SEVERITY_ALERT: EIP-7702 Type-4 transaction names owned custody address(es): "
            f"{', '.join(sorted(named_owned_addrs))}"
        )
        logger.warning(alert_message)
        # Invariant #7: Immutable hash-chained audit log
        audit_service.append_entry(
            event_type="HIGH_SEVERITY_ALERT",
            request_id=f"alert-7702-owned-{int(datetime.now(UTC).timestamp())}",
            verdict="ALERT",
            data_label=DataLabel.REAL,
        )

    # Evaluate each authorization item
    for idx, auth in enumerate(decoded_tx.authorizations):
        # Determine authority: recovered authority, or fallback to transaction sender
        authority = (auth.authority or decoded_tx.from_address or "").strip().lower()
        delegate_addr = auth.address.strip()
        is_authority_owned = authority in owned

        # Rule 1: Only authorities in OWNED_ADDRESSES require code hash allowlisting
        if not is_authority_owned:
            continue

        # Rule 2 & 5: Resolve code through RpcClient (fail-closed on RPC failure)
        try:
            code_hex = rpc_client.get_code(delegate_addr)
        except Exception as exc:
            logger.warning(
                "delegation_guard_rpc_failed_get_code delegate=%s: %s",
                delegate_addr,
                exc,
            )
            return DelegationCheckResult(
                passed=False,
                code="DELEGATION_RPC_FAILURE",
                detail=f"RPC error resolving bytecode for delegate {delegate_addr}: {exc}",
                is_alert=is_alert,
                alert_severity="HIGH" if is_alert else None,
                alert_message=alert_message,
            )

        code_hash = compute_code_hash(code_hex)
        code_bytes = bytes.fromhex(code_hex[2:] if code_hex.startswith("0x") else code_hex)

        inspected.append(
            {
                "index": idx,
                "authority": authority,
                "delegate": delegate_addr,
                "code_hash": code_hash,
            }
        )

        # Rule 1 & 2: Compare to allowlist strictly by code hash, never address alone
        allowlist_entry = policy.delegate_allowlist.get(code_hash.lower())
        if allowlist_entry is None:
            return DelegationCheckResult(
                passed=False,
                code="DELEGATION_OWNED_ADDRESS",
                detail=(
                    f"Delegate {delegate_addr} code hash {code_hash} is not in delegate_allowlist "
                    f"for owned authority {authority}."
                ),
                is_alert=is_alert,
                alert_severity="HIGH" if is_alert else None,
                alert_message=alert_message,
                inspected_delegates=inspected,
            )

        # Rule 3: Reject upgradeable proxies unless explicitly marked reviewed_proxy_ok
        if not allowlist_entry.reviewed_proxy_ok:
            # Check A: EIP-1967 implementation slot non-zero
            try:
                slot_val = rpc_client.get_storage_at(delegate_addr, EIP1967_IMPLEMENTATION_SLOT)
            except Exception as exc:
                logger.warning(
                    "delegation_guard_rpc_failed_get_storage delegate=%s: %s",
                    delegate_addr,
                    exc,
                )
                return DelegationCheckResult(
                    passed=False,
                    code="DELEGATION_RPC_FAILURE",
                    detail=f"RPC error reading implementation slot for delegate {delegate_addr}: {exc}",
                    is_alert=is_alert,
                    alert_severity="HIGH" if is_alert else None,
                    alert_message=alert_message,
                    inspected_delegates=inspected,
                )

            clean_slot = slot_val.strip().lower()
            try:
                slot_int = int(clean_slot, 16)
            except ValueError:
                slot_int = 0

            if slot_int != 0:
                return DelegationCheckResult(
                    passed=False,
                    code="DELEGATION_UPGRADEABLE_PROXY",
                    detail=(
                        f"Delegate {delegate_addr} has non-zero EIP-1967 implementation slot ({slot_val}) "
                        "and is not marked reviewed_proxy_ok."
                    ),
                    is_alert=is_alert,
                    alert_severity="HIGH" if is_alert else None,
                    alert_message=alert_message,
                    inspected_delegates=inspected,
                )

            # Check B: DELEGATECALL opcode (0xF4) present in bytecode
            if has_delegatecall_opcode(code_bytes):
                return DelegationCheckResult(
                    passed=False,
                    code="DELEGATION_UPGRADEABLE_PROXY",
                    detail=(
                        f"Delegate {delegate_addr} bytecode contains DELEGATECALL opcode "
                        "and is not marked reviewed_proxy_ok."
                    ),
                    is_alert=is_alert,
                    alert_severity="HIGH" if is_alert else None,
                    alert_message=alert_message,
                    inspected_delegates=inspected,
                )

    return DelegationCheckResult(
        passed=True,
        is_alert=is_alert,
        alert_severity="HIGH" if is_alert else None,
        alert_message=alert_message,
        inspected_delegates=inspected,
    )
