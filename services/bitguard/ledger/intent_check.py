"""Engine stage for withdrawal intent reconciliation (Milestone S08 / F2)."""


from pydantic import BaseModel

from services.bitguard.ledger.base import LedgerConnector
from services.bitguard.ledger.metrics import intent_metrics
from services.bitguard.ledger.mock import mock_ledger_connector
from services.bitguard.ledger.models import IntentStatus, WithdrawalIntent
from services.bitguard.models import DecodedTx, SigningRequest


class IntentCheckResult(BaseModel):
    """Outcome of intent reconciliation stage."""

    passed: bool
    code: str | None = None
    detail: str | None = None
    intent: WithdrawalIntent | None = None


def extract_decoded_destination(decoded: DecodedTx) -> str:
    """Extracts the intended recipient address strictly from canonical decoded transaction bytes."""
    if decoded.chain.strip().lower() in ["bitcoin", "btc", "bitcoin_regtest", "bitcoin_testnet"] and decoded.to_address:
        return decoded.to_address.strip()
    if decoded.calls and decoded.calls[0].recipient:
        return decoded.calls[0].recipient.strip()
    if decoded.to_address:
        return decoded.to_address.strip()
    return ""


def extract_decoded_amount(decoded: DecodedTx) -> str:
    """Extracts transfer amount strictly from canonical decoded transaction bytes."""
    if decoded.chain.strip().lower() in ["bitcoin", "btc", "bitcoin_regtest", "bitcoin_testnet"] and decoded.amount:
        return decoded.amount.strip()
    if decoded.calls and decoded.calls[0].amount:
        return decoded.calls[0].amount.strip()
    return decoded.amount.strip()


def check_intent(
    request: SigningRequest,
    decoded: DecodedTx,
    ledger: LedgerConnector | None = None,
) -> IntentCheckResult:
    """Evaluates transaction against custody ledger withdrawal intent.

    Invariants:
    - Invariant #3: Fail-closed on missing ledger intent or store outage.
    - Invariant #4: Always verify strictly from raw transaction bytes (DecodedTx),
      ignoring any caller-supplied unverified metadata fields.
    """
    connector = ledger or mock_ledger_connector

    # 1. Intent ID presence
    intent_id = request.intent_id.strip() if request.intent_id else None
    if not intent_id:
        intent_metrics.record_unmatched("INTENT_MISSING")
        return IntentCheckResult(
            passed=False,
            code="INTENT_MISSING",
            detail="Withdrawal intent ID is missing from signing request.",
        )

    # 2. Intent existence
    intent = connector.get_intent(intent_id)
    if intent is None:
        intent_metrics.record_unmatched("INTENT_MISSING")
        return IntentCheckResult(
            passed=False,
            code="INTENT_MISSING",
            detail=f"Withdrawal intent '{intent_id}' does not exist in custody ledger.",
        )

    # 3. Idempotency check: intent can be consumed once (F2)
    if connector.is_consumed(intent.id):
        intent_metrics.record_unmatched("INTENT_REPLAY")
        return IntentCheckResult(
            passed=False,
            code="INTENT_REPLAY",
            detail=f"Withdrawal intent '{intent.id}' has already been consumed and cannot be replayed.",
            intent=intent,
        )

    # 4. Status checks: must be APPROVED, not PAID or CANCELLED
    if intent.status == IntentStatus.PAID.value:
        intent_metrics.record_unmatched("INTENT_ALREADY_PAID")
        return IntentCheckResult(
            passed=False,
            code="INTENT_ALREADY_PAID",
            detail=f"Withdrawal intent '{intent.id}' has already been paid.",
            intent=intent,
        )

    if intent.status != IntentStatus.APPROVED.value:
        intent_metrics.record_unmatched("INTENT_NOT_APPROVED")
        return IntentCheckResult(
            passed=False,
            code="INTENT_NOT_APPROVED",
            detail=f"Withdrawal intent '{intent.id}' status is '{intent.status}' (expected APPROVED).",
            intent=intent,
        )

    # 5. Destination check: strictly from DecodedTx
    decoded_dest = extract_decoded_destination(decoded).lower()
    intent_dest = intent.destination.strip().lower()
    if not decoded_dest or decoded_dest != intent_dest:
        intent_metrics.record_unmatched("INTENT_MISMATCH_DESTINATION")
        return IntentCheckResult(
            passed=False,
            code="INTENT_MISMATCH_DESTINATION",
            detail=f"Decoded destination '{decoded_dest}' does not match intent destination '{intent_dest}'.",
            intent=intent,
        )

    # 6. Amount check: strictly from DecodedTx (exact integer match in smallest units)
    decoded_amt_str = extract_decoded_amount(decoded)
    try:
        if int(decoded_amt_str) != int(intent.amount):
            intent_metrics.record_unmatched("INTENT_MISMATCH_AMOUNT")
            return IntentCheckResult(
                passed=False,
                code="INTENT_MISMATCH_AMOUNT",
                detail=f"Decoded amount '{decoded_amt_str}' does not match intent amount '{intent.amount}'.",
                intent=intent,
            )
    except ValueError:
        intent_metrics.record_unmatched("INTENT_MISMATCH_AMOUNT")
        return IntentCheckResult(
            passed=False,
            code="INTENT_MISMATCH_AMOUNT",
            detail=f"Non-integer amount encountered in comparison: decoded '{decoded_amt_str}' vs intent '{intent.amount}'.",
            intent=intent,
        )

    # 7. Chain check
    decoded_chain = decoded.chain.strip().lower()
    intent_chain = intent.chain.strip().lower()
    # Normalize eip155 and bitcoin aliases
    is_chain_match = (decoded_chain == intent_chain) or (
        decoded_chain in ["ethereum", "eip155:1"] and intent_chain in ["ethereum", "eip155:1"]
    ) or (
        decoded_chain in ["bitcoin", "btc"] and intent_chain in ["bitcoin", "btc"]
    )
    if not is_chain_match:
        intent_metrics.record_unmatched("INTENT_MISMATCH_CHAIN")
        return IntentCheckResult(
            passed=False,
            code="INTENT_MISMATCH_CHAIN",
            detail=f"Decoded chain '{decoded_chain}' does not match intent chain '{intent_chain}'.",
            intent=intent,
        )

    # 8. Asset check
    decoded_asset = decoded.asset.strip().upper()
    intent_asset = intent.asset.strip().upper()
    if decoded_asset != intent_asset and decoded_asset.lower() != intent_asset.lower():
        intent_metrics.record_unmatched("INTENT_MISMATCH_ASSET")
        return IntentCheckResult(
            passed=False,
            code="INTENT_MISMATCH_ASSET",
            detail=f"Decoded asset '{decoded_asset}' does not match intent asset '{intent_asset}'.",
            intent=intent,
        )

    # All checks passed
    intent_metrics.record_matched()
    return IntentCheckResult(passed=True, intent=intent)
