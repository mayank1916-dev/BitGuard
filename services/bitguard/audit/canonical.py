"""Canonical JSON serialization and cryptographic hash chaining (Milestone S21 / F18).

Invariants:
- Invariant #7: Immutable Audit Trail. entry_hash = sha256(prev_hash || canonical_json(entry)).
- Invariant #8: Explicit Data Provenance.
"""

import hashlib
import json
from typing import Any

GENESIS_PREV_HASH: str = "0" * 64


def canonical_json(data: Any) -> str:
    """Serializes arbitrary Python data structures into canonical RFC 8785 JSON representation.

    Guarantees:
    - Deterministic key ordering (alphabetical sort).
    - Compact separators (no extraneous whitespace).
    - UTF-8 characters preserved (ensure_ascii=False).
    - Types without native JSON representation stringified via default=str.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def compute_entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    """Computes SHA-256 hash according to Invariant #7 and Milestone S21 specification:

    entry_hash = sha256(prev_hash || canonical_json(entry))
    """
    canon = canonical_json(entry)
    payload_bytes = (prev_hash + canon).encode("utf-8")
    return hashlib.sha256(payload_bytes).hexdigest()
