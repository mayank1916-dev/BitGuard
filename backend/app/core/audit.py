import copy
import hashlib
import time

from pydantic import BaseModel, Field

from backend.app.models import Decision


class AuditEntry(BaseModel):
    """An immutable, cryptographically chained decision audit record."""
    index: int
    timestamp: float
    request_id: str
    action: str  # 'allow' | 'hold' | 'deny'
    risk: int    # 0 - 100
    rule_hits: list[str] = Field(default_factory=list)
    prev_hash: str
    entry_hash: str


def compute_entry_hash(
    prev_hash: str,
    timestamp: float,
    request_id: str,
    action: str,
    risk: int,
    rule_hits: list[str],
) -> str:
    """
    Computes deterministic SHA-256 hash for an audit entry:
    SHA-256(f"{prev_hash}:{timestamp}:{request_id}:{action}:{risk}:{','.join(sorted(rule_hits))}")
    """
    sorted_rules = ",".join(sorted(rule_hits))
    payload = f"{prev_hash}:{timestamp}:{request_id}:{action}:{risk}:{sorted_rules}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """
    Append-only tamper-evident audit ledger with SHA-256 hash chaining.
    Genesis block links to 64 zeroes.
    """

    GENESIS_PREV_HASH: str = "0" * 64

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []
        self._backup_entries: list[AuditEntry] = []
        self.is_tampered: bool = False

    def append_entry(
        self,
        request_id: str,
        action: str,
        risk: int,
        rule_hits: list[str],
        timestamp: float | None = None,
    ) -> AuditEntry:
        """Appends a new decision to the hash chain."""
        ts = timestamp if timestamp is not None else time.time()
        prev_hash = self.entries[-1].entry_hash if self.entries else self.GENESIS_PREV_HASH
        idx = len(self.entries)

        entry_hash = compute_entry_hash(
            prev_hash=prev_hash,
            timestamp=ts,
            request_id=request_id,
            action=action,
            risk=risk,
            rule_hits=rule_hits,
        )

        entry = AuditEntry(
            index=idx,
            timestamp=ts,
            request_id=request_id,
            action=action,
            risk=risk,
            rule_hits=rule_hits,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.entries.append(entry)
        self._snapshot_backup()
        return entry

    def append_decision(
        self,
        decision: Decision,
        timestamp: float | None = None,
    ) -> AuditEntry:
        """Helper to append directly from a PolicyEngine Decision model."""
        rules: list[str] = []
        for r in decision.reasons:
            if isinstance(r, dict) and "rule" in r:
                rules.append(str(r["rule"]))
            elif isinstance(r, str):
                rules.append(r)

        return self.append_entry(
            request_id=decision.request_id,
            action=decision.action,
            risk=decision.risk,
            rule_hits=rules,
            timestamp=timestamp,
        )

    def verify_integrity(self) -> tuple[bool, int | None]:
        """
        Iterates through the chain, recomputes hashes, and checks link integrity.
        Returns (True, None) if intact, or (False, corrupted_index) if compromised.
        """
        for i, entry in enumerate(self.entries):
            # Check expected prev_hash
            expected_prev = self.entries[i - 1].entry_hash if i > 0 else self.GENESIS_PREV_HASH
            if entry.prev_hash != expected_prev:
                return (False, i)

            # Recompute entry hash
            recomputed = compute_entry_hash(
                prev_hash=entry.prev_hash,
                timestamp=entry.timestamp,
                request_id=entry.request_id,
                action=entry.action,
                risk=entry.risk,
                rule_hits=entry.rule_hits,
            )
            if recomputed != entry.entry_hash:
                return (False, i)

        return (True, None)

    def tamper_test_corrupt_entry(self, index: int) -> bool:
        """
        Modifies a stored record's payload (e.g., changes deny to allow, alters risk)
        without recalculating the hash to demonstrate tamper detection.
        """
        if index < 0 or index >= len(self.entries):
            return False

        # Make sure backup is preserved
        if not self._backup_entries:
            self._snapshot_backup()

        target = self.entries[index]
        # Modify fields
        new_action = "allow" if target.action != "allow" else "deny"
        new_risk = 0 if target.risk > 50 else 99

        # Replace with mutated entry (keeping existing entry_hash to create mismatch)
        mutated = AuditEntry(
            index=target.index,
            timestamp=target.timestamp,
            request_id=target.request_id,
            action=new_action,
            risk=new_risk,
            rule_hits=target.rule_hits,
            prev_hash=target.prev_hash,
            entry_hash=target.entry_hash,
        )
        self.entries[index] = mutated
        self.is_tampered = True
        return True

    def reset_ledger(self) -> None:
        """
        Clears all tampered entries, restores or rebuilds the pristine chain
        from the genesis block, and marks is_tampered = False.
        """
        if self._backup_entries:
            self.entries = copy.deepcopy(self._backup_entries)

        # Re-chain and compute deterministic hashes from genesis block
        prev_h = self.GENESIS_PREV_HASH
        for idx, entry in enumerate(self.entries):
            entry.index = idx
            entry.prev_hash = prev_h
            entry.entry_hash = compute_entry_hash(
                prev_hash=entry.prev_hash,
                timestamp=entry.timestamp,
                request_id=entry.request_id,
                action=entry.action,
                risk=entry.risk,
                rule_hits=entry.rule_hits,
            )
            prev_h = entry.entry_hash

        self.is_tampered = False
        self._snapshot_backup()

    def reset(self) -> None:
        """Alias for reset_ledger."""
        self.reset_ledger()

    def get_root_hash(self) -> str:
        """Returns the latest head/root hash of the chain."""
        return self.entries[-1].entry_hash if self.entries else self.GENESIS_PREV_HASH

    def _snapshot_backup(self) -> None:
        """Takes a clean backup snapshot whenever a legitimate entry is added."""
        self._backup_entries = copy.deepcopy(self.entries)
