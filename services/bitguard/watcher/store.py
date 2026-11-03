"""Storage and repository for watched hot wallet addresses (Milestone S17 / F6).

Invariants:
- Invariant #7: Immutable Audit Trail.
- Invariant #8: Explicit Data Provenance (data_label REAL).
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.bitguard.database import get_session_factory
from services.bitguard.db_models import WatchedAddressRecord
from services.bitguard.models import CreateWatchedAddressRequest, DataLabel, WatchedAddress

logger = logging.getLogger("bitguard.watcher.store")


class WatchedAddressStore:
    """Manages persistent and in-memory storage of internal hot wallet addresses monitored by the watcher."""

    def __init__(self) -> None:
        self._by_id: dict[str, WatchedAddress] = {}
        self._by_address: dict[str, str] = {}  # f"{chain}:{address.lower()}" -> id
        self._seed_default_addresses()

    def _seed_default_addresses(self) -> None:
        """Seeds initial default monitored hot wallet addresses for lab/demo environments."""
        defaults = [
            WatchedAddress(
                id="wa-seed-eth-01",
                address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                chain="ethereum",
                label="Primary Hot Wallet ETH-1",
                expected_code_hash=None,
                allowed_delegates=["0x1111111111111111111111111111111111111111"],
                last_known_nonce=42,
                signed_count=12,
                last_scanned_block=102,
                status="ACTIVE",
                data_label=DataLabel.REAL,
                delegation_state="none",
                delegate_address=None,
                delegate_code_hash=None,
                provider_agreement="all agree",
                recent_alerts=[],
            ),
            WatchedAddress(
                id="wa-seed-eth-02",
                address="0x1234567890123456789012345678901234567890",
                chain="ethereum",
                label="Arbitrum Gateway Staging Vault",
                expected_code_hash=None,
                allowed_delegates=["0x2222222222222222222222222222222222222222"],
                last_known_nonce=10,
                signed_count=4,
                last_scanned_block=102,
                status="ACTIVE",
                data_label=DataLabel.REAL,
                delegation_state="allowed delegate",
                delegate_address="0x2222222222222222222222222222222222222222",
                delegate_code_hash="0xc1d5b4ce3e2a6227293fccce2904121c8647bbe16c1216340b851bf12d12560e",
                provider_agreement="all agree",
                recent_alerts=[],
            ),
            WatchedAddress(
                id="wa-seed-eth-03",
                address="0x8888888888888888888888888888888888888888",
                chain="ethereum",
                label="Base L2 Settlement Escrow",
                expected_code_hash=None,
                allowed_delegates=[],
                last_known_nonce=1,
                signed_count=0,
                last_scanned_block=102,
                status="ACTIVE",
                data_label=DataLabel.REAL,
                delegation_state="none",
                delegate_address=None,
                delegate_code_hash=None,
                provider_agreement="all agree",
                recent_alerts=[],
            ),
        ]
        for item in defaults:
            self._by_id[item.id] = item
            self._by_address[f"{item.chain.lower()}:{item.address.lower()}"] = item.id

    def _record_to_domain(self, record: WatchedAddressRecord) -> WatchedAddress:
        return WatchedAddress(
            id=record.id,
            address=record.address,
            chain=record.chain,
            label=record.label,
            expected_code_hash=record.expected_code_hash,
            allowed_delegates=list(record.allowed_delegates or []),
            last_known_nonce=record.last_known_nonce,
            signed_count=record.signed_count,
            last_scanned_block=record.last_scanned_block,
            status=record.status,
            data_label=DataLabel(record.data_label or "REAL"),
            created_at=record.created_at,
        )

    def create(self, req: CreateWatchedAddressRequest, db: Session | None = None) -> WatchedAddress:
        """Registers a new watched address."""
        key = f"{req.chain.lower()}:{req.address.lower()}"
        if key in self._by_address:
            existing_id = self._by_address[key]
            existing = self._by_id.get(existing_id)
            if existing:
                return existing

        watched_id = f"wa-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)

        domain = WatchedAddress(
            id=watched_id,
            address=req.address,
            chain=req.chain.lower(),
            label=req.label,
            expected_code_hash=req.expected_code_hash,
            allowed_delegates=req.allowed_delegates,
            last_known_nonce=req.initial_nonce,
            signed_count=0,
            last_scanned_block=None,
            status="ACTIVE",
            data_label=DataLabel.REAL,
            created_at=now,
        )

        self._by_id[watched_id] = domain
        self._by_address[key] = watched_id

        # Persist to database if available
        record = WatchedAddressRecord(
            id=domain.id,
            address=domain.address,
            chain=domain.chain,
            label=domain.label,
            expected_code_hash=domain.expected_code_hash,
            allowed_delegates=domain.allowed_delegates,
            last_known_nonce=domain.last_known_nonce,
            signed_count=domain.signed_count,
            last_scanned_block=domain.last_scanned_block,
            status=domain.status,
            data_label=domain.data_label.value,
            created_at=domain.created_at,
        )

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("postgres_unavailable_using_memory: %s", exc)

        if session is not None:
            try:
                session.merge(record)
                session.commit()
            except Exception as exc:
                logger.warning("failed_persisting_watched_address: %s", exc)
                session.rollback()
            finally:
                if should_close:
                    session.close()

        return domain

    def get(self, watched_id: str, db: Session | None = None) -> WatchedAddress | None:
        """Retrieves a watched address by ID."""
        if watched_id in self._by_id:
            return self._by_id[watched_id]

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("postgres_unavailable: %s", exc)

        if session is not None:
            try:
                record = session.get(WatchedAddressRecord, watched_id)
                if record is not None:
                    domain = self._record_to_domain(record)
                    self._by_id[domain.id] = domain
                    self._by_address[f"{domain.chain.lower()}:{domain.address.lower()}"] = domain.id
                    return domain
            except Exception as exc:
                logger.warning("failed_getting_watched_address: %s", exc)
            finally:
                if should_close:
                    session.close()

        return None

    def get_by_address(self, address: str, chain: str = "ethereum") -> WatchedAddress | None:
        """Retrieves a watched address by blockchain address and chain."""
        key = f"{chain.lower()}:{address.lower()}"
        wid = self._by_address.get(key)
        if wid:
            return self._by_id.get(wid)
        return None

    def list_all(self, db: Session | None = None) -> list[WatchedAddress]:
        """Lists all registered watched addresses."""
        if self._by_id:
            return list(self._by_id.values())

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("postgres_unavailable: %s", exc)

        if session is not None:
            try:
                stmt = select(WatchedAddressRecord)
                records = session.execute(stmt).scalars().all()
                results = [self._record_to_domain(r) for r in records]
                for d in results:
                    self._by_id[d.id] = d
                    self._by_address[f"{d.chain.lower()}:{d.address.lower()}"] = d.id
                return results
            except Exception as exc:
                logger.warning("failed_listing_watched_addresses: %s", exc)
            finally:
                if should_close:
                    session.close()

        return list(self._by_id.values())

    def update(self, watched_id: str, updates: dict[str, Any], db: Session | None = None) -> WatchedAddress | None:
        """Updates attributes on a watched address."""
        domain = self.get(watched_id, db=db)
        if domain is None:
            return None

        for k, v in updates.items():
            if v is not None and hasattr(domain, k):
                setattr(domain, k, v)

        self._by_id[watched_id] = domain

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("postgres_unavailable: %s", exc)

        if session is not None:
            try:
                record = session.get(WatchedAddressRecord, watched_id)
                if record is not None:
                    for k, v in updates.items():
                        if v is not None and hasattr(record, k):
                            setattr(record, k, v)
                    session.commit()
            except Exception as exc:
                logger.warning("failed_updating_watched_address: %s", exc)
                session.rollback()
            finally:
                if should_close:
                    session.close()

        return domain

    def delete(self, watched_id: str, db: Session | None = None) -> bool:
        """Deletes a watched address."""
        domain = self._by_id.pop(watched_id, None)
        if domain:
            self._by_address.pop(f"{domain.chain.lower()}:{domain.address.lower()}", None)

        session = db
        should_close = False
        if session is None:
            try:
                factory = get_session_factory()
                session = factory()
                should_close = True
            except Exception as exc:
                logger.debug("postgres_unavailable: %s", exc)

        if session is not None:
            try:
                record = session.get(WatchedAddressRecord, watched_id)
                if record is not None:
                    session.delete(record)
                    session.commit()
                    return True
            except Exception as exc:
                logger.warning("failed_deleting_watched_address: %s", exc)
                session.rollback()
            finally:
                if should_close:
                    session.close()

        return domain is not None

    def record_signed_tx(self, address: str, chain: str = "ethereum") -> None:
        """Increments the BitGuard-signed transaction counter for an address."""
        key = f"{chain.lower()}:{address.lower()}"
        wid = self._by_address.get(key)
        if wid and wid in self._by_id:
            self._by_id[wid].signed_count += 1

    def clear(self) -> None:
        """Clears memory state for tests."""
        self._by_id.clear()
        self._by_address.clear()


watched_address_store = WatchedAddressStore()
