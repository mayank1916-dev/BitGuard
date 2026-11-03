"""Database migration and ORM model tests for BitGuard canonical tables."""

from datetime import UTC, datetime

import alembic.command
import alembic.config
import sqlalchemy as sa
from sqlalchemy.orm import Session

from services.bitguard.db_models import (
    ApprovalRecord,
    AuditEntryRecord,
    BreakerStateRecord,
    DailyGroupMetricsRecord,
    DecisionRecord,
    HoldTicketRecord,
    PolicyVersionRecord,
    WalletGroupRecord,
    WatchedAddressRecord,
)


def test_alembic_migrations_lifecycle():
    """Verify Alembic migrations apply cleanly and create canonical schema."""
    engine = sa.create_engine("sqlite:///:memory:")

    alembic_cfg = alembic.config.Config("services/bitguard/alembic.ini")
    alembic_cfg.set_main_option("script_location", "services/bitguard/alembic")

    with engine.connect() as connection:
        alembic_cfg.attributes["connection"] = connection
        # Upgrade to head
        alembic.command.upgrade(alembic_cfg, "head")

        # Verify tables exist via SQLAlchemy inspect
        inspector = sa.inspect(connection)
        tables = set(inspector.get_table_names())
        expected_tables = {
            "decisions",
            "hold_tickets",
            "approvals",
            "policy_versions",
            "audit_entries",
            "watched_addresses",
            "breaker_state",
            "wallet_groups",
            "daily_group_metrics",
        }
        assert expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}"

        # Test inserting and reading back records using ORM session
        with Session(bind=connection) as session:
            now = datetime.now(UTC)

            dec = DecisionRecord(
                id="dec-db-001",
                request_id="req-db-001",
                verdict="ALLOW",
                would_have_verdict="DENY",
                risk_score=90,
                reasons=[{"code": "SUSPICIOUS_DELEGATION", "weight": 90, "detail": "Test"}],
                mode="SHADOW",
                policy_version="v1.0.0",
                data_label="SYNTHETIC",
                wallet_group="hot-eth-1",
                is_false_positive=False,
                created_at=now,
            )
            ht = HoldTicketRecord(
                id="ht-db-001",
                request_id="req-db-001",
                tx_digest="0xdigest001",
                reasons=[],
                status="PENDING",
                expires_at=now,
                created_at=now,
            )
            appr = ApprovalRecord(
                id="appr-db-001",
                hold_ticket_id="ht-db-001",
                approver_id="admin-01",
                tx_digest="0xdigest001",
                webauthn_signature="sig-bytes",
                created_at=now,
            )
            pv = PolicyVersionRecord(
                id="pv-db-001",
                version="v1.0.0",
                author="compliance",
                rules={"max_velocity": 10},
                is_active=True,
                created_at=now,
            )
            ae = AuditEntryRecord(
                index=1,
                timestamp=1730000000.0,
                event_type="DECISION",
                request_id="req-db-001",
                verdict="ALLOW",
                prev_hash="0" * 64,
                entry_hash="1" * 64,
                data_label="REPORTED",
            )
            wa = WatchedAddressRecord(
                id="wa-db-001",
                address="0xabc123",
                chain="ethereum",
                label="Primary Hot Wallet",
                allowed_delegates=["0xdel1"],
                created_at=now,
            )
            bs = BreakerStateRecord(
                id=1,
                state="NORMAL",
                reason="Nominal",
                data_label="REAL",
                updated_at=now,
            )
            wg = WalletGroupRecord(
                id="hot-eth-1",
                name="Hot Ethereum Primary",
                mode="SHADOW",
                wallets=["0xabc123"],
                shadow_started_at=now,
                unexplained_decode_failures=0,
                created_at=now,
                updated_at=now,
            )
            dgm = DailyGroupMetricsRecord(
                id="hot-eth-1:2026-11-03",
                wallet_group="hot-eth-1",
                date="2026-11-03",
                would_have_blocked_count=1,
                would_have_blocked_value=50000.0,
                allowed_count=10,
                false_positive_count=0,
                updated_at=now,
            )

            session.add_all([dec, ht, appr, pv, ae, wa, bs, wg, dgm])
            session.commit()

            # Query back to ensure data persistence
            stored_dec = session.query(DecisionRecord).filter_by(id="dec-db-001").first()
            assert stored_dec is not None
            assert stored_dec.verdict == "ALLOW"
            assert stored_dec.would_have_verdict == "DENY"
            assert stored_dec.wallet_group == "hot-eth-1"

            stored_wg = session.query(WalletGroupRecord).filter_by(id="hot-eth-1").first()
            assert stored_wg is not None
            assert stored_wg.mode == "SHADOW"

            stored_dgm = session.query(DailyGroupMetricsRecord).filter_by(id="hot-eth-1:2026-11-03").first()
            assert stored_dgm is not None
            assert stored_dgm.would_have_blocked_count == 1

        # Downgrade back to base to verify downgrade migration
        alembic.command.downgrade(alembic_cfg, "base")
        inspector_post = sa.inspect(connection)
        remaining_tables = set(inspector_post.get_table_names())
        for tbl in expected_tables:
            assert tbl not in remaining_tables, f"Table {tbl} was not dropped by downgrade"
