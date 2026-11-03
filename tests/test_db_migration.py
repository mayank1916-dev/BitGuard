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
    DecisionRecord,
    HoldTicketRecord,
    PolicyVersionRecord,
    WatchedAddressRecord,
)


def test_alembic_migrations_lifecycle():
    """Verify Alembic migration 0002 applies cleanly and creates canonical schema."""
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
        }
        assert expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}"

        # Test inserting and reading back records using ORM session
        with Session(bind=connection) as session:
            now = datetime.now(UTC)

            dec = DecisionRecord(
                id="dec-db-001",
                request_id="req-db-001",
                verdict="DENY",
                risk_score=100,
                reasons=[{"code": "ENGINE_NOT_IMPLEMENTED", "weight": 100, "detail": "Test"}],
                mode="SIMULATION",
                policy_version="v0.1.0",
                data_label="SYNTHETIC",
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
                verdict="DENY",
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

            session.add_all([dec, ht, appr, pv, ae, wa, bs])
            session.commit()

            # Query back to ensure data persistence
            stored_dec = session.query(DecisionRecord).filter_by(id="dec-db-001").first()
            assert stored_dec is not None
            assert stored_dec.verdict == "DENY"

            stored_bs = session.query(BreakerStateRecord).filter_by(id=1).first()
            assert stored_bs is not None
            assert stored_bs.state == "NORMAL"

        # Downgrade back to base to verify downgrade migration
        alembic.command.downgrade(alembic_cfg, "base")
        inspector_post = sa.inspect(connection)
        remaining_tables = set(inspector_post.get_table_names())
        for tbl in expected_tables:
            assert tbl not in remaining_tables, f"Table {tbl} was not dropped by downgrade"
