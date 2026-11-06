"""Quarantine hold tickets expansion and state transition constraints (Milestone S14).

Revision ID: 0009_quarantine_hold_tickets_expansion
Revises: 0008_audit_chain_v2
Create Date: 2026-11-06 22:00:00.000000

Invariants & Rules:
- Enforce valid state transitions in code and with a database constraint or trigger.
- Terminal states (DENIED, EXPIRED, CANCELLED, RELEASED) cannot change.
- Single-use guarantee for approval token releases.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009_quarantine_hold_tickets_expansion"
down_revision: str | None = "0008_audit_chain_v2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Expand hold_tickets with canonical S14 columns and state constraints."""
    # 1. Add canonical S14 columns
    op.add_column("hold_tickets", sa.Column("digest", sa.String(length=128), nullable=True))
    op.add_column("hold_tickets", sa.Column("decoded_tx", sa.JSON(), nullable=True))
    op.add_column("hold_tickets", sa.Column("requester_identity", sa.String(length=128), nullable=True))
    op.add_column(
        "hold_tickets",
        sa.Column("state", sa.String(length=32), nullable=False, server_default="PENDING"),
    )
    op.add_column("hold_tickets", sa.Column("release_not_before", sa.DateTime(timezone=True), nullable=True))
    op.add_column("hold_tickets", sa.Column("released_at", sa.DateTime(timezone=True), nullable=True))

    # 2. Backfill existing rows if present
    conn = op.get_bind()
    conn.execute(sa.text("UPDATE hold_tickets SET digest = tx_digest WHERE digest IS NULL"))
    conn.execute(sa.text("UPDATE hold_tickets SET requester_identity = requester_id WHERE requester_identity IS NULL"))
    conn.execute(sa.text("UPDATE hold_tickets SET state = status WHERE state = 'PENDING' AND status IS NOT NULL"))

    # 3. Create database trigger based on dialect
    dialect = conn.dialect.name
    if dialect == "postgresql":
        conn.execute(sa.text("""
            CREATE OR REPLACE FUNCTION check_hold_ticket_transition() RETURNS TRIGGER AS $$
            BEGIN
                IF OLD.state IN ('DENIED', 'EXPIRED', 'CANCELLED', 'RELEASED') AND OLD.state != NEW.state THEN
                    RAISE EXCEPTION 'Cannot transition from terminal state % to %', OLD.state, NEW.state;
                END IF;
                IF OLD.state = 'APPROVED' AND NEW.state NOT IN ('APPROVED', 'RELEASED', 'CANCELLED') THEN
                    RAISE EXCEPTION 'Invalid transition from APPROVED to %', NEW.state;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        """))
        conn.execute(sa.text("""
            CREATE TRIGGER trg_hold_tickets_state_transition
            BEFORE UPDATE ON hold_tickets
            FOR EACH ROW
            EXECUTE FUNCTION check_hold_ticket_transition();
        """))
    elif dialect == "sqlite":
        conn.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_hold_tickets_terminal_state
            BEFORE UPDATE OF state, status ON hold_tickets
            FOR EACH ROW
            WHEN OLD.state IN ('DENIED', 'EXPIRED', 'CANCELLED', 'RELEASED') AND OLD.state != NEW.state
            BEGIN
                SELECT RAISE(ABORT, 'Cannot transition from terminal state');
            END;
        """))
        conn.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_hold_tickets_invalid_approved
            BEFORE UPDATE OF state, status ON hold_tickets
            FOR EACH ROW
            WHEN OLD.state = 'APPROVED' AND NEW.state NOT IN ('APPROVED', 'RELEASED', 'CANCELLED')
            BEGIN
                SELECT RAISE(ABORT, 'Invalid transition from APPROVED');
            END;
        """))


def downgrade() -> None:
    """Drop S14 columns and triggers from hold_tickets."""
    conn = op.get_bind()
    dialect = conn.dialect.name
    if dialect == "postgresql":
        conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_hold_tickets_state_transition ON hold_tickets"))
        conn.execute(sa.text("DROP FUNCTION IF EXISTS check_hold_ticket_transition()"))
    elif dialect == "sqlite":
        conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_hold_tickets_terminal_state"))
        conn.execute(sa.text("DROP TRIGGER IF EXISTS trg_hold_tickets_invalid_approved"))

    op.drop_column("hold_tickets", "released_at")
    op.drop_column("hold_tickets", "release_not_before")
    op.drop_column("hold_tickets", "state")
    op.drop_column("hold_tickets", "requester_identity")
    op.drop_column("hold_tickets", "decoded_tx")
    op.drop_column("hold_tickets", "digest")
