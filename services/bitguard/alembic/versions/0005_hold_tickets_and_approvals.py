"""Hold tickets and approvals schema expansion (Milestone S16 / F10).

Revision ID: 0005_hold_tickets_and_approvals
Revises: 0004_decision_persistence_and_indexes
Create Date: 2026-11-03 22:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_hold_tickets_and_approvals"
down_revision: str | None = "0004_decision_persistence_and_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add raw_tx, chain, wallet, amount_usd, requester_id, reservation_id, risk_score, signed_result, data_label to hold_tickets and approver_role, assertion_data to approvals."""
    # Columns for hold_tickets
    op.add_column("hold_tickets", sa.Column("raw_tx", sa.Text(), nullable=True))
    op.add_column("hold_tickets", sa.Column("chain", sa.String(length=32), nullable=True, server_default="ethereum"))
    op.add_column("hold_tickets", sa.Column("wallet", sa.String(length=128), nullable=True))
    op.add_column("hold_tickets", sa.Column("amount_usd", sa.Float(), nullable=True, server_default="0.0"))
    op.add_column("hold_tickets", sa.Column("requester_id", sa.String(length=128), nullable=True))
    op.add_column("hold_tickets", sa.Column("reservation_id", sa.String(length=128), nullable=True))
    op.add_column("hold_tickets", sa.Column("risk_score", sa.Integer(), nullable=True, server_default="0"))
    op.add_column("hold_tickets", sa.Column("signed_result", sa.JSON(), nullable=True))
    op.add_column("hold_tickets", sa.Column("data_label", sa.String(length=16), nullable=True, server_default="REAL"))

    # Columns for approvals
    op.add_column("approvals", sa.Column("approver_role", sa.String(length=64), nullable=True, server_default="Approver"))
    op.add_column("approvals", sa.Column("assertion_data", sa.JSON(), nullable=True, server_default="{}"))


def downgrade() -> None:
    """Drop added columns from hold_tickets and approvals."""
    op.drop_column("approvals", "assertion_data")
    op.drop_column("approvals", "approver_role")

    op.drop_column("hold_tickets", "data_label")
    op.drop_column("hold_tickets", "signed_result")
    op.drop_column("hold_tickets", "risk_score")
    op.drop_column("hold_tickets", "reservation_id")
    op.drop_column("hold_tickets", "requester_id")
    op.drop_column("hold_tickets", "amount_usd")
    op.drop_column("hold_tickets", "wallet")
    op.drop_column("hold_tickets", "chain")
    op.drop_column("hold_tickets", "raw_tx")
