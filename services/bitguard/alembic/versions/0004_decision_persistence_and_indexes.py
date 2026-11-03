"""Decision persistence, timings, and query indexes (Milestone S13).

Revision ID: 0004_decision_persistence_and_indexes
Revises: 0003_modes_and_metrics
Create Date: 2026-11-03 21:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_decision_persistence_and_indexes"
down_revision: str | None = "0003_modes_and_metrics"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add timings, wallet, chain columns and indexes for verdict and time on decisions table."""
    # Add columns to decisions table
    op.add_column("decisions", sa.Column("timings", sa.JSON(), server_default="{}", nullable=False))
    op.add_column("decisions", sa.Column("wallet", sa.String(length=64), nullable=True))
    op.add_column("decisions", sa.Column("chain", sa.String(length=64), nullable=True))

    # Add indexes for efficient filtering and cursor pagination
    op.create_index("ix_decisions_verdict", "decisions", ["verdict"])
    op.create_index("ix_decisions_created_at", "decisions", ["created_at"])
    op.create_index("ix_decisions_wallet", "decisions", ["wallet"])
    op.create_index("ix_decisions_chain", "decisions", ["chain"])


def downgrade() -> None:
    """Drop added indexes and columns from decisions table."""
    op.drop_index("ix_decisions_chain", table_name="decisions")
    op.drop_index("ix_decisions_wallet", table_name="decisions")
    op.drop_index("ix_decisions_created_at", table_name="decisions")
    op.drop_index("ix_decisions_verdict", table_name="decisions")

    op.drop_column("decisions", "chain")
    op.drop_column("decisions", "wallet")
    op.drop_column("decisions", "timings")
