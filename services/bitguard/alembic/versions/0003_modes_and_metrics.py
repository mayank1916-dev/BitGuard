"""Wallet group modes, shadow counters, and false-positive tracking (Milestone S04).

Revision ID: 0003_modes_and_metrics
Revises: 0002_canonical_schema
Create Date: 2026-11-03 16:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_modes_and_metrics"
down_revision: str | None = "0002_canonical_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add would_have_verdict and metrics columns to decisions, create wallet_groups and daily_group_metrics."""
    # Add columns to decisions table
    op.add_column("decisions", sa.Column("would_have_verdict", sa.String(length=16), nullable=True))
    op.add_column(
        "decisions",
        sa.Column("wallet_group", sa.String(length=64), server_default="default", nullable=False),
    )
    op.add_column(
        "decisions",
        sa.Column("is_false_positive", sa.Boolean(), server_default=sa.false(), nullable=False),
    )

    # Create wallet_groups table
    op.create_table(
        "wallet_groups",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("mode", sa.String(length=32), server_default="SIMULATION", nullable=False),
        sa.Column("wallets", sa.JSON(), nullable=False),
        sa.Column("shadow_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enforce_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("unexplained_decode_failures", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Create daily_group_metrics table
    op.create_table(
        "daily_group_metrics",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("wallet_group", sa.String(length=64), nullable=False, index=True),
        sa.Column("date", sa.String(length=16), nullable=False, index=True),
        sa.Column("would_have_blocked_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("would_have_blocked_value", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("allowed_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("false_positive_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    """Drop tables and columns added in upgrade."""
    op.drop_table("daily_group_metrics")
    op.drop_table("wallet_groups")
    op.drop_column("decisions", "is_false_positive")
    op.drop_column("decisions", "wallet_group")
    op.drop_column("decisions", "would_have_verdict")
