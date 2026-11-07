"""Backtest reports table for historical and synthetic policy evaluation (Milestone S22 / F8).

Revision ID: 0011_backtest_reports
Revises: 0010_policy_versions_expansion
Create Date: 2026-11-07 23:50:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011_backtest_reports"
down_revision: str | None = "0010_policy_versions_expansion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Creates the backtest_reports table."""
    op.create_table(
        "backtest_reports",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("draft_policy_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("draft_policy_hash", sa.String(length=64), nullable=False, index=True),
        sa.Column("baseline_policy_id", sa.String(length=64), nullable=True),
        sa.Column("baseline_policy_hash", sa.String(length=64), nullable=True),
        sa.Column("total_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("real_events_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("synthetic_events_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("allowed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("held_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("denied_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("holds_per_day", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("estimated_false_positives", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("synthetic_loss_prevented_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("synthetic_loss_allowed_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("policy_diff", sa.JSON(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    """Drops the backtest_reports table."""
    op.drop_table("backtest_reports")
