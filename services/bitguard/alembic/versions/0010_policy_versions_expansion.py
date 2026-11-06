"""Policy versions schema expansion for versioned policy governance (Milestone S20 / Section D).

Revision ID: 0010_policy_versions_expansion
Revises: 0009_quarantine_hold_tickets_expansion
Create Date: 2026-11-07 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010_policy_versions_expansion"
down_revision: str | None = "0009_quarantine_hold_tickets_expansion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Expands policy_versions table with content, hash, signatures, approvals, and governance columns."""
    op.add_column("policy_versions", sa.Column("content", sa.JSON(), nullable=True))
    op.add_column(
        "policy_versions",
        sa.Column("content_hash", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "policy_versions",
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
    )
    op.add_column(
        "policy_versions",
        sa.Column("change_type", sa.String(length=32), nullable=False, server_default="TIGHTEN"),
    )
    op.add_column("policy_versions", sa.Column("ed25519_signature", sa.Text(), nullable=True))
    op.add_column("policy_versions", sa.Column("signatures", sa.JSON(), nullable=True))
    op.add_column("policy_versions", sa.Column("approvals", sa.JSON(), nullable=True))
    op.add_column("policy_versions", sa.Column("backtest_report_id", sa.String(length=64), nullable=True))
    op.add_column("policy_versions", sa.Column("cool_down_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("policy_versions", sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("policy_versions", sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("policy_versions", sa.Column("rollback_reason", sa.Text(), nullable=True))

    # Backfill content from rules if present
    conn = op.get_bind()
    conn.execute(sa.text("UPDATE policy_versions SET content = rules WHERE content IS NULL"))
    conn.execute(sa.text("UPDATE policy_versions SET status = 'ACTIVE' WHERE is_active = 1"))


def downgrade() -> None:
    """Removes added governance columns from policy_versions."""
    op.drop_column("policy_versions", "rollback_reason")
    op.drop_column("policy_versions", "rolled_back_at")
    op.drop_column("policy_versions", "activated_at")
    op.drop_column("policy_versions", "cool_down_until")
    op.drop_column("policy_versions", "backtest_report_id")
    op.drop_column("policy_versions", "approvals")
    op.drop_column("policy_versions", "signatures")
    op.drop_column("policy_versions", "ed25519_signature")
    op.drop_column("policy_versions", "change_type")
    op.drop_column("policy_versions", "status")
    op.drop_column("policy_versions", "content_hash")
    op.drop_column("policy_versions", "content")
