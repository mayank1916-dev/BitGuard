"""Breaker state expansion and de-escalation tickets (Milestone S18 / F9, F14).

Revision ID: 0007_breaker_expansion
Revises: 0006_watched_addresses_expansion
Create Date: 2026-11-03 23:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_breaker_expansion"
down_revision: str | None = "0006_watched_addresses_expansion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add updated_by and token_epoch to breaker_state, create breaker_deescalations table."""
    op.add_column("breaker_state", sa.Column("updated_by", sa.String(length=64), nullable=False, server_default="system"))
    op.add_column("breaker_state", sa.Column("token_epoch", sa.Integer(), nullable=False, server_default="1"))

    op.create_table(
        "breaker_deescalations",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("current_state", sa.String(length=32), nullable=False),
        sa.Column("target_state", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("challenge", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("approvals_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Drop breaker_deescalations table, remove updated_by and token_epoch columns."""
    op.drop_table("breaker_deescalations")
    with op.batch_alter_table("breaker_state") as batch_op:
        batch_op.drop_column("token_epoch")
        batch_op.drop_column("updated_by")
