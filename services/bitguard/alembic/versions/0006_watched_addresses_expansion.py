"""Watched addresses expansion (Milestone S17 / F6).

Revision ID: 0006_watched_addresses_expansion
Revises: 0005_hold_tickets_and_approvals
Create Date: 2026-11-03 22:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_watched_addresses_expansion"
down_revision: str | None = "0005_hold_tickets_and_approvals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add last_known_nonce, signed_count, last_scanned_block, status, data_label to watched_addresses table."""
    op.add_column("watched_addresses", sa.Column("last_known_nonce", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("watched_addresses", sa.Column("signed_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("watched_addresses", sa.Column("last_scanned_block", sa.Integer(), nullable=True))
    op.add_column("watched_addresses", sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"))
    op.add_column("watched_addresses", sa.Column("data_label", sa.String(length=16), nullable=False, server_default="REAL"))


def downgrade() -> None:
    """Drop added columns from watched_addresses table."""
    op.drop_column("watched_addresses", "data_label")
    op.drop_column("watched_addresses", "status")
    op.drop_column("watched_addresses", "last_scanned_block")
    op.drop_column("watched_addresses", "signed_count")
    op.drop_column("watched_addresses", "last_known_nonce")
