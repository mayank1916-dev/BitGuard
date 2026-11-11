"""Add caller identity and build attestation columns to decisions table (Milestone S33 / F16).

Revision ID: 0012_caller_identity_fields
Revises: 0011_backtest_reports
Create Date: 2026-11-11 15:55:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012_caller_identity_fields"
down_revision: str | None = "0011_backtest_reports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Adds caller_identity, caller_image_digest, caller_deploy_time, caller_source_ip columns."""
    op.add_column("decisions", sa.Column("caller_identity", sa.String(length=256), nullable=True))
    op.add_column("decisions", sa.Column("caller_image_digest", sa.String(length=128), nullable=True))
    op.add_column("decisions", sa.Column("caller_deploy_time", sa.DateTime(timezone=True), nullable=True))
    op.add_column("decisions", sa.Column("caller_source_ip", sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Removes caller identity columns from decisions."""
    op.drop_column("decisions", "caller_source_ip")
    op.drop_column("decisions", "caller_deploy_time")
    op.drop_column("decisions", "caller_image_digest")
    op.drop_column("decisions", "caller_identity")
