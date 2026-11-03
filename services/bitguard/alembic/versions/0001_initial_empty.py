"""Initial empty migration baseline.

Revision ID: 0001_initial_empty
Revises:
Create Date: 2026-11-03 12:00:00.000000

"""
from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "0001_initial_empty"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Empty baseline migration."""
    pass


def downgrade() -> None:
    """Empty baseline downgrade."""
    pass
