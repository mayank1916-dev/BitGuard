"""Audit chain v2 schema and object-lock anchoring (Milestone S21 / F18).

Revision ID: 0008_audit_chain_v2
Revises: 0007_breaker_expansion
Create Date: 2026-11-04 00:30:00.000000

Invariants:
- Invariant #7: Immutable Audit Trail. Revoke UPDATE and DELETE for application roles.
- Invariant #8: Explicit Data Provenance. All audit records store data_label.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008_audit_chain_v2"
down_revision: str | None = "0007_breaker_expansion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Migrate audit_entries to canonical seq, ts, actor, action, payload schema and create audit_anchors."""
    # Recreate audit_entries with canonical S21 schema
    op.drop_table("audit_entries")
    op.create_table(
        "audit_entries",
        sa.Column("seq", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("ts", sa.Float(), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False, server_default="system"),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("prev_hash", sa.String(length=128), nullable=False),
        sa.Column("entry_hash", sa.String(length=128), nullable=False),
        sa.Column("data_label", sa.String(length=16), nullable=False, server_default="REAL"),
    )

    op.create_table(
        "audit_anchors",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("seq", sa.BigInteger(), nullable=False, index=True),
        sa.Column("head_hash", sa.String(length=128), nullable=False),
        sa.Column("ts", sa.Float(), nullable=False),
        sa.Column("storage_uri", sa.String(length=512), nullable=False),
        sa.Column("data_label", sa.String(length=16), nullable=False, server_default="REAL"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Invariant #7: Revoke UPDATE and DELETE on PostgreSQL
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("REVOKE UPDATE, DELETE ON audit_entries FROM PUBLIC;")
        op.execute("REVOKE UPDATE, DELETE ON audit_anchors FROM PUBLIC;")


def downgrade() -> None:
    """Downgrade audit_anchors and restore audit_entries v1."""
    op.drop_table("audit_anchors")
    op.drop_table("audit_entries")
    op.create_table(
        "audit_entries",
        sa.Column("index", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.Float(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("prev_hash", sa.String(length=128), nullable=False),
        sa.Column("entry_hash", sa.String(length=128), nullable=False),
        sa.Column("data_label", sa.String(length=16), nullable=False),
    )
