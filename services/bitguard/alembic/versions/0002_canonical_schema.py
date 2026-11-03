"""Canonical BitGuard schema migration for core entities.

Revision ID: 0002_canonical_schema
Revises: 0001_initial_empty
Create Date: 2026-11-03 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_canonical_schema"
down_revision: str | None = "0001_initial_empty"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create canonical tables for decisions, hold tickets, approvals, policy, audit, watched addresses and breaker."""
    op.create_table(
        "decisions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("request_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("data_label", sa.String(length=16), nullable=False),
        sa.Column("evaluation_latency_ms", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "hold_tickets",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("request_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("tx_digest", sa.String(length=128), nullable=False, index=True),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "approvals",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("hold_ticket_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("approver_id", sa.String(length=128), nullable=False),
        sa.Column("tx_digest", sa.String(length=128), nullable=False),
        sa.Column("webauthn_signature", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "policy_versions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("version", sa.String(length=64), nullable=False, unique=True),
        sa.Column("author", sa.String(length=128), nullable=False),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

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

    op.create_table(
        "watched_addresses",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("address", sa.String(length=128), nullable=False, index=True),
        sa.Column("chain", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("expected_code_hash", sa.String(length=128), nullable=True),
        sa.Column("allowed_delegates", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "breaker_state",
        sa.Column("id", sa.Integer(), primary_key=True, default=1),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("data_label", sa.String(length=16), nullable=False, server_default="REAL"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    """Drop canonical tables in reverse order."""
    op.drop_table("breaker_state")
    op.drop_table("watched_addresses")
    op.drop_table("audit_entries")
    op.drop_table("policy_versions")
    op.drop_table("approvals")
    op.drop_table("hold_tickets")
    op.drop_table("decisions")
