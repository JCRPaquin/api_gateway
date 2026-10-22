"""Add durable notification outbox.

Revision ID: 4a1b2c3d4e5f
Revises: f2f57cb2a5b0
Create Date: 2026-10-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "4a1b2c3d4e5f"
down_revision: Union[str, None] = "f2f57cb2a5b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("dedupe_key", sa.String(length=320), nullable=True),
        sa.Column("last_error", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key"),
    )
    op.create_index(
        op.f("ix_notification_outbox_state"), "notification_outbox", ["state"], unique=False
    )
    op.create_index(
        op.f("ix_notification_outbox_available_at"),
        "notification_outbox",
        ["available_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_notification_outbox_available_at"), table_name="notification_outbox")
    op.drop_index(op.f("ix_notification_outbox_state"), table_name="notification_outbox")
    op.drop_table("notification_outbox")
