"""Add one-time account action tokens.

Revision ID: b8f2a6d41c73
Revises: 7f6e5d4c3b2a
Create Date: 2026-10-22

The cutover intentionally invalidates every legacy password-reset action.
Rollback recreates the bounded parent's digest-free delivery identity table
empty because old actions cannot be migrated safely.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b8f2a6d41c73"
down_revision: Union[str, None] = "7f6e5d4c3b2a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "account_action_token",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("delivery_id", sa.String(length=36), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("target_email", sa.String(length=255), nullable=True),
        sa.Column("state_digest", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('password_reset', 'verify_registration', 'change_email')",
            name="ck_account_action_token_purpose",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id", "purpose", name="uq_account_action_token_user_purpose"
        ),
        sa.UniqueConstraint(
            "delivery_id", name="uq_account_action_token_delivery_id"
        ),
    )
    op.create_index(
        "ix_account_action_token_token_digest",
        "account_action_token",
        ["token_digest"],
        unique=True,
    )


    op.drop_table("password_change_request")


def downgrade() -> None:
    op.create_table(
        "password_change_request",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("delivery_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "delivery_id", name="uq_password_change_request_delivery_id"
        ),
    )


    op.drop_index(
        "ix_account_action_token_token_digest",
        table_name="account_action_token",
    )
    op.drop_table("account_action_token")
