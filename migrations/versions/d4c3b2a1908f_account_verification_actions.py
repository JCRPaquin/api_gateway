"""Cut over verification and email changes to account actions.

Revision ID: d4c3b2a1908f
Revises: b8f2a6d41c73
Create Date: 2026-10-22

Dropping ``email_change_request`` intentionally invalidates every email-change
link issued by the legacy generic-token workflow. Downgrade recreates the table
empty because those bearer credentials cannot be restored safely.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d4c3b2a1908f"
down_revision: Union[str, None] = "b8f2a6d41c73"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    null_target = bind.execute(
        sa.text(
            "SELECT id FROM account_action_token "
            "WHERE target_email IS NULL LIMIT 1"
        )
    ).first()
    if null_target is not None:
        raise RuntimeError(
            "Account-action rows without target email must be removed before upgrade"
        )
    with op.batch_alter_table("account_action_token") as batch_op:
        batch_op.alter_column(
            "target_email",
            existing_type=sa.String(length=255),
            nullable=False,
        )
    op.drop_table("email_change_request")


def downgrade() -> None:
    op.create_table(
        "email_change_request",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("token", sa.String(length=255), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("new_email", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token"),
    )
    with op.batch_alter_table("account_action_token") as batch_op:
        batch_op.alter_column(
            "target_email",
            existing_type=sa.String(length=255),
            nullable=True,
        )
