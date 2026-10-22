"""Harden digest rows, add recoverable delivery, and backfill client activity.

Revision ID: 7d1c4a9e2b31
Revises: e5f6a7b8c9d0
Create Date: 2026-10-22

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "7d1c4a9e2b31"
down_revision: Union[str, None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The OAuth cutover deletes every legacy row, so no null plaintext-era
    # placeholder can survive into digest-only storage.
    op.alter_column(
        "oauth2token",
        "access_token",
        existing_type=sa.String(length=64),
        nullable=False,
    )
    op.add_column(
        "oauth2token",
        sa.Column(
            "credential_delivery_pending",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    op.add_column(
        "oauth2token",
        sa.Column("credential_delivery_path", sa.Text(), nullable=True),
    )
    op.create_check_constraint(
        "ck_oauth2token_delivery_state",
        "oauth2token",
        (
            "(credential_delivery_pending AND credential_delivery_path IS NOT NULL) "
            "OR (NOT credential_delivery_pending AND credential_delivery_path IS NULL)"
        ),
    )
    op.execute(
        """
        UPDATE oauth2client AS client
        SET last_activity = CASE
            WHEN last_activity IS NULL
                 OR last_activity < (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
                THEN (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
            ELSE last_activity
        END
        WHERE EXISTS (
            SELECT 1
            FROM oauth2token AS token
            WHERE token.client_id = client.id
              AND token.access_token IS NOT NULL
              AND BTRIM(token.access_token) <> ''
              AND COALESCE(token.access_token_revoked_at, 0) = 0
              AND token.issued_at + token.expires_in > EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
        )
        """
    )


def downgrade() -> None:
    # A pending digest has never reached its one-time explicit output. It
    # cannot be represented safely after removing delivery state.
    op.execute(
        sa.text(
            "DELETE FROM oauth2token WHERE credential_delivery_pending = true"
        )
    )
    op.alter_column(
        "oauth2token",
        "access_token",
        existing_type=sa.String(length=64),
        nullable=True,
    )
    op.drop_constraint(
        "ck_oauth2token_delivery_state", "oauth2token", type_="check"
    )
    op.drop_column("oauth2token", "credential_delivery_path")
    op.drop_column("oauth2token", "credential_delivery_pending")
    # The activity backfill is intentionally retained because older activity
    # values cannot be reconstructed safely.
