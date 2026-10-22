"""Harden OAuth bearer issuance and invalidate legacy credentials.

Revision ID: e5f6a7b8c9d0
Revises: d4c3b2a1908f
Create Date: 2026-10-22

Every legacy access/refresh token and client secret is intentionally destroyed.
Downgrade changes the schema only; it never recreates or fabricates secrets.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4c3b2a1908f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Plaintext bearer values cannot be transformed safely without possessing
    # the raw value at the point of issuance. Invalidate all of them.
    op.execute(sa.text("DELETE FROM oauth2token"))
    # Legacy anonymous clients have no browser-binding proof and must not be
    # claimable. Cover both the historical default owner and metadata marker.
    op.execute(
        sa.text(
            "DELETE FROM oauth2client WHERE user_id IN "
            "(SELECT fs_uniquifier FROM \"user\" WHERE email = 'anonymous@ads') "
            "OR client_metadata LIKE '%Anonymous client%'"
        )
    )
    # Existing per-route dictionaries may contain regular expressions. They
    # are cleared rather than reinterpreted as exact endpoint identifiers.
    op.execute(
        sa.text("UPDATE oauth2client SET individual_ratelimit_multipliers = NULL")
    )
    op.execute(sa.text("DELETE FROM oauth2client WHERE user_id IS NULL"))

    with op.batch_alter_table("oauth2client") as batch_op:
        batch_op.drop_column("client_secret")
        batch_op.drop_column("client_secret_expires_at")
        batch_op.add_column(
            sa.Column(
                "credential_purpose",
                sa.String(length=16),
                nullable=False,
                server_default="browser",
            )
        )
        batch_op.add_column(sa.Column("binding_digest", sa.String(length=64)))
        batch_op.alter_column("user_id", existing_type=sa.String(), nullable=False)
        batch_op.alter_column(
            "ratelimit_multiplier",
            existing_type=sa.Float(),
            nullable=False,
            server_default="1.0",
        )
        batch_op.create_check_constraint(
            "ck_oauth2client_credential_purpose",
            "credential_purpose IN ('anonymous', 'browser', 'personal', 'operator')",
        )
        batch_op.create_check_constraint(
            "ck_oauth2client_anonymous_binding",
            "(credential_purpose = 'anonymous' AND binding_digest IS NOT NULL) "
            "OR (credential_purpose <> 'anonymous' AND binding_digest IS NULL)",
        )
        batch_op.create_index(
            "ix_oauth2client_binding_digest", ["binding_digest"], unique=False
        )

    op.create_index(
        "uq_oauth2client_active_personal_owner",
        "oauth2client",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("credential_purpose = 'personal'"),
        sqlite_where=sa.text("credential_purpose = 'personal'"),
    )

    with op.batch_alter_table("oauth2token") as batch_op:
        batch_op.drop_index("ix_oauth2token_access_token")
        batch_op.drop_column("refresh_token")
        batch_op.drop_column("refresh_token_revoked_at")
        batch_op.add_column(sa.Column("token_key_id", sa.String(length=64)))
        batch_op.add_column(
            sa.Column(
                "token_digest_version",
                sa.SmallInteger(),
                nullable=False,
                server_default="1",
            )
        )
        batch_op.add_column(
            sa.Column(
                "credential_purpose",
                sa.String(length=16),
                nullable=False,
                server_default="browser",
            )
        )
        batch_op.alter_column(
            "access_token", existing_type=sa.String(length=255), type_=sa.String(64)
        )
        batch_op.alter_column("user_id", existing_type=sa.String(), nullable=False)
        batch_op.alter_column("client_id", existing_type=sa.Integer(), nullable=False)
        batch_op.create_check_constraint(
            "ck_oauth2token_credential_purpose",
            "credential_purpose IN ('anonymous', 'browser', 'personal', 'operator')",
        )
        batch_op.create_check_constraint(
            "ck_oauth2token_digest_version", "token_digest_version = 1"
        )
        batch_op.create_unique_constraint(
            "uq_oauth2token_key_digest", ["token_key_id", "access_token"]
        )

    # No rows remain, so making key IDs mandatory cannot preserve unsafe state.
    with op.batch_alter_table("oauth2token") as batch_op:
        batch_op.alter_column(
            "token_key_id", existing_type=sa.String(length=64), nullable=False
        )


def downgrade() -> None:
    # Digest records cannot become legacy plaintext bearer credentials.
    op.execute(sa.text("DELETE FROM oauth2token"))
    # Restore only nullable, empty schema compatibility columns needed by the
    # parent revision's own downgrade. No credential value is reconstructed.
    with op.batch_alter_table("oauth2token") as batch_op:
        batch_op.drop_constraint("uq_oauth2token_key_digest", type_="unique")
        batch_op.drop_constraint("ck_oauth2token_digest_version", type_="check")
        batch_op.drop_constraint("ck_oauth2token_credential_purpose", type_="check")
        batch_op.alter_column(
            "access_token", existing_type=sa.String(length=64), type_=sa.String(255)
        )
        batch_op.drop_column("credential_purpose")
        batch_op.drop_column("token_digest_version")
        batch_op.drop_column("token_key_id")
        batch_op.create_index("ix_oauth2token_access_token", ["access_token"], unique=True)
        batch_op.add_column(
            sa.Column("refresh_token", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("refresh_token_revoked_at", sa.Integer(), nullable=True)
        )
        batch_op.alter_column("user_id", existing_type=sa.String(), nullable=True)
        batch_op.alter_column("client_id", existing_type=sa.Integer(), nullable=True)

    op.drop_index(
        "uq_oauth2client_active_personal_owner", table_name="oauth2client"
    )
    with op.batch_alter_table("oauth2client") as batch_op:
        batch_op.drop_index("ix_oauth2client_binding_digest")
        batch_op.drop_constraint("ck_oauth2client_anonymous_binding", type_="check")
        batch_op.drop_constraint("ck_oauth2client_credential_purpose", type_="check")
        batch_op.drop_column("binding_digest")
        batch_op.drop_column("credential_purpose")
        batch_op.add_column(
            sa.Column("client_secret", sa.String(length=120), nullable=True)
        )
        batch_op.add_column(
            sa.Column("client_secret_expires_at", sa.Integer(), nullable=True)
        )
        batch_op.alter_column("user_id", existing_type=sa.String(), nullable=True)
        batch_op.alter_column(
            "ratelimit_multiplier", existing_type=sa.Float(), nullable=True
        )
