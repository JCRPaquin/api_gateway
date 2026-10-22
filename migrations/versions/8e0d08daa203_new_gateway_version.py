"""New gateway version

Revision ID: 8e0d08daa203
Revises: 137ee54fd373
Create Date: 2024-01-25 11:36:56.081089

"""
import datetime
import json
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision: str = "8e0d08daa203"
down_revision: Union[str, None] = "137ee54fd373"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DIAGNOSTIC_ID_LIMIT = 5


def _reject_nonstandard_json_constant(_value):
    raise ValueError("non-standard JSON constant")


def _contains_unrepresentable_postgresql_text(value):
    if isinstance(value, str):
        if "\x00" in value:
            return True
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return True
        return False
    if isinstance(value, dict):
        return any(
            _contains_unrepresentable_postgresql_text(key)
            or _contains_unrepresentable_postgresql_text(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_unrepresentable_postgresql_text(item) for item in value)
    return False


def _count_rows(connection, table_name):
    return connection.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()


def _reject_rows(connection, description, count_query, id_query=None):
    invalid_count = connection.execute(text(count_query)).scalar()
    if not invalid_count:
        return

    detail = ""
    if id_query:
        row_ids = [
            row[0]
            for row in connection.execute(
                text(f"{id_query} LIMIT {DIAGNOSTIC_ID_LIMIT}")
            )
        ]
        detail = f"; sample row ids: {row_ids}"
    raise RuntimeError(f"Migration preflight rejected {invalid_count} {description}{detail}")


def _upgrade_preflight(connection):
    source_counts = {
        "clients": _count_rows(connection, "oauth2client"),
        "tokens": _count_rows(connection, "oauth2token"),
    }

    _reject_rows(
        connection,
        "legacy token rows with invalid required values",
        """
        SELECT COUNT(*)
        FROM oauth2token
        WHERE access_token IS NULL
           OR expires IS NULL
           OR NOT isfinite(expires)
           OR client_id IS NULL
           OR LENGTH(token_type) > 40
        """,
        """
        SELECT id
        FROM oauth2token
        WHERE access_token IS NULL
           OR expires IS NULL
           OR client_id IS NULL
           OR NOT isfinite(expires)
           OR LENGTH(token_type) > 40
        ORDER BY id
        """,
    )
    _reject_rows(
        connection,
        "legacy client rows with invalid required values",
        """
        SELECT COUNT(*)
        FROM oauth2client
        WHERE client_id IS NULL
           OR client_secret IS NULL
           OR LENGTH(client_id) > 48
           OR LENGTH(client_secret) > 120
           OR name IS NULL
           OR BTRIM(name) = ''
           OR LENGTH(name) > 255
        """,
    )
    _reject_rows(
        connection,
        "legacy role association rows with null required values",
        """
        SELECT COUNT(*)
        FROM roles_users
        WHERE user_id IS NULL OR role_id IS NULL
        """,
    )
    _reject_rows(
        connection,
        "legacy client rows whose user relationship cannot be mapped",
        """
        SELECT COUNT(*)
        FROM oauth2client AS client
        WHERE client.user_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM users WHERE users.id = client.user_id)
        """,
    )
    _reject_rows(
        connection,
        "legacy token rows whose client relationship cannot be mapped",
        """
        SELECT COUNT(*)
        FROM oauth2token AS token
        WHERE NOT EXISTS (
            SELECT 1 FROM oauth2client AS client
            WHERE client.client_id = token.client_id
        )
        """,
        """
        SELECT token.id
        FROM oauth2token AS token
        WHERE NOT EXISTS (
            SELECT 1 FROM oauth2client AS client
            WHERE client.client_id = token.client_id
        )
        ORDER BY token.id
        """,
    )
    _reject_rows(
        connection,
        "legacy token rows whose user relationship cannot be mapped",
        """
        SELECT COUNT(*)
        FROM oauth2token AS token
        WHERE token.user_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM users WHERE users.id = token.user_id)
        """,
        """
        SELECT token.id
        FROM oauth2token AS token
        WHERE token.user_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM users WHERE users.id = token.user_id)
        ORDER BY token.id
        """,
    )
    return source_counts


def _validate_upgrade_copy(connection, source_counts):
    destination_counts = {
        "clients": _count_rows(connection, "oauth2client"),
        "tokens": _count_rows(connection, "oauth2token"),
    }
    if source_counts != destination_counts:
        raise RuntimeError(
            "Migration copy count mismatch: "
            f"source={source_counts}, destination={destination_counts}"
        )

    _reject_rows(
        connection,
        "copied client rows with missing required values or incorrect user relationships",
        """
        SELECT COUNT(*)
        FROM oauth2client_old AS source
        LEFT JOIN oauth2client AS destination
          ON destination.client_id = source.client_id
        LEFT JOIN users ON users.id = source.user_id
        WHERE destination.id IS NULL
           OR destination.client_secret IS NULL
           OR destination.client_metadata IS NULL
           OR destination.user_id IS DISTINCT FROM users.fs_uniquifier
        """,
    )
    _reject_rows(
        connection,
        "copied token rows with missing values or incorrect relationships",
        """
        SELECT COUNT(*)
        FROM oauth2token_old AS source
        LEFT JOIN oauth2token AS destination
          ON destination.access_token = source.access_token
        LEFT JOIN users ON users.id = source.user_id
        LEFT JOIN oauth2client ON oauth2client.client_id = source.client_id
        WHERE destination.id IS NULL
           OR destination.access_token IS NULL
           OR destination.issued_at IS NULL
           OR destination.expires_in IS NULL
           OR destination.access_token_revoked_at IS NULL
           OR destination.refresh_token_revoked_at IS NULL
           OR destination.user_id IS DISTINCT FROM users.fs_uniquifier
           OR destination.client_id IS DISTINCT FROM oauth2client.id
           OR destination.issued_at + destination.expires_in
              IS DISTINCT FROM FLOOR(EXTRACT(EPOCH FROM source.expires))::bigint
        """,
        """
        SELECT source.id
        FROM oauth2token_old AS source
        LEFT JOIN oauth2token AS destination
          ON destination.access_token = source.access_token
        LEFT JOIN users ON users.id = source.user_id
        LEFT JOIN oauth2client ON oauth2client.client_id = source.client_id
        WHERE destination.id IS NULL
           OR destination.access_token IS NULL
           OR destination.issued_at IS NULL
           OR destination.expires_in IS NULL
           OR destination.access_token_revoked_at IS NULL
           OR destination.refresh_token_revoked_at IS NULL
           OR destination.user_id IS DISTINCT FROM users.fs_uniquifier
           OR destination.client_id IS DISTINCT FROM oauth2client.id
           OR destination.issued_at + destination.expires_in
              IS DISTINCT FROM FLOOR(EXTRACT(EPOCH FROM source.expires))::bigint
        ORDER BY source.id
        """,
    )


def _validate_client_metadata(connection):
    invalid_count = 0
    invalid_ids = []
    rows = connection.execute(
        text("SELECT id, client_metadata FROM oauth2client ORDER BY id")
    )
    for row_id, serialized_metadata in rows:
        valid = True
        try:
            metadata = json.loads(
                serialized_metadata,
                parse_constant=_reject_nonstandard_json_constant,
            )
        except (TypeError, ValueError, RecursionError):
            valid = False
            metadata = {}

        if not isinstance(metadata, dict):
            valid = False
            metadata = {}
        if _contains_unrepresentable_postgresql_text(metadata):
            valid = False

        client_name = metadata.get("client_name")
        if (
            not isinstance(client_name, str)
            or not client_name.strip()
            or len(client_name) > 255
        ):
            valid = False

        website = metadata.get("website")
        if website is not None and (not isinstance(website, str) or len(website) > 255):
            valid = False

        for field in ("is_confidential", "is_internal"):
            value = metadata.get(field)
            if value is not None and not (
                isinstance(value, bool) or value in ("true", "false")
            ):
                valid = False

        created = metadata.get("created")
        if created is not None:
            if not isinstance(created, str) or not created:
                valid = False
            else:
                try:
                    datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
                except ValueError:
                    valid = False

        if not valid:
            invalid_count += 1
            if len(invalid_ids) < DIAGNOSTIC_ID_LIMIT:
                invalid_ids.append(row_id)

    if invalid_count:
        raise RuntimeError(
            "Migration preflight rejected "
            f"{invalid_count} client rows with invalid compatibility metadata; "
            f"sample row ids: {invalid_ids}"
        )


def _downgrade_preflight(connection):
    source_counts = {
        "clients": _count_rows(connection, "oauth2client"),
        "tokens": _count_rows(connection, "oauth2token"),
    }

    _reject_rows(
        connection,
        "client rows with null or overlong legacy credentials",
        """
        SELECT COUNT(*)
        FROM oauth2client
        WHERE client_id IS NULL
           OR client_secret IS NULL
           OR LENGTH(client_id) > 255
           OR LENGTH(client_secret) > 255
        """,
        """
        SELECT id
        FROM oauth2client
        WHERE client_id IS NULL
           OR client_secret IS NULL
           OR LENGTH(client_id) > 255
           OR LENGTH(client_secret) > 255
        ORDER BY id
        """,
    )
    _reject_rows(
        connection,
        "client rows with duplicate legacy client ids",
        """
        SELECT COUNT(*)
        FROM oauth2client AS client
        WHERE client.client_id IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM oauth2client AS duplicate
              WHERE duplicate.client_id = client.client_id
                AND duplicate.id <> client.id
          )
        """,
        """
        SELECT client.id
        FROM oauth2client AS client
        WHERE client.client_id IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM oauth2client AS duplicate
              WHERE duplicate.client_id = client.client_id
                AND duplicate.id <> client.id
          )
        ORDER BY client.id
        """,
    )
    _validate_client_metadata(connection)
    _reject_rows(
        connection,
        "client rows whose user relationship cannot be mapped",
        """
        SELECT COUNT(*)
        FROM oauth2client AS client
        WHERE client.user_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM users WHERE users.fs_uniquifier = client.user_id
          )
        """,
        """
        SELECT client.id
        FROM oauth2client AS client
        WHERE client.user_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM users WHERE users.fs_uniquifier = client.user_id
          )
        ORDER BY client.id
        """,
    )
    _reject_rows(
        connection,
        "token rows with null required values or unrepresentable expiration",
        """
        SELECT COUNT(*)
        FROM oauth2token
        WHERE access_token IS NULL
           OR issued_at IS NULL
           OR expires_in IS NULL
           OR issued_at::numeric + expires_in::numeric
              NOT BETWEEN -210866803200 AND 9224318015999
        """,
        """
        SELECT id
        FROM oauth2token
        WHERE access_token IS NULL
           OR issued_at IS NULL
           OR expires_in IS NULL
           OR issued_at::numeric + expires_in::numeric
              NOT BETWEEN -210866803200 AND 9224318015999
        ORDER BY id
        """,
    )
    _reject_rows(
        connection,
        "token rows with duplicate non-null refresh tokens",
        """
        SELECT COUNT(*)
        FROM oauth2token AS token
        WHERE token.refresh_token IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM oauth2token AS duplicate
              WHERE duplicate.refresh_token = token.refresh_token
                AND duplicate.id <> token.id
          )
        """,
        """
        SELECT token.id
        FROM oauth2token AS token
        WHERE token.refresh_token IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM oauth2token AS duplicate
              WHERE duplicate.refresh_token = token.refresh_token
                AND duplicate.id <> token.id
          )
        ORDER BY token.id
        """,
    )
    _reject_rows(
        connection,
        "token rows whose client relationship cannot be mapped",
        """
        SELECT COUNT(*)
        FROM oauth2token AS token
        WHERE token.client_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM oauth2client AS client
              WHERE client.id = token.client_id
          )
        """,
        """
        SELECT token.id
        FROM oauth2token AS token
        WHERE token.client_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM oauth2client AS client
              WHERE client.id = token.client_id
          )
        ORDER BY token.id
        """,
    )
    _reject_rows(
        connection,
        "token rows whose user relationship cannot be mapped",
        """
        SELECT COUNT(*)
        FROM oauth2token AS token
        WHERE token.user_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM users WHERE users.fs_uniquifier = token.user_id
          )
        """,
        """
        SELECT token.id
        FROM oauth2token AS token
        WHERE token.user_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM users WHERE users.fs_uniquifier = token.user_id
          )
        ORDER BY token.id
        """,
    )
    return source_counts


def _validate_downgrade_copy(connection, source_counts):
    destination_counts = {
        "clients": _count_rows(connection, "oauth2client_old"),
        "tokens": _count_rows(connection, "oauth2token_old"),
    }
    if source_counts != destination_counts:
        raise RuntimeError(
            "Migration copy count mismatch: "
            f"source={source_counts}, destination={destination_counts}"
        )

    _reject_rows(
        connection,
        "copied legacy client rows with missing values or incorrect user relationships",
        """
        SELECT COUNT(*)
        FROM oauth2client AS source
        LEFT JOIN oauth2client_old AS destination
          ON destination.client_id = source.client_id
        LEFT JOIN users ON users.fs_uniquifier = source.user_id
        WHERE destination.client_id IS NULL
           OR destination.name IS NULL
           OR destination.client_secret IS NULL
           OR destination.created IS NULL
           OR destination.user_id IS DISTINCT FROM users.id
        """,
        """
        SELECT source.id
        FROM oauth2client AS source
        LEFT JOIN oauth2client_old AS destination
          ON destination.client_id = source.client_id
        LEFT JOIN users ON users.fs_uniquifier = source.user_id
        WHERE destination.client_id IS NULL
           OR destination.name IS NULL
           OR destination.client_secret IS NULL
           OR destination.created IS NULL
           OR destination.user_id IS DISTINCT FROM users.id
        ORDER BY source.id
        """,
    )
    _reject_rows(
        connection,
        "copied legacy token rows with incorrect relationships or expiration",
        """
        SELECT COUNT(*)
        FROM oauth2token AS source
        LEFT JOIN oauth2token_old AS destination
          ON destination.access_token = source.access_token
        LEFT JOIN oauth2client AS client ON client.id = source.client_id
        LEFT JOIN users ON users.fs_uniquifier = source.user_id
        WHERE destination.id IS NULL
           OR destination.client_id IS DISTINCT FROM client.client_id
           OR destination.user_id IS DISTINCT FROM users.id
           OR EXTRACT(EPOCH FROM destination.expires)::bigint
              IS DISTINCT FROM source.issued_at::bigint + source.expires_in
        """,
        """
        SELECT source.id
        FROM oauth2token AS source
        LEFT JOIN oauth2token_old AS destination
          ON destination.access_token = source.access_token
        LEFT JOIN oauth2client AS client ON client.id = source.client_id
        LEFT JOIN users ON users.fs_uniquifier = source.user_id
        WHERE destination.id IS NULL
           OR destination.client_id IS DISTINCT FROM client.client_id
           OR destination.user_id IS DISTINCT FROM users.id
           OR EXTRACT(EPOCH FROM destination.expires)::bigint
              IS DISTINCT FROM source.issued_at::bigint + source.expires_in
        ORDER BY source.id
        """,
    )


def upgrade() -> None:
    connection = op.get_bind()
    source_counts = _upgrade_preflight(connection)
    migration_epoch = connection.execute(
        text("SELECT FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::bigint")
    ).scalar()

    # email_change_request >>>
    op.create_table(
        "email_change_request",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("token", sa.String(length=255), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("new_email", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token"),
    )

    # <<< email_change_request

    # password_change_request >>>
    op.create_table(
        "password_change_request",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("token", sa.String(length=255), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token"),
    )
    # <<< password_change_request

    # users >>>
    op.alter_column("users", "ratelimit_level", new_column_name="ratelimit_quota")
    op.alter_column("users", "name", new_column_name="given_name")
    op.add_column("users", sa.Column("family_name", sa.String(length=255), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "fs_uniquifier",
            sa.String(length=64),
            nullable=False,
            server_default=text("(gen_random_uuid())"),
        ),
    )

    user_ids = op.get_bind().execute("SELECT id FROM users")

    for user_id in user_ids:
        op.execute(
            f"UPDATE users SET fs_uniquifier = '{uuid.uuid4().hex}' WHERE id = {user_id[0]}"
        )

    op.create_unique_constraint("uq_users_fs_uniquifier", "users", ["fs_uniquifier"])
    op.alter_column("users", "fs_uniquifier", server_default=None)
    # <<< users

    # oauth2client >>>
    op.drop_index("oauth2client_name_key", table_name="oauth2client")
    op.drop_index("oauth2client_user_id_key", table_name="oauth2client")
    op.drop_constraint("oauth2client_user_id_fkey", "oauth2client", type_="foreignkey")
    op.rename_table("oauth2client", "oauth2client_old")

    op.create_table(
        "oauth2client",
        sa.Column("client_id", sa.String(length=48), nullable=True),
        sa.Column("client_secret", sa.String(length=120), nullable=True),
        sa.Column("client_id_issued_at", sa.Integer(), nullable=False),
        sa.Column("client_secret_expires_at", sa.Integer(), nullable=False),
        sa.Column("client_metadata", sa.Text(), nullable=True),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("ratelimit_multiplier", sa.Float(), nullable=True),
        sa.Column("individual_ratelimit_multipliers", sa.JSON(), nullable=True),
        sa.Column("last_activity", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.fs_uniquifier"],
            name="fk_oauth2client_user_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(op.f("ix_oauth2client_client_id"), "oauth2client", ["client_id"], unique=False)

    op.execute(
        """INSERT INTO oauth2client (client_id, client_secret, client_id_issued_at, client_secret_expires_at, user_id, ratelimit_multiplier, last_activity, client_metadata)
                SELECT client_id, client_secret, 0, 0, (SELECT fs_uniquifier FROM users WHERE id = user_id), ratelimit, last_activity,
                row_to_json((SELECT d FROM (SELECT name AS client_name, description, website, is_confidential, created, is_internal, _default_scopes, _redirect_uris) d))
                FROM oauth2client_old"""
    )
    # <<< oauth2client

    # oauth2token >>>
    op.drop_index("oauth2token_client_id_key", table_name="oauth2token")
    op.drop_index("oauth2token_is_personal_key", table_name="oauth2token")
    op.drop_constraint("oauth2token_refresh_token_key", "oauth2token", type_="unique")
    op.drop_index("oauth2token_user_id_key", table_name="oauth2token")
    op.drop_constraint("oauth2token_client_id_fkey", "oauth2token", type_="foreignkey")
    op.drop_constraint("oauth2token_user_id_fkey", "oauth2token", type_="foreignkey")
    op.rename_table("oauth2token", "oauth2token_old")

    op.create_table(
        "oauth2token",
        sa.Column("token_type", sa.String(length=40), nullable=True),
        sa.Column("access_token", sa.String(length=255), nullable=False),
        sa.Column("refresh_token", sa.String(length=255), nullable=True),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("access_token_revoked_at", sa.Integer(), nullable=False),
        sa.Column("refresh_token_revoked_at", sa.Integer(), nullable=False),
        sa.Column("expires_in", sa.BigInteger(), nullable=False),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("client_id", sa.Integer(), nullable=True),
        sa.Column("is_personal", sa.Boolean(), default=False),
        sa.Column("is_internal", sa.Boolean, default=False),
        sa.ForeignKeyConstraint(
            ["client_id"], ["oauth2client.id"], name="fk_oauth2token_client_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.fs_uniquifier"], name="fk_oauth2token_user_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("access_token"),
    )
    op.create_index(
        op.f("ix_oauth2token_refresh_token"), "oauth2token", ["refresh_token"], unique=False
    )

    connection.execute(
        text(
            """INSERT INTO oauth2token (token_type, access_token, refresh_token, scope, issued_at, access_token_revoked_at, refresh_token_revoked_at, expires_in, user_id, client_id, is_personal, is_internal)
               SELECT token_type, access_token, refresh_token, _scopes, :migration_epoch, 0, 0,
                      FLOOR(EXTRACT(EPOCH FROM expires))::bigint - :migration_epoch,
                      (SELECT fs_uniquifier FROM users WHERE id = user_id),
                      (SELECT id FROM oauth2client WHERE client_id = source.client_id),
                      is_personal, is_internal
               FROM oauth2token_old AS source"""
        ),
        {"migration_epoch": migration_epoch},
    )

    # <<< oauth2token
    _validate_upgrade_copy(connection, source_counts)


    # roles_users >>>
    op.alter_column("roles_users", "user_id", existing_type=sa.INTEGER(), nullable=False)

    op.alter_column("roles_users", "role_id", existing_type=sa.INTEGER(), nullable=False)
    # <<< roles_users

    op.drop_table("oauth2client_old")
    op.drop_table("oauth2token_old")

    # ### end Alembic commands ###


def downgrade() -> None:
    connection = op.get_bind()
    source_counts = _downgrade_preflight(connection)

    op.drop_index(op.f("ix_oauth2token_refresh_token"), table_name="oauth2token")
    op.drop_index(op.f("ix_oauth2client_client_id"), table_name="oauth2client")
    op.drop_constraint("fk_oauth2client_user_id", "oauth2client", type_="foreignkey")
    op.drop_constraint("fk_oauth2token_client_id", "oauth2token", type_="foreignkey")
    op.drop_constraint("fk_oauth2token_user_id", "oauth2token", type_="foreignkey")
    op.drop_constraint("uq_users_fs_uniquifier", "users", type_="unique")

    # roles_users >>>
    op.alter_column("roles_users", "role_id", existing_type=sa.INTEGER(), nullable=True)

    op.alter_column("roles_users", "user_id", existing_type=sa.INTEGER(), nullable=True)
    # <<< roles_users

    # oauth2client >>>
    op.create_table(
        "oauth2client_old",
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("website", sa.String(length=255), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_secret", sa.String(length=255), nullable=False),
        sa.Column("is_confidential", sa.Boolean(), nullable=True),
        sa.Column("is_internal", sa.Boolean(), nullable=True),
        sa.Column("last_activity", sa.DateTime(), nullable=True),
        sa.Column("_redirect_uris", sa.Text(), nullable=True),
        sa.Column("_default_scopes", sa.Text(), nullable=True),
        sa.Column("ratelimit", sa.Float(), nullable=True),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="oauth2client_user_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("client_id"),
    )

    connection.execute(
        text(
            """INSERT INTO oauth2client_old (client_id, client_secret, user_id, ratelimit, last_activity, name, description, website, is_confidential, _default_scopes, _redirect_uris, created, is_internal)
               SELECT client_id,
                      client_secret,
                      (SELECT id FROM users WHERE fs_uniquifier = user_id),
                      ratelimit_multiplier,
                      last_activity,
                      client_metadata::json->>'client_name',
                      client_metadata::json->>'description',
                      client_metadata::json->>'website',
                      CASE client_metadata::json->>'is_confidential'
                          WHEN 'false' THEN false
                          ELSE true
                      END,
                      COALESCE(
                          client_metadata::json->>'_default_scopes',
                          client_metadata::json->>'scope'
                      ),
                      client_metadata::json->>'_redirect_uris',
                      COALESCE(
                          (client_metadata::json->>'created')::timestamp,
                          to_timestamp(client_id_issued_at) AT TIME ZONE 'UTC'
                      ),
                      CASE client_metadata::json->>'is_internal'
                          WHEN 'true' THEN true
                          ELSE false
                      END
               FROM oauth2client"""
        )
    )

    op.create_index("oauth2client_user_id_key", "oauth2client_old", ["user_id"])
    op.create_index("oauth2client_name_key", "oauth2client_old", ["name"])
    # <<< oauth2client

    # oauth2token >>>
    op.create_table(
        "oauth2token_old",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("client_id", sa.String(length=255), nullable=True),
        sa.Column("token_type", sa.String(length=40), nullable=True),
        sa.Column("access_token", sa.String(length=255), nullable=False),
        sa.Column("refresh_token", sa.String(length=255), nullable=True),
        sa.Column("_scopes", sa.Text(), nullable=True),
        sa.Column("expires", sa.DateTime(), nullable=True),
        sa.Column("is_personal", sa.Boolean(), default=False, nullable=True),
        sa.Column("is_internal", sa.Boolean, default=False, nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="oauth2token_user_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth2client_old.client_id"],
            name="oauth2token_client_id_fkey",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("access_token"),
        sa.UniqueConstraint("refresh_token"),
    )

    connection.execute(
        text(
            """INSERT INTO oauth2token_old (token_type, access_token, refresh_token, _scopes, expires, user_id, client_id, is_personal, is_internal)
               SELECT token_type,
                      access_token,
                      refresh_token,
                      scope,
                      to_timestamp(
                          issued_at::double precision + expires_in::double precision
                      ) AT TIME ZONE 'UTC',
                      (SELECT id FROM users WHERE fs_uniquifier = user_id),
                      (SELECT client_id FROM oauth2client WHERE id = token.client_id),
                      COALESCE(is_personal, false),
                      COALESCE(is_internal, false)
               FROM oauth2token AS token"""
        )
    )

    _validate_downgrade_copy(connection, source_counts)

    op.create_index("oauth2token_client_id_key", "oauth2token_old", ["client_id"])
    op.create_index("oauth2token_user_id_key", "oauth2token_old", ["user_id"])
    op.create_index("oauth2token_is_personal_key", "oauth2token_old", ["is_personal"])
    op.create_unique_constraint(
        "oauth2token_refresh_token_key", "oauth2token_old", ["refresh_token"]
    )
    # <<< oauth2token

    # users >>>
    op.drop_column("users", "fs_uniquifier")
    op.drop_column("users", "family_name")
    op.alter_column("users", "given_name", new_column_name="name")
    op.alter_column("users", "ratelimit_quota", new_column_name="ratelimit_level")
    # <<< users

    # password_change_request >>>
    op.drop_table("password_change_request")
    # <<< password_change_request

    # email_change_request >>>
    op.drop_table("email_change_request")
    # <<< email_change_request

    op.drop_table("oauth2client")
    op.rename_table("oauth2client_old", "oauth2client")
    op.drop_table("oauth2token")
    op.rename_table("oauth2token_old", "oauth2token")

    # # ### end Alembic commands ###
