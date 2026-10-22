import datetime
import importlib
import json
import os
import uuid

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text


REVISIONS = {
    "base": "migrations.versions.51f3b3b5cd5d_creating_basic_db_structure",
    "seed": "migrations.versions.26889be04d70_creating_default_user_accounts",
    "quota": "migrations.versions.2e0c0694da22_add_user_ratelimit_level",
    "client_fields": "migrations.versions.45eb49b7e934_add_ratelimit_to_oauth_clients",
    "indexes": "migrations.versions.c619e555696_adding_indexes",
    "citext": "migrations.versions.137ee54fd373_case_insensitive_email",
    "gateway": "migrations.versions.8e0d08daa203_new_gateway_version",
    "table_names": "migrations.versions.6b45dbb33d43_update_role_and_user_table_names",
    "current_indexes": "migrations.versions.fc5e2283de94_updating_indexes",
    "access_index": "migrations.versions.f2f57cb2a5b0_add_index_on_access_token",
}


@pytest.fixture
def migration_connection():
    database_url = os.environ.get("SQLALCHEMY_DATABASE_URI")
    if not database_url or not database_url.startswith("postgresql"):
        pytest.skip("migration integrity tests require the configured PostgreSQL test database")

    engine = sa.create_engine(database_url)
    schema = f"migration_integrity_{uuid.uuid4().hex}"
    with engine.begin() as admin_connection:
        admin_connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    connection = engine.connect()
    transaction = connection.begin()
    connection.execute(text(f'SET LOCAL search_path TO "{schema}", public'))
    try:
        yield connection
    finally:
        transaction.rollback()
        connection.close()
        with engine.begin() as admin_connection:
            admin_connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()


def _run_revision(connection, revision_name, direction="upgrade"):
    revision = importlib.import_module(REVISIONS[revision_name])
    revision.op = Operations(MigrationContext.configure(connection))
    getattr(revision, direction)()
    return revision


def _prepare_predecessor(connection):
    for revision_name in ("base", "seed", "quota", "client_fields", "indexes", "citext"):
        _run_revision(connection, revision_name)


def _upgrade_to_head(connection):
    for revision_name in ("gateway", "table_names", "current_indexes", "access_index"):
        _run_revision(connection, revision_name)


def _downgrade_to_gateway(connection):
    for revision_name in ("access_index", "current_indexes", "table_names"):
        _run_revision(connection, revision_name, "downgrade")


def _table_exists(connection, table_name):
    return connection.execute(
        text(
            """SELECT EXISTS (
                   SELECT 1
                   FROM information_schema.tables
                   WHERE table_schema = current_schema()
                     AND table_name = :table_name
               )"""
        ),
        {"table_name": table_name},
    ).scalar()


def _insert_legacy_client(connection, client_id, name):
    connection.execute(
        text(
            """INSERT INTO oauth2client
                   (name, user_id, client_id, client_secret, is_confidential,
                    is_internal, _default_scopes, ratelimit, created)
               SELECT :name, id, :client_id, :client_secret, true, false,
                      :scopes, 1.0, TIMESTAMP '2020-01-02 03:04:05'
               FROM users
               WHERE email = 'anonymous@ads'"""
        ),
        {
            "name": name,
            "client_id": client_id,
            "client_secret": f"secret-for-{client_id}",
            "scopes": "api legacy",
        },
    )


def test_seed_identity_and_timestamp_do_not_depend_on_runtime_config(
    migration_connection, monkeypatch
):
    def reject_runtime_app(*args, **kwargs):
        raise AssertionError("historical seed migration consulted runtime configuration")

    monkeypatch.setattr("apigateway.app.create_app", reject_runtime_app)
    _run_revision(migration_connection, "base")
    monkeypatch.setenv("ANONYMOUS_BOOTSTRAP_USER_EMAIL", "configured-elsewhere@example.org")

    seed_revision = _run_revision(migration_connection, "seed")
    seeded = migration_connection.execute(
        text(
            """SELECT email, confirmed_at, registered_at
               FROM users
               WHERE email = :email"""
        ),
        {"email": seed_revision.SEED_EMAIL},
    ).one()

    assert seeded.email == "anonymous@ads"
    assert seeded.confirmed_at == seeded.registered_at

    migration_connection.execute(
        text("INSERT INTO users (email) VALUES ('configured-elsewhere@example.org')")
    )
    _run_revision(migration_connection, "seed", "downgrade")

    remaining_emails = {
        row[0] for row in migration_connection.execute(text("SELECT email FROM users"))
    }
    assert "anonymous@ads" not in remaining_emails
    assert "configured-elsewhere@example.org" in remaining_emails


def test_upgrade_null_preflight_fails_before_schema_changes(migration_connection):
    _prepare_predecessor(migration_connection)
    _insert_legacy_client(migration_connection, "legacy-client", "Legacy client")
    invalid_ids = [
        row[0]
        for row in migration_connection.execute(
            text(
                """INSERT INTO oauth2token
                       (client_id, token_type, access_token, expires)
                   SELECT 'legacy-client', 'Bearer', 'must-not-leak-' || value, NULL
                   FROM generate_series(1, 7) AS generated(value)
                   RETURNING id"""
            )
        )
    ]

    with pytest.raises(RuntimeError) as error:
        _run_revision(migration_connection, "gateway")

    message = str(error.value)
    assert "7 legacy token rows with invalid required values" in message
    assert f"sample row ids: {invalid_ids[:5]}" in message
    assert str(invalid_ids[5:]) not in message
    assert "must-not-leak" not in message
    assert _table_exists(migration_connection, "oauth2client")
    assert not _table_exists(migration_connection, "oauth2client_old")
    assert not _table_exists(migration_connection, "email_change_request")


def test_downgrade_null_preflight_fails_before_schema_changes(migration_connection):
    _prepare_predecessor(migration_connection)
    _upgrade_to_head(migration_connection)
    user_id = migration_connection.execute(
        text("SELECT fs_uniquifier FROM \"user\" WHERE email = 'anonymous@ads'")
    ).scalar()
    invalid_id = migration_connection.execute(
        text(
            """INSERT INTO oauth2client
                   (client_id, client_secret, client_id_issued_at,
                    client_secret_expires_at, client_metadata, user_id)
               VALUES
                   (NULL, 'not-reported', 1700000000, 0, :metadata, :user_id)
               RETURNING id"""
        ),
        {
            "metadata": json.dumps({"client_name": "Invalid client", "scope": "api"}),
            "user_id": user_id,
        },
    ).scalar()
    _downgrade_to_gateway(migration_connection)

    with pytest.raises(RuntimeError) as error:
        _run_revision(migration_connection, "gateway", "downgrade")

    assert "1 client rows with null or overlong legacy credentials" in str(error.value)
    assert str(invalid_id) in str(error.value)
    assert "not-reported" not in str(error.value)
    assert _table_exists(migration_connection, "oauth2client")
    assert not _table_exists(migration_connection, "oauth2client_old")

    invalid_metadata = '{"client_name": "metadata-must-not-leak"'
    migration_connection.execute(
        text(
            """UPDATE oauth2client
               SET client_id = 'repaired-client-id',
                   client_metadata = :metadata
               WHERE id = :client_id"""
        ),
        {"metadata": invalid_metadata, "client_id": invalid_id},
    )
    with pytest.raises(RuntimeError) as metadata_error:
        _run_revision(migration_connection, "gateway", "downgrade")

    assert "1 client rows with invalid compatibility metadata" in str(
        metadata_error.value
    )
    assert str(invalid_id) in str(metadata_error.value)
    assert "metadata-must-not-leak" not in str(metadata_error.value)
    assert _table_exists(migration_connection, "oauth2client")
    assert not _table_exists(migration_connection, "oauth2client_old")

    unsafe_metadata_rows = (
        (
            r'{"client_name":"Safe name","description":"escaped-null-\u0000"}',
            r"\u0000",
        ),
        (
            r'{"client_name":"Safe name","scope":"unpaired-surrogate-\ud800"}',
            r"\ud800",
        ),
    )
    for unsafe_metadata, forbidden_value in unsafe_metadata_rows:
        migration_connection.execute(
            text(
                """UPDATE oauth2client
                   SET client_metadata = :metadata
                   WHERE id = :client_id"""
            ),
            {"metadata": unsafe_metadata, "client_id": invalid_id},
        )
        with pytest.raises(RuntimeError) as text_error:
            _run_revision(migration_connection, "gateway", "downgrade")

        text_error_message = str(text_error.value)
        assert "1 client rows with invalid compatibility metadata" in (
            text_error_message
        )
        assert str(invalid_id) in text_error_message
        assert forbidden_value not in text_error_message
        assert _table_exists(migration_connection, "oauth2client")
        assert not _table_exists(migration_connection, "oauth2client_old")


def test_oauth_round_trip_preserves_relationships_expiration_and_metadata(
    migration_connection,
):
    _prepare_predecessor(migration_connection)
    _insert_legacy_client(migration_connection, "legacy-a", "Legacy A")
    _insert_legacy_client(migration_connection, "legacy-b", "Legacy B")
    legacy_expiration = datetime.datetime(2035, 6, 7, 8, 9, 10)
    migration_connection.execute(
        text(
            """INSERT INTO oauth2token
                   (client_id, user_id, token_type, access_token, refresh_token,
                    expires, _scopes, is_personal, is_internal)
               SELECT 'legacy-a', id, 'Bearer', 'legacy-access', 'legacy-refresh',
                      :expires, 'api legacy', false, false
               FROM users
               WHERE email = 'anonymous@ads'"""
        ),
        {"expires": legacy_expiration},
    )

    _upgrade_to_head(migration_connection)

    issued_at_value, expires_in_value = migration_connection.execute(
        text(
            """SELECT issued_at, expires_in
               FROM oauth2token
               WHERE access_token = 'legacy-access'"""
        )
    ).one()
    expected_expiration = int(
        legacy_expiration.replace(tzinfo=datetime.timezone.utc).timestamp()
    )
    assert issued_at_value > 0
    assert expires_in_value == expected_expiration - issued_at_value

    clients = migration_connection.execute(
        text("SELECT id, client_id FROM oauth2client ORDER BY id")
    ).all()
    actual_client_id, expected_legacy_client_id = clients[0]
    wrong_client_id, wrong_legacy_client_id = clients[1]
    assert actual_client_id != wrong_client_id
    assert expected_legacy_client_id != wrong_legacy_client_id

    user_id = migration_connection.execute(
        text("SELECT fs_uniquifier FROM \"user\" WHERE email = 'anonymous@ads'")
    ).scalar()
    issued_at = 1700000000
    expires_in = 7200
    migration_connection.execute(
        text(
            """INSERT INTO oauth2token
                   (id, token_type, access_token, refresh_token, scope, issued_at,
                    access_token_revoked_at, refresh_token_revoked_at, expires_in,
                    user_id, client_id, is_personal, is_internal)
               VALUES
                   (:id, 'Bearer', 'current-access', 'current-refresh', 'api', :issued_at,
                    0, 0, :expires_in, :user_id, :client_id, false, false)"""
        ),
        {
            "id": wrong_client_id,
            "issued_at": issued_at,
            "expires_in": expires_in,
            "user_id": user_id,
            "client_id": actual_client_id,
        },
    )
    migration_connection.execute(
        text(
            """INSERT INTO oauth2client
                   (client_id, client_secret, client_id_issued_at,
                    client_secret_expires_at, client_metadata, user_id)
               VALUES
                   ('current-client', 'current-secret', :issued_at, 0, :metadata, :user_id)"""
        ),
        {
            "issued_at": issued_at,
            "metadata": json.dumps(
                {"client_name": "Current client", "scope": "api user"}
            ),
            "user_id": user_id,
        },
    )

    _downgrade_to_gateway(migration_connection)
    _run_revision(migration_connection, "gateway", "downgrade")

    current_token = migration_connection.execute(
        text(
            """SELECT client_id, expires, user_id
               FROM oauth2token
               WHERE access_token = 'current-access'"""
        )
    ).one()
    expected_user_id = migration_connection.execute(
        text("SELECT id FROM users WHERE email = 'anonymous@ads'")
    ).scalar()
    assert current_token.client_id == expected_legacy_client_id
    assert current_token.user_id == expected_user_id
    assert current_token.expires == datetime.datetime.utcfromtimestamp(
        issued_at + expires_in
    )
    assert current_token.expires.year != 1970

    round_trip_expiration = migration_connection.execute(
        text("SELECT expires FROM oauth2token WHERE access_token = 'legacy-access'")
    ).scalar()
    assert round_trip_expiration == legacy_expiration

    current_client = migration_connection.execute(
        text(
            """SELECT name, _default_scopes, created
               FROM oauth2client
               WHERE client_id = 'current-client'"""
        )
    ).one()
    client_name, default_scopes, created = current_client
    assert client_name == "Current client"
    assert default_scopes == "api user"
    assert created == datetime.datetime.utcfromtimestamp(issued_at)
    client_count = migration_connection.execute(
        text("SELECT COUNT(*) FROM oauth2client")
    ).scalar()
    token_count = migration_connection.execute(
        text("SELECT COUNT(*) FROM oauth2token")
    ).scalar()
    assert client_count == 3
    assert token_count == 2
