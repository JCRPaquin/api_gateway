import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url


ROOT = Path(__file__).parents[2]


def _postgres_uri():
    uri = os.environ.get("TEST_DATABASE_URI")
    if uri and make_url(uri).get_backend_name() == "postgresql":
        return uri
    if os.environ.get("REQUIRE_POSTGRES_SECURITY_TESTS") == "1":
        pytest.fail("REQUIRE_POSTGRES_SECURITY_TESTS requires PostgreSQL")
    pytest.skip("OAuth migration behavior requires PostgreSQL")


def _schema_uri(uri, schema):
    url = make_url(uri)
    query = dict(url.query)
    query["options"] = "-csearch_path={}".format(schema)
    return url.set(query=query).render_as_string(hide_password=False)


def _alembic_config():
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    return config


def test_migration_uri_validation_never_outputs_secret():
    canary = "migration-uri-password-canary"
    environment = dict(os.environ)
    environment["SQLALCHEMY_DATABASE_URI"] = (
        "mysql://migration-user:{}@database.invalid/gateway".format(canary)
    )
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert canary not in result.stdout
    assert canary not in result.stderr
    assert "SQLALCHEMY_DATABASE_URI is invalid" in result.stderr


def test_oauth_migration_invalidates_legacy_state_and_downgrades_empty(monkeypatch):
    base_uri = _postgres_uri()
    schema = "oauth_security_{}".format(uuid.uuid4().hex)
    admin_engine = sa.create_engine(base_uri, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as connection:
        connection.execute(sa.text('CREATE SCHEMA "{}"'.format(schema)))

    isolated_uri = _schema_uri(base_uri, schema)
    monkeypatch.setenv("SQLALCHEMY_DATABASE_URI", isolated_uri)
    config = _alembic_config()
    engine = sa.create_engine(isolated_uri)
    try:
        command.upgrade(config, "d4c3b2a1908f")
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    'INSERT INTO "user" '
                    "(id, email, active, fs_uniquifier, ratelimit_quota) VALUES "
                    "(9001, 'legacy@example.org', true, 'legacy-owner', -1), "
                    "(9002, 'anonymous@ads', true, 'legacy-anonymous-owner', -1)"
                )
            )
            regular_client = connection.execute(
                sa.text(
                    "INSERT INTO oauth2client "
                    "(client_id, client_secret, client_id_issued_at, "
                    "client_secret_expires_at, client_metadata, user_id, "
                    "ratelimit_multiplier, individual_ratelimit_multipliers) "
                    "VALUES ('legacy-client', 'plaintext-client-secret', 1, 0, "
                    "'{\"client_name\": \"legacy\"}', 'legacy-owner', 1, "
                    "'{\"oauth_.*\": 9}') RETURNING id"
                )
            ).scalar_one()
            connection.execute(
                sa.text(
                    "INSERT INTO oauth2client "
                    "(client_id, client_secret, client_id_issued_at, "
                    "client_secret_expires_at, client_metadata, user_id, "
                    "ratelimit_multiplier) VALUES "
                    "('anonymous-client', 'anonymous-secret', 1, 0, "
                    "'{\"description\": \"Anonymous client\"}', "
                    "'legacy-anonymous-owner', 1)"
                )
            )
            connection.execute(
                sa.text(
                    "INSERT INTO oauth2token "
                    "(token_type, access_token, refresh_token, scope, issued_at, "
                    "access_token_revoked_at, refresh_token_revoked_at, expires_in, "
                    "user_id, client_id, is_personal, is_internal) VALUES "
                    "('Bearer', 'plaintext-access-token', 'plaintext-refresh-token', "
                    "'api', 1, 0, 0, 3600, 'legacy-owner', :client_id, false, false)"
                ),
                {"client_id": regular_client},
            )

        command.upgrade(config, "head")
        inspector = sa.inspect(engine)
        client_columns = {column["name"] for column in inspector.get_columns("oauth2client")}
        token_columns = {column["name"] for column in inspector.get_columns("oauth2token")}
        assert "client_secret" not in client_columns
        assert "client_secret_expires_at" not in client_columns
        assert "refresh_token" not in token_columns
        assert "refresh_token_revoked_at" not in token_columns
        assert {
            "token_key_id",
            "token_digest_version",
            "credential_purpose",
            "credential_delivery_pending",
            "credential_delivery_path",
        } <= token_columns
        assert {"credential_purpose", "binding_digest"} <= client_columns
        assert next(
            column
            for column in inspector.get_columns("oauth2token")
            if column["name"] == "access_token"
        )["nullable"] is False
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT count(*) FROM oauth2token")) == 0
            assert connection.scalar(
                sa.text("SELECT version_num FROM alembic_version")
            ) == "7d1c4a9e2b31"
            assert connection.scalar(
                sa.text(
                    "SELECT count(*) FROM oauth2client "
                    "WHERE user_id = 'legacy-anonymous-owner'"
                )
            ) == 0
            assert connection.scalar(
                sa.text(
                    "SELECT individual_ratelimit_multipliers FROM oauth2client "
                    "WHERE user_id = 'legacy-owner'"
                )
            ) is None
        constraints = {
            constraint["name"]
            for constraint in inspector.get_check_constraints("oauth2client")
        }
        assert "ck_oauth2client_anonymous_binding" in constraints
        token_constraints = {
            constraint["name"]
            for constraint in inspector.get_check_constraints("oauth2token")
        }
        assert "ck_oauth2token_delivery_state" in token_constraints
        assert any(
            index["name"] == "uq_oauth2client_active_personal_owner"
            and index["unique"]
            for index in inspector.get_indexes("oauth2client")
        )

        with engine.begin() as connection:
            client_id = connection.execute(
                sa.text(
                    "INSERT INTO oauth2client "
                    "(client_id, client_id_issued_at, client_metadata, user_id, "
                    "ratelimit_multiplier, credential_purpose) VALUES "
                    "('digest-client', 1, '{\"client_name\": \"digest\"}', "
                    "'legacy-owner', 1, 'personal') RETURNING id"
                )
            ).scalar_one()
            connection.execute(
                sa.text(
                    "INSERT INTO oauth2token "
                    "(token_type, access_token, scope, issued_at, "
                    "access_token_revoked_at, expires_in, user_id, client_id, "
                    "is_personal, is_internal, token_key_id, token_digest_version, "
                    "credential_purpose) VALUES "
                    "('Bearer', :digest, 'api', 1, 0, 3600, 'legacy-owner', "
                    ":client_id, true, false, 'current', 1, 'personal')"
                ),
                {"digest": "a" * 64, "client_id": client_id},
            )

        command.downgrade(config, "d4c3b2a1908f")
        inspector = sa.inspect(engine)
        client_columns = {column["name"] for column in inspector.get_columns("oauth2client")}
        token_columns = {column["name"] for column in inspector.get_columns("oauth2token")}
        assert {"client_secret", "client_secret_expires_at"} <= client_columns
        assert {"refresh_token", "refresh_token_revoked_at"} <= token_columns
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT count(*) FROM oauth2token")) == 0
            assert connection.scalar(
                sa.text("SELECT count(client_secret) FROM oauth2client")
            ) == 0
    finally:
        engine.dispose()
        with admin_engine.connect() as connection:
            connection.execute(sa.text('DROP SCHEMA IF EXISTS "{}" CASCADE'.format(schema)))
        admin_engine.dispose()
