import datetime
import hashlib
import time

import pytest
from click import BadParameter
from click.testing import CliRunner

from apigateway.cli import (
    _delete_ids,
    cleanup_clients,
    cleanup_tokens,
    cleanup_users,
    parse_timedelta,
)
from apigateway.models import OAuth2Client, OAuth2Token, User


def _user(app, suffix, registered_at=None, confirmed_at=None):
    user = User(
        email="user-{0}@example.test".format(suffix),
        fs_uniquifier="user-{0}".format(suffix),
        active=True,
        registered_at=registered_at or datetime.datetime.utcnow(),
        confirmed_at=confirmed_at,
    )
    app.db.session.add(user)
    app.db.session.flush()
    return user


def _client(app, user, suffix, last_activity=None, ratelimit=1.0):
    client = OAuth2Client(
        user_id=user.fs_uniquifier,
        client_id="client-{0}".format(suffix),
        last_activity=last_activity,
        ratelimit_multiplier=ratelimit,
        credential_purpose="browser",
    )
    client.set_client_metadata(
        {"client_name": "client-{0}".format(suffix), "scope": "api"}
    )
    app.db.session.add(client)
    app.db.session.flush()
    return client


def _token(app, client, suffix, issued_at, expires_in):
    token = OAuth2Token(
        user_id=client.user_id,
        client_id=client.id,
        token_type="Bearer",
        access_token=hashlib.sha256(suffix.encode("utf-8")).hexdigest(),
        token_key_id="test-active",
        token_digest_version=1,
        credential_purpose="browser",
        scope="api",
        issued_at=issued_at,
        expires_in=expires_in,
    )
    app.db.session.add(token)
    app.db.session.flush()
    return token


@pytest.mark.parametrize(
    "value",
    [
        "days=0",
        "days=-1",
        "days=nan",
        "days=inf",
        "microseconds=0.1",
        "months=1",
        "days=1=hours=2",
        "bad",
    ],
)
def test_parse_timedelta_rejects_unsafe_values(value):
    with pytest.raises(BadParameter):
        parse_timedelta(value)


def test_guarded_user_delete_preserves_new_confirmation(app):
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    user = _user(
        app,
        "confirmed-race",
        registered_at=cutoff - datetime.timedelta(days=1),
    )
    app.db.session.commit()
    selected_ids = [user.id]

    user.confirmed_at = datetime.datetime.utcnow()
    app.db.session.commit()
    predicates = (User.registered_at <= cutoff, User.confirmed_at.is_(None))
    deleted = _delete_ids(app.db.session, User, selected_ids, predicates)
    app.db.session.commit()

    assert deleted == 0
    assert app.db.session.query(User).filter_by(id=selected_ids[0]).one_or_none() is not None


def test_guarded_client_delete_preserves_new_activity(app):
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=90)
    user = _user(app, "activity-race")
    client = _client(
        app,
        user,
        "activity-race",
        cutoff - datetime.timedelta(days=1),
    )
    app.db.session.commit()
    selected_ids = [client.id]

    client.last_activity = datetime.datetime.utcnow()
    app.db.session.commit()
    predicates = (
        OAuth2Client.last_activity.isnot(None),
        OAuth2Client.last_activity <= cutoff,
        OAuth2Client.ratelimit_multiplier <= 1.0,
    )
    deleted = _delete_ids(
        app.db.session, OAuth2Client, selected_ids, predicates
    )
    app.db.session.commit()

    assert deleted == 0
    assert (
        app.db.session.query(OAuth2Client)
        .filter_by(id=selected_ids[0])
        .one_or_none()
        is not None
    )


def test_cleanup_users_dry_run_and_confirmation(app):
    stale = _user(
        app,
        "stale",
        registered_at=datetime.datetime.utcnow() - datetime.timedelta(days=3),
    )
    confirmed = _user(
        app,
        "confirmed",
        registered_at=datetime.datetime.utcnow() - datetime.timedelta(days=3),
        confirmed_at=datetime.datetime.utcnow(),
    )
    stale_id = stale.id
    confirmed_id = confirmed.id
    app.db.session.commit()
    runner = CliRunner()

    result = runner.invoke(cleanup_users, ["--timedelta", "days=1", "--dry-run"])
    assert result.exit_code == 0
    assert "1 stale unconfirmed users" in result.output
    assert app.db.session.query(User).filter_by(id=stale_id).one_or_none() is not None

    result = runner.invoke(
        cleanup_users, ["--timedelta", "days=1"], input="n\n"
    )
    assert result.exit_code != 0
    assert app.db.session.query(User).filter_by(id=stale_id).one_or_none() is not None

    result = runner.invoke(cleanup_users, ["--timedelta", "days=1", "--yes"])
    assert result.exit_code == 0
    assert app.db.session.query(User).filter_by(id=stale_id).one_or_none() is None
    assert app.db.session.query(User).filter_by(id=confirmed_id).one_or_none() is not None


def test_cleanup_tokens_deletes_only_expired_child(app):
    user = _user(app, "tokens")
    client = _client(app, user, "tokens", datetime.datetime.utcnow())
    now = int(time.time())
    expired = _token(app, client, "expired", now - 120, 60)
    valid = _token(app, client, "valid", now, 3600)
    expired_id = expired.id
    valid_id = valid.id
    client_id = client.id
    app.db.session.commit()

    result = CliRunner().invoke(cleanup_tokens, ["--yes"])

    assert result.exit_code == 0
    assert app.db.session.query(OAuth2Token).filter_by(id=expired_id).one_or_none() is None
    assert app.db.session.query(OAuth2Token).filter_by(id=valid_id).one_or_none() is not None
    assert app.db.session.query(OAuth2Client).filter_by(id=client_id).one_or_none() is not None


def test_cleanup_clients_applies_all_filters_and_excludes_null_activity(app):
    old = datetime.datetime.utcnow() - datetime.timedelta(days=100)
    user = _user(app, "clients")
    other_user = _user(app, "other-clients")
    eligible = _client(app, user, "eligible", old, ratelimit=1.0)
    too_large = _client(app, user, "large", old, ratelimit=2.0)
    wrong_user = _client(app, other_user, "other", old, ratelimit=1.0)
    null_activity = _client(app, user, "null", None, ratelimit=1.0)
    eligible_id = eligible.id
    survivor_ids = [too_large.id, wrong_user.id, null_activity.id]
    user_id = user.fs_uniquifier
    app.db.session.commit()

    result = CliRunner().invoke(
        cleanup_clients,
        [
            "--timedelta",
            "days=90",
            "--userid",
            user_id,
            "--ratelimit",
            "1",
            "--yes",
        ],
    )

    assert result.exit_code == 0
    assert app.db.session.query(OAuth2Client).filter_by(id=eligible_id).one_or_none() is None
    for client_id in survivor_ids:
        assert app.db.session.query(OAuth2Client).filter_by(id=client_id).one_or_none() is not None


@pytest.mark.parametrize("value", ["-1", "nan", "inf", "-inf"])
def test_cleanup_clients_rejects_unsafe_ratelimit(app, value):
    result = CliRunner().invoke(
        cleanup_clients,
        ["--timedelta", "days=90", "--ratelimit", value, "--dry-run"],
    )
    assert result.exit_code != 0
    assert "finite and nonnegative" in result.output


def test_cleanup_failure_rolls_back_and_exits_nonzero(app, monkeypatch):
    user = _user(
        app,
        "failure",
        registered_at=datetime.datetime.utcnow() - datetime.timedelta(days=3),
    )
    app.db.session.commit()
    rollback_calls = []

    def fail_commit():
        raise RuntimeError("synthetic database failure")

    original_rollback = app.db.session.rollback

    def record_rollback():
        rollback_calls.append(True)
        original_rollback()

    monkeypatch.setattr(app.db.session, "commit", fail_commit)
    monkeypatch.setattr(app.db.session, "rollback", record_rollback)
    result = CliRunner().invoke(cleanup_users, ["--timedelta", "days=1", "--yes"])

    assert result.exit_code != 0
    assert "transaction rolled back" in result.output
    assert len(rollback_calls) == 1
    assert app.db.session.query(User).filter_by(id=user.id).one_or_none() is not None


def test_cleanup_clients_preserves_active_and_pending_credentials(app):
    old = datetime.datetime.utcnow() - datetime.timedelta(days=100)
    user = _user(app, "protected-clients")
    active_client = _client(app, user, "active", old)
    pending_client = _client(app, user, "pending", old)
    now = int(time.time())
    _token(app, active_client, "active", now, 3600)
    pending = _token(app, pending_client, "pending", now - 7200, 1)
    pending.credential_delivery_pending = True
    pending.credential_delivery_path = "/safe/operator-output"
    protected_ids = {active_client.id, pending_client.id}
    app.db.session.commit()

    result = CliRunner().invoke(
        cleanup_clients, ["--timedelta", "days=90", "--yes"]
    )

    assert result.exit_code == 0
    assert {
        row.id
        for row in app.db.session.query(OAuth2Client)
        .filter(OAuth2Client.id.in_(protected_ids))
        .all()
    } == protected_ids


def test_cleanup_users_preserves_bootstrap_and_oauth_owners(app):
    stale = datetime.datetime.utcnow() - datetime.timedelta(days=2)
    bootstrap = _user(app, "bootstrap", registered_at=stale)
    bootstrap.email = app.config["ANONYMOUS_BOOTSTRAP_USER_EMAIL"]
    owner = _user(app, "owner", registered_at=stale)
    _client(app, owner, "owned", datetime.datetime.utcnow())
    protected_ids = {bootstrap.id, owner.id}
    app.db.session.commit()

    result = CliRunner().invoke(
        cleanup_users, ["--timedelta", "hours=24", "--yes"]
    )

    assert result.exit_code == 0
    assert {
        row.id
        for row in app.db.session.query(User)
        .filter(User.id.in_(protected_ids))
        .all()
    } == protected_ids
