import math
import os
import threading
import time

import pytest
from flask import g

from apigateway import extensions
from apigateway.exceptions import ValidationError
from apigateway.models import OAuth2Client, OAuth2Token, User


def _user(app, suffix, *, quota=-1, scopes="api user", anonymous=False):
    email = app.config["ANONYMOUS_BOOTSTRAP_USER_EMAIL"] if anonymous else f"{suffix}@example.org"
    user = User(
        email=email,
        fs_uniquifier=f"owner-{suffix}",
        active=True,
        ratelimit_quota=quota,
        _allowed_scopes=scopes,
    )
    app.db.session.add(user)
    app.db.session.commit()
    return user


def _issue(app, owner, **overrides):
    values = {"purpose": "personal", "scopes": ["api"]}
    values.update(overrides)
    return app.auth_service.issue_credential(owner, **values)

def _clear_request_auth_state():
    g.pop("_login_user", None)
    g.pop("authlib_server_oauth2_token", None)
    g.pop("access_modality", None)


def test_default_scopes_are_checked_before_issuance(app):
    with app.app_context():
        owner = _user(app, "narrow-default", scopes="user")
        with pytest.raises(ValidationError):
            _issue(app, owner, scopes=None)
        assert app.db.session.query(OAuth2Client).count() == 0


@pytest.mark.parametrize("quota,allowed", [(None, True), (0, False), (-1, True), (-2, False), (-0.5, False)])
def test_quota_sentinel_semantics(app, quota, allowed):
    with app.app_context():
        owner = _user(app, str(quota).replace(".", "-"), quota=quota)
        if allowed:
            _issue(app, owner)
            assert app.db.session.query(OAuth2Token).count() == 1
        else:
            with pytest.raises(ValidationError):
                _issue(app, owner)


def test_aggregate_capacity_uses_maximum_exact_route_capacity(app):
    @app.get("/oauth-policy-test")
    def oauth_policy_test():
        return "ok"

    with app.app_context():
        owner = _user(app, "aggregate", quota=4)
        first = _issue(
            app,
            owner,
            purpose="operator",
            ratelimit_multiplier=1,
            individual_ratelimit_multipliers={"oauth_policy_test": 3},
        )
        assert first.client.ratelimit_multiplier == 1
        with pytest.raises(ValidationError):
            _issue(app, owner, purpose="personal", ratelimit_multiplier=2)


@pytest.mark.parametrize("value", [0, -1, math.inf, -math.inf, math.nan, "2"])
def test_non_finite_or_non_positive_multipliers_fail_closed(app, value):
    with app.app_context():
        owner = _user(app, repr(value))
        with pytest.raises(ValidationError):
            _issue(app, owner, ratelimit_multiplier=value)


def test_route_multiplier_requires_exact_registered_endpoint(app):
    @app.get("/oauth-exact")
    def oauth_exact():
        return "ok"

    with app.app_context():
        owner = _user(app, "exact")
        with pytest.raises(ValidationError):
            _issue(
                app,
                owner,
                individual_ratelimit_multipliers={"oauth_.*": 2},
            )
        issued = _issue(
            app,
            owner,
            individual_ratelimit_multipliers={"oauth_exact": 2},
        )
        assert issued.client.individual_ratelimit_multipliers == {"oauth_exact": 2.0}


def test_anonymous_database_cap_and_binding_separation(app, monkeypatch):
    monkeypatch.setitem(app.config, "ANONYMOUS_CREDENTIAL_DATABASE_CAP", 1)
    with app.app_context():
        owner = _user(app, "anonymous", anonymous=True, scopes="")
        first = _issue(
            app,
            owner,
            purpose="anonymous",
            scopes=[],
            binding_digest=app.auth_service.binding_digest("browser-a"),
        )
        rotated = _issue(
            app,
            owner,
            purpose="anonymous",
            scopes=[],
            binding_digest=app.auth_service.binding_digest("browser-a"),
        )
        assert first.client.id == rotated.client.id
        with pytest.raises(ValidationError):
            _issue(
                app,
                owner,
                purpose="anonymous",
                scopes=[],
                binding_digest=app.auth_service.binding_digest("browser-b"),
            )


def test_hmac_key_rotation_accepts_prior_then_rejects_stale(app, monkeypatch):
    with app.app_context():
        owner = _user(app, "rotation")
        issued = _issue(app, owner)
        old_id = app.auth_service._active_access_token_key_id
        old_key = app.auth_service._access_token_keys[old_id]
        client = app.test_client()
        protected = client.get(
            "/accounts/protected",
            headers={"Authorization": "Bearer " + issued.access_token},
        )
        assert protected.status_code == 200
        assert protected.get_json()["oauth"] == "rotation@example.org"
        _clear_request_auth_state()

        monkeypatch.setattr(
            app.auth_service,
            "_access_token_keys",
            {
                "new": b"new-access-token-hmac-key-32-bytes-minimum",
                old_id: old_key,
            },
        )
        monkeypatch.setattr(app.auth_service, "_active_access_token_key_id", "new")
        monkeypatch.setattr(
            app.auth_service, "accepted_access_token_key_ids", ("new", old_id)
        )
        assert (
            client.get(
                "/accounts/protected",
                headers={"Authorization": "Bearer " + issued.access_token},
            ).status_code
            == 200
        )
        _clear_request_auth_state()
        monkeypatch.setattr(
            app.auth_service,
            "_access_token_keys",
            {"new": b"new-access-token-hmac-key-32-bytes-minimum"},
        )
        monkeypatch.setattr(
            app.auth_service, "accepted_access_token_key_ids", ("new",)
        )
        assert (
            client.get(
                "/accounts/protected",
                headers={"Authorization": "Bearer " + issued.access_token},
            ).status_code
            == 401
        )


def _anonymous_browser(app, monkeypatch, redis_result):
    monkeypatch.setitem(app.config, "SESSION_COOKIE_PATH", "/")
    monkeypatch.setattr(extensions.redis_service._redis_client, "eval", redis_result)
    _clear_request_auth_state()
    g.pop("csrf_token", None)
    browser = app.test_client()
    csrf = browser.get(
        "/accounts/csrf", base_url="https://localhost"
    ).get_json()["csrf"]
    _clear_request_auth_state()
    response = browser.post(
        "/accounts/bootstrap",
        json={},
        headers={
            "X-CSRFToken": csrf,
            "Referer": "https://localhost/accounts/csrf",
        },
        base_url="https://localhost",
    )
    return browser, response


def test_anonymous_post_requires_csrf_before_redis_admission(app, monkeypatch):
    with app.app_context():
        _user(app, "anonymous-csrf", anonymous=True, scopes="")
    calls = []

    def admitted(*args, **kwargs):
        calls.append(True)
        return 1

    monkeypatch.setattr(extensions.redis_service._redis_client, "eval", admitted)
    response = app.test_client().post(
        "/accounts/bootstrap", json={}, base_url="https://localhost"
    )
    assert response.status_code == 400
    assert calls == []


def test_anonymous_post_is_session_bound_bounded_and_metadata_only(app, monkeypatch):
    with app.app_context():
        anonymous_owner = _user(app, "anonymous-route", anonymous=True, scopes="")
        owner_id = anonymous_owner.fs_uniquifier
    browser, response = _anonymous_browser(
        app, monkeypatch, lambda *args, **kwargs: 1
    )
    assert response.status_code == 201
    body = response.get_json()
    raw = body["access_token"]
    assert body["anonymous"] is True
    assert 0 < body["expires_at"] - int(time.time()) <= 24 * 60 * 60
    assert response.headers["Cache-Control"] == "no-store"
    _clear_request_auth_state()

    metadata = browser.get("/accounts/bootstrap", base_url="https://localhost")
    assert metadata.status_code == 200
    assert "access_token" not in metadata.get_json()
    _clear_request_auth_state()
    rejected = browser.get(
        "/accounts/bootstrap",
        headers={"Authorization": "Bearer " + raw},
        base_url="https://localhost",
    )
    assert rejected.status_code == 401
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.user_id == owner_id
        assert token.client.user_id == owner_id
        assert token.user_id != app.config["ANONYMOUS_BOOTSTRAP_USER_EMAIL"]


@pytest.mark.parametrize("redis_behavior,status", [("exhausted", 429), ("error", 503)])
def test_anonymous_redis_admission_is_authoritative(
    app, monkeypatch, redis_behavior, status
):
    with app.app_context():
        _user(app, "anonymous-" + redis_behavior, anonymous=True, scopes="")

    if redis_behavior == "error":
        def admission_error(*args, **kwargs):
            raise RuntimeError("redis unavailable")

        behavior = admission_error
    else:
        behavior = lambda *args, **kwargs: 0
    _, response = _anonymous_browser(app, monkeypatch, behavior)
    assert response.status_code == status
    with app.app_context():
        assert app.db.session.query(OAuth2Client).count() == 0


def test_personal_route_post_get_csrf_no_store_and_one_time_raw(app, monkeypatch):
    with app.app_context():
        owner = _user(app, "route", scopes="api")
        owner_id = owner.fs_uniquifier
    monkeypatch.setitem(app.config, "SESSION_COOKIE_PATH", "/")
    client = app.test_client()
    with client.session_transaction() as browser_session:
        browser_session["_user_id"] = owner_id
        browser_session["_fresh"] = True
    _clear_request_auth_state()

    rejected = client.post(
        "/accounts/user/token", json={}, base_url="https://localhost"
    )
    assert rejected.status_code == 400
    g.pop("csrf_token", None)
    _clear_request_auth_state()
    csrf = client.get("/accounts/csrf", base_url="https://localhost").get_json()["csrf"]
    _clear_request_auth_state()
    issued = client.post(
        "/accounts/user/token",
        json={},
        headers={"X-CSRFToken": csrf, "Referer": "https://localhost/accounts/csrf"},
        base_url="https://localhost",
    )
    assert issued.status_code == 201
    raw = issued.get_json()["access_token"]
    assert issued.headers["Cache-Control"] == "no-store"
    assert issued.headers["Pragma"] == "no-cache"

    metadata = client.get("/accounts/user/token", base_url="https://localhost")
    assert metadata.status_code == 200
    assert "access_token" not in metadata.get_json()
    assert client.put("/accounts/user/token", base_url="https://localhost").status_code == 405
    bearer = client.get(
        "/accounts/user/token",
        headers={"Authorization": f"Bearer {raw}"},
        base_url="https://localhost",
    )
    assert bearer.status_code == 401
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.access_token != raw


def test_relative_expiry_bounds(app):
    with app.app_context():
        owner = _user(app, "expiry")
        issued = _issue(app, owner, expires_in=30 * 86400)
        assert issued.token.expires_in == 30 * 86400
        with pytest.raises(ValidationError):
            _issue(app, owner, expires_in=30 * 86400 + 1)


def test_postgres_owner_lock_prevents_concurrent_overissuance(app):
    require_postgres = os.getenv("REQUIRE_POSTGRES_SECURITY_TESTS") == "1"
    if app.db.engine.dialect.name != "postgresql":
        if require_postgres:
            pytest.fail("REQUIRE_POSTGRES_SECURITY_TESTS requires PostgreSQL")
        pytest.skip("row-lock regression requires PostgreSQL")

    with app.app_context():
        owner = _user(app, "concurrent", quota=1)
        owner_id = owner.fs_uniquifier
    barrier = threading.Barrier(2)
    outcomes = []

    def worker(purpose):
        with app.app_context():
            barrier.wait()
            try:
                app.auth_service.issue_credential(
                    owner_id,
                    purpose=purpose,
                    scopes=["api"],
                    ratelimit_multiplier=1,
                )
                outcomes.append("issued")
            except ValidationError:
                outcomes.append("rejected")
            finally:
                app.db.session.remove()

    threads = [
        threading.Thread(target=worker, args=("personal",)),
        threading.Thread(target=worker, args=("operator",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert sorted(outcomes) == ["issued", "rejected"]
    with app.app_context():
        assert app.db.session.query(OAuth2Token).count() == 1
