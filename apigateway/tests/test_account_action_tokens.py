from datetime import datetime, timedelta, timezone
from unittest import mock
from urllib.parse import urlsplit
import json

import pytest
from flask import g, session as flask_session
from flask_login import current_user, login_user
from sqlalchemy.orm import Session

from apigateway import notifications, views
from apigateway.email_templates import PasswordResetEmail
from apigateway.exceptions import AccountActionTokenError
from apigateway.models import (
    AccountActionToken,
    NotificationOutbox,
    OAuth2Client,
    OAuth2Token,
    User,
)
from apigateway.utils import DeliveryResult, DeliveryState


def clear_cached_user():
    g.pop("_login_user", None)
    g.pop("authlib_server_oauth2_token", None)
    g.pop("access_modality", None)


def reset_request_login_state():
    flask_session.pop("_user_id", None)
    flask_session.pop("_fresh", None)
    clear_cached_user()


def create_user(
    app,
    *,
    user_id,
    email,
    fs_uniquifier,
    password="Valid_password1",
    confirmed=True,
):
    with app.session_scope() as session:
        user = User(
            id=user_id,
            email=email,
            password=password,
            fs_uniquifier=fs_uniquifier,
            active=True,
            confirmed_at=datetime.utcnow() if confirmed else None,
        )
        session.add(user)
        session.commit()
    return user_id


def issue_password_reset(app, user_id, now=None):
    with app.session_scope() as session:
        user = session.query(User).filter_by(id=user_id).one()
        token = app.security_service.issue_account_action_token(
            session,
            user_id=user_id,
            purpose="password_reset",
            target_email=str(user.email),
            now=now,
        )
        session.commit()
    return token


@pytest.mark.parametrize("authenticated_as_other", [False, True])
def test_reset_issuance_is_bound_to_resolved_target(
    app, authenticated_as_other
):
    victim_id = create_user(
        app,
        user_id=101,
        email="victim@example.com",
        fs_uniquifier="victim-session",
    )
    other_id = create_user(
        app,
        user_id=102,
        email="other@example.com",
        fs_uniquifier="other-session",
    )

    with app.test_request_context(
        json={
            "email": "victim@example.com",
            "g-recaptcha-response": "test",
        }
    ):
        reset_request_login_state()
        if authenticated_as_other:
            other = app.db.session.query(User).filter_by(id=other_id).one()
            login_user(other)
        response, status = views.ResetPasswordView().post()
        reset_request_login_state()

    assert status == 202
    assert "eligible" in response["message"]
    job = app.db.session.query(NotificationOutbox).one()
    assert job.event_type == "password_reset_request"
    assert app.db.session.query(AccountActionToken).count() == 0

    accepted = DeliveryResult("email", DeliveryState.SENT, "sent")
    with mock.patch.object(notifications, "send_email", return_value=accepted) as send:
        notifications.process_outbox_batch()
    token = urlsplit(send.call_args.kwargs["verification_url"]).fragment.rsplit("/", 1)[1]
    assert send.call_args.args[1] == "victim@example.com"

    with app.session_scope() as session:
        action = session.query(AccountActionToken).one()
        user, verified_action = app.security_service.verify_account_action_token(
            session, token, "password_reset"
        )
        assert user.id == victim_id
        assert verified_action.id == action.id
        assert action.user_id == victim_id
        assert action.token_digest == app.security_service.account_action_token_digest(
            token
        )
        assert token not in action.token_digest
        assert action.target_email == "victim@example.com"
        assert len(action.state_digest) == 64


def test_reset_initiation_hides_account_state_and_never_issues_for_bootstrap(
    app, monkeypatch
):
    bootstrap_email = "anonymous-bootstrap@example.com"
    monkeypatch.setitem(
        app.config, "ANONYMOUS_BOOTSTRAP_USER_EMAIL", bootstrap_email
    )
    create_user(
        app,
        user_id=103,
        email=bootstrap_email,
        fs_uniquifier="bootstrap-session",
    )
    create_user(
        app,
        user_id=104,
        email="unverified@example.com",
        fs_uniquifier="unverified-session",
        confirmed=False,
    )

    outcomes = []
    for email in (
        bootstrap_email,
        "unverified@example.com",
        "missing@example.com",
    ):
        with app.test_request_context(
            json={"email": email, "g-recaptcha-response": "test"}
        ):
            reset_request_login_state()
            outcomes.append(views.ResetPasswordView().post())
            reset_request_login_state()

    assert [status for _, status in outcomes] == [202, 202, 202]
    with mock.patch.object(notifications, "send_email") as send:
        notifications.process_outbox_batch()
    send.assert_not_called()
    assert app.db.session.query(AccountActionToken).count() == 0


def test_forced_reset_enqueues_action_and_delivery_atomically(app, monkeypatch):
    create_user(
        app,
        user_id=105,
        email="forced@example.com",
        fs_uniquifier="forced-session",
        password="password",
    )
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)

    response = app.test_client().post(
        "/accounts/user/login",
        json={"email": "forced@example.com", "password": "password"},
    )

    assert response.status_code == 422, response.get_json()
    action = app.db.session.query(AccountActionToken).one()
    job = app.db.session.query(NotificationOutbox).one()
    assert job.event_type == "password_reset_action"
    assert job.payload["action_id"] == action.delivery_id
    assert all(
        forbidden not in json.dumps(job.payload).lower()
        for forbidden in ("password", "token", "verification_url")
    )


def test_issuance_replaces_same_user_and_purpose(app):
    user_id = create_user(
        app,
        user_id=105,
        email="replace@example.com",
        fs_uniquifier="replace-session",
    )
    first = issue_password_reset(app, user_id)
    second = issue_password_reset(app, user_id)

    assert first != second
    with app.session_scope() as session:
        assert session.query(AccountActionToken).count() == 1
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session, first, "password_reset"
            )
        user, _ = app.security_service.verify_account_action_token(
            session, second, "password_reset"
        )
        assert user.id == user_id


def test_reset_verification_is_read_only(app):
    user_id = create_user(
        app,
        user_id=106,
        email="inspect@example.com",
        fs_uniquifier="inspect-session",
    )
    token = issue_password_reset(app, user_id)

    with app.test_request_context(json={"token": token}):
        reset_request_login_state()
        response, status = views.ResetPasswordVerifyView().post()
        assert not current_user.is_authenticated
        reset_request_login_state()

    assert status == 200
    assert response == {"email": "inspect@example.com"}
    action = app.db.session.query(AccountActionToken).one()
    assert action.user_id == user_id


def test_issuance_requires_explicit_subject_purpose_and_target(app):
    user_id = create_user(
        app,
        user_id=106,
        email="explicit@example.com",
        fs_uniquifier="explicit-session",
    )
    with app.session_scope() as session:
        with pytest.raises(ValueError, match="exactly one"):
            app.security_service.issue_account_action_token(
                session,
                purpose="password_reset",
                target_email=None,
            )
        with pytest.raises(ValueError, match="does not match"):
            app.security_service.issue_account_action_token(
                session,
                user_id=user_id,
                purpose="password_reset",
                target_email="attacker@example.com",
            )
        with pytest.raises(ValueError, match="unknown"):
            app.security_service.issue_account_action_token(
                session,
                user_id=user_id,
                purpose="unknown",
                target_email=None,
            )


def test_account_action_expiry_is_configurable(app, monkeypatch):
    user_id = create_user(
        app,
        user_id=107,
        email="lifetime@example.com",
        fs_uniquifier="lifetime-session",
    )
    monkeypatch.setitem(
        app.config, "SECURITY_SERVICE_ACCOUNT_ACTION_TOKEN_EXPIRES", 90
    )
    issue_password_reset(
        app, user_id, now=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    action = app.db.session.query(AccountActionToken).one()
    assert (action.expires_at - action.issued_at).total_seconds() == 90


@pytest.mark.parametrize("host", ("localhost", "scixplorer.org"))
def test_reset_mail_uses_fragment_link_and_avoids_fixed_expiry(
    app, monkeypatch, host
):
    monkeypatch.setitem(
        app.config, "SECURITY_SERVICE_ACCOUNT_ACTION_TOKEN_EXPIRES", 90
    )
    verify_config_key = "SCIX_VERIFY_URL" if host == "scixplorer.org" else "VERIFY_URL"
    monkeypatch.setitem(
        app.config,
        verify_config_key,
        "https://ui.example/account/verify?source=mail",
    )
    token = "RESET_TOKEN_FRAGMENT_CANARY"
    with app.test_request_context(headers={"Host": host}):
        environment = notifications.request_environment(host)
        verification_url = notifications._password_reset_url(
            environment["verify_url"], token
        )
    parsed = urlsplit(verification_url)
    assert token not in parsed.path
    assert token not in parsed.query
    assert token in parsed.fragment
    assert "24 hours" not in PasswordResetEmail.msg_plain
    assert "24 hours" not in PasswordResetEmail.msg_html


def test_malformed_token_is_rejected_even_with_matching_digest_row(app):
    user_id = create_user(
        app,
        user_id=107,
        email="malformed@example.com",
        fs_uniquifier="malformed-session",
    )
    malformed = "not-a-signed-account-action"
    now = datetime.now(timezone.utc)
    with app.session_scope() as session:
        user = session.query(User).filter_by(id=user_id).one()
        session.add(
            AccountActionToken(
                delivery_id="00000000-0000-0000-0000-000000000107",
                token_digest=app.security_service.account_action_token_digest(
                    malformed
                ),
                user_id=user_id,
                purpose="password_reset",
                target_email="malformed@example.com",
                state_digest=app.security_service._account_action_state_digest(
                    user, "password_reset"
                ),
                issued_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        session.commit()
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session, malformed, "password_reset"
            )

    with app.test_request_context(
        json={
            "token": malformed,
            "password1": "New_valid_password2",
            "password2": "New_valid_password2",
        }
    ):
        reset_request_login_state()
        response, status = views.ResetPasswordView().put()
        assert status == 400
        assert response == {"message": "Invalid or expired account action token"}
        reset_request_login_state()
    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert user.validate_password("Valid_password1")
    assert not user.validate_password("New_valid_password2")


def test_malformed_signed_schema_is_rejected(app):
    malformed = app.security_service._account_action_serializer.dumps(
        {
            "version": 1,
            "user_id": 1,
            "purpose": "password_reset",
            "nonce": "a" * 32,
        },
        salt=app.security_service._account_action_salt("password_reset"),
    )
    with app.session_scope() as session:
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session, malformed, "password_reset"
            )


@pytest.mark.parametrize("seconds_after_issue", [24 * 60 * 60, 24 * 60 * 60 + 1])
def test_expiry_and_exact_boundary_are_rejected(app, seconds_after_issue):
    user_id = create_user(
        app,
        user_id=1080 + (seconds_after_issue - 24 * 60 * 60),
        email="expired-{}@example.com".format(seconds_after_issue),
        fs_uniquifier="expired-session-{}".format(seconds_after_issue),
    )
    issued_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    token = issue_password_reset(app, user_id, now=issued_at)

    with app.session_scope() as session:
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session,
                token,
                "password_reset",
                now=issued_at + timedelta(seconds=seconds_after_issue),
            )

    with app.test_request_context(
        json={
            "token": token,
            "password1": "New_valid_password2",
            "password2": "New_valid_password2",
        }
    ):
        reset_request_login_state()
        _, status = views.ResetPasswordView().put()
        assert status == 400
        reset_request_login_state()
    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert user.validate_password("Valid_password1")


def test_cross_purpose_and_row_subject_mismatch_are_rejected(app):
    first_id = create_user(
        app,
        user_id=109,
        email="first@example.com",
        fs_uniquifier="first-session",
    )
    second_id = create_user(
        app,
        user_id=110,
        email="second@example.com",
        fs_uniquifier="second-session",
    )
    token = issue_password_reset(app, first_id)

    with app.session_scope() as session:
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session, token, "change_email"
            )
        action = session.query(AccountActionToken).one()
        action.user_id = second_id
        session.commit()
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session, token, "password_reset"
            )


@pytest.mark.parametrize(
    "mutation",
    ("password", "email", "inactive", "unconfirmed"),
)
def test_password_reset_is_bound_to_current_account_state(app, mutation):
    user_id = create_user(
        app,
        user_id=114,
        email="state-bound@example.com",
        fs_uniquifier="state-bound-session",
    )
    reset_token = issue_password_reset(app, user_id)

    with app.session_scope() as session:
        user = session.query(User).filter_by(id=user_id).one()
        if mutation == "password":
            user.password = "Changed_valid_password2"
        elif mutation == "email":
            user.email = "changed-state@example.com"
        elif mutation == "inactive":
            user.active = False
        else:
            user.confirmed_at = None
        session.commit()

    with app.test_request_context(
        json={
            "token": reset_token,
            "password1": "Attacker_valid_password3",
            "password2": "Attacker_valid_password3",
        }
    ):
        reset_request_login_state()
        _, status = views.ResetPasswordView().put()
        assert status == 400
        reset_request_login_state()

    with app.session_scope() as session:
        user = session.query(User).filter_by(id=user_id).one()
        assert user.fs_uniquifier == "state-bound-session"
        assert not user.validate_password("Attacker_valid_password3")
        if mutation == "password":
            assert user.validate_password("Changed_valid_password2")
        else:
            assert user.validate_password("Valid_password1")
        assert session.query(AccountActionToken).count() == 1


def test_successful_reset_rotates_session_revokes_oauth_and_logs_in(
    app, monkeypatch
):
    user_id = create_user(
        app,
        user_id=111,
        email="reset@example.com",
        fs_uniquifier="old-session-id",
    )
    with app.session_scope() as session:
        oauth_client = OAuth2Client(
            user_id="old-session-id",
            client_id="owned-client",
        )
        oauth_client.set_client_metadata(
            {"client_name": "ADS API client", "scope": "user"}
        )
        session.add(oauth_client)
        session.flush()
        session.add(
            OAuth2Token(
                user_id="old-session-id",
                client_id=oauth_client.id,
                token_type="Bearer",
                access_token="owned-access-token",
                scope="user",
                issued_at=1,
                expires_in=4102444800,
            )
        )
        session.commit()
    reset_token = issue_password_reset(app, user_id)

    bearer_client = app.test_client()
    clear_cached_user()
    assert (
        bearer_client.get(
            "/accounts/protected",
            headers={"Authorization": "Bearer owned-access-token"},
        ).status_code
        == 200
    )
    clear_cached_user()

    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    monkeypatch.setitem(app.config, "SESSION_COOKIE_PATH", "/")
    reset_browser = app.test_client()
    response = reset_browser.put(
        "/accounts/user/reset-password",
        json={
            "token": reset_token,
            "password1": "New_valid_password2",
            "password2": "New_valid_password2",
        },
        base_url="https://localhost",
    )
    assert response.status_code == 200, response.get_json()
    assert "no-store" in response.headers["Cache-Control"]
    with reset_browser.session_transaction() as browser_session:
        replacement_session_id = browser_session["_user_id"]
    assert replacement_session_id != "old-session-id"

    clear_cached_user()
    assert (
        reset_browser.get(
            "/accounts/user/token", base_url="https://localhost"
        ).status_code
        == 200
    )
    clear_cached_user()
    assert (
        bearer_client.get(
            "/accounts/protected",
            headers={"Authorization": "Bearer owned-access-token"},
        ).status_code
        == 401
    )
    clear_cached_user()

    with app.session_scope() as session:
        user = session.query(User).filter_by(id=user_id).one()
        assert user.validate_password("New_valid_password2")
        assert user.fs_uniquifier == replacement_session_id
        assert session.query(AccountActionToken).count() == 0
        assert session.query(OAuth2Client).count() == 0
        assert session.query(OAuth2Token).count() == 0

    replay = reset_browser.put(
        "/accounts/user/reset-password",
        json={
            "token": reset_token,
            "password1": "Another_valid_password3",
            "password2": "Another_valid_password3",
        },
        base_url="https://localhost",
    )
    assert replay.status_code == 400
    clear_cached_user()

    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert user.validate_password("New_valid_password2")
    assert not user.validate_password("Another_valid_password3")


def test_failure_before_commit_rolls_back_password_session_and_consumption(app):
    user_id = create_user(
        app,
        user_id=112,
        email="rollback@example.com",
        fs_uniquifier="rollback-session-id",
    )
    with app.session_scope() as session:
        oauth_client = OAuth2Client(
            user_id="rollback-session-id",
            client_id="rollback-client",
        )
        session.add(oauth_client)
        session.flush()
        session.add(
            OAuth2Token(
                user_id="rollback-session-id",
                client_id=oauth_client.id,
                access_token="rollback-access-token",
            )
        )
        session.commit()
    reset_token = issue_password_reset(app, user_id)

    with app.test_request_context(
        json={
            "token": reset_token,
            "password1": "New_valid_password2",
            "password2": "New_valid_password2",
        }
    ):
        reset_request_login_state()
        with mock.patch.object(
            Session,
            "commit",
            side_effect=RuntimeError("injected transaction failure"),
        ):
            with pytest.raises(RuntimeError, match="injected"):
                views.ResetPasswordView().put()
        assert not current_user.is_authenticated
        reset_request_login_state()

    with app.session_scope() as session:
        user = session.query(User).filter_by(id=user_id).one()
        assert user.validate_password("Valid_password1")
        assert not user.validate_password("New_valid_password2")
        assert user.fs_uniquifier == "rollback-session-id"
        assert session.query(AccountActionToken).count() == 1
        assert session.query(OAuth2Client).count() == 1
        assert session.query(OAuth2Token).count() == 1
        verified_user, _ = app.security_service.verify_account_action_token(
            session, reset_token, "password_reset"
        )
        assert verified_user.id == user_id


def test_reset_consumption_requires_valid_csrf(app, monkeypatch):
    user_id = create_user(
        app,
        user_id=115,
        email="csrf-reset@example.com",
        fs_uniquifier="csrf-reset-session",
    )
    reset_token = issue_password_reset(app, user_id)
    monkeypatch.setitem(app.config, "SESSION_COOKIE_PATH", "/")
    client = app.test_client()

    clear_cached_user()
    rejected = client.put(
        "/accounts/user/reset-password",
        json={
            "token": reset_token,
            "password1": "New_valid_password2",
            "password2": "New_valid_password2",
        },
        base_url="https://localhost",
    )
    assert rejected.status_code == 400
    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert user.validate_password("Valid_password1")
    assert app.db.session.query(AccountActionToken).count() == 1

    clear_cached_user()
    csrf_response = client.get("/accounts/csrf", base_url="https://localhost")
    csrf_token = json.loads(csrf_response.data)["csrf"]
    clear_cached_user()
    accepted = client.put(
        "/accounts/user/reset-password",
        json={
            "token": reset_token,
            "password1": "New_valid_password2",
            "password2": "New_valid_password2",
        },
        headers={
            "X-CSRFToken": csrf_token,
            "Referer": "https://localhost/accounts/csrf",
        },
        base_url="https://localhost",
    )
    assert accepted.status_code == 200
    clear_cached_user()

    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert user.validate_password("New_valid_password2")
    assert app.db.session.query(AccountActionToken).count() == 0


def test_old_browser_session_is_revoked_after_reset(app, monkeypatch):
    user_id = create_user(
        app,
        user_id=113,
        email="sessions@example.com",
        fs_uniquifier="stolen-session-id",
    )
    reset_token = issue_password_reset(app, user_id)
    monkeypatch.setitem(app.config, "SESSION_COOKIE_PATH", "/")
    old_client = app.test_client()
    with old_client.session_transaction() as browser_session:
        browser_session["_user_id"] = "stolen-session-id"
        browser_session["_fresh"] = True
    clear_cached_user()
    assert (
        old_client.get(
            "/accounts/user/token", base_url="https://localhost"
        ).status_code
        == 200
    )
    clear_cached_user()

    with app.test_request_context(
        json={
            "token": reset_token,
            "password1": "New_valid_password2",
            "password2": "New_valid_password2",
        }
    ):
        reset_request_login_state()
        views.ResetPasswordView().put()
        reset_request_login_state()

    clear_cached_user()
    response = old_client.get(
        "/accounts/user/token", base_url="https://localhost"
    )
    assert response.status_code == 401
    clear_cached_user()


def test_body_routes_old_routes_and_sensitive_no_store(app, monkeypatch):
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    client = app.test_client()
    clear_cached_user()
    assert (
        client.post(
            "/accounts/user/reset-password/old@example.com",
            json={
                "email": "old@example.com",
                "g-recaptcha-response": "test",
            },
        ).status_code
        == 404
    )

    assert client.get("/accounts/user/reset-password/old-token").status_code == 404
    assert (
        client.put(
            "/accounts/user/reset-password/old-token",
            json={
                "password1": "New_valid_password2",
                "password2": "New_valid_password2",
            },
        ).status_code
        == 404
    )
    assert client.get("/accounts/user/reset-password").status_code == 405
    assert client.get("/accounts/user/reset-password/verify").status_code == 405

    sensitive_responses = (
        client.get("/accounts/csrf"),
        client.get("/accounts/bootstrap"),
        client.post(
            "/accounts/user/login",
            json={"email": "missing@example.com", "password": "invalid"},
        ),
        client.post(
            "/accounts/user/change-password",
            json={
                "old_password": "Old_valid_password1",
                "new_password1": "New_valid_password2",
                "new_password2": "New_valid_password2",
            },
        ),
        client.post(
            "/accounts/user/reset-password/verify",
            json={"token": "malformed"},
        ),
        client.put(
            "/accounts/user/reset-password",
            json={
                "token": "malformed",
                "password1": "New_valid_password2",
                "password2": "New_valid_password2",
            },
        ),
        client.get("/accounts/user/token"),
    )
    for response in sensitive_responses:
        assert "no-store" in response.headers["Cache-Control"]
        assert response.headers["Pragma"] == "no-cache"

    status = client.get("/accounts/status")
    assert "no-store" not in status.headers.get("Cache-Control", "")
    clear_cached_user()
