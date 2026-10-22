import ast
import os
import inspect
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest import mock
from urllib.parse import urlsplit
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

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


def issue_email_action(app, user_id, purpose, target_email, now=None):
    with app.session_scope() as session:
        token = app.security_service.issue_account_action_token(
            session,
            user_id=user_id,
            purpose=purpose,
            target_email=target_email,
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

    legacy_token = "legacy-verification-bearer"
    with mock.patch.object(
        app.security_service, "verify_account_action_token"
    ) as verify:
        for method in ("GET", "POST", "PUT"):
            response = client.open(
                f"/accounts/verify/{legacy_token}",
                method=method,
                json={"token": legacy_token},
            )
            assert response.status_code in {404, 405}
        unsupported_verify_method = client.get("/accounts/verify")
        assert unsupported_verify_method.status_code == 405
        verify.assert_not_called()

    sensitive_responses = (
        unsupported_verify_method,
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
        client.post("/accounts/verify", json={"token": "malformed"}),
        client.put("/accounts/verify", json={"token": "malformed"}),
        client.put("/accounts/user/person@example.org/verify"),
        client.get("/accounts/user/token"),
    )
    for response in sensitive_responses:
        assert "no-store" in response.headers["Cache-Control"]
        assert response.headers["Pragma"] == "no-cache"

    status = client.get("/accounts/status")
    assert "no-store" not in status.headers.get("Cache-Control", "")
    clear_cached_user()


def test_verification_inspection_requires_csrf_and_rejects_unbounded_tokens(
    app, monkeypatch
):
    client = app.test_client()
    with mock.patch.object(
        app.security_service, "verify_account_action_token"
    ) as verify:
        rejected = client.post(
            "/accounts/verify",
            json={"token": "body-only-verification-bearer"},
            base_url="https://localhost",
        )
        assert rejected.status_code == 400
        verify.assert_not_called()

        monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
        for method in ("POST", "PUT"):
            response = client.open(
                "/accounts/verify",
                method=method,
                json={"token": "x" * 4097},
                base_url="https://localhost",
            )
            assert response.status_code == 400
            assert response.get_json() == {
                "message": "Invalid or expired account action token"
            }
        verify.assert_not_called()


def test_verification_exception_log_uses_constant_request_target(app):
    token = "secret-body-token-that-must-not-be-logged"
    with mock.patch.object(app.logger, "error") as logged, app.test_request_context(
        "/accounts/verify", method="PUT", json={"token": token}
    ):
        app.log_exception((RuntimeError, RuntimeError("failure"), None))

    assert token not in repr(logged.call_args)
    assert "/accounts/verify" in repr(logged.call_args)





def test_registration_commits_user_action_and_delivery_before_mail(app):
    payload = {
        "email": "atomic-registration@example.com",
        "password1": "Valid_password1",
        "password2": "Valid_password1",
        "g-recaptcha-response": "test",
    }
    with app.test_request_context(
        "/accounts/user", method="POST", json=payload
    ), mock.patch.object(views, "verify_recaptcha", return_value=True), mock.patch.object(
        notifications, "send_email"
    ) as send:
        response, status = views.UserManagementView().post()

    assert status == 202
    assert response == {"message": views.ACCOUNT_ACCEPTED_MESSAGE}
    user = app.db.session.query(User).filter_by(
        email="atomic-registration@example.com"
    ).one()
    action = app.db.session.query(AccountActionToken).one()
    job = app.db.session.query(NotificationOutbox).one()
    assert action.user_id == user.id
    assert action.purpose == "verify_registration"
    assert job.event_type == "account_action_delivery"
    assert job.payload["action_id"] == action.delivery_id
    assert "token" not in json.dumps(job.payload).lower()
    send.assert_not_called()


def test_registration_queue_failure_rolls_back_user_and_action(app):
    payload = {
        "email": "rollback-registration@example.com",
        "password1": "Valid_password1",
        "password2": "Valid_password1",
        "g-recaptcha-response": "test",
    }
    rejected = DeliveryResult("email", DeliveryState.REJECTED, "outbox_full")
    with app.test_request_context(
        "/accounts/user", method="POST", json=payload
    ), mock.patch.object(
        views, "verify_recaptcha", return_value=True
    ), mock.patch.object(
        views, "enqueue_notification", return_value=rejected
    ):
        _, status, _ = views.UserManagementView().post()

    assert status == 503
    assert app.db.session.query(User).count() == 0
    assert app.db.session.query(AccountActionToken).count() == 0
    assert app.db.session.query(NotificationOutbox).count() == 0


def test_concurrent_absent_registration_matches_existing_account_outcome(
    app, monkeypatch
):
    if app.db.engine.dialect.name != "postgresql":
        if os.environ.get("REQUIRE_POSTGRES_SECURITY_TESTS") == "1":
            pytest.fail("PostgreSQL security tests were required but not configured")
        pytest.skip("PostgreSQL row and unique-conflict semantics required")

    payload = {
        "email": "concurrent-registration@example.com",
        "password1": "Valid_password1",
        "password2": "Valid_password1",
        "g-recaptcha-response": "test",
    }
    arrivals = Barrier(2)
    original_create_user = app.security_service.create_user

    def synchronized_create_user(*args, **kwargs):
        arrivals.wait(timeout=10)
        return original_create_user(*args, **kwargs)

    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    monkeypatch.setattr(views, "verify_recaptcha", lambda _token: True)
    monkeypatch.setattr(
        app.security_service, "create_user", synchronized_create_user
    )
    app.db.session.remove()

    def register():
        response = app.test_client().post(
            "/accounts/user", json=payload, base_url="https://localhost"
        )
        return response.status_code, response.get_json()

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _index: register(), range(2)))

    expected = (202, {"message": views.ACCOUNT_ACCEPTED_MESSAGE})
    assert responses == [expected, expected]
    assert app.db.session.query(User).filter_by(
        email="concurrent-registration@example.com"
    ).count() == 1
    assert app.db.session.query(AccountActionToken).count() == 1
    jobs = app.db.session.query(NotificationOutbox).all()
    assert sorted(job.event_type for job in jobs) == [
        "account_action_delivery",
        "template_email",
    ]


def test_registration_inspection_does_not_mutate_or_swap_session(app, monkeypatch):
    target_id = create_user(
        app,
        user_id=201,
        email="pending@example.com",
        fs_uniquifier="pending-session",
        confirmed=False,
    )
    other_id = create_user(
        app,
        user_id=202,
        email="other-viewer@example.com",
        fs_uniquifier="other-viewer-session",
    )
    token = issue_email_action(
        app, target_id, "verify_registration", "pending@example.com"
    )
    monkeypatch.setitem(app.config, "SESSION_COOKIE_PATH", "/")
    client = app.test_client()
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
    clear_cached_user()
    login = client.post(
        "/accounts/user/login",
        json={
            "email": "other-viewer@example.com",
            "password": "Valid_password1",
        },
        base_url="https://localhost",
    )
    assert login.status_code == 200
    clear_cached_user()
    with client.session_transaction() as browser_session:
        session_before = dict(browser_session)

    clear_cached_user()
    response = client.post(
        "/accounts/verify",
        json={"token": token},
        base_url="https://localhost",
    )
    clear_cached_user()

    assert response.status_code == 200
    assert response.get_json()["flow"] == "verify_registration"
    with client.session_transaction() as browser_session:
        assert dict(browser_session) == session_before
    with app.session_scope() as session:
        target = session.query(User).filter_by(id=target_id).one()
        assert target.confirmed_at is None
        assert session.query(AccountActionToken).count() == 1
        assert session.query(User).filter_by(id=other_id).one().confirmed_at is not None



def test_email_change_inspection_does_not_apply_target(app):
    user_id = create_user(
        app,
        user_id=211,
        email="inspect-current@example.com",
        fs_uniquifier="inspect-email-change-session",
    )
    token = issue_email_action(
        app, user_id, "change_email", "inspect-target@example.com"
    )

    with app.test_request_context(method="POST", json={"token": token}):
        reset_request_login_state()
        response, status = views.VerifyEmailView().post()
        assert status == 200
        assert response == {
            "flow": "change_email",
            "email": "inspect-target@example.com",
        }
        assert not current_user.is_authenticated
        reset_request_login_state()

    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert str(user.email) == "inspect-current@example.com"
    assert app.db.session.query(AccountActionToken).count() == 1


def test_registration_put_requires_csrf_consumes_once_and_logs_in_after_commit(
    app, monkeypatch
):
    user_id = create_user(
        app,
        user_id=203,
        email="csrf-registration@example.com",
        fs_uniquifier="csrf-registration-session",
        confirmed=False,
    )
    token = issue_email_action(
        app,
        user_id,
        "verify_registration",
        "csrf-registration@example.com",
    )
    monkeypatch.setitem(app.config, "SESSION_COOKIE_PATH", "/")
    rejected_client = app.test_client()

    clear_cached_user()
    rejected = rejected_client.put(
        "/accounts/verify",
        json={"token": token},
        base_url="https://localhost",
    )
    assert rejected.status_code == 400
    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert user.confirmed_at is None
    assert app.db.session.query(AccountActionToken).count() == 1

    client = app.test_client()
    clear_cached_user()
    g.pop("csrf_token", None)
    csrf = client.get("/accounts/csrf", base_url="https://localhost").get_json()[
        "csrf"
    ]
    clear_cached_user()
    accepted = client.put(
        "/accounts/verify",
        json={"token": token},
        headers={
            "X-CSRFToken": csrf,
            "Referer": "https://localhost/accounts/csrf",
        },
        base_url="https://localhost",
    )
    assert accepted.status_code == 200, accepted.get_json()
    with client.session_transaction() as browser_session:
        assert browser_session["_user_id"] == "csrf-registration-session"
    clear_cached_user()

    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert user.confirmed_at is not None
    assert app.db.session.query(AccountActionToken).count() == 0
    replay = client.put(
        "/accounts/verify",
        json={"token": token},
        headers={
            "X-CSRFToken": csrf,
            "Referer": "https://localhost/accounts/csrf",
        },
        base_url="https://localhost",
    )
    assert replay.status_code == 400
    assert replay.get_json() == {
        "message": "Invalid or expired account action token"
    }
    clear_cached_user()


def test_registration_action_rejects_missing_row_cross_purpose_and_subject_mismatch(
    app,
):
    first_id = create_user(
        app,
        user_id=204,
        email="first-pending@example.com",
        fs_uniquifier="first-pending-session",
        confirmed=False,
    )
    second_id = create_user(
        app,
        user_id=205,
        email="second-pending@example.com",
        fs_uniquifier="second-pending-session",
        confirmed=False,
    )
    token = issue_email_action(
        app,
        first_id,
        "verify_registration",
        "first-pending@example.com",
    )
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
                session, token, "verify_registration"
            )
        session.delete(action)
        session.commit()
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session, token, "verify_registration"
            )


def test_registration_action_rejects_exact_expiry_and_changed_target(app):
    user_id = create_user(
        app,
        user_id=206,
        email="expiring-pending@example.com",
        fs_uniquifier="expiring-pending-session",
        confirmed=False,
    )
    issued_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    token = issue_email_action(
        app,
        user_id,
        "verify_registration",
        "expiring-pending@example.com",
        now=issued_at,
    )
    with app.session_scope() as session:
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session,
                token,
                "verify_registration",
                now=issued_at + timedelta(hours=24),
            )
        user = session.query(User).filter_by(id=user_id).one()
        user.email = "changed-pending@example.com"
        session.commit()
        with pytest.raises(AccountActionTokenError):
            app.security_service.verify_account_action_token(
                session,
                token,
                "verify_registration",
                now=issued_at + timedelta(hours=1),
            )
        assert session.query(AccountActionToken).count() == 1


def test_email_change_applies_only_bound_target_and_replays_fail(app):
    user_id = create_user(
        app,
        user_id=207,
        email="current@example.com",
        fs_uniquifier="email-change-session",
    )
    token = issue_email_action(
        app, user_id, "change_email", "bound-target@example.com"
    )

    with app.test_request_context(method="PUT", json={"token": token}):
        reset_request_login_state()
        response, status = views.VerifyEmailView().put()
        assert status == 200
        assert response["flow"] == "change_email"
        reset_request_login_state()

    user = app.db.session.query(User).filter_by(id=user_id).one()
    assert str(user.email) == "bound-target@example.com"
    assert app.db.session.query(AccountActionToken).count() == 0
    with app.test_request_context(method="PUT", json={"token": token}):
        reset_request_login_state()
        response, status = views.VerifyEmailView().put()
        assert status == 400
        assert response == {
            "message": "Invalid or expired account action token"
        }
        reset_request_login_state()


def test_email_change_target_claimed_before_consume_rolls_back(app):
    user_id = create_user(
        app,
        user_id=208,
        email="change-owner@example.com",
        fs_uniquifier="change-owner-session",
    )
    token = issue_email_action(
        app, user_id, "change_email", "newly-claimed@example.com"
    )
    create_user(
        app,
        user_id=209,
        email="newly-claimed@example.com",
        fs_uniquifier="target-owner-session",
    )

    with app.test_request_context(method="PUT", json={"token": token}):
        reset_request_login_state()
        response, status = views.VerifyEmailView().put()
        assert status == 400
        assert response == {
            "message": "Invalid or expired account action token"
        }
        reset_request_login_state()

    with app.session_scope() as session:
        user = session.query(User).filter_by(id=user_id).one()
        assert str(user.email) == "change-owner@example.com"
        action = session.query(AccountActionToken).one()
        verified_user, verified_action = (
            app.security_service.verify_account_action_token(
                session, token, "change_email"
            )
        )
        assert verified_user.id == user_id
        assert verified_action.id == action.id


def test_verification_resend_replaces_action_and_delivery(app):
    user_id = create_user(
        app,
        user_id=210,
        email="resend-pending@example.com",
        fs_uniquifier="resend-pending-session",
        confirmed=False,
    )
    original = issue_email_action(
        app,
        user_id,
        "verify_registration",
        "resend-pending@example.com",
    )
    original_action = app.db.session.query(AccountActionToken).one()
    environment = notifications.request_environment("localhost")
    notifications.enqueue_notification(
        "account_action_delivery",
        {"action_id": original_action.delivery_id, **environment},
        dedupe_key=f"account-action-delivery:{original_action.delivery_id}",
    )
    original_job = app.db.session.query(NotificationOutbox).one()
    original_job.state = "retry"
    original_job.available_at = datetime.utcnow() + timedelta(hours=1)
    app.db.session.commit()
    result = notifications.enqueue_account_request(
        "verification_resend_request",
        "resend-pending@example.com",
        "localhost",
    )
    assert result.state == DeliveryState.QUEUED
    claim = notifications.claim_notification()
    assert notifications._prepare_verification_resend(*claim) is None

    action = app.db.session.query(AccountActionToken).one()
    replacement = app.security_service.derive_account_action_token(action)
    assert replacement != original
    jobs = app.db.session.query(NotificationOutbox).order_by(
        NotificationOutbox.id
    ).all()
    assert jobs[0].state == "suppressed"
    assert jobs[0].payload == {}
    assert jobs[0].last_error == "action_replaced"
    job = jobs[1]
    assert job.event_type == "account_action_delivery"
    assert job.payload["action_id"] == action.delivery_id
    assert original not in json.dumps(job.payload)
    with pytest.raises(AccountActionTokenError):
        app.security_service.verify_account_action_token(
            app.db.session, original, "verify_registration"
        )
    user, current = app.security_service.verify_account_action_token(
        app.db.session, replacement, "verify_registration"
    )
    assert user.id == user_id
    assert current.id == action.id


def test_account_verification_migration_is_single_head_and_legacy_free():
    from apigateway import models, notifications as notification_module, services

    versions = Path(__file__).parents[2] / "migrations" / "versions"
    revisions = {}
    for path in versions.glob("*.py"):
        tree = ast.parse(path.read_text())
        values = {}
        for node in tree.body:
            if (
                isinstance(node, (ast.Assign, ast.AnnAssign))
                and isinstance(node.value, ast.Constant)
            ):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        values[target.id] = node.value.value
        revisions[values["revision"]] = values.get("down_revision")
    heads = set(revisions) - {parent for parent in revisions.values() if parent}
    assert heads == {"d4c3b2a1908f"}
    assert revisions["d4c3b2a1908f"] == "b8f2a6d41c73"

    assert not hasattr(models, "EmailChangeRequest")
    service = services.SecurityService
    for method in (
        "change_email",
        "generate_email_token",
        "verify_email_token",
        "generate_token",
        "verify_token",
    ):
        assert not hasattr(service, method)
    production_source = inspect.getsource(notification_module)
    assert "EmailChangeRequest" not in production_source
    assert "email_change_verification" not in production_source
