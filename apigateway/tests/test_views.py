
from datetime import datetime
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
import requests
from flask_login import current_user, login_user
from marshmallow import ValidationError
from werkzeug.exceptions import Unauthorized

from apigateway import views
from apigateway.email_templates import EmailChangedNotification
from apigateway.models import AnonymousUser, EmailChangeRequest, User
from apigateway.schemas import bootstrap_response
from apigateway.domains import canonicalize_domain
from apigateway.utils import (
    DeliveryResult,
    DeliveryState,
    ProxyView,
    generate_complete_blocklist,
)


class TestBootstrapView:
    @pytest.fixture
    def bootstrap(self):
        return views.BootstrapView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "test_user"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_get_authenticated_user(self, app, bootstrap, mock_regular_user, authenticated_user):
        with app.test_request_context(json={}):
            response, status_code = bootstrap.get()

            assert status_code == 200
            assert not bootstrap_response.validate(response)

    def test_get_authenticated_user_with_params(
        self, app, bootstrap, mock_regular_user, authenticated_user
    ):
        req_json = {
            "scope": "test_scope",
            "client_name": "test_client",
            "redirect_uri": "test_uri",
        }
        with app.test_request_context(json=req_json):
            response, status_code = bootstrap.get()
            parsed_response = bootstrap_response.load(response)

            assert status_code == 200
            assert not bootstrap_response.validate(response)
            assert parsed_response.scopes == req_json["scope"].split(" ")

    def test_get_anonymous_user_with_params(self, app, bootstrap, mock_anon_user):
        json = {"scope": "test_scope", "client_name": "test_client", "redirect_uri": "test_uri"}
        with app.test_request_context(json=json):
            with pytest.raises(Unauthorized):
                bootstrap.get()


class TestUserAuthView:
    @pytest.fixture
    def user_auth_view(self):
        return views.UserAuthView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    @pytest.fixture
    def unverified_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.email = "test_unverified@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id_unverified"
            app.db.session.add(user)
            app.db.session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_successful_login(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": authenticated_user.email, "password": "Valid_password1"}
        ):
            _, status_code = user_auth_view.post()

            assert status_code == 200

    def test_post_invalid_password(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": authenticated_user.email, "password": "invalid_password"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()

    def test_post_invalid_email(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": "invalid@gmail.com", "password": "Valid_password1"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()

    def test_post_unverified_account(self, app, unverified_user, user_auth_view):
        with app.test_request_context(
            json={"email": unverified_user.email, "password": "Valid_password1"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()


class TestProxyView:
    @pytest.fixture(scope="function")
    def mock_session(self):
        with patch("requests.Session", new_callable=MagicMock) as mock_session:
            mock_session.return_value.get.return_value.status_code = 200
            mock_session.return_value.get.return_value.headers = {
                "test_allowed_header": "value",
                "test_disallowed_header": "value",
            }
            yield mock_session

    @pytest.fixture(scope="module")
    def proxy_view(self):
        return ProxyView.as_view(
            "proxy_view", deploy_path="/proxy", remote_base_url="http://remote.com"
        )

    @pytest.fixture(scope="module", autouse=True)
    def register_proxy_view(self, app, proxy_view):
        app.add_url_rule("/proxy", view_func=proxy_view, methods=["GET", "POST"])

    @pytest.fixture
    def client(self, app):
        return app.test_client()

    def test_proxy_request_get(self, client, mock_session, mock_redis_service):
        response = client.get("/proxy")
        assert response.status_code == 200
        assert mock_session.return_value.get.call_count == 1

    def test_proxy_request_connection_error(self, client, mock_session, mock_redis_service):
        mock_session.return_value.get.side_effect = requests.exceptions.ConnectionError
        response = client.get("/proxy")
        assert response.data == b"504 Gateway Timeout"
        assert response.status_code == 504
        assert response.content_type == "text/html; charset=utf-8"
        assert response.content_length is not None

    def test_proxy_request_timeout(self, client, mock_session, mock_redis_service):
        mock_session.return_value.get.side_effect = requests.exceptions.Timeout
        response = client.get("/proxy")
        assert response.data == b"504 Gateway Timeout"
        assert response.status_code == 504
        assert response.content_type == "text/html; charset=utf-8"
        assert response.content_length is not None

    def test_allowed_headers(self, app, client, mock_session, mock_redis_service):
        response = client.get("/proxy")
        assert "test_allowed_header" in list(response.headers.keys())

    def test_disallowed_headers(self, app, client, mock_session, mock_redis_service):
        response = client.get("/proxy")
        assert "test_disallowed_header" not in list(response.headers.keys())


class TestCSRFView:
    @pytest.fixture
    def csrf_view(self):
        return views.CSRFView()

    def test_get_csrf_token(self, app, csrf_view):
        with app.test_request_context():
            data, status_code = csrf_view.get()
            assert status_code == 200
            assert "csrf" in data


class TestOAuthProtectedView:
    @pytest.fixture
    def oauth_protected_view(self):
        return views.OAuthProtectedView()

    def test_get(self, app, oauth_protected_view, mock_regular_user, mock_current_token):
        with app.test_request_context():
            mock_current_token.user = mock_regular_user
            data, status_code = oauth_protected_view.get()
            assert status_code == 200
            assert data["oauth"] == mock_regular_user.email


class TestUserManagementView:
    @pytest.fixture
    def user_management_view(self):
        return views.UserManagementView()

    @pytest.fixture
    def new_user_data(self):
        return {
            "given_name": "Test",
            "family_name": "User",
            "email": "testuser@gmail.com",
            "password1": "test_passwordU1",
            "password2": "test_passwordU1",
            "g-recaptcha-response": "test-captcha",
        }

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_new_user(self, app, user_management_view, new_user_data):
        with app.test_request_context(json=new_user_data):
            response, status_code = user_management_view.post()
            assert status_code == 202
            assert response == {"message": views.ACCOUNT_ACCEPTED_MESSAGE}

    def test_post_new_user_invalid_data(self, app, user_management_view, new_user_data):
        new_user_data["email"] = "invalid_email"
        with app.test_request_context(json=new_user_data):
            with pytest.raises(ValidationError):
                user_management_view.post()

    @pytest.mark.parametrize("domain", ["0-mail.com", "0-MAIL.COM"])
    def test_post_new_user_disposable_email(
        self, app, user_management_view, new_user_data, domain
    ):
        new_user_data["email"] = f"test@{domain}"
        with app.test_request_context(json=new_user_data):
            _, status_code = user_management_view.post()
            assert status_code == 400

    def test_post_new_user_disposable_email_from_local_blocklist(
        self, app, user_management_view, new_user_data
    ):
        new_user_data["email"] = "test@BLOBAPPS.COM"
        with app.test_request_context(json=new_user_data):
            _, status_code = user_management_view.post()
            assert status_code == 400

    def test_domain_policy_normalizes_curated_entries(self):
        assert canonicalize_domain(" BlobApps.COM.\n") == "blobapps.com"
        assert "blobapps.com" in generate_complete_blocklist()

    def test_post_existing_user(self, app, user_management_view, authenticated_user):
        existing_user = {
            "given_name": "Test",
            "family_name": "User",
            "password1": "test_passwordU1",
            "password2": "test_passwordU1",
            "email": authenticated_user.email,
            "g-recaptcha-response": "test-captcha",
        }

        with app.test_request_context(json=existing_user):
            response, status_code = user_management_view.post()
            assert status_code == 202
            assert response == {"message": views.ACCOUNT_ACCEPTED_MESSAGE}

    def test_delete_user(self, app, user_management_view, authenticated_user):
        with app.test_request_context():
            login_user(authenticated_user)
            response, status_code = user_management_view.delete()
            assert status_code == 200
            assert response["message"] == "success"


class TestLogoutView:
    @pytest.fixture
    def logout_view(self):
        return views.LogoutView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_logout(self, app, logout_view, authenticated_user):
        with app.test_request_context():
            login_user(authenticated_user)
            _, status_code = logout_view.post()
            assert status_code == 200
            assert isinstance(current_user._get_current_object(), AnonymousUser)


class TestChangePasswordView:
    @pytest.fixture
    def change_password_view(self):
        return views.ChangePasswordView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_change_password(self, app, change_password_view, authenticated_user):
        with app.test_request_context(
            json={
                "old_password": "Valid_password1",
                "new_password1": "New_valid_password1",
                "new_password2": "New_valid_password1",
            }
        ):
            login_user(authenticated_user)
            response, status_code = change_password_view.post()
            assert status_code == 200
            assert response["message"] == "success"

    def test_post_change_password_invalid_new_password(
        self, app, change_password_view, authenticated_user
    ):
        with app.test_request_context(
            json={
                "old_password": "Valid_password1",
                "new_password1": "invalid_password",
                "new_password2": "invalid_password",
            }
        ):
            login_user(authenticated_user)
            with pytest.raises(ValidationError):
                change_password_view.post()

    def test_post_change_password_not_matching_password(
        self, app, change_password_view, authenticated_user
    ):
        with app.test_request_context(
            json={
                "old_password": "Valid_password1",
                "new_password1": "Valid_password12",
                "new_password2": "Valid_password22",
            }
        ):
            login_user(authenticated_user)
            with pytest.raises(ValidationError):
                change_password_view.post()

    def test_post_change_password_invalid_old_password(
        self, app, change_password_view, authenticated_user
    ):
        with app.test_request_context(
            json={
                "old_password": "invalid_password",
                "new_password1": "New_valid_password1",
                "new_password2": "New_valid_password1",
            }
        ):
            login_user(authenticated_user)
            response, status_code = change_password_view.post()
            assert status_code == 401
            assert "error" in response


class TestChangeEmailView:
    @pytest.fixture
    def change_email_view(self):
        return views.ChangeEmailView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    @pytest.fixture
    def send_email_mock(self):
        queued = DeliveryResult("email", DeliveryState.QUEUED, "queued")
        with mock.patch(
            "apigateway.views.enqueue_notification", return_value=queued
        ) as action_mail, mock.patch(
            "apigateway.views.enqueue_template_email", return_value=queued
        ) as notice_mail:
            yield action_mail, notice_mail

    def test_post_change_email(self, app, change_email_view, authenticated_user, send_email_mock):
        old_email = authenticated_user.email
        action_mail, notice_mail = send_email_mock
        with app.test_request_context(
            json={"password": "Valid_password1", "email": "new_email@gmail.com"},
        ):
            login_user(authenticated_user)
            _, status_code = change_email_view.post()
            assert status_code == 202
            assert action_mail.call_args.args[0] == "email_change_verification"
            assert action_mail.call_args.args[1]["action_id"] > 0
            assert action_mail.call_args.args[1]["ui_env"] == "ADS"
            assert action_mail.call_args.kwargs["commit"] is False
            notice_mail.assert_called_once_with(
                old_email,
                EmailChangedNotification,
                ui_env="ADS",
                ui_url="https://ui.adsabs.harvard.edu",
                dedupe_key=f"change-email-notify:{authenticated_user.id}",
                session=mock.ANY,
                commit=False,
                replace=True,
            )

    def test_post_change_email_scix(self, app, change_email_view, authenticated_user, send_email_mock):
        old_email = authenticated_user.email
        action_mail, notice_mail = send_email_mock
        with app.test_request_context(
            json={"password": "Valid_password1", "email": "new_email@gmail.com"},
            headers={"Host": "scixplorer.org"},
        ):
            login_user(authenticated_user)
            _, status_code = change_email_view.post()
            assert status_code == 202
            assert action_mail.call_args.args[1]["ui_env"] == "SciX"
            assert action_mail.call_args.args[1]["ui_url"] == "https://scixplorer.org"
            notice_mail.assert_called_once_with(
                old_email,
                EmailChangedNotification,
                ui_env="SciX",
                ui_url="https://scixplorer.org",
                dedupe_key=f"change-email-notify:{authenticated_user.id}",
                session=mock.ANY,
                commit=False,
                replace=True,
            )

    def test_post_change_email_incorrect_password(
        self, app, change_email_view, authenticated_user
    ):
        with app.test_request_context(
            json={"password": "Incorrect_password1", "email": "new_email@gmail.com"}
        ):
            login_user(authenticated_user)
            response, status_code = change_email_view.post()
            assert status_code == 401
            assert response["error"] == "the provided password is incorrect"

    def test_post_change_email_invalid_email(self, app, change_email_view, authenticated_user):
        with app.test_request_context(
            json={"password": "Valid_password1", "email": "invalid_email"}
        ):
            login_user(authenticated_user)
            with pytest.raises(ValidationError):
                change_email_view.post()

    def test_post_change_email_existing_email(self, app, change_email_view, authenticated_user):
        with app.test_request_context(
            json={"password": "Valid_password1", "email": authenticated_user.email}
        ):
            login_user(authenticated_user)
            _, status_code = change_email_view.post()
            assert status_code == 403


class TestVerifyEmailView:
    @pytest.fixture
    def verify_email_view(self):
        return views.VerifyEmailView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    @pytest.fixture
    def email_change_request(self, app, authenticated_user):
        with app.session_scope() as session:
            request = EmailChangeRequest()
            request.user_id = authenticated_user.id
            request.new_email = "new_email@gmail.com"
            session.add(request)
            session.commit()
            yield request

        with app.session_scope() as session:
            session.delete(request)
            session.commit()

    def test_get_valid_token(
        self, app, verify_email_view, authenticated_user, email_change_request
    ):
        with app.test_request_context():
            email_change_request.token = app.security_service.generate_email_token()
            login_user(authenticated_user)
            response, status_code = verify_email_view.get(email_change_request.token)
            assert status_code == 200
            assert response["message"] == "success"

    def test_get_no_associated_token(self, app, verify_email_view, authenticated_user):
        with app.test_request_context():
            login_user(authenticated_user)
            _, status_code = verify_email_view.get(app.security_service.generate_email_token())
            assert status_code == 200

    def test_get_invalid_token(self, app, verify_email_view, authenticated_user):
        with app.test_request_context():
            login_user(authenticated_user)
            with pytest.raises(ValueError, match="unknown verification token"):
                verify_email_view.get("invalid_token")
