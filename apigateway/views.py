import binascii
import hashlib
import json
from datetime import datetime

from authlib.integrations.flask_oauth2 import current_token
from flask import current_app, render_template, request, session
from flask.sessions import SecureCookieSessionInterface
from flask_login import current_user, login_required, login_user, logout_user
from flask_restful import Resource, abort
from flask_wtf.csrf import generate_csrf
from marshmallow import ValidationError
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import gen_salt

from apigateway import email_templates as templates
from apigateway import exceptions, extensions, schemas
from apigateway.domains import canonicalize_email
from apigateway.models import AccountActionToken, OAuth2Client, OAuth2Token, User
from apigateway.notifications import (
    ACCOUNT_ACCEPTED_MESSAGE,
    enqueue_account_request,
    enqueue_feedback_notifications,
    enqueue_notification,
    enqueue_template_email,
    request_environment,
)
from apigateway.utils import (
    DeliveryState,
    generate_complete_blocklist,
    get_json_body,
    make_json_diff,
    require_non_anonymous_bootstrap_user,
    verify_recaptcha,
)
from werkzeug.exceptions import RequestEntityTooLarge

def _account_body():
    return get_json_body(
        request, max_bytes=current_app.config.get("ACCOUNT_MAX_REQUEST_BYTES", 16_384)
    )


def _queue_unavailable_response():
    return {"message": "Notification service unavailable"}, 503, {"Retry-After": "60"}

_REGISTRATION_EMAIL_CONSTRAINTS = frozenset(
    {"users_email_key", "user_email_key"}
)


def _is_registration_email_conflict(error: IntegrityError) -> bool:
    """Match only PostgreSQL's unique constraint for the account email."""
    original = getattr(error, "orig", None)
    sqlstate = getattr(original, "sqlstate", None) or getattr(
        original, "pgcode", None
    )
    diagnostic = getattr(original, "diag", None)
    return (
        sqlstate == "23505"
        and getattr(diagnostic, "constraint_name", None)
        in _REGISTRATION_EMAIL_CONSTRAINTS
    )


def _locked_registration_user(session, canonical_email):
    return (
        session.query(User)
        .filter_by(email=canonical_email)
        .with_for_update()
        .first()
    )


def _invalid_account_action_response():
    return {"message": exceptions.AccountActionTokenError().value}, 400


_EMAIL_ACTION_PURPOSES = ("verify_registration", "change_email")


def _verify_email_action(session, token: str, *, for_update: bool = False):
    """Resolve an email action without allowing one purpose to authorize another."""
    for purpose in _EMAIL_ACTION_PURPOSES:
        try:
            user, action = extensions.security_service.verify_account_action_token(
                session,
                token,
                purpose,
                for_update=for_update,
            )
        except exceptions.AccountActionTokenError:
            continue

        try:
            current_email = extensions.security_service.normalize_account_email(
                str(user.email)
            )
        except (TypeError, ValueError):
            raise exceptions.AccountActionTokenError()
        if (
            not user.active
            or user.is_anonymous_bootstrap_user
            or (
                purpose == "verify_registration"
                and (
                    user.confirmed_at is not None
                    or action.target_email != current_email
                )
            )
            or (
                purpose == "change_email"
                and (
                    user.confirmed_at is None
                    or action.target_email == current_email
                    or session.query(User.id)
                    .filter(
                        User.email == action.target_email,
                        User.id != user.id,
                    )
                    .first()
                    is not None
                )
            )
        ):
            raise exceptions.AccountActionTokenError()
        return purpose, user, action
    raise exceptions.AccountActionTokenError()





class BootstrapView(Resource):

    decorators = [extensions.auth_service.require_oauth(optional=True)]

    def get(self):
        params = schemas.bootstrap_request.load(_account_body())

        if not current_user.is_authenticated:
            bootstrap_user: User = User.query.filter_by(is_anonymous_bootstrap_user=True).first()
            if not bootstrap_user or not login_user(bootstrap_user):
                abort(500, message="Could not login as bootstrap user")

        if current_user.is_anonymous_bootstrap_user and (
            params.scope or params.client_name or params.redirect_uri
        ):
            abort(
                401,
                message="""Sorry, you cant change scope/name/redirect_uri when creating temporary OAuth application""",
            )

        if current_user.is_anonymous_bootstrap_user:
            client_id: str = None
            if "oauth_client" in session:
                client_id = session["oauth_client"]
            elif current_token:
                client_id = current_token.client.client_id

            if client_id:
                try:
                    client, token = extensions.auth_service.load_client(client_id)
                except exceptions.NoClientError:
                    client, token = extensions.auth_service.bootstrap_anonymous_user()
                    session["oauth_client"] = client.client_id
            # Check if the client_id is valid and that there is no client/user mismatch
            if not client_id or (
                client.user_id != current_user.get_id()
                and not current_user.is_anonymous_bootstrap_user
            ):
                client, token = extensions.auth_service.bootstrap_anonymous_user()
                session["oauth_client"] = client.client_id

        else:
            client, token = extensions.auth_service.bootstrap_user(
                client_name=params.client_name,
                scope=params.scope,
                ratelimit_multiplier=params.ratelimit,
                individual_ratelimit_multipliers=params.individual_ratelimits,
                expires=params.expires,
                create_client=params.create_new,
            )

        response = {
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "expires_at": token.expires_at(),
            "token_type": token.token_type,
            "scopes": token.scope.split(" ") if token.scope else [],
            "username": token.user.email,
            "anonymous": token.user.is_anonymous_bootstrap_user,
            "client_id": client.client_id,
            "client_name": client.client_name,
            "client_secret": client.client_secret,
            "ratelimit": client.ratelimit_multiplier,
            "individual_ratelimits": client.individual_ratelimit_multipliers,
            "given_name": token.user.given_name,
            "family_name": token.user.family_name,
        }
        return schemas.bootstrap_response.dump(response), 200


class UserAuthView(Resource):
    """Implements login and logout functionality"""

    decorators = [extensions.limiter_service.shared_limit("30/120 second")]

    def post(self):
        params = schemas.user_auth_request.load(_account_body())
        canonical_email = canonicalize_email(params.email)
        with current_app.session_scope() as session:
            user: User = (
                session.query(User)
                .filter_by(email=canonical_email)
                .with_for_update()
                .first()
            )

            if not user or not user.validate_password(params.password):
                abort(401, message="Invalid username or password")
            if not user.confirmed_at:
                abort(401, message="The account has not been verified")

            try:
                schemas.PasswordValidator()(params.password)
            except:  # noqa
                current_app.logger.info(
                    "Forcing creation of password reset action for user: %s", user.id
                )
                token = extensions.security_service.issue_account_action_token(
                    session,
                    user_id=user.id,
                    purpose="password_reset",
                    target_email=str(user.email),
                )
                action = session.query(AccountActionToken).filter_by(
                    token_digest=extensions.security_service.account_action_token_digest(token)
                ).one()
                environment = request_environment(request.headers.get("Host", ""))
                outcome = enqueue_notification(
                    "password_reset_action",
                    {"action_id": action.delivery_id, **environment},
                    dedupe_key=f"password-reset-delivery:{action.delivery_id}",
                    session=session,
                    commit=False,
                )
                if outcome.state != DeliveryState.QUEUED:
                    session.rollback()
                    return _queue_unavailable_response()
                session.commit()

                abort(
                    422,
                    message=(
                        "Your password does not meet the new requirements. "
                        "A password-reset email delivery request has been accepted."
                    ),
                )

            if current_user.is_authenticated:
                logout_user()

            login_user(user)

            user.last_login_at = datetime.now()
            user.login_count = user.login_count + 1 if user.login_count else 1

            session.commit()

        return {"message": "Successfully logged in"}, 200



class CSRFView(Resource):
    """
    Returns a csrf token
    """

    decorators = [extensions.limiter_service.limit("50/600 second")]

    def get(self):
        """
        Returns a csrf token
        """
        return {"csrf": generate_csrf()}, 200


class StatusView(Resource):
    """A resource that provides a health check endpoint for the API Gateway"""

    def get(self):
        return {"app": current_app.name, "status": "online"}, 200


class OAuthProtectedView(Resource):
    """A resource that checks whether the request is authorized with OAuth2.0."""

    decorators = [extensions.auth_service.require_oauth()]

    def get(self):
        return {"app": current_app.name, "oauth": current_token.user.email}, 200


class UserManagementView(Resource):
    """Create an account together with its durable verification action."""

    decorators = [extensions.limiter_service.shared_limit("50/600 second")]
    complete_blocklist = generate_complete_blocklist()

    def post(self):
        params = schemas.user_register_request.load(_account_body())
        if not verify_recaptcha(params.g_recaptcha_response):
            return {"error": "captcha was not verified"}, 403

        try:
            canonical_email = canonicalize_email(params.email)
        except ValueError as exc:
            return {"error": str(exc)}, 400
        domain = canonical_email.rsplit("@", 1)[1]
        if (
            current_app.config.get("BLOCK_DISPOSABLE_EMAIL_DOMAINS", False)
            and domain in self.complete_blocklist
        ):
            return {
                "error": "Account registration with disposable email services is not allowed."
            }, 400

        session = extensions.db.session
        environment = request_environment(request.headers.get("Host", ""))
        try:
            user = _locked_registration_user(session, canonical_email)
            created = False
            if user is None:
                try:
                    user = extensions.security_service.create_user(
                        email=canonical_email,
                        password=params.password1,
                        commit=False,
                        given_name=params.given_name,
                        family_name=params.family_name,
                        registered_at=datetime.utcnow(),
                        active=True,
                        login_count=0,
                    )
                    created = True
                except IntegrityError as error:
                    if not _is_registration_email_conflict(error):
                        raise
                    session.rollback()
                    user = _locked_registration_user(session, canonical_email)
                    if user is None:
                        raise

            if created:
                extensions.security_service.issue_account_action_token(
                    session,
                    user_id=user.id,
                    purpose="verify_registration",
                    target_email=canonical_email,
                )
                action = session.query(AccountActionToken).filter_by(
                    user_id=user.id, purpose="verify_registration"
                ).one()
                outcome = enqueue_notification(
                    "account_action_delivery",
                    {"action_id": action.delivery_id, **environment},
                    dedupe_key=f"account-action-delivery:{action.delivery_id}",
                    session=session,
                    commit=False,
                )
            else:
                outcome = enqueue_template_email(
                    canonical_email,
                    templates.AccountRegistrationAttemptEmail,
                    ui_env=environment["ui_env"],
                    ui_url=environment["ui_url"],
                    dedupe_key=f"registration:{canonical_email}",
                    session=session,
                    commit=False,
                )
            if outcome.state != DeliveryState.QUEUED:
                session.rollback()
                return _queue_unavailable_response()
            session.commit()
        except Exception:
            session.rollback()
            current_app.logger.exception("Registration transaction failed")
            return _queue_unavailable_response()
        return {"message": ACCOUNT_ACCEPTED_MESSAGE}, 202

    @login_required
    @require_non_anonymous_bootstrap_user
    def delete(self):
        with current_app.session_scope() as session:
            user = session.query(User).filter_by(
                fs_uniquifier=current_user.get_id()
            ).first()
            logout_user()
            session.delete(user)
            session.commit()
        return {"message": "success"}, 200

    @login_required
    @require_non_anonymous_bootstrap_user
    def put(self):
        params = schemas.update_user_request.load(_account_body())
        with current_app.session_scope() as session:
            user = session.query(User).filter_by(
                fs_uniquifier=current_user.get_id()
            ).first()
            user.given_name = params.given_name or user.given_name
            user.family_name = params.family_name or user.family_name
            session.commit()
        return {"message": "success"}, 200


class LogoutView(Resource):
    """Logs out the current user"""

    def post(self):
        logout_user()
        return {"message": "success"}, 200


class ChangePasswordView(Resource):
    @login_required
    @require_non_anonymous_bootstrap_user
    def post(self):
        params = schemas.change_password_request.load(_account_body())

        if not current_user.validate_password(params.old_password):
            return {"error": "please verify your current password"}, 401

        extensions.security_service.change_password(current_user, params.new_password1)
        return {"message": "success"}, 200


class ResetPasswordView(Resource):
    """Issue and consume password-reset account actions without URL credentials."""
    def get(self):
        abort(405, message="Method not allowed")

    def post(self):
        params = schemas.reset_password_initiate_request.load(_account_body())
        if not verify_recaptcha(params.g_recaptcha_response):
            return {"error": "captcha was not verified"}, 403
        try:
            canonical_email = canonicalize_email(params.email)
        except ValueError:
            return {"message": ACCOUNT_ACCEPTED_MESSAGE}, 202
        outcome = enqueue_account_request(
            "password_reset_request", canonical_email, request.headers.get("Host", "")
        )
        if outcome.state != DeliveryState.QUEUED:
            return _queue_unavailable_response()
        return {"message": ACCOUNT_ACCEPTED_MESSAGE}, 202

    def put(self):
        params = schemas.reset_password_request.load(_account_body())

        committed_user_id = None
        with current_app.session_scope() as session:
            try:
                user, action = extensions.security_service.verify_account_action_token(
                    session,
                    params.token,
                    "password_reset",
                    for_update=True,
                )
                previous_session_id = user.fs_uniquifier
                session.query(OAuth2Token).filter(
                    OAuth2Token.user_id == previous_session_id
                ).delete(synchronize_session=False)
                session.query(OAuth2Client).filter(
                    OAuth2Client.user_id == previous_session_id
                ).delete(synchronize_session=False)
                extensions.security_service.set_password_in_transaction(
                    user, params.password1
                )
                user.fs_uniquifier = gen_salt(64)
                session.delete(action)
                committed_user_id = user.id
                session.commit()
            except exceptions.AccountActionTokenError as error:
                session.rollback()
                return {"message": error.value}, 400
            except Exception:
                session.rollback()
                raise

        user = User.query.filter_by(id=committed_user_id).one()
        login_user(user)
        return {"message": "success"}, 200


class ResetPasswordVerifyView(Resource):
    """Inspect a password-reset capability without consuming it."""
    def get(self):
        abort(405, message="Method not allowed")


    def post(self):
        params = schemas.account_action_token_request.load(_account_body())
        with current_app.session_scope() as session:
            try:
                user, _ = extensions.security_service.verify_account_action_token(
                    session,
                    params.token,
                    "password_reset",
                )
            except exceptions.AccountActionTokenError as error:
                session.rollback()
                return {"message": error.value}, 400
            return {"email": user.email}, 200


class ChangeEmailView(Resource):
    decorators = [
        extensions.limiter_service.shared_limit("5/600 second"),
        login_required,
        require_non_anonymous_bootstrap_user,
    ]

    def post(self):
        params = schemas.change_email_request.load(_account_body())
        try:
            canonical_email = canonicalize_email(params.email)
        except ValueError:
            return {"error": "the provided email address is invalid"}, 400
        if not extensions.security_service.validate_email(canonical_email):
            return {"error": "the provided email address is invalid"}, 400

        session = extensions.db.session
        try:
            user = (
                session.query(User)
                .populate_existing()
                .filter(User.id == current_user.id)
                .with_for_update()
                .one_or_none()
            )
            if user is None:
                session.rollback()
                return {"message": "Unauthorized"}, 401
            if not user.validate_password(params.password):
                session.rollback()
                return {"error": "the provided password is incorrect"}, 401
            if session.query(User.id).filter(User.email == canonical_email).first():
                session.rollback()
                return {
                    "error": "{0} has already been registered".format(params.email)
                }, 403

            extensions.security_service.issue_account_action_token(
                session,
                user_id=user.id,
                purpose="change_email",
                target_email=canonical_email,
            )
            action = session.query(AccountActionToken).filter_by(
                user_id=user.id, purpose="change_email"
            ).one()
            environment = request_environment(request.headers.get("Host", ""))
            verification_outcome = enqueue_notification(
                "account_action_delivery",
                {"action_id": action.delivery_id, **environment},
                dedupe_key=f"account-action-delivery:{action.delivery_id}",
                session=session,
                commit=False,
            )
            notification_outcome = enqueue_template_email(
                str(user.email),
                templates.EmailChangedNotification,
                ui_env=environment["ui_env"],
                ui_url=environment["ui_url"],
                dedupe_key=f"change-email-notify:{user.id}",
                session=session,
                commit=False,
                replace=True,
            )
            if any(
                outcome.state != DeliveryState.QUEUED
                for outcome in (verification_outcome, notification_outcome)
            ):
                session.rollback()
                return _queue_unavailable_response()
            session.commit()
            return {"message": "success"}, 202
        except Exception:
            session.rollback()
            current_app.logger.exception("Email change transaction failed")
            return _queue_unavailable_response()


class VerifyEmailView(Resource):
    """Inspect or consume a body-carried registration or email-change action."""

    decorators = [extensions.limiter_service.shared_limit("20/600 second")]

    def post(self):
        try:
            params = schemas.account_action_token_request.load(_account_body())
        except ValidationError:
            return _invalid_account_action_response()

        with current_app.session_scope() as session:
            try:
                purpose, _, action = _verify_email_action(session, params.token)
                response = {"flow": purpose, "email": action.target_email}
                session.rollback()
                return response, 200
            except exceptions.AccountActionTokenError:
                session.rollback()
                return _invalid_account_action_response()

    def put(self):
        try:
            params = schemas.account_action_token_request.load(_account_body())
        except ValidationError:
            return _invalid_account_action_response()

        committed_user_id = None
        purpose = None
        session = extensions.db.session
        try:
            purpose, user, action = _verify_email_action(
                session, params.token, for_update=True
            )
            if purpose == "verify_registration":
                current_email = extensions.security_service.normalize_account_email(
                    str(user.email)
                )
                if action.target_email != current_email:
                    raise exceptions.AccountActionTokenError()
                user.confirmed_at = datetime.utcnow()
            else:
                target_email = (
                    extensions.security_service.normalize_account_email(
                        action.target_email
                    )
                )
                if (
                    target_email
                    == extensions.security_service.normalize_account_email(
                        str(user.email)
                    )
                    or session.query(User.id)
                    .filter(User.email == target_email, User.id != user.id)
                    .first()
                    is not None
                ):
                    raise exceptions.AccountActionTokenError()
                user.email = target_email

            committed_user_id = user.id
            session.delete(action)
            session.commit()
        except (exceptions.AccountActionTokenError, IntegrityError):
            session.rollback()
            return _invalid_account_action_response()
        except Exception:
            session.rollback()
            raise

        committed_user = User.query.filter_by(id=committed_user_id).one()
        login_user(committed_user)
        return {"message": "success", "flow": purpose}, 200


class VerificationResendView(Resource):
    """Accept an account-independent verification resend request."""

    decorators = [extensions.limiter_service.shared_limit("20/600 second")]

    def put(self, email):
        try:
            schemas.validate_public_email(email)
            canonical_email = canonicalize_email(email)
        except (ValueError, ValidationError):
            return {"message": "Invalid email address"}, 400
        outcome = enqueue_account_request(
            "verification_resend_request",
            canonical_email,
            request.headers.get("Host", ""),
        )
        if outcome.state != DeliveryState.QUEUED:
            return _queue_unavailable_response()
        return {"message": ACCOUNT_ACCEPTED_MESSAGE}, 202





class ChacheManagementView(Resource):
    """A view for managing the cache.

    This class provides an API endpoint for clearing the cache based on the provided key and parameters.


    Examples:

    Clearing the cache for a specific resource and parameters:

    DELETE
    {
        "key": "/scan/metadata/article/extra/123",
        "parameters": {"test": "123"}
    }

    """

    decorators = [extensions.auth_service.require_oauth("adsws:internal")]

    def delete(self):
        params = schemas.clear_cache_request.load(get_json_body(request))
        extensions.cache_service.clear_cache(params.key, params.parameters)
        return {"message": "success"}, 200


class LimiterManagementView(Resource):
    """A view for managing rate limits.

    This class provides an API endpoint for clearing rate limits based on the provided key and scope.

    Examples:

    Clearing the rate limit for a specific internal resource and user:

    DELETE
    {
        "key": "csrfview",
        "scope": "csrfview:user@example.com"
    }

    Clearing the rate limit for a external resource and user:

    DELETE
    {
        "key": "/scan/metadata/collection",
        "scope": "user@example.com"
    }


    """

    decorators = [extensions.auth_service.require_oauth("adsws:internal")]

    def delete(self):
        params = schemas.clear_limit_request.load(get_json_body(request))
        extensions.limiter_service.clear_limits(params.key, params.scope)
        return {"message": "success"}, 200


class UserInfoView(Resource):
    """
    Implements getting user info from session ID, access token or
    client id. It should be limited to internal use only.
    """

    decorators = [
        # extensions.limiter_service.shared_limit("500/43200 second"),
        extensions.auth_service.require_oauth("adsws:internal"),
    ]

    def get(self, account_data):
        """
        This endpoint provides the full identifying data associated to a given
        session, user id, access token or client id. Example:

        curl -H 'authorization: Bearer:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            'https://dev.adsabs.harvard.edu/v1/accounts/info/yyyy'

        Where 'yyyy' can be a session, access token, user id or client id.

        Notice that sessions are not server side, but client stored and server
        signed to avoid user manipulation.
        """
        ## Input data can be a session, a access token or a user id
        # 1) Try to treat input data as a session
        try:
            session_data = self._decodeFlaskCookie(account_data)
            if "oauth_client" in session_data:
                # Anonymous users always have their oauth_client id in the session
                token = (
                    OAuth2Token.query.join(OAuth2Client)
                    .filter(OAuth2Client.client_id == session_data["oauth_client"])
                    .first()
                )
                if token:
                    return self._translate(token, source="session:client_id")
                else:
                    # Token not found in database
                    return {"message": "Identifier not found [ERR 010]"}, 404

            elif "user_id" in session_data:
                # There can be more than one token per user (generally one for
                # BBB and one for API requests), when client id is not stored
                # in the session (typically for authenticated users) we pick
                # just the first in the database that corresponds to BBB since
                # sessions are used by BBB and not API requests
                client = OAuth2Client.query.filter_by(
                    user_id=session_data["user_id"], name="BB client"
                ).first()

                if client:
                    token = OAuth2Token.query.filter_by(
                        client_id=client.id, user_id=session_data["user_id"]
                    ).first()

                    if token:
                        return self._translate(token, source="session:user_id")
                    else:
                        # Token not found in database
                        return {"message": "Identifier not found [ERR 020]"}, 404
                else:
                    # Client ID not found in database
                    return {"message": "Identifier not found [ERR 030]"}, 404
            elif "_user_id" in session_data:
                # There can be more than one token per user (generally one for
                # BBB and one for API requests), when client id is not stored
                # in the session (typically for authenticated users) we pick
                # just the first in the database that corresponds to BBB since
                # sessions are used by BBB and not API requests
                client = OAuth2Client.query.filter_by(
                    user_id=session_data["_user_id"], name="BB client"
                ).first()

                if client:
                    token = OAuth2Token.query.filter_by(
                        client_id=client.id, user_id=session_data["_user_id"]
                    ).first()

                    if token:
                        return self._translate(token, source="session:user_id")
                    else:
                        # Token not found in database
                        return {"message": "Identifier not found [ERR 020]"}, 404
                else:
                    # Client ID not found in database
                    return {"message": "Identifier not found [ERR 030]"}, 404
            else:
                # This should not happen, all ADS created session should contain that parameter
                return {"message": "Missing oauth_client/user_id parameter in session"}, 500
        except Exception:
            # Try next identifier type
            pass

        # 2) Try to treat input data as access token
        token = OAuth2Token.query.filter_by(access_token=account_data).first()
        if token:
            return self._translate(token, source="access_token")

        # 3) Try to treat input data as client id
        token = (
            OAuth2Token.query.join(OAuth2Client)
            .filter(OAuth2Client.client_id == account_data)
            .first()
        )
        if token:
            return self._translate(token, source="client_id")

        # Data not decoded sucessfully/Identifier not found
        return {"message": "Identifier not found [ERR 050]"}, 404

    def _translate(self, token: OAuth2Token, source=None):
        user: User = token.user
        anonymous = user.is_anonymous_bootstrap_user

        hashed_client_id = self._hash_id(token.client_id)
        hashed_user_id = hashed_client_id if anonymous else self._hash_id(token.user_id)

        return {
            "hashed_user_id": hashed_user_id,  # Permanent, all the anonymous users will have hashed_client_id instead
            "hashed_client_id": hashed_client_id,  # A single user has a client ID for the BB token and another for the API, anonymous users have a unique client ID linked to the anonymous user id (id 1)
            "anonymous": anonymous,  # True, False or None if email could not be retreived/anonymous validation could not be executed
            "source": source,  # Identifier used to recover information: session:client_id, session:user_id, user_id, access_token, client_id
        }, 200

    def _decodeFlaskCookie(self, cookie_value):
        sscsi = SecureCookieSessionInterface()
        signingSerializer = sscsi.get_signing_serializer(current_app)
        return signingSerializer.loads(cookie_value)

    def _hash_id(self, id):
        # 10 rounds of SHA-256 hash digest algorithm for HMAC (pseudorandom function)
        # with a length of 2x32
        # NOTE: 100,000 rounds is recommended but it is too slow and security is not
        # that important here, thus we just do 10 rounds

        if id is None:
            return None

        return binascii.hexlify(
            hashlib.pbkdf2_hmac(
                "sha256",
                str(id).encode(),
                str(current_app.secret_key).encode(),
                10,
                dklen=32,
            )
        ).decode()


class UserFeedbackView(Resource):
    """Validate, bound, and enqueue public feedback notifications."""

    decorators = [
        extensions.limiter_service.shared_limit("500/600 second"),
        extensions.csrf.exempt,
    ]

    def post(self):
        params = get_json_body(
            request,
            max_bytes=current_app.config.get("FEEDBACK_MAX_REQUEST_BYTES", 262_144),
        )
        params = schemas.validate_feedback_payload(
            params,
            current_app.config["FEEDBACK_FORMS_ORIGIN"],
            current_app.config["BBB_FEEDBACK_ORIGIN"],
        )
        if not verify_recaptcha(params.get("g-recaptcha-response")):
            return {"message": "Captcha was not verified"}, 403

        email_body, attachments, submitter_email = self._prepare_email_and_attachments(params)
        subject = params["_subject"]
        if subject == "Associated Articles":
            subject = f"{subject} ({params['relationship']})"

        email_result, slack_result = enqueue_feedback_notifications(
            params.get("name", "TownCrier"),
            submitter_email,
            subject,
            email_body,
            attachments,
            self._prepare_slack_data(params, subject, email_body),
        )
        delivery = {
            "email": email_result.state.value,
            "slack": slack_result.state.value,
        }
        if all(
            outcome.state == DeliveryState.QUEUED
            for outcome in (email_result, slack_result)
        ):
            return {"message": "accepted", "delivery": delivery}, 202
        return {"message": "Notification service unavailable", "delivery": delivery}, 503

    def _prepare_email_and_attachments(self, params):
        template = current_app.config["FEEDBACK_TEMPLATES"].get(params["_subject"])
        attachments = self._prepare_attachments(params, template)
        body = self._prepare_email_body(params, template)
        submitter_email = (
            params["email"]
            if params["origin"] == current_app.config["FEEDBACK_FORMS_ORIGIN"]
            else params["_replyto"]
        )
        return body, attachments, submitter_email

    @staticmethod
    def _escape_slack_text(value):
        controlled = "".join(
            char
            for char in str(value)
            if char in "\n\t" or (ord(char) >= 32 and ord(char) != 127)
        )
        return controlled.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _prepare_slack_data(self, params, subject, email_body):
        forms_origin = current_app.config["FEEDBACK_FORMS_ORIGIN"]
        is_form = params["origin"] == forms_origin
        text = (
            f'Received data from feedback form "{subject}" from {params["email"]}'
            if is_form
            else f"Incoming Feedback\n{email_body}"
        )
        text = self._escape_slack_text(text)
        payload = {
            "text": text,
            "channel": current_app.config["FEEDBACK_SLACK_CHANNEL"],
            "username": current_app.config["FEEDBACK_SLACK_USERNAME"],
            "icon_emoji": (
                current_app.config["FORM_SLACK_EMOJI"]
                if is_form
                else current_app.config["FEEDBACK_SLACK_EMOJI"]
            ),
            "mrkdwn": False,
        }
        max_bytes = current_app.config.get("FEEDBACK_SLACK_MAX_PAYLOAD_BYTES", 65_536)
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > max_bytes:
            available = max(max_bytes - 1024, 0)
            payload["text"] = payload["text"].encode("utf-8")[:available].decode(
                "utf-8", errors="ignore"
            )
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        if len(encoded) > max_bytes:
            raise RequestEntityTooLarge("Slack payload is too large")
        return payload

    def _prepare_email_body(self, params, template):
        if not template:
            raise ValueError(f"No template found for {params['_subject']}")
        render_params = dict(params)
        if template.get("update", False):
            render_params["diff"] = make_json_diff(params["original"], params["updated"])
        elif template.get("new", False):
            new_record = dict(params["new"])
            new_record["author_list"] = ";".join(new_record.get("authors", []))
            render_params["new"] = new_record
        body = render_template(template["file"], data=render_params).replace("[tab]", "\t")
        if len(body.encode("utf-8")) > 262_144:
            raise RequestEntityTooLarge("Rendered feedback body is too large")
        return body

    def _prepare_attachments(self, params, template):
        records = []
        if template.get("new", False):
            records.append(("new_record.json", params["new"]))
        if template.get("update", False):
            records.extend(
                (
                    ("updated_record.json", params["updated"]),
                    ("original_record.json", params["original"]),
                )
            )
        if len(records) > 2:
            raise RequestEntityTooLarge("Too many feedback attachments")

        attachments = []
        total = 0
        for filename, record in records:
            encoded = json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            if len(encoded) > 131_072:
                raise RequestEntityTooLarge("Feedback attachment is too large")
            total += len(encoded)
            if total > 262_144:
                raise RequestEntityTooLarge("Feedback attachments are too large")
            attachments.append((filename, encoded))
        return attachments


class PersonalTokenView(Resource):
    decorators = [
        extensions.limiter_service.shared_limit("500/43200 second"),
        login_required,
        require_non_anonymous_bootstrap_user,
    ]

    def get(self):
        clients = (
            OAuth2Client.query.filter_by(user_id=current_user.get_id())
            .order_by(OAuth2Client.client_id_issued_at.desc())
            .all()
        )

        client = next((c for c in clients if c.client_name == "ADS API client"), None)

        if not client:
            return {"message": "No ADS API client found"}, 200

        token = OAuth2Token.query.filter_by(
            client_id=client.id,
            user_id=current_user.get_id(),
        ).first()

        if not token:
            current_app.logger.error(
                "No token found for ADS API Client with id {0}. This should not happen!".format(
                    client.id
                )
            )
            return {"message": "No token found for ADS API client"}, 500

        response = {
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "expires_at": token.expires_at(),
            "token_type": token.token_type,
            "scopes": token.scope.split(" ") if token.scope else [],
            "username": token.user.email,
            "anonymous": token.user.is_anonymous_bootstrap_user,
            "client_id": client.client_id,
            "user_id": current_user.get_id(),
        }

        return schemas.personal_token_response.dump(response), 200

    def put(self):
        salt_length = current_app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)

        clients = (
            OAuth2Client.query.filter_by(user_id=current_user.get_id())
            .order_by(OAuth2Client.client_id_issued_at.desc())
            .all()
        )

        client = next((c for c in clients if c.client_name == "ADS API client"), None)

        with current_app.session_scope() as session:
            if not client:
                client = OAuth2Client(
                    user_id=current_user.get_id(),
                    last_activity=datetime.now(),
                )
                client.set_client_metadata(
                    {
                        "client_name": "ADS API client",
                        "description": "ADS API client",
                        "scope": " ".join(current_app.config.get("USER_API_DEFAULT_SCOPES", "")),
                        "is_internal": True,
                    }
                )
                client.gen_salt()

                session.add(client)
                session.commit()

                token = OAuth2Token(
                    token_type="Bearer",
                    client_id=client.id,
                    user_id=client.user_id,
                    access_token=gen_salt(salt_length),
                    refresh_token=gen_salt(salt_length),
                    scope=" ".join(current_app.config.get("USER_API_DEFAULT_SCOPES", "")),
                    expires_in=(datetime(2050, 1, 1) - datetime.now()).total_seconds(),
                )
                session.add(token)

            else:
                token = (
                    session.query(OAuth2Token)
                    .filter_by(
                        client_id=client.id,
                        user_id=current_user.get_id(),
                    )
                    .first()
                )

                if not token:
                    current_app.logger.error(
                        "No token found for ADS API Client with id {0}. This should not happen!".format(
                            client.id
                        )
                    )
                    return {"message": "No token found for the ADS API client"}, 500

                token.access_token = gen_salt(salt_length)

            session.commit()

            response = {
                "access_token": token.access_token,
                "refresh_token": token.refresh_token,
                "expires_at": token.expires_at(),
                "token_type": token.token_type,
                "scopes": token.scope.split(" ") if token.scope else [],
                "username": token.user.email,
                "anonymous": token.user.is_anonymous_bootstrap_user,
                "client_id": client.client_id,
                "user_id": current_user.get_id(),
            }

            return schemas.personal_token_response.dump(response), 200


class UserResolverView(Resource):
    """Resolves an email or uid into a string formatted user object"""

    decorators = [extensions.auth_service.require_oauth("adsws:internal")]

    def get(self, id):
        """
        :param identifier: email address or uid
        :return: json containing user info or 404
        """

        try:
            user_id = int(id)
        except ValueError:
            user_id = None
        try:
            email_id = canonicalize_email(id) if "@" in id else id
        except ValueError:
            email_id = None

        u = User.query.filter(
            or_(
                User.id == user_id,
                User.email == email_id,
                User.fs_uniquifier == id,
            )
        ).first()

        if u is None:
            abort(404)

        return {
            "id": u.id,
            "email": u.email,
        }


class Resources(Resource):
    """Overview of available resources"""

    def get(self):
        r = {}
        app = current_app
        r[app.name] = {}
        r[app.name]["base"] = request.script_root

        for rule in app.url_map.iter_rules():
            is_external = rule.endpoint.startswith("/")
            split_rule = rule.rule[1:].split("/")

            first_path = split_rule[0] if is_external or len(split_rule) > 1 else "general"

            # If the first path is not in the dictionary, add it
            if first_path not in r[app.name]:
                r[app.name][first_path] = []

            # Append the rule to the corresponding first path
            r[app.name][first_path].append(rule.rule)

        return r
