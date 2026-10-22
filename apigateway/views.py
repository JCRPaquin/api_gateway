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
from werkzeug.security import gen_salt

from apigateway import email_templates as templates
from apigateway import exceptions, extensions, schemas
from apigateway.domains import canonicalize_email
from apigateway.models import (
    EmailChangeRequest,
    OAuth2Client,
    OAuth2Token,
    PasswordChangeRequest,
    User,
)
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
                self._delete_existing_password_change_requests(session, user.id)
                action = self._create_password_change_request(session, user.id)
                session.flush()
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

                current_app.logger.info("Forcing password reset for user {}".format(user.email))

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

    def _delete_existing_password_change_requests(self, session, user_id: int):
        session.query(PasswordChangeRequest).filter(
            PasswordChangeRequest.user_id == user_id
        ).delete()

    def _create_password_change_request(self, session, user_id: int):
        password_change_request = PasswordChangeRequest(user_id=user_id)
        session.add(password_change_request)
        return password_change_request


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
    """A Resource for user registration.

    This resource handles user registration requests. It checks if the user is already registered
    and creates a new user if not"""

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
            user = session.query(User).filter_by(email=canonical_email).first()
            if user is None:
                user = extensions.security_service.create_user(
                    email=canonical_email,
                    password=params.password1,
                    commit=False,
                    given_name=params.given_name,
                    family_name=params.family_name,
                    registered_at=datetime.utcnow(),
                    login_count=0,
                )
                outcome = enqueue_notification(
                    "welcome_email",
                    {"user_id": user.id, **environment},
                    dedupe_key=f"registration:{canonical_email}",
                    session=session,
                    commit=False,
                    replace=True,
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
            user: User = session.query(User).filter_by(fs_uniquifier=current_user.get_id()).first()
            logout_user()
            session.delete(user)
            session.commit()

        return {"message": "success"}, 200

    @login_required
    @require_non_anonymous_bootstrap_user
    def put(self):
        params = schemas.update_user_request.load(_account_body())

        with current_app.session_scope() as session:
            user: User = session.query(User).filter_by(fs_uniquifier=current_user.get_id()).first()
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
    def get(self, token_or_email):
        user = extensions.security_service.verify_password_token(token=token_or_email)
        return {"email": user.email}, 200

    def post(self, token_or_email):
        params = schemas.captcha_request.load(_account_body())
        if not verify_recaptcha(params.g_recaptcha_response):
            return {"error": "captcha was not verified"}, 403
        try:
            schemas.validate_public_email(token_or_email)
            canonical_email = canonicalize_email(token_or_email)
        except (ValueError, ValidationError):
            return {"message": "Invalid email address"}, 400
        outcome = enqueue_account_request(
            "password_reset_request", canonical_email, request.headers.get("Host", "")
        )
        if outcome.state != DeliveryState.QUEUED:
            return _queue_unavailable_response()
        return {"message": ACCOUNT_ACCEPTED_MESSAGE}, 202

    def put(self, token_or_email):
        params = schemas.reset_password_request.load(_account_body())

        with current_app.session_scope() as session:
            try:
                # Resolve the account without taking the action lock, then acquire
                # locks in the same User -> PasswordChangeRequest order as reset
                # generation. The second lookup both locks and revalidates the
                # exact generation named by the bearer.
                candidate = extensions.security_service.verify_password_action(
                    token_or_email, session=session
                )
                user = (
                    session.query(User)
                    .filter_by(id=candidate.user_id)
                    .with_for_update()
                    .one()
                )
                action = extensions.security_service.verify_password_action(
                    token_or_email, session=session, for_update=True
                )
                if action.user_id != user.id:
                    raise ValueError("password reset action account changed")

                user = extensions.security_service.change_password(
                    user, params.password1, session=session, commit=False
                )
                session.delete(action)
                session.commit()
            except Exception:
                session.rollback()
                raise

            login_user(user)
            return {"message": "success"}, 200


class ChangeEmailView(Resource):
    decorators = [
        extensions.limiter_service.shared_limit("5/600 second"),
        login_required,
        require_non_anonymous_bootstrap_user,
    ]

    def post(self):
        params = schemas.change_email_request.load(_account_body())

        if not current_user.validate_password(params.password):
            return {"error": "the provided password is incorrect"}, 401

        try:
            canonical_email = canonicalize_email(params.email)
        except ValueError:
            return {"error": "the provided email address is invalid"}, 400
        if not extensions.security_service.validate_email(canonical_email):
            return {"error": "the provided email address is invalid"}, 400

        session = extensions.db.session
        try:
            if self._is_email_registered(session, canonical_email):
                return {"error": "{0} has already been registered".format(params.email)}, 403

            token: str = extensions.security_service.generate_email_token()
            self._delete_existing_email_change_requests(session)
            action = self._create_email_change_request(session, token, canonical_email)
            session.flush()
            environment = request_environment(request.headers.get("Host", ""))
            verification_outcome = enqueue_notification(
                "email_change_verification",
                {"action_id": action.id, **environment},
                dedupe_key=f"change-email-verify:{current_user.id}",
                session=session,
                commit=False,
                replace=True,
            )
            notification_outcome = enqueue_template_email(
                current_user.email,
                templates.EmailChangedNotification,
                ui_env=environment["ui_env"],
                ui_url=environment["ui_url"],
                dedupe_key=f"change-email-notify:{current_user.id}",
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

    def _delete_existing_email_change_requests(self, session):
        session.query(EmailChangeRequest).filter(
            EmailChangeRequest.user_id == current_user.id
        ).delete()

    def _create_email_change_request(self, session, token: str, new_email: str):
        email_change_request = EmailChangeRequest(
            token=token,
            user_id=current_user.id,
            new_email=new_email,
        )
        session.add(email_change_request)
        return email_change_request

    def _is_email_registered(self, session, email: str):
        return session.query(User).filter_by(email=email).first() is not None



class VerifyEmailView(Resource):
    decorators = [extensions.limiter_service.shared_limit("20/600 second")]

    def get(self, token):
        user = extensions.security_service.verify_email_token(token)
        with current_app.session_scope() as session:
            email_change_request = session.query(EmailChangeRequest).filter_by(token=token).first()
            if email_change_request is not None:
                extensions.security_service.change_email(
                    email_change_request.user, email_change_request.new_email
                )

                session.delete(email_change_request)

            session.query(User).filter_by(id=user.id).update({"confirmed_at": datetime.utcnow()})
            session.commit()
            login_user(user)

            return {"message": "success"}, 200

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
