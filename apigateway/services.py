"""Module defining API Gateway services."""

import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Callable, Tuple
from urllib.parse import urljoin

import requests
from authlib.integrations.flask_oauth2 import current_token, token_authenticated
from authlib.oauth2.rfc6750 import BearerTokenValidator
from cachelib.serializers import RedisSerializer
from flask import Flask, current_app, g, request
from flask.wrappers import Response
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.extension import LimitDecorator
from flask_limiter.util import get_remote_address
from flask_login import current_user
from flask_security import Security, SQLAlchemyUserDatastore
from itsdangerous import URLSafeSerializer
from kafka import KafkaProducer
from redis import Redis, StrictRedis
from redis.exceptions import ConnectionError, TimeoutError
from sqlalchemy import func, or_
from werkzeug.datastructures import Headers

from apigateway import extensions
from apigateway.domains import canonicalize_email
from apigateway.exceptions import (
    AccountActionTokenError,
    NoClientError,
    ValidationError,
)
from apigateway.models import (
    AccountActionToken,
    AnonymousUser,
    OAuth2Client,
    OAuth2Token,
    Role,
    User,
)
from apigateway.utils import GatewayResourceProtector, ProxyView

def normalize_scopes(scopes):
    """Return scopes in stable order, with whitespace and duplicates removed."""
    normalized = []
    seen = set()
    for value in scopes or []:
        for scope in value.split():
            if scope not in seen:
                seen.add(scope)
                normalized.append(scope)
    return normalized


def validate_user_scopes(user: User, scopes):
    """Validate and normalize requested scopes against a user's scope policy."""
    requested_scopes = normalize_scopes(scopes)
    allowed_scopes = set(user.allowed_scopes)
    if "*" not in allowed_scopes and not allowed_scopes.issuperset(requested_scopes):
        raise ValidationError(
            "The user account (%s) does not have the requested scopes. Requested: %s, Allowed: %s"
            % (user.email, set(requested_scopes), allowed_scopes)
        )
    return requested_scopes


def validate_client_scopes(client: OAuth2Client, scopes):
    """Validate requested scopes against an existing client's authorization envelope."""
    requested_scopes = normalize_scopes(scopes)
    authorized_scopes = set((client.scope or "").split())
    if "*" not in authorized_scopes and not authorized_scopes.issuperset(requested_scopes):
        raise ValidationError(
            "The OAuth client does not authorize the requested scopes. Requested: %s, Authorized: %s"
            % (set(requested_scopes), authorized_scopes)
        )
    return requested_scopes




class GatewayService:
    """Base class for initializing a service, setting up logging and config."""

    def __init__(self, name: str, app: Flask = None):
        self._name = name
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Initializes the application with this service.

        Args:
            app (Flask): The Flask application to initialize.
        """
        if app is None:
            return

        self._logger = logging.getLogger(f"{app.name}.{self._name}")

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions[self._name.lower()] = self

        app.__setattr__(self._name.lower(), self)

        self._app = app

    def get_service_config(self, key: str, default: any = None) -> any:
        """Get the value of a configuration setting for this service.
        The name of the service is prepended to the key to form the full configuration key.

        Args:
            key (str): The name of the configuration setting to retrieve.
            default (any, optional): The default value to return if the configuration setting is not found. Defaults to None.

        Returns:
            any: The value of the configuration setting, or the default value if the setting is not found.
        """
        return self._app.config.get(self._name + "_" + key, default)


@dataclass(frozen=True)
class IssuedCredential:
    """A raw credential paired with the persisted non-secret records."""

    client: OAuth2Client
    token: OAuth2Token
    access_token: str


class DigestBearerTokenValidator(BearerTokenValidator):
    """Authenticate raw bearer values against accepted keyed digests."""

    def __init__(self, service):
        super().__init__()
        self.service = service

    def authenticate_token(self, token_string):
        return self.service.lookup_access_token(token_string)

    def token_revoked(self, token):
        return bool(getattr(token, "revoked", False))


class AuthService(GatewayService):
    """A class that provides authentication services for the API Gateway."""

    MODALITY_HEADER = "X-Access-Modality"

    def __init__(self, name: str = "AUTH_SERVICE"):
        """Initializes the AuthService.

        Args:
            name (str, optional): The name of the AuthService. Defaults to "AUTH".
        """
        super().__init__(name)
        self.require_oauth = GatewayResourceProtector()

    def init_app(self, app: Flask):
        """Initializes the AuthService with the Flask app.

        Args:
            app (Flask): The Flask app to initialize the AuthService with.
        """
        super().init_app(app)
        self._access_token_keys = app.config["ACCESS_TOKEN_HMAC_KEYS"]
        self._active_access_token_key_id = app.config[
            "ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID"
        ]
        self.accepted_access_token_key_ids = tuple(self._access_token_keys)
        self.require_oauth.register_token_validator(DigestBearerTokenValidator(self))
        self._register_hooks(app)

    def _register_hooks(self, app: Flask):
        """Registers hooks that manipulate the headers of the request.

        Args:
            app (Flask): The Flask application to register the hooks with.
        """

        @app.before_request
        def before_request_hook():
            """Adds the X-api-uid header to the request if the user is authenticated with a session cookie."""
            headers = Headers(request.headers.items())

            # Stop clients from spoofing the identity/modality headers.
            headers.pop(AuthService.MODALITY_HEADER, None)
            headers.pop("X-api-uid", None)

            if current_user.is_authenticated:
                headers.add_header("X-api-uid", current_user.id)

            request.headers = headers

        token_authenticated.connect(self._token_authenticated, weak=False)

    def _token_authenticated(self, sender, token: OAuth2Token = None, **kwargs):
        """Record bearer activity durably and add authenticated request headers."""
        if token is None:
            return

        user = token.user
        if user is None:
            extensions.db.session.rollback()
            raise NoClientError("OAuth token has no associated owner")
        client = self._record_bearer_activity(token)

        user_id = user.id
        headers = Headers(request.headers.items())
        headers.add_header("X-api-uid", user_id)

        # The only differentiator between API and UI clients is the client_name
        client_name = client.client_name
        modality = "api" if client_name and "API" in client_name else "ui"

        g.access_modality = modality
        headers[AuthService.MODALITY_HEADER] = modality
        request.headers = headers

    def digest_access_token(self, raw_token: str, key_id: str = None) -> str:
        """Return the versioned HMAC digest used for bearer lookup."""
        if not isinstance(raw_token, str) or not raw_token:
            return ""
        selected_key_id = key_id or self._active_access_token_key_id
        key = self._access_token_keys[selected_key_id]
        return hmac.new(
            key, ("v1:" + raw_token).encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _record_bearer_activity(self, token: OAuth2Token) -> OAuth2Client:
        """Persist throttled bearer activity before the protected view runs."""
        if not isinstance(token, OAuth2Token):
            client = getattr(token, "client", None)
            if client is None:
                raise NoClientError("OAuth token has no associated client")
            return client
        if token.client_id is None:
            extensions.db.session.rollback()
            raise NoClientError("OAuth token has no associated client")

        session = extensions.db.session
        client = (
            session.query(OAuth2Client)
            .filter(OAuth2Client.id == token.client_id)
            .one_or_none()
        )
        if client is None:
            session.rollback()
            raise NoClientError("OAuth client no longer exists")

        try:
            interval = float(
                self._app.config.get("OAUTH2_ACTIVITY_WRITE_INTERVAL", 300)
            )
        except (TypeError, ValueError):
            interval = 0.0
        if not math.isfinite(interval) or interval < 0:
            interval = 0.0
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stale_before = now - timedelta(seconds=interval)

        try:
            updated = (
                session.query(OAuth2Client)
                .filter(
                    OAuth2Client.id == token.client_id,
                    or_(
                        OAuth2Client.last_activity.is_(None),
                        OAuth2Client.last_activity <= stale_before,
                    ),
                )
                .update(
                    {OAuth2Client.last_activity: now},
                    synchronize_session=False,
                )
            )
            if updated == 0:
                client = (
                    session.query(OAuth2Client)
                    .filter(OAuth2Client.id == token.client_id)
                    .populate_existing()
                    .one_or_none()
                )
                if client is None:
                    raise NoClientError("OAuth client no longer exists")
            session.commit()
        except Exception:
            session.rollback()
            raise
        return client

    def lookup_access_token(self, raw_token: str):
        candidates = [
            (key_id, self.digest_access_token(raw_token, key_id))
            for key_id in self.accepted_access_token_key_ids
        ]
        if not candidates:
            return None
        return (
            extensions.db.session.query(OAuth2Token)
            .filter(
                or_(
                    *[
                        (
                            (OAuth2Token.token_key_id == key_id)
                            & (OAuth2Token.access_token == digest)
                        )
                        for key_id, digest in candidates
                    ]
                )
            )
            .first()
        )

    _ANONYMOUS_ADMISSION_SCRIPT = """
local source_count = redis.call('INCR', KEYS[1])
if source_count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
local global_count = redis.call('INCR', KEYS[2])
if global_count == 1 then redis.call('EXPIRE', KEYS[2], ARGV[4]) end
if source_count > tonumber(ARGV[1]) or global_count > tonumber(ARGV[3]) then
    return 0
end
return 1
"""

    @staticmethod
    def _fixed_window_limit(value):
        counts, remainder = value.split("/", 1)
        seconds = remainder.split(" ", 1)[0]
        return int(counts), int(seconds)

    def admit_anonymous_issuance(self, source: str) -> bool:
        """Atomically enforce authoritative source and global Redis limits."""
        source_limit, source_window = self._fixed_window_limit(
            self._app.config["ANONYMOUS_ISSUANCE_SOURCE_LIMIT"]
        )
        global_limit, global_window = self._fixed_window_limit(
            self._app.config["ANONYMOUS_ISSUANCE_GLOBAL_LIMIT"]
        )
        now = int(time.time())
        source_bucket = now // source_window
        global_bucket = now // global_window
        source_digest = hashlib.sha256(
            (source or "unknown").encode("utf-8")
        ).hexdigest()
        result = extensions.redis_service.eval(
            self._ANONYMOUS_ADMISSION_SCRIPT,
            2,
            "oauth:anonymous:source:{}:{}".format(source_digest, source_bucket),
            "oauth:anonymous:global:{}".format(global_bucket),
            source_limit,
            source_window + 1,
            global_limit,
            global_window + 1,
        )
        return int(result) == 1

    @staticmethod
    def binding_digest(binding_id: str) -> str:
        if not isinstance(binding_id, str) or not binding_id:
            raise ValidationError("A browser binding is required")
        return hashlib.sha256(("oauth-browser-v1:" + binding_id).encode()).hexdigest()

    def get_credential_metadata(
        self, owner, *, purpose: str, binding_digest: str = None
    ):
        """Return non-secret metadata for an owner's current credential."""
        query = OAuth2Client.query.filter_by(
            user_id=owner.get_id(), credential_purpose=purpose
        )
        if purpose == "anonymous":
            if not binding_digest:
                return None
            query = query.filter_by(binding_digest=binding_digest)
        client = query.order_by(OAuth2Client.id.desc()).first()
        if client is None:
            return None
        token = (
            OAuth2Token.query.filter_by(
                client_id=client.id,
                user_id=owner.get_id(),
                credential_purpose=purpose,
            )
            .order_by(OAuth2Token.id.desc())
            .first()
        )
        if token is None or token.is_expired():
            return None
        return client, token

    def issue_credential(
        self,
        owner,
        *,
        purpose: str,
        scopes=None,
        expires_in: int = None,
        client_name: str = None,
        ratelimit_multiplier: float = 1.0,
        individual_ratelimit_multipliers: dict = None,
        binding_digest: str = None,
        rotate: bool = True,
        credential_delivery_path: str = None,
        prepare_delivery: Callable = None,
    ) -> IssuedCredential:
        """Create or rotate a bearer credential in one locked transaction.

        ``owner`` is explicit by design: this policy primitive never derives
        authorization from Flask's ``current_user``.
        """
        db_session = extensions.db.session
        try:
            locked_owner = self._lock_owner(db_session, owner)
            self._validate_owner_and_purpose(
                locked_owner, purpose, binding_digest=binding_digest
            )
            resolved_scopes = self._resolve_and_validate_scopes(
                locked_owner, purpose, scopes
            )
            lifetime = self._validate_expiry(purpose, expires_in)
            base_capacity, route_capacities = self._validate_capacities(
                ratelimit_multiplier, individual_ratelimit_multipliers
            )

            existing = self._find_locked_client(
                db_session,
                locked_owner,
                purpose,
                binding_digest=binding_digest,
            )
            if existing is not None and (
                db_session.query(OAuth2Token.id)
                .filter_by(
                    client_id=existing.id,
                    credential_delivery_pending=True,
                )
                .first()
                is not None
            ):
                raise ValidationError(
                    "Credential delivery is pending and must be recovered first"
                )
            if existing is not None and not rotate:
                raise ValidationError("An active credential already exists")

            requested_capacity = max(
                [base_capacity] + list(route_capacities.values())
            )
            self._enforce_quota(
                db_session,
                locked_owner,
                requested_capacity,
                purpose,
                existing_client=existing,
            )

            if existing is None:
                client = OAuth2Client(
                    user_id=locked_owner.get_id(),
                    ratelimit_multiplier=base_capacity,
                    individual_ratelimit_multipliers=route_capacities or None,
                    last_activity=datetime.now(timezone.utc).replace(tzinfo=None),
                    credential_purpose=purpose,
                    binding_digest=binding_digest,
                )
                client.set_client_metadata(
                    {
                        "client_name": client_name
                        or self._default_client_name(purpose),
                        "description": client_name
                        or self._default_client_name(purpose),
                        "scope": " ".join(resolved_scopes),
                    }
                )
                client.gen_salt()
                db_session.add(client)
                db_session.flush()
            else:
                client = existing
                client.ratelimit_multiplier = base_capacity
                client.individual_ratelimit_multipliers = route_capacities or None
                client.last_activity = datetime.now(timezone.utc).replace(tzinfo=None)
                client.set_client_metadata(
                    {
                        "client_name": client_name or client.client_name,
                        "description": client_name or client.client_name,
                        "scope": " ".join(resolved_scopes),
                    }
                )
                db_session.query(OAuth2Token).filter_by(client_id=client.id).delete(
                    synchronize_session=False
                )

            raw_token = secrets.token_urlsafe(32)
            token = OAuth2Token(
                token_type="Bearer",
                client_id=client.id,
                user_id=locked_owner.get_id(),
                access_token=self.digest_access_token(raw_token),
                token_key_id=self._active_access_token_key_id,
                token_digest_version=1,
                scope=" ".join(resolved_scopes),
                expires_in=lifetime,
                credential_purpose=purpose,
                is_personal=purpose in {"personal", "operator"},
                credential_delivery_pending=credential_delivery_path is not None,
                credential_delivery_path=credential_delivery_path,
            )
            if (credential_delivery_path is None) != (prepare_delivery is None):
                raise ValidationError(
                    "Credential delivery path and preparation callback are both required"
                )
            db_session.add(token)
            db_session.flush()
            issued = IssuedCredential(client, token, raw_token)
            if prepare_delivery is not None:
                prepare_delivery(issued)
            db_session.commit()
            return issued
        except Exception:
            db_session.rollback()
            raise

    def _lock_owner(self, db_session, owner):
        query = db_session.query(User)
        if isinstance(owner, User):
            if owner.id is not None:
                query = query.filter(User.id == owner.id)
            else:
                query = query.filter(User.fs_uniquifier == owner.get_id())
        elif isinstance(owner, str):
            query = query.filter(User.fs_uniquifier == owner)
        else:
            raise ValidationError("A valid credential owner is required")
        locked_owner = query.with_for_update().one_or_none()
        if locked_owner is None:
            raise ValidationError("Credential owner not found")
        return locked_owner

    def _validate_owner_and_purpose(self, owner, purpose, *, binding_digest):
        if purpose not in {"anonymous", "browser", "personal", "operator"}:
            raise ValidationError("Invalid credential purpose")
        if not owner.active:
            raise ValidationError("Credential owner is inactive")
        if purpose == "anonymous":
            if not owner.is_anonymous_bootstrap_user or not binding_digest:
                raise ValidationError("Invalid anonymous credential owner or binding")
        elif owner.is_anonymous_bootstrap_user:
            raise ValidationError("Anonymous owners cannot receive this credential")

    def _default_client_name(self, purpose):
        if purpose in {"personal", "operator"}:
            return "ADS API client"
        return self._app.config.get("BOOTSTRAP_CLIENT_NAME", "BB client")

    def _resolve_and_validate_scopes(self, owner, purpose, scopes):
        if scopes is None:
            key = (
                "BOOTSTRAP_SCOPES"
                if purpose == "anonymous"
                else "USER_API_DEFAULT_SCOPES"
                if purpose in {"personal", "operator"}
                else "USER_DEFAULT_SCOPES"
            )
            scopes = self._app.config.get(key, [])
        elif isinstance(scopes, str):
            scopes = scopes.split()
        if not isinstance(scopes, (list, tuple)) or any(
            not isinstance(scope, str) or not scope for scope in scopes
        ):
            raise ValidationError("Scopes must be a list of non-empty strings")
        resolved = tuple(dict.fromkeys(scopes))
        allowed = set(owner.allowed_scopes)
        if "*" not in allowed and not allowed.issuperset(resolved):
            raise ValidationError("Requested scopes exceed the owner's allowed scopes")
        return resolved

    def _validate_expiry(self, purpose, expires_in):
        maximum = 24 * 60 * 60 if purpose == "anonymous" else 30 * 24 * 60 * 60
        if expires_in is None:
            expires_in = (
                self._app.config.get("BOOTSTRAP_TOKEN_EXPIRES", maximum)
                if purpose == "anonymous"
                else self._app.config.get("PERSONAL_TOKEN_EXPIRES", maximum)
            )
        if (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, (int, float))
            or not math.isfinite(expires_in)
            or expires_in <= 0
            or expires_in > maximum
        ):
            raise ValidationError("Credential lifetime is outside the allowed bound")
        return int(expires_in)

    def _validate_capacities(self, base, routes):
        def valid(value):
            return (
                not isinstance(value, bool)
                and isinstance(value, (int, float))
                and math.isfinite(value)
                and value > 0
            )

        if not valid(base):
            raise ValidationError("Rate-limit capacity must be finite and positive")
        if routes is None:
            return float(base), {}
        if not isinstance(routes, dict):
            raise ValidationError("Route capacities must be an object")
        registered = set(self._app.view_functions)
        normalized = {}
        for endpoint, value in routes.items():
            if (
                not isinstance(endpoint, str)
                or endpoint not in registered
                or not valid(value)
            ):
                raise ValidationError(
                    "Route capacities require exact registered endpoint names "
                    "and finite positive values"
                )
            normalized[endpoint] = float(value)
        return float(base), normalized

    def _find_locked_client(
        self, db_session, owner, purpose, *, binding_digest=None
    ):
        query = db_session.query(OAuth2Client).filter_by(
            user_id=owner.get_id(), credential_purpose=purpose
        )
        if purpose == "anonymous":
            query = query.filter_by(binding_digest=binding_digest)
        return query.with_for_update().first()

    @staticmethod
    def _client_capacity(client):
        route_values = (client.individual_ratelimit_multipliers or {}).values()
        return max([client.ratelimit_multiplier] + list(route_values))

    def _enforce_quota(
        self, db_session, owner, requested, purpose, *, existing_client=None
    ):
        quota = owner.ratelimit_quota
        if quota is None:
            quota = self._app.config.get("AUTH_SERVICE_DEFAULT_OWNER_QUOTA", 2.0)
        if (
            isinstance(quota, bool)
            or not isinstance(quota, (int, float))
            or not math.isfinite(quota)
            or (quota < 0 and quota != -1)
        ):
            raise ValidationError("Owner rate-limit quota is invalid")
        if quota == 0:
            raise ValidationError("Credential issuance is suspended")
        if purpose == "anonymous" and existing_client is None:
            cap = self._app.config["ANONYMOUS_CREDENTIAL_DATABASE_CAP"]
            count = (
                db_session.query(func.count(OAuth2Client.id))
                .filter(OAuth2Client.credential_purpose == "anonymous")
                .scalar()
            )
            if count >= cap:
                raise ValidationError("Anonymous credential capacity is exhausted")
        if quota == -1:
            return
        query = (
            db_session.query(OAuth2Client)
            .join(OAuth2Token)
            .filter(
                OAuth2Client.user_id == owner.get_id(),
                OAuth2Token.issued_at + OAuth2Token.expires_in > int(time.time()),
            )
        )
        if existing_client is not None:
            query = query.filter(OAuth2Client.id != existing_client.id)
        used = sum(self._client_capacity(client) for client in query.all())
        if used + requested > quota:
            raise ValidationError("Owner credential quota is exhausted")


class ProxyService(GatewayService):
    """A class for registering remote webservices and resources with the Flask application."""

    def __init__(self, name: str = "PROXY_SERVICE"):
        super().__init__(name)

    def register_services(self):
        """Registers all services specified in the configuration file."""
        self.allowed_headers = self.get_service_config("ALLOWED_HEADERS", [])

        services = self.get_service_config("WEBSERVICES", {})
        for url, deploy_path in services.items():
            self.register_service(url, deploy_path)

        self._register_hooks(self._app)

    def _register_hooks(self, app: Flask):
        """Registers hooks that manipulate the response headers.

        Args:
            app (Flask): The Flask app to register hooks for.
        """

        @app.after_request
        def _after_request_hook(response: Response):
            if not getattr(g, "proxy_upstream_response", False):
                return response

            allowed_headers = {header.lower() for header in self.allowed_headers}
            gateway_response_headers = {"content-type", "content-length"}
            filtered_headers = {
                key: value
                for key, value in response.headers.items()
                if key.lower() in allowed_headers
                or key.lower() in gateway_response_headers
            }
            response.headers.clear()
            for key, value in filtered_headers.items():
                response.headers.add_header(key, value)
            return response

    def register_service(self, base_url: str, deploy_path: str, csrf_exempt: bool = True):
        """Registers a single service with the Flask application

        Args:
            base_url (str): The base URL of the service.
            deploy_path (str): The deployment path of the service
            csrf_exempt (bool, optional): Whether to exempt the services from CSRF protection. Defaults to True.
        """
        self._logger.info("Registering service %s at %s", base_url, deploy_path)

        try:
            resource_json = self._fetch_resource_document(base_url)
        except requests.exceptions.RequestException as ex:
            self._logger.error("Could not fetch resource document for %s: %s", base_url, ex)
            return

        self._logger.info("Discovered %s endpoints:", deploy_path)
        for remote_path, properties in resource_json.items():
            self._logger.info("- %s", remote_path)

            properties.setdefault(
                "rate_limit",
                self.get_service_config("DEFAULT_RATE_LIMIT", [1000, 86400]),
            )
            properties.setdefault("scopes", self.get_service_config("DEFAULT_SCOPES", []))
            properties.setdefault("authorization", True)
            properties.setdefault("cache", None)

            # Create the view
            rule_name = local_path = (
                deploy_path
                if remote_path == "/"
                else os.path.join(deploy_path, remote_path.rstrip("/")[1:])
            )
            proxy_view = ProxyView.as_view(rule_name, deploy_path, base_url)

            if csrf_exempt:
                extensions.csrf.exempt(proxy_view)

            # If configured by the webservice, decorate view with the cache service
            if properties["cache"] is not None:
                cache = properties["cache"]
                proxy_view = extensions.cache_service.cached(
                    timeout=cache.get("timeout", 60000),
                    include_query_parameters=cache.get("query_parameters", True),
                    excluded_parameters=cache.get("excluded_parameters", []),
                )(proxy_view)

            # Decorate view with the rate limiter service
            counts = properties["rate_limit"][0]
            per_second = properties["rate_limit"][1]
            proxy_view = extensions.limiter_service.shared_limit(
                counts=counts,
                per_second=per_second,
            )(proxy_view)

            extensions.limiter_service.group_endpoint(local_path, counts, per_second)

            # Decorate view with the auth service, unless explicitly disabled
            if properties["authorization"]:
                proxy_view = extensions.auth_service.require_oauth(properties["scopes"])(
                    proxy_view
                )

            # Register the view with Flask
            self._app.add_url_rule(
                rule_name,
                endpoint=local_path,
                view_func=proxy_view,
                methods=properties["methods"],
                provide_automatic_options=True,
            )

    def _fetch_resource_document(self, base_url: str) -> dict:
        """
        Fetches the resource document for a given base URL.

        Args:
            base_url (str): The base URL of the service.

        Returns:
            A dictionary containing the resource document.
        """

        resource_url = urljoin(base_url, self.get_service_config("RESOURCE_ENDPOINT", "/"))

        try:
            timeout = self.get_service_config("RESOURCE_TIMEOUT", 5)
            response = requests.get(resource_url, timeout=timeout)
            response.raise_for_status()

            extensions.storage_service.set(resource_url, response.json())
            return response.json()
        except requests.exceptions.RequestException as ex:
            if extensions.storage_service.has(resource_url):
                self._logger.info("Using cached resource document for %s", resource_url)
                return extensions.storage_service.get(resource_url)
            else:
                raise ex


class LimiterService(GatewayService, Limiter):
    """A service that provides rate limiting functionality for API endpoints.

    This service extends the `GatewayService` and `Limiter` classes to provide rate limiting functionality
    for API endpoints. It defines methods for registering hooks to track request processing time and
    shared limits for rate limiting.

    """

    def __init__(self, name: str = "LIMITER_SERVICE"):
        """Initializes a new instance of the `LimiterService` class.

        Args:
            name (str, optional): The name of the service. Defaults to "LIMITER_SERVICE".
        """
        GatewayService.__init__(self, name)
        Limiter.__init__(
            self, key_func=self._key_func, in_memory_fallback_enabled=True, auto_check=False
        )
        self._symbolic_ratelimits = {}

    def init_app(self, app: Flask):
        """Initializes the service with the specified Flask application.

        This method initializes the service with the specified Flask application by setting default
        configuration values and registering hooks.

        Args:
            app (Flask): The Flask application to initialize the service with.
        """
        GatewayService.init_app(self, app)

        app.config.setdefault("RATELIMIT_STORAGE_URI", self.get_service_config("STORAGE_URI"))
        app.config.setdefault("RATELIMIT_STRATEGY", self.get_service_config("STRATEGY"))
        app.config.setdefault(
            "RATELIMIT_HEADERS_ENABLED", self.get_service_config("HEADERS_ENABLED", True)
        )

        Limiter.init_app(self, app)

        self._ratelimit_groups = self.get_service_config("GROUPS", {})

        self._register_hooks(app)

    def _register_hooks(self, app: Flask):
        """Registers hooks for tracking request processing time.

        This method registers hooks for tracking request processing time before and after each request.

        Args:
            app (Flask): The Flask application to register the hooks with.
        """

        # Request timing starts in the decorated admission wrapper so it includes
        # completed handler work and is associated with the exact admitted limits.
        def _token_authenticated(sender, token=None, **kwargs):
            client = OAuth2Client.query.filter_by(id=token.client_id).first()
            level = getattr(client, "ratelimit", 1.0) if client else 0.0
            headers = Headers(request.headers.items())
            headers.add_header("X-Adsws-Ratelimit-Level", str(level))
            request.headers = headers

        token_authenticated.connect(_token_authenticated, weak=False)

    def limit(
        self,
        limit_value: str = None,
        counts: int = None,
        per_second: int = None,
        scope: str = None,
        key_func: Callable[[], str] = None,
        error_message: str = None,
        exempt_when: Callable[[], bool] = None,
        override_defaults: bool = True,
        deduct_when: Callable[[Response], bool] = None,
        cost: int | Callable[[], int] = None,
    ):
        return self._limit_and_check(
            limit_value,
            counts,
            per_second,
            scope,
            key_func,
            error_message,
            exempt_when,
            override_defaults,
            deduct_when,
            cost,
            shared=False,
        )

    def shared_limit(
        self,
        limit_value: str = None,
        counts: int = None,
        per_second: int = None,
        scope: str = None,
        key_func: Callable[[], str] = None,
        error_message: str = None,
        exempt_when: Callable[[], bool] = None,
        override_defaults: bool = True,
        deduct_when: Callable[[Response], bool] = None,
        cost: int | Callable[[], int] = None,
    ):
        return self._limit_and_check(
            limit_value,
            counts,
            per_second,
            scope,
            key_func,
            error_message,
            exempt_when,
            override_defaults,
            deduct_when,
            cost,
            shared=True,
        )

    def group_endpoint(self, endpoint: str, counts: int, per_second: int):
        for group, values in self._ratelimit_groups.items():
            if any(re.match(pattern, endpoint) for pattern in values.get("patterns", [])):
                if group not in self._symbolic_ratelimits.keys():
                    self._symbolic_ratelimits[group] = {
                        "name": group,
                        "counts": values.get("counts", counts),
                        "per_second": values.get("per_second", per_second),
                    }

                self._logger.info(f'"{endpoint}" added to limiter group "{group}"')
                self._symbolic_ratelimits[endpoint] = self._symbolic_ratelimits[group]
                break

    def clear_limits(self, request_endpoint: str, scope: str):
        if request_endpoint == "*":
            self._logger.info("Clearing all limits")
            self.reset()
            extensions.storage_service.delete_prefix(f"{self._name}//")
        else:
            defaults, decorated = self.limit_manager.resolve_limits(self._app, request_endpoint)
            all_limits = list(defaults) + list(decorated)
            for limit in all_limits:
                key = limit.limit.key_for(request_endpoint, scope)
                self._logger.info("Clearing limit for key %s", key)
                self.storage.clear(key)

            extensions.storage_service.delete(
                f"{self._name}//{self._key_func(request_endpoint)}/total_microseconds"
            )
            extensions.storage_service.delete(
                f"{self._name}//{self._key_func(request_endpoint)}/count"
            )

    def _limit_and_check(
        self,
        limit_value: str = None,
        counts: int = None,
        per_second: int = None,
        scope: str = None,
        key_func: Callable[[], str] = None,
        error_message: str = None,
        exempt_when: Callable[[], bool] = None,
        override_defaults: bool = True,
        deduct_when: Callable[[Response], bool] = None,
        cost: int | Callable[[], int] = None,
        shared: bool = False,
    ):
        if limit_value is None and (counts is None or per_second is None):
            raise ValueError("Either limit_value or counts and per_second must be provided")

        adaptive_cost = cost is None

        def inner(func):
            LimitDecorator(
                self,
                limit_value=(
                    limit_value
                    if limit_value
                    else lambda: self._calculate_limit_value(counts, per_second)
                ),
                scope=scope if scope else self._scope_func,
                shared=shared,
                key_func=key_func if key_func else self._key_func,
                error_message=error_message,
                exempt_when=exempt_when,
                override_defaults=override_defaults,
                deduct_when=deduct_when,
                cost=cost if cost is not None else 1,
            )(func)

            @wraps(func)
            def check(*args, **kwargs):
                started_ns = time.monotonic_ns()
                self.check()
                result = func(*args, **kwargs)
                if adaptive_cost and self._is_successful_response(result):
                    self._record_completed_request(started_ns)
                return result

            return check

        return inner

    @staticmethod
    def _is_successful_response(result) -> bool:
        if isinstance(result, Response):
            return result.status_code < 400
        if (
            isinstance(result, tuple)
            and len(result) > 1
            and isinstance(result[1], int)
        ):
            return result[1] < 400
        return True


    def _calculate_limit_value(self, counts: int, per_second: int) -> str:
        """Calculates the limit string for the specified counts and per second values.

        This function is called on each request which is why it is possible to have individual
        rate limits for each user.

        Args:
            counts (int): The maximum number of requests allowed per `per_second`.
            per_second (int): The time window in seconds for the rate limit.
        Returns:
            str: The limit string value for the rate limit.
        """
        client = getattr(current_token, "client", None)
        multiplier = getattr(client, "ratelimit_multiplier", 1.0)
        individual_multipliers = getattr(client, "individual_ratelimit_multipliers", None)

        if individual_multipliers:
            route_multiplier = individual_multipliers.get(request.endpoint)
            if route_multiplier is not None:
                multiplier = max(multiplier, route_multiplier)

        if request.endpoint in self._symbolic_ratelimits:
            counts: int = self._symbolic_ratelimits[request.endpoint]["counts"]
            per_second: int = self._symbolic_ratelimits[request.endpoint]["per_second"]

        return "{0}/{1} second".format(int(counts * multiplier), per_second)

    def _record_completed_request(self, started_ns: int) -> int:
        if not self.get_service_config("SCALING_COST_ENABLED", False):
            return 1
        max_seconds = max(
            float(self.get_service_config("MAX_ACCOUNTED_SECONDS", 60)), 0.0
        )
        elapsed_us = min(
            max((time.monotonic_ns() - started_ns) // 1000, 0),
            int(max_seconds * 1_000_000),
        )
        g.processing_time = elapsed_us / 1_000_000
        threshold = max(
            int(self.get_service_config("SCALING_COST_THRESHOLD", 100)), 0
        )
        max_cost = max(int(self.get_service_config("MAX_COST", 10)), 1)
        ttl = max(
            int(self.get_service_config("ESTIMATOR_TTL_SECONDS", 600)), 1
        )
        highest_cost = 1
        for request_limit in self.current_limits:
            effective_key = json.dumps(
                [str(request_limit.key), str(request_limit.scope)],
                separators=(",", ":"),
            )
            aggregate = (
                f"{self._name}//adaptive/"
                f"{hashlib.sha256(effective_key.encode('utf-8')).hexdigest()}"
            )
            total_us, completed_count = extensions.storage_service.atomic_snapshot_and_add(
                f"{aggregate}/total_microseconds",
                f"{aggregate}/count",
                elapsed_us,
                ttl,
            )
            cost = 1
            if completed_count >= threshold and completed_count > 0 and total_us > 0:
                mean_us = total_us / completed_count
                if mean_us > 0 and elapsed_us > mean_us:
                    scaled = math.floor(math.log2(elapsed_us / mean_us) * 5)
                    cost = 1 + min(max(scaled, 0), max_cost - 1)
            surcharge = cost - 1
            if surcharge:
                self.limiter.hit(
                    request_limit.limit,
                    *request_limit.request_args,
                    cost=surcharge,
                )
            highest_cost = max(highest_cost, cost)
        return highest_cost

    def _key_func(self, request_endpoint=None) -> str:
        """Returns the key for the rate limit.

        This method returns the key for the rate limit based on the API endpoint.

        Returns:
            str: The key for the rate limit.
        """

        request_endpoint = request_endpoint or request.endpoint

        if request_endpoint in self._symbolic_ratelimits:
            return self._symbolic_ratelimits[request_endpoint]["name"]
        return request_endpoint

    def _scope_func(self, endpoint_name: str) -> str:
        """Returns the scope for the rate limit.

        This method returns the scope for the rate limit based on the OAuth user.
        If the user coild not be determined the remote address is used.

        Args:
            endpoint_name (str): The name of the API endpoint.

        Returns:
            str: The scope for the rate limit.
        """
        if current_token:
            return "{email}:{client}".format(
                email=current_token.user.email, client=current_token.client_id
            )

        elif current_user.is_authenticated and not current_user.is_anonymous_bootstrap_user:
            return "{email}".format(email=current_user.email)

        else:
            return get_remote_address()


class RedisService(GatewayService):
    """A service class for interacting with a Redis database.

    Args:
        name (str): The name of the service.
        strict (bool): Whether to use strict Redis or not.
        **kwargs: Additional keyword arguments to pass to the Redis client.

    """

    def __init__(self, name: str = "REDIS_SERVICE", strict: bool = True, **kwargs):
        super().__init__(name)
        self._redis_client = None
        self._provider_class = StrictRedis if strict else Redis
        self._provider_kwargs = kwargs

    def init_app(self, app: Flask):
        super().init_app(app)

        redis_url = self.get_service_config("URL", "redis://redis:6379/0")
        self._redis_client = self._provider_class.from_url(redis_url, **self._provider_kwargs)

    def alive(self) -> bool:
        """Checks if the Redis database is alive.

        Returns:
            bool: True if the Redis database is alive, False otherwise.
        """
        try:
            return self._redis_client.ping()
        except:  # noqa
            return False

    def get_connection_pool(self):
        if self._redis_client:
            return self._redis_client.connection_pool
        else:
            return None

    def __getattr__(self, name):
        return getattr(self._redis_client, name, None)

    def __getitem__(self, name):
        return self._redis_client[name]

    def __setitem__(self, name, value):
        self._redis_client[name] = value

    def __delitem__(self, name):
        del self._redis_client[name]


class StorageService(GatewayService):
    """A service class for interacting with storage.

    This class provides methods for setting, getting, deleting, and incrementing values in storage.
    It supports both Redis storage and fallbacks to memory storage in case Redis is down.
    """

    def __init__(self, name: str = "STORAGE_SERVICE"):
        super().__init__(name)
        self._fallback_storage: dict = {}
        self._fallback_lock = threading.RLock()
        self._fallback_expirations: dict[str, float] = {}

    def init_app(self, app: Flask, redis_service: RedisService):
        super().init_app(app)
        self._redis_service = redis_service
        self._redis_down = False
        self._serializer = RedisSerializer()

    def _serialize(self, value: any) -> str | bytes:
        """Serializes the given value.

        Args:
            value (any): The value to serialize.

        Returns:
            str | bytes: The serialized value.
        """
        if isinstance(value, (int, float, str)):
            return str(value)
        else:
            return self._serializer.dumps(value)

    def _transfer_to_redis(self):
        """Transfer unexpired fallback values to Redis."""
        now = time.monotonic()
        for key, value in self._fallback_storage.items():
            expiration = self._fallback_expirations.get(key)
            if expiration is not None and expiration <= now:
                continue
            if isinstance(value, dict):
                value = json.dumps(value)
            self._redis_service.set(key, self._serialize(value))
            if expiration is not None:
                self._redis_service.expire(key, max(math.ceil(expiration - now), 1))
        self._fallback_storage.clear()
        self._fallback_expirations.clear()

    def handle_redis_exception(func):
        def wrapper(self, *args, **kwargs):
            if self._redis_down and self._redis_service.alive():
                self._redis_down = False
                self._logger.info("Redis is back up, transferring data from fallback storage")
                self._transfer_to_redis()

            try:
                return func(self, *args, **kwargs)
            except (ConnectionError, TimeoutError):
                self._redis_down = True
                self._logger.warning("Redis is down, falling back to local storage")
                return func(self, *args, **kwargs)
            except Exception as ex:
                self._logger.error("Failed to handle Redis exception", ex)
                raise

        return wrapper

    @handle_redis_exception
    def set(self, key: str, value: str, timeout: int = None) -> bool:
        if not self._redis_down:
            value = self._serialize(value)

            if timeout is None:
                return bool(self._redis_service.set(key, value))
            else:
                return bool(self._redis_service.setex(key, timeout, value))
        else:
            self._fallback_storage[key] = value
            return True

    @handle_redis_exception
    def get(self, key: str) -> str:
        if not self._redis_down:
            value = self._redis_service.get(key)

            if value is not None:
                value = self._serializer.loads(value)

            return value
        else:
            return self._fallback_storage.get(key)

    @handle_redis_exception
    def delete(self, key: str) -> bool:
        if not self._redis_down:
            return bool(self._redis_service.delete(key))
        else:
            self._fallback_expirations.pop(key, None)
            return bool(self._fallback_storage.pop(key, None))

    @handle_redis_exception
    def incr(self, key: str) -> int:
        if not self._redis_down:
            return self._redis_service.incr(key)
        else:
            self._fallback_storage[key] = self._fallback_storage.get(key, 0) + 1
            return self._fallback_storage[key]

    @handle_redis_exception
    def incrby(self, key: str, increment: int) -> int:
        if not self._redis_down:
            return self._redis_service.incrby(key, increment)
        else:
            self._fallback_storage[key] = self._fallback_storage.get(key, 0) + increment
            return self._fallback_storage[key]

    @handle_redis_exception
    def delete_prefix(self, prefix: str) -> int:
        if not self._redis_down:
            keys = list(self._redis_service.scan_iter(match=f"{prefix}*"))
            return int(self._redis_service.delete(*keys)) if keys else 0
        with self._fallback_lock:
            keys = [key for key in self._fallback_storage if key.startswith(prefix)]
            for key in keys:
                del self._fallback_storage[key]
                self._fallback_expirations.pop(key, None)
            return len(keys)

    @handle_redis_exception
    def atomic_snapshot_and_add(
        self,
        total_key: str,
        count_key: str,
        elapsed_microseconds: int,
        ttl_seconds: int,
    ) -> tuple[int, int]:
        """Return the prior aggregate, add a sample, and refresh the rolling TTL."""
        ttl_seconds = max(int(ttl_seconds), 1)
        if not self._redis_down:
            script = """
                local total = tonumber(redis.call('GET', KEYS[1]) or '0')
                local count = tonumber(redis.call('GET', KEYS[2]) or '0')
                redis.call('INCRBY', KEYS[1], ARGV[1])
                redis.call('INCRBY', KEYS[2], 1)
                redis.call('EXPIRE', KEYS[1], ARGV[2])
                redis.call('EXPIRE', KEYS[2], ARGV[2])
                return {total, count}
            """
            total, count = self._redis_service.eval(
                script,
                2,
                total_key,
                count_key,
                int(elapsed_microseconds),
                ttl_seconds,
            )
            return int(total), int(count)
        with self._fallback_lock:
            now = time.monotonic()
            if self._fallback_expirations.get(total_key, 0) <= now:
                self._fallback_storage.pop(total_key, None)
            if self._fallback_expirations.get(count_key, 0) <= now:
                self._fallback_storage.pop(count_key, None)
            total = int(self._fallback_storage.get(total_key, 0))
            count = int(self._fallback_storage.get(count_key, 0))
            self._fallback_storage[total_key] = total + int(elapsed_microseconds)
            self._fallback_storage[count_key] = count + 1
            expiration = now + ttl_seconds
            self._fallback_expirations[total_key] = expiration
            self._fallback_expirations[count_key] = expiration
            return total, count

    @handle_redis_exception
    def incrbyfloat(self, key: str, increment: float) -> float:
        if not self._redis_down:
            return self._redis_service.incrbyfloat(key, increment)
        else:
            self._fallback_storage[key] = self._fallback_storage.get(key, 0.0) + increment
            return self._fallback_storage[key]

    @handle_redis_exception
    def has(self, key: str) -> bool:
        if not self._redis_down:
            return bool(self._redis_service.exists(key))
        else:
            return key in self._fallback_storage


class CacheService(GatewayService, Cache):
    """A service class that provides caching functionality for the API Gateway."""

    def __init__(self, name: str = "CACHE_SERVICE"):
        GatewayService.__init__(self, name)
        Cache.__init__(self)

    def init_app(self, app: Flask):
        GatewayService.init_app(self, app)

        app.config.setdefault("CACHE_REDIS_URL", self.get_service_config("REDIS_URI"))
        app.config.setdefault("CACHE_TYPE", self.get_service_config("CACHE_TYPE", "RedisCache"))

        Cache.init_app(self, app)

    def clear_cache(self, request_path: str, parameters: dict) -> bool:
        """Clears the cache for the specified request path and parameters.

        Args:
            request_path (str): The request path.
            parameters (dict): The request parameters used to construct the cache key.

        Returns:
            bool: True if the cache is cleared successfully, False otherwise.
        """
        if request_path == "*":
            self._logger.info("Clearing all cache")
            return self.clear()

        params_tuple = list(parameters.items()) if parameters else []
        key = self._make_cache_key(request_path, params_tuple)
        self._logger.info("Clearing cache for key %s", key)
        return self.delete(key)

    def cached(
        self,
        timeout: int = None,
        unless: int = None,
        forced_update: int = None,
        response_filter: int = None,
        include_query_parameters: bool = True,
        excluded_parameters: list = [],
    ) -> Callable:
        """
        Decorator that caches the response of a function/method.

        Args:
            timeout (int, optional): The cache timeout in seconds. Defaults to None.
            unless (int, optional): The cache will not be used if the function/method returns a value equal to this parameter. Defaults to None.
            forced_update (int, optional): The cache will be forcibly updated if the function/method returns a value equal to this parameter. Defaults to None.
            response_filter (int, optional): The cache will be filtered using this parameter. Defaults to None.
            include_query_parameters (bool, optional): Determines whether to include query parameters in the cache key. Defaults to True.
            excluded_parameters (list, optional): List of parameters to exclude from the cache key. Defaults to [].

        Returns:
            Callable: The decorated function/method.
        """
        return Cache.cached(
            self,
            timeout=timeout,
            unless=unless,
            forced_update=forced_update,
            response_filter=response_filter,
            make_cache_key=lambda *args, **kwargs: self._make_cache_key_from_request(
                include_query_parameters, excluded_parameters
            ),
        )

    def _make_cache_key_from_request(
        self, include_query_parameters: bool, excluded_parameters: list
    ) -> str:
        """
        Generate a cache key based on the request.

        Args:
            include_query_parameters (bool): Flag indicating whether to include query parameters in the cache key.
            excluded_parameters (list): List of query parameters to exclude from the cache key.

        Returns:
            str: The generated cache key.
        """
        request_params = []
        if include_query_parameters:
            request_params = sorted(
                (k, v) for (k, v) in request.args.items(multi=True) if k not in excluded_parameters
            )

        return self._make_cache_key(request.path, request_params)

    def _make_cache_key(
        self,
        request_path: str,
        request_params: list[tuple[str, str]] = None,
        hash_method: Callable = hashlib.md5,
    ) -> str:
        """Generate a cache key for the given request.

        Args:
            request_path (str): The path of the request.
            request_params (list[tuple[str, str]], optional): The parameters of the request. Defaults to None.
            hash_method (Callable, optional): The hash method to use. Defaults to hashlib.md5.

        Returns:
            str: The generated cache key.
        """
        cache_key = "view/%s" % request_path

        if request_params:
            args_as_bytes = str(request_params).encode()
            cache_arg_hash = hash_method(args_as_bytes)
            cache_arg_hash = str(cache_arg_hash.hexdigest())

            cache_key += "/{}".format(cache_arg_hash)

        return cache_key


class SecurityService(GatewayService, Security):
    """A service for managing user authentication and authorization.

    This service creates and manages users and roles, changes credentials, and
    issues and verifies purpose-bound account-action capabilities.


    """
    ACCOUNT_ACTION_PURPOSES = frozenset(
        ("password_reset", "verify_registration", "change_email")
    )
    _ACCOUNT_ACTION_SALT_CONFIG = {
        "password_reset": "VERIFY_PASSWORD_SALT",
        "verify_registration": "VERIFY_EMAIL_SALT",
        "change_email": "VERIFY_EMAIL_SALT",
    }
    _ACCOUNT_ACTION_PAYLOAD_KEYS = frozenset(
        (
            "version",
            "user_id",
            "purpose",
            "nonce",
            "target_email",
            "state_digest",
        )
    )
    _ACCOUNT_ACTION_VERSION = 1


    def __init__(self, name: str = "SECURITY_SERVICE"):
        GatewayService.__init__(self, name)
        Security.__init__(self, register_blueprint=False)

    def init_app(self, app: Flask):
        GatewayService.init_app(self, app)
        app.config.setdefault(
            "SECURITY_PASSWORD_HASH", self.get_service_config("PASSWORD_HASH", "pbkdf2_sha512")
        )
        app.config.setdefault(
            "SECURITY_PASSWORD_SALT",
            self.get_service_config("PASSWORD_SALT", app.config.get("SECRET_KEY")),
        )
        app.config.setdefault("SECURITY_STATIC_FOLDER", None)

        Security.init_app(
            self,
            app,
            datastore=SQLAlchemyUserDatastore(extensions.db, User, Role),
            anonymous_user=AnonymousUser,
        )

        self._account_action_serializer = URLSafeSerializer(
            self.get_service_config("SECRET_KEY")
        )

    def create_user(self, email: str, password: str, commit: bool = True, **kwargs) -> User:
        """Creates a new user with the specified email and password.

        Args:
            email (str): The email of the user.
            password (str): The password of the user.
            roles (list, optional): The roles of the user. Defaults to None.
            kwargs (dict): Additional keyword arguments to pass to the user.

        Raises:
            ValueError: If the email or password is invalid.

        Returns:
            User: The created user.
        """

        email = canonicalize_email(email)
        email = self._mail_util.validate(email)
        pbad, password = self._password_util.validate(password, True)

        if pbad is not None:
            raise ValueError(", ".join(pbad))

        # Passwords are hashed in the setter of the model. No need to do it here.
        user = self.datastore.create_user(email=email, password=password, **kwargs)
        if commit:
            self.datastore.commit()
        else:
            self.datastore.db.session.flush()

        return user

    def create_role(self, name: str, description: str = None, **kwargs) -> Role:
        """Creates a new role with the specified name and description.

        Args:
            name (str): The name of the role.
            description (str, optional): The description of the role. Defaults to None.
            kwargs (dict): Additional keyword arguments to pass to the role.

        Returns:
            Role: The created role.
        """
        role = self.datastore.create_role(name=name, description=description, **kwargs)
        self.datastore.commit()
        return role

    def add_role_to_user(self, user: User, role: Role) -> bool:
        """Adds the specified role to the specified user.

        Args:
            user (User): The user to add the role to.
            role (Role): The role to add to the user.

        Returns:
            bool: True if the role was added successfully, False otherwise.
        """
        if self.datastore.add_role_to_user(user, role):
            self.datastore.commit()
            return True
        else:
            return False

    def set_password_in_transaction(self, user: User, password: str) -> User:
        """Validate and hash a password without committing the caller's transaction."""
        pbad, password = self._password_util.validate(password, True)
        if pbad is not None:
            raise ValueError(", ".join(pbad))
        user.password = password
        return user

    def change_password(
        self, user: User, password: str, *, session=None, commit: bool = True
    ) -> User:
        """Change a password within either this service's or the caller's transaction."""
        transaction = session or self.datastore.db.session
        user = transaction.merge(user)
        self.set_password_in_transaction(user, password)
        if commit:
            transaction.commit()
        return user


    def validate_email(self, email: str) -> bool:
        """
        Validate an email address.

        Args:
            email (str): The email address to validate.

        Returns:
            bool: True if the email address is valid, False otherwise.
        """
        try:
            self._mail_util.validate(canonicalize_email(email))
        except Exception:
            return False

        return True



    @staticmethod
    def account_action_token_digest(token: str) -> str:
        """Return the complete bearer token's SHA-256 digest."""
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise AccountActionTokenError()
        try:
            return hashlib.sha256(token.encode("utf-8")).hexdigest()
        except UnicodeError:
            raise AccountActionTokenError()

    @staticmethod
    def _utc_datetime(value: datetime) -> datetime:
        if not isinstance(value, datetime):
            raise AccountActionTokenError()
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def normalize_account_email(email: str) -> str:
        if not isinstance(email, str):
            raise ValueError("account actions require an email target")
        try:
            normalized = canonicalize_email(email)
        except ValueError as exc:
            raise ValueError("account actions require a canonical email target") from exc
        if len(normalized) > 255:
            raise ValueError("account actions require a bounded email target")
        return normalized

    def _account_action_state_digest(self, user: User, purpose: str) -> str:
        state = json.dumps(
            {
                "active": bool(user.active),
                "confirmed": user.confirmed_at is not None,
                "email": self.normalize_account_email(str(user.email)),
                "password": user.password or "",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            self._account_action_salt(purpose).encode("utf-8"),
            state,
            hashlib.sha256,
        ).hexdigest()

    def _validate_account_action_target(self, target_email) -> str:
        return self.normalize_account_email(target_email)

    def _account_action_salt(self, purpose: str) -> str:
        config_key = self._ACCOUNT_ACTION_SALT_CONFIG.get(purpose)
        if config_key is None:
            raise AccountActionTokenError()
        configured_salt = self.get_service_config(config_key)
        return "account-action:{}:{}".format(purpose, configured_salt)

    def issue_account_action_token(
        self,
        session,
        *,
        user: User = None,
        user_id: int = None,
        purpose: str,
        target_email,
        now: datetime = None,
    ) -> str:
        """Issue and persist one target-bound account-action capability."""
        if (user is None) == (user_id is None):
            raise ValueError("provide exactly one of user or user_id")
        if user is not None:
            user_id = user.id
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("account action tokens require a persisted user")
        if purpose not in self.ACCOUNT_ACTION_PURPOSES:
            raise ValueError("unknown account action purpose")
        target_email = self._validate_account_action_target(target_email)

        locked_user = (
            session.query(User)
            .populate_existing()
            .filter(User.id == user_id)
            .with_for_update()
            .one_or_none()
        )
        if locked_user is None:
            raise ValueError("account action user does not exist")
        current_email = self.normalize_account_email(str(locked_user.email))
        if locked_user.is_anonymous_bootstrap_user or not locked_user.active:
            raise ValueError("user is not eligible for account actions")
        if purpose == "password_reset":
            if locked_user.confirmed_at is None:
                raise ValueError("user is not eligible for password reset")
            if target_email != current_email:
                raise ValueError("password reset target does not match the user")
        elif purpose == "verify_registration":
            if locked_user.confirmed_at is not None or target_email != current_email:
                raise ValueError("user is not eligible for registration verification")
        elif locked_user.confirmed_at is None or target_email == current_email:
            raise ValueError("user is not eligible for email change")
        state_digest = self._account_action_state_digest(locked_user, purpose)

        issued_at = self._utc_datetime(now or datetime.now(timezone.utc))
        expires_in = self.get_service_config(
            "ACCOUNT_ACTION_TOKEN_EXPIRES", 24 * 60 * 60
        )
        if type(expires_in) is not int or expires_in <= 0:
            raise ValueError("account action token expiry must be a positive integer")
        expires_at = issued_at + timedelta(seconds=expires_in)
        delivery_id = str(uuid.uuid4())
        token = self._serialize_account_action_token(
            user_id=locked_user.id,
            purpose=purpose,
            target_email=target_email,
            state_digest=state_digest,
            delivery_id=delivery_id,
        )

        session.query(AccountActionToken).filter(
            AccountActionToken.user_id == locked_user.id,
            AccountActionToken.purpose == purpose,
        ).delete(synchronize_session=False)
        session.add(
            AccountActionToken(
                delivery_id=delivery_id,
                token_digest=self.account_action_token_digest(token),
                user_id=locked_user.id,
                purpose=purpose,
                target_email=target_email,
                state_digest=state_digest,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        )
        session.flush()
        return token

    def _account_action_nonce(self, purpose: str, delivery_id: str) -> str:
        return hmac.new(
            self._account_action_salt(purpose).encode("utf-8"),
            delivery_id.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _serialize_account_action_token(
        self,
        *,
        user_id: int,
        purpose: str,
        target_email: str,
        state_digest: str,
        delivery_id: str,
    ) -> str:
        payload = {
            "version": self._ACCOUNT_ACTION_VERSION,
            "user_id": user_id,
            "purpose": purpose,
            "nonce": self._account_action_nonce(purpose, delivery_id),
            "target_email": target_email,
            "state_digest": state_digest,
        }
        return self._account_action_serializer.dumps(
            payload, salt=self._account_action_salt(purpose)
        )

    def derive_account_action_token(self, action: AccountActionToken) -> str:
        """Derive a bearer in memory from the exact persisted action."""
        token = self._serialize_account_action_token(
            user_id=action.user_id,
            purpose=action.purpose,
            target_email=action.target_email,
            state_digest=action.state_digest,
            delivery_id=action.delivery_id,
        )
        if not hmac.compare_digest(
            self.account_action_token_digest(token), action.token_digest
        ):
            raise AccountActionTokenError()
        return token

    def _decode_account_action_token(self, token: str, purpose: str) -> dict:
        if purpose not in self.ACCOUNT_ACTION_PURPOSES:
            raise AccountActionTokenError()
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise AccountActionTokenError()
        try:
            payload = self._account_action_serializer.loads(
                token, salt=self._account_action_salt(purpose)
            )
        except Exception:
            self._logger.warning("Account action token rejected")
            raise AccountActionTokenError()
        if type(payload) is not dict or set(payload) != self._ACCOUNT_ACTION_PAYLOAD_KEYS:
            raise AccountActionTokenError()
        if (
            type(payload["version"]) is not int
            or payload["version"] != self._ACCOUNT_ACTION_VERSION
        ):
            raise AccountActionTokenError()
        if type(payload["user_id"]) is not int or payload["user_id"] <= 0:
            raise AccountActionTokenError()
        if payload["purpose"] != purpose:
            raise AccountActionTokenError()
        nonce = payload["nonce"]
        if (
            not isinstance(nonce, str)
            or not 32 <= len(nonce) <= 128
            or re.fullmatch(r"[A-Za-z0-9_-]+", nonce) is None
        ):
            raise AccountActionTokenError()
        try:
            self._validate_account_action_target(payload["target_email"])
        except ValueError:
            raise AccountActionTokenError()
        state_digest = payload["state_digest"]
        if (
            not isinstance(state_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", state_digest) is None
        ):
            raise AccountActionTokenError()
        return payload

    def verify_account_action_token(
        self,
        session,
        token: str,
        purpose: str,
        *,
        for_update: bool = False,
        now: datetime = None,
    ) -> Tuple[User, AccountActionToken]:
        """Verify a capability and return its locked or read-only state."""
        payload = self._decode_account_action_token(token, purpose)
        user_query = session.query(User).filter(User.id == payload["user_id"])
        user_query = user_query.populate_existing()
        if for_update:
            user_query = user_query.with_for_update()
        user = user_query.one_or_none()
        if user is None:
            raise AccountActionTokenError()

        digest = self.account_action_token_digest(token)
        action_query = (
            session.query(AccountActionToken)
            .filter(AccountActionToken.token_digest == digest)
            .populate_existing()
        )
        if for_update:
            action_query = action_query.with_for_update()
        action = action_query.one_or_none()
        if (
            action is None
            or action.user_id != user.id
            or action.purpose != purpose
            or action.target_email != payload["target_email"]
            or not isinstance(action.state_digest, str)
            or not hmac.compare_digest(
                action.state_digest, payload["state_digest"]
            )
        ):
            raise AccountActionTokenError()

        try:
            current_state_digest = self._account_action_state_digest(user, purpose)
            current_email = self.normalize_account_email(str(user.email))
        except (TypeError, ValueError):
            raise AccountActionTokenError()
        if not hmac.compare_digest(current_state_digest, action.state_digest):
            raise AccountActionTokenError()
        if not user.active or user.is_anonymous_bootstrap_user:
            raise AccountActionTokenError()
        if purpose == "password_reset" and (
            user.confirmed_at is None or current_email != action.target_email
        ):
            raise AccountActionTokenError()
        if purpose == "verify_registration" and (
            user.confirmed_at is not None or current_email != action.target_email
        ):
            raise AccountActionTokenError()
        if purpose == "change_email" and (
            user.confirmed_at is None or current_email == action.target_email
        ):
            raise AccountActionTokenError()

        checked_at = self._utc_datetime(now or datetime.now(timezone.utc))
        issued_at = self._utc_datetime(action.issued_at)
        expires_at = self._utc_datetime(action.expires_at)
        if issued_at >= expires_at or checked_at >= expires_at:
            raise AccountActionTokenError()
        return user, action



class KafkaProducerService(GatewayService):
    def __init__(self, name: str = "KAFKA_PRODUCER_SERVICE"):
        GatewayService.__init__(self, name)

    def init_app(self, app: Flask):
        super().init_app(app)
        self._producer = self._init_producer()
        self._register_hooks(app)

    def _init_producer(self) -> KafkaProducer | None:
        try:
            return KafkaProducer(
                bootstrap_servers=",".join(
                    self.get_service_config("BOOTSTRAP_SERVERS", ["localhost:9092"])
                ),
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                request_timeout_ms=self.get_service_config("REQUEST_TIMEOUT_MS", 500),
                acks=0,  # Fire and forget. We don't want issues with the broker to affect the Gateway.
            )
        except Exception as ex:
            self._logger.error("Could not connect to Kafka: %s", ex)
            return None

    def _register_hooks(self, app: Flask):
        @app.after_request
        def _after_request_hook(response: Response):
            if self._producer is not None:
                try:
                    real_user = current_user._get_current_object()
                except RuntimeError:
                    current_app.logger.exception("Unable to collect real user. Most likely due to unbound session.")
                    return response
                self._producer.send(
                    self.get_service_config("REQUEST_TOPIC"),
                    {
                        "user_id": real_user.get_id(),
                        "client_id": (
                            current_token.client_id
                            if current_token and hasattr(current_token, "client")
                            else ""
                        ),
                        "endpoint": request.endpoint,
                        "method": request.method,
                        "timestamp": datetime.now().isoformat(),
                        "status_code": response.status_code,
                    },
                )

            return response

    def __getattr__(self, name):
        return getattr(self._producer, name, None)

    def __getitem__(self, name):
        return self._producer[name]

    def __setitem__(self, name, value):
        self._producer[name] = value

    def __delitem__(self, name):
        del self._producer[name]
