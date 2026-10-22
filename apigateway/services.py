"""Module defining API Gateway services."""

import hashlib
import hmac
import json
import logging
import math
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from functools import wraps
from typing import Callable, Tuple
from urllib.parse import urlencode, urlsplit, urlunsplit

import requests
from authlib.integrations.flask_oauth2 import current_token, token_authenticated
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from cachelib.serializers import RedisSerializer
from flask import Flask, current_app, g, request
from flask.wrappers import Response
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.extension import LimitDecorator
from flask_limiter.util import get_remote_address
from flask_login import current_user
from flask_security import Security, SQLAlchemyUserDatastore
from itsdangerous import URLSafeTimedSerializer
from kafka import KafkaProducer
from redis import Redis, StrictRedis
from redis.exceptions import ConnectionError, TimeoutError
from sqlalchemy import func
from werkzeug.datastructures import Headers
from werkzeug.exceptions import MethodNotAllowed, NotFound
from werkzeug.routing import RequestRedirect
from werkzeug.security import gen_salt

from apigateway import extensions
from apigateway.exceptions import NoClientError, NotFoundError, ValidationError
from apigateway.models import AnonymousUser, OAuth2Client, OAuth2Token, Role, User
from apigateway.utils import GatewayResourceProtector, ProxyView


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
        bearer_cls = create_bearer_token_validator(extensions.db.session, OAuth2Token)
        self.require_oauth.register_token_validator(bearer_cls())
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
        """Adds the X-api-uid and X-Access-Modality headers for token-authenticated requests."""
        if token is None or not token.user:
            return

        headers = Headers(request.headers.items())
        headers.add_header("X-api-uid", token.user.id)

        # The only differentiator between API and UI clients is the client_name
        client = token.client
        client_name = client.client_name if client is not None else None
        modality = "api" if client_name and "API" in client_name else "ui"

        g.access_modality = modality
        headers[AuthService.MODALITY_HEADER] = modality

        request.headers = headers

    def load_client(self, client_id: str) -> Tuple[OAuth2Client, OAuth2Token]:
        """Loads the OAuth2Client and OAuth2Token for the given client_id.

        Args:
            client_id (str): The ID of the client to load.

        Raises:
            NoClientError: If the client with the given ID is not found.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the given client_id.
        """
        client = OAuth2Client.query.filter_by(client_id=client_id).first()

        if client is None:
            raise NoClientError(f"Client {client_id} not found")

        token = OAuth2Token.query.filter_by(client_id=client.id).first()

        if token is None or token.is_expired():
            token = self._create_temporary_token(client)
            extensions.db.session.add(token)

        client.last_activity = datetime.now()
        extensions.db.session.add(client)
        extensions.db.session.commit()

        return client, token

    def bootstrap_user(
        self,
        client_name: str = None,
        scope: str = None,
        ratelimit_multiplier: float = 1.0,
        expires: datetime = datetime(2050, 1, 1),
        create_client: bool = False,
        individual_ratelimit_multipliers: dict = None,
    ) -> Tuple[OAuth2Client, OAuth2Token]:
        """Bootstraps a user with an OAuth2Client and OAuth2Token.

        Args:
            client_name (type, optional): The name of the client. Defaults to None.
            scopes (type, optional): The scopes for the client. Defaults to None.
            ratelimit_multiplier (float, optional): The ratelimit factor for the client. Defaults to 1.0.
            expires (type, optional): The expiration date for the token. Defaults to datetime(2050, 1, 1).
            create_client (bool, optional): Whether to create a new client or not. Defaults to False.
            individual_ratelimit_multipliers (dict, optional): A dictionary of individual ratelimit multipliers for specific endpoints. Defaults to None.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the user.
        """
        if current_user.is_anonymous_bootstrap_user:
            return self.bootstrap_anonymous_user()

        client_name = client_name or self._app.config.get("BOOTSTRAP_CLIENT_NAME", "BB client")

        clients = (
            OAuth2Client.query.filter_by(user_id=current_user.get_id())
            .order_by(OAuth2Client.client_id_issued_at.desc())
            .all()
        )

        # Metadata is a computed property so we need to filter after the query
        client = next((c for c in clients if c.client_name == client_name), None)

        if client is None or create_client:
            self._validate_ratelimit(ratelimit_multiplier)
            self._validate_scopes(scope)

            client = OAuth2Client(
                user_id=current_user.get_id(),
                ratelimit_multiplier=ratelimit_multiplier,
                individual_ratelimit_multipliers=individual_ratelimit_multipliers,
                last_activity=datetime.now(),
            )
            client.set_client_metadata(
                {
                    "client_name": client_name,
                    "description": client_name,
                    "scope": scope or " ".join(self._app.config.get("USER_DEFAULT_SCOPES", "")),
                }
            )

            client.gen_salt()
            extensions.db.session.add(client)
            extensions.db.session.flush()

            token = self._create_user_token(client, expires=expires)
            extensions.db.session.add(token)

            self._logger.info("Created BB client for {email}".format(email=current_user.email))
        else:
            token = OAuth2Token.query.filter_by(
                client_id=client.id,
                user_id=current_user.get_id(),
            ).first()

            if token is None:
                token = self._create_user_token(client, expires=expires)

                extensions.db.session.add(token)
                self._logger.info("Created BB client for {email}".format(email=current_user.email))

            client.last_activity = datetime.now()
            extensions.db.session.add(client)

        extensions.db.session.commit()

        return client, token

    def bootstrap_anonymous_user(self) -> Tuple[OAuth2Client, OAuth2Token]:
        """Bootstraps an anonymous user with an OAuth2Client and OAuth2Token.

        Raises:
            ValidationError: If the current user is not an anonymous bootstrap user.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the anonymous user.
        """
        if not current_user.is_anonymous_bootstrap_user:
            raise ValidationError("Only anonymous bootstrap user can create temporary tokens")

        client = OAuth2Client(
            user_id=current_user.get_id(),
            last_activity=datetime.now(),
        )

        client.set_client_metadata(
            {
                "client_name": self._app.config.get("BOOTSTRAP_CLIENT_NAME", "BB client"),
                "description": "Anonymous client",
                "scope": " ".join(self._app.config.get("BOOTSTRAP_SCOPES", "")),
            }
        )

        client.gen_salt()
        extensions.db.session.add(client)
        extensions.db.session.flush()

        token = self._create_temporary_token(client)
        extensions.db.session.add(token)
        extensions.db.session.commit()

        return client, token

    def _create_user_token(
        self,
        client: OAuth2Client,
        expires=datetime(2050, 1, 1),
    ) -> OAuth2Token:
        """Creates an OAuth2Token for the given OAuth2Client.

        Args:
            client (OAuth2Client): The OAuth2Client to create the token for.
            expires (type, optional): The expiration date for the token. Defaults to datetime(2050, 1, 1).

        Returns:
            OAuth2Token: The created OAuth2Token.
        """
        salt_length = self._app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)

        token = OAuth2Token(
            token_type="bearer",
            client_id=client.id,
            user_id=client.user_id,
            access_token=gen_salt(salt_length),
            refresh_token=gen_salt(salt_length),
            scope=client.scope,
            expires_in=(expires - datetime.now()).total_seconds(),
        )

        return token

    def _create_temporary_token(self, client: OAuth2Client) -> OAuth2Token:
        """Creates a temporary OAuth2Token for the given OAuth2Client.

        Args:
            client (OAuth2Client): The OAuth2Client to create the token for.

        Raises:
            ValidationError: If the current user is not an anonymous bootstrap user.

        Returns:
            OAuth2Token: The created temporary OAuth2Token.
        """
        if not current_user.is_anonymous_bootstrap_user:
            raise ValidationError("Only bootstrap user can create temporary tokens")

        salt_length = self._app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)
        expires_in: int = self._app.config.get("BOOTSTRAP_TOKEN_EXPIRES", 3600 * 24)

        return OAuth2Token(
            token_type="bearer",
            client_id=client.id,
            user_id=client.user_id,
            access_token=gen_salt(salt_length),
            refresh_token=gen_salt(salt_length),
            scope=client.scope,
            expires_in=expires_in,
        )

    def _validate_ratelimit(self, requested_ratelimit: float):
        """
        Check if the current user has enough capacity to create a new client.

        Args:
            requested_ratelimit (float): The amount of capacity requested for the new client.

        Raises:
            ValidationError: If the current user account does not have enough capacity to create a new client.
        """
        quota = current_user.ratelimit_quota or 2.0
        if quota == -1:
            return

        used_ratelimit = (
            extensions.db.session.query(func.sum(OAuth2Client.ratelimit_multiplier).label("sum"))
            .filter(OAuth2Client.user_id == current_user.get_id())
            .first()[0]
            or 0.0
        )

        if quota - (used_ratelimit + requested_ratelimit) < 0:
            raise ValidationError(
                "The current user account (%s) does not have enough capacity to create a new client. Requested: %s, Available: %s"
                % (current_user.email, requested_ratelimit, quota - used_ratelimit)
            )

    def _validate_scopes(self, scopes: str):
        allowed_scopes = set(current_user.allowed_scopes)

        if "*" in allowed_scopes or scopes is None:
            return

        requested_scopes = set(scopes.split())

        if not allowed_scopes.issuperset(requested_scopes):
            raise ValidationError(
                "The current user account (%s) does not have the requested scopes. Requested: %s, Allowed: %s"
                % (current_user.email, requested_scopes, allowed_scopes)
            )


class ProxyService(GatewayService):
    """Register authenticated discovery routes under strict local policy."""

    _SUPPORTED_METHODS = {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    }

    def __init__(self, name: str = "PROXY_SERVICE"):
        super().__init__(name)

    @staticmethod
    def _canonical_path(path: str, *, field: str) -> str:
        if not isinstance(path, str) or not path.startswith("/"):
            raise RuntimeError(f"{field} must be an absolute URL path")
        if len(path) > 256 or (path != "/" and path.endswith("/")):
            raise RuntimeError(f"{field} is not canonical")
        if (
            "\\" in path
            or "%" in path
            or "?" in path
            or "#" in path
            or "<" in path
            or ">" in path
            or "//" in path
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            raise RuntimeError(f"{field} contains an ambiguous URL path")
        if any(segment in {".", ".."} for segment in path.split("/")):
            raise RuntimeError(f"{field} contains a dot segment")
        return path

    @staticmethod
    def _strict_json(raw: bytes):
        def reject_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise RuntimeError("Discovery document contains duplicate keys")
                result[key] = value
            return result

        try:
            return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise RuntimeError("Discovery document is not valid bounded UTF-8 JSON") from error

    def _validate_document_shape(self, document):
        max_depth = self.get_service_config("DISCOVERY_MAX_JSON_DEPTH", 8)
        max_entries = self.get_service_config("DISCOVERY_MAX_JSON_ENTRIES", 2048)
        max_fields = self.get_service_config("DISCOVERY_MAX_FIELDS", 1024)
        entries = 0
        fields = 0

        def visit(value, depth):
            nonlocal entries, fields
            if depth > max_depth:
                raise RuntimeError("Discovery document exceeds JSON depth limit")
            if isinstance(value, dict):
                fields += len(value)
                entries += len(value)
                if fields > max_fields:
                    raise RuntimeError("Discovery document exceeds field limit")
                for child in value.values():
                    visit(child, depth + 1)
            elif isinstance(value, list):
                entries += len(value)
                for child in value:
                    visit(child, depth + 1)
            if entries > max_entries:
                raise RuntimeError("Discovery document exceeds entry limit")

        visit(document, 1)

    def _validate_document(self, raw: bytes) -> list:
        document = self._strict_json(raw)
        self._validate_document_shape(document)
        if (
            not isinstance(document, dict)
            or set(document) != {"version", "routes"}
            or type(document["version"]) is not int
            or document["version"] != 1
            or not isinstance(document["routes"], list)
        ):
            raise RuntimeError("Discovery document does not match schema version 1")
        routes = document["routes"]
        if len(routes) > self.get_service_config("DISCOVERY_MAX_ROUTES", 256):
            raise RuntimeError("Discovery document has too many routes")

        seen_paths = set()
        validated = []
        for route in routes:
            if not isinstance(route, dict) or set(route) != {"path", "methods"}:
                raise RuntimeError("Discovery route contains unsupported fields")
            path = self._canonical_path(route["path"], field="Discovery route path")
            methods = route["methods"]
            if (
                not isinstance(methods, list)
                or not methods
                or any(
                    not isinstance(method, str)
                    or method not in self._SUPPORTED_METHODS
                    for method in methods
                )
                or len(set(methods)) != len(methods)
            ):
                raise RuntimeError("Discovery route methods are invalid")
            if path in seen_paths:
                raise RuntimeError("Discovery document contains duplicate routes")
            seen_paths.add(path)
            validated.append({"path": path, "methods": methods})
        return validated

    @staticmethod
    def _discovery_url(base_url: str, discovery_path: str) -> str:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError("Discovery and proxy origins must use HTTPS")
        base_path = parsed.path.rstrip("/")
        path = base_path + ("" if discovery_path == "/" else discovery_path)
        return urlunsplit((parsed.scheme, parsed.netloc, path or "/", "", ""))

    def _verify_discovery(
        self, raw: bytes, timestamp: str, signature: str, secret
    ) -> list:
        if (
            not isinstance(timestamp, str)
            or not timestamp.isascii()
            or not timestamp.isdigit()
        ):
            raise RuntimeError("Discovery timestamp is invalid")
        timestamp_value = int(timestamp)
        max_age = self.get_service_config("DISCOVERY_MAX_AGE_SECONDS", 300)
        now = int(time.time())
        if timestamp_value > now + 30 or now - timestamp_value > max_age:
            raise RuntimeError("Discovery document is stale")
        if not isinstance(secret, (str, bytes)) or not secret:
            raise RuntimeError("Discovery HMAC key is required")
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
        expected = hmac.new(
            secret_bytes, timestamp.encode("ascii") + b"\n" + raw, hashlib.sha256
        ).hexdigest()
        supplied = (
            signature[3:]
            if isinstance(signature, str) and signature.startswith("v1=")
            else ""
        )
        if not hmac.compare_digest(expected, supplied):
            raise RuntimeError("Discovery signature is invalid")
        return self._validate_document(raw)

    def _read_discovery_body(self, response, started_at: float) -> bytes:
        if response.headers.get("Content-Encoding", "identity").lower() not in {
            "",
            "identity",
        }:
            raise RuntimeError("Encoded discovery documents are not accepted")
        maximum = self.get_service_config("DISCOVERY_MAX_BYTES", 262_144)
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                if int(declared) > maximum:
                    raise RuntimeError("Discovery document exceeds byte limit")
            except ValueError as error:
                raise RuntimeError("Discovery Content-Length is invalid") from error
        total_deadline = self.get_service_config(
            "DISCOVERY_TOTAL_TIMEOUT_SECONDS", 10
        )
        chunks = []
        total = 0
        for chunk in response.iter_content(chunk_size=min(65536, maximum + 1)):
            if time.monotonic() - started_at > total_deadline:
                raise RuntimeError("Discovery total deadline exceeded")
            total += len(chunk)
            if total > maximum:
                raise RuntimeError("Discovery document exceeds byte limit")
            chunks.append(chunk)
        return b"".join(chunks)

    def register_services(self):
        services = self.get_service_config("WEBSERVICES", {})
        if not isinstance(services, dict):
            raise RuntimeError("PROXY_SERVICE_WEBSERVICES must be a mapping")
        for service_name, service in services.items():
            self.register_service(service_name, service)

    def register_service(self, service_name: str, service: dict):
        if not isinstance(service_name, str) or not service_name:
            raise RuntimeError("Proxy service names must be nonempty strings")
        if not isinstance(service, dict):
            raise RuntimeError("Proxy service configuration must be a mapping")
        required = {"base_url", "deploy_path", "discovery_hmac_key", "policy"}
        allowed = required | {
            "discovery_path",
            "discovery_cache",
            "tls_ca_bundle",
        }
        if not required.issubset(service) or not set(service).issubset(allowed):
            raise RuntimeError("Proxy service configuration has missing or unknown fields")

        deploy_path = self._canonical_path(service["deploy_path"], field="Deploy path")
        if deploy_path == "/" or "/" in deploy_path[1:]:
            raise RuntimeError(
                "Proxy services require a dedicated non-root top-level prefix"
            )
        discovery_path = self._canonical_path(
            service.get("discovery_path", "/resources"), field="Discovery path"
        )
        base_url = service["base_url"]
        parsed_base = urlsplit(base_url)
        self._canonical_path(
            parsed_base.path.rstrip("/") or "/", field="Proxy origin base path"
        )
        discovery_url = self._discovery_url(base_url, discovery_path)
        routes = self._fetch_resource_document(
            service_name, discovery_url, service
        )
        policy = service["policy"]
        if not isinstance(policy, dict) or set(policy) - {"default", "routes"}:
            raise RuntimeError("Proxy local policy is invalid")
        default_policy = policy.get("default", {})
        route_policies = policy.get("routes", {})
        if not isinstance(default_policy, dict) or not isinstance(route_policies, dict):
            raise RuntimeError("Proxy local policy is invalid")
        discovered_paths = {route["path"] for route in routes}
        for policy_path in route_policies:
            canonical_policy_path = self._canonical_path(
                policy_path, field="Proxy policy route path"
            )
            if canonical_policy_path not in discovered_paths:
                raise RuntimeError("Proxy policy contains an undiscovered route")
        seen_endpoints = set()
        for route in routes:
            remote_path = route["path"]
            local_path = (
                deploy_path
                if remote_path == "/"
                else deploy_path.rstrip("/") + remote_path
            )
            prefix = deploy_path.rstrip("/") + "/"
            if local_path != deploy_path and not local_path.startswith(prefix):
                raise RuntimeError("Discovered route escapes its deployment prefix")
            endpoint = f"proxy:{service_name}:{remote_path}"
            if endpoint in seen_endpoints or endpoint in self._app.view_functions:
                raise RuntimeError("Duplicate proxy endpoint")
            if self._route_collides(local_path, route["methods"]):
                raise RuntimeError("Proxy route collides with an existing route")
            seen_endpoints.add(endpoint)

            local = dict(default_policy)
            override = route_policies.get(remote_path, {})
            if not isinstance(override, dict):
                raise RuntimeError("Proxy route policy must be a mapping")
            local.update(override)
            properties = self._validate_local_policy(local, route["methods"])
            cache_policy = properties["cache"]
            proxy_view = ProxyView.as_view(
                endpoint,
                deploy_path,
                base_url,
                remote_path,
                properties["methods"],
                properties["authorization"],
                cache_policy is not None,
                service.get("tls_ca_bundle"),
            )
            if properties["csrf_exempt"]:
                extensions.csrf.exempt(proxy_view)
            if cache_policy is not None:
                proxy_view = extensions.cache_service.cached(
                    timeout=cache_policy["ttl_seconds"],
                    namespace=f"{service_name}:{local_path}",
                    query_policy=cache_policy["query_parameters"],
                    representation_policy=cache_policy["representation_headers"],
                    max_object_bytes=self.get_service_config(
                        "MAX_CACHE_OBJECT_BYTES", 1024 * 1024
                    ),
                )(proxy_view)
            counts, per_second = properties["rate_limit"]
            proxy_view = extensions.limiter_service.shared_limit(
                counts=counts, per_second=per_second
            )(proxy_view)
            extensions.limiter_service.group_endpoint(
                local_path, counts, per_second
            )
            if properties["authorization"]:
                proxy_view = extensions.auth_service.require_oauth(
                    properties["scopes"]
                )(proxy_view)
            self._app.add_url_rule(
                local_path,
                endpoint=endpoint,
                view_func=proxy_view,
                methods=properties["methods"],
                provide_automatic_options=False,
            )

    def _route_collides(self, local_path: str, methods: list) -> bool:
        matcher = self._app.url_map.bind("")
        checked_methods = set(methods)
        if "GET" in checked_methods:
            checked_methods.add("HEAD")
        for method in checked_methods:
            try:
                matcher.match(local_path, method=method)
            except RequestRedirect:
                return True
            except (NotFound, MethodNotAllowed):
                continue
            return True
        return False

    def _validate_local_policy(self, policy, discovered_methods):
        allowed = {
            "methods",
            "authorization",
            "scopes",
            "csrf_exempt",
            "rate_limit",
            "cache",
        }
        if not isinstance(policy, dict) or set(policy) - allowed:
            raise RuntimeError("Proxy local policy contains unsupported fields")
        methods = policy.get("methods", ["GET", "HEAD"])
        authorization = policy.get("authorization", True)
        scopes = policy.get("scopes", [])
        csrf_exempt = policy.get("csrf_exempt", False)
        rate_limit = policy.get(
            "rate_limit", self.get_service_config("DEFAULT_RATE_LIMIT", [1000, 86400])
        )
        cache = policy.get("cache")
        if (
            not isinstance(methods, list)
            or not methods
            or any(
                not isinstance(method, str)
                or method not in self._SUPPORTED_METHODS
                for method in methods
            )
            or len(set(methods)) != len(methods)
            or not set(discovered_methods).issubset(methods)
            or type(authorization) is not bool
            or type(csrf_exempt) is not bool
            or not isinstance(scopes, list)
            or any(not isinstance(scope, str) or not scope for scope in scopes)
            or not isinstance(rate_limit, list)
            or len(rate_limit) != 2
            or any(type(value) is not int or value <= 0 for value in rate_limit)
        ):
            raise RuntimeError("Proxy local policy is invalid")
        methods = list(discovered_methods)
        if cache is not None:
            cache = self._validate_cache_policy(cache, authorization, methods)
        return {
            "methods": methods,
            "authorization": authorization,
            "scopes": scopes,
            "csrf_exempt": csrf_exempt,
            "rate_limit": rate_limit,
            "cache": cache,
        }

    def _validate_cache_policy(self, cache, authorization, methods):
        if (
            authorization
            or methods != ["GET"]
            or not isinstance(cache, dict)
            or set(cache)
            != {"ttl_seconds", "query_parameters", "representation_headers"}
            or type(cache["ttl_seconds"]) is not int
            or not 1 <= cache["ttl_seconds"] <= 300
            or not isinstance(cache["query_parameters"], dict)
            or not isinstance(cache["representation_headers"], dict)
        ):
            raise RuntimeError("Only bounded public GET cache policy is accepted")

        query_policy = cache["query_parameters"]
        max_parameters = self.get_service_config("MAX_CACHE_QUERY_PARAMETERS", 8)
        max_query_bytes = self.get_service_config("MAX_CACHE_QUERY_VALUE_BYTES", 128)
        max_query_values = self.get_service_config("MAX_CACHE_QUERY_VALUES", 32)
        if len(query_policy) > max_parameters:
            raise RuntimeError("Proxy cache query grammar has too many parameters")
        normalized_query = {}
        for name, values in query_policy.items():
            if (
                not isinstance(name, str)
                or not name
                or len(name.encode("utf-8")) > 64
                or not isinstance(values, list)
                or not values
                or len(values) > max_query_values
                or any(
                    not isinstance(value, str)
                    or len(value.encode("utf-8")) > max_query_bytes
                    for value in values
                )
                or len(set(values)) != len(values)
            ):
                raise RuntimeError("Proxy cache query grammar is invalid")
            normalized_query[name] = sorted(values)

        representation_policy = cache["representation_headers"]
        forwarded_headers = {
            header.lower()
            for header in self.get_service_config(
                "REQUEST_HEADERS",
                ["Accept", "Accept-Language", "Content-Type"],
            )
        }
        max_header_values = self.get_service_config(
            "MAX_CACHE_HEADER_VALUES", 16
        )
        max_header_bytes = self.get_service_config(
            "MAX_CACHE_HEADER_VALUE_BYTES", 256
        )
        normalized_headers = {}
        for name, values in representation_policy.items():
            if not isinstance(name, str) or not isinstance(values, list):
                raise RuntimeError("Proxy cache representation grammar is invalid")
            normalized_name = name.strip().lower()
            normalized_values = [
                value if isinstance(value, str) else None
                for value in values
            ]
            if (
                not normalized_name
                or normalized_name in normalized_headers
                or len(values) > max_header_values
                or any(
                    not value
                    or len(value.encode("utf-8")) > max_header_bytes
                    for value in normalized_values
                )
                or len(set(normalized_values)) != len(normalized_values)
            ):
                raise RuntimeError("Proxy cache representation grammar is invalid")
            normalized_headers[normalized_name] = sorted(normalized_values)
        if set(normalized_headers) != forwarded_headers:
            raise RuntimeError(
                "Proxy cache must declare finite values for every forwarded header"
            )
        return {
            "ttl_seconds": cache["ttl_seconds"],
            "query_parameters": normalized_query,
            "representation_headers": normalized_headers,
        }


    def _fetch_resource_document(self, service_name, resource_url, service):
        cache_key = f"proxy-discovery:{service_name}"
        verify = service.get(
            "tls_ca_bundle", self.get_service_config("TLS_CA_BUNDLE", True)
        )
        if not (verify is True or isinstance(verify, str) and bool(verify)):
            raise RuntimeError(
                "Discovery TLS verification requires system trust or a CA bundle path"
            )
        try:
            total_deadline = self.get_service_config(
                "DISCOVERY_TOTAL_TIMEOUT_SECONDS", 10
            )
            started_at = time.monotonic()
            response = requests.get(
                resource_url,
                headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                timeout=(
                    min(
                        self.get_service_config(
                            "DISCOVERY_CONNECT_TIMEOUT_SECONDS", 3
                        ),
                        total_deadline,
                    ),
                    min(
                        self.get_service_config("DISCOVERY_READ_TIMEOUT_SECONDS", 5),
                        total_deadline,
                    ),
                ),
                allow_redirects=False,
                stream=True,
                verify=verify,
            )
            try:
                response.raise_for_status()
                if response.status_code != 200:
                    raise RuntimeError("Discovery response status must be 200")
                raw = self._read_discovery_body(response, started_at)
                timestamp = response.headers.get("X-Discovery-Timestamp")
                signature = response.headers.get("X-Discovery-Signature")
                routes = self._verify_discovery(
                    raw, timestamp, signature, service["discovery_hmac_key"]
                )
            finally:
                response.close()
            if service.get("discovery_cache", False):
                extensions.storage_service.set(
                    cache_key,
                    {
                        "body": raw.decode("utf-8"),
                        "timestamp": timestamp,
                        "signature": signature,
                    },
                    timeout=self.get_service_config(
                        "DISCOVERY_MAX_AGE_SECONDS", 300
                    ),
                )
            return routes
        except (requests.exceptions.RequestException, RuntimeError):
            if not service.get("discovery_cache", False):
                raise
            cached = extensions.storage_service.get(cache_key)
            if not isinstance(cached, dict) or set(cached) != {
                "body",
                "timestamp",
                "signature",
            }:
                raise RuntimeError("No authenticated fresh discovery cache is available")
            return self._verify_discovery(
                cached["body"].encode("utf-8"),
                cached["timestamp"],
                cached["signature"],
                service["discovery_hmac_key"],
            )


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

        @app.before_request
        def _before_request_hook():
            g.request_start_time = time.time()

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
        else:
            defaults, decorated = self.limit_manager.resolve_limits(self._app, request_endpoint)
            all_limits = list(defaults) + list(decorated)
            for limit in all_limits:
                key = limit.limit.key_for(request_endpoint, scope)
                self._logger.info("Clearing limit for key %s", key)
                self.storage.clear(key)

            extensions.storage_service.delete(
                f"{self._name}//{self._key_func(request_endpoint)}/time"
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
                cost=cost if cost else self._cost_func,
            )(func)

            @wraps(func)
            def check(*args, **kwargs):
                self.check()
                return func(*args, **kwargs)

            return check

        return inner

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
            multiplier = next(
                (
                    value
                    for pattern, value in individual_multipliers.items()
                    if re.match(pattern, request.endpoint)
                ),
                multiplier,
            )

        if request.endpoint in self._symbolic_ratelimits:
            counts: int = self._symbolic_ratelimits[request.endpoint]["counts"]
            per_second: int = self._symbolic_ratelimits[request.endpoint]["per_second"]

        return "{0}/{1} second".format(int(counts * multiplier), per_second)

    def _cost_func(self) -> int:
        """Calculates the cost for the rate limit.

        This method calculates the cost for the rate limit based on the processing time of the request.

        Returns:
            int: The cost for the rate limit.
        """

        self._calc_new_mean_time()

        if self.get_service_config("SCALING_COST_ENABLED", False):

            request_count = float(
                extensions.storage_service.get(f"{self._name}//{self._key_func()}/count") or 0
            )

            if request_count > self.get_service_config("SCALING_COST_THRESHOLD", 100):

                request_mean_time = float(
                    extensions.storage_service.get(f"{self._name}//{self._key_func()}/time") or 0
                )

                request_time = getattr(g, "processing_time", 0)

                if request_time <= request_mean_time:
                    return 1

                # Calculate the ratio of processing time to mean time
                ratio = request_time / request_mean_time

                # Calculate the cost based on the log2 of the ratio
                #
                # Example:
                # 1 + log(1, 2) * 5 = 1 + 0 = 1
                # 1 + log(2, 2) * 5 = 1 + 1 * 5 = 6
                # 1 + log(3, 2) * 5 ≈ 1 + 1.585 * 5 ≈ 9.925
                return 1 + min(int(math.log(ratio, 2) * 5), 9)

        return 1

    def _calc_new_mean_time(self):
        processing_time: float = max(0.0, time.time() - g.request_start_time)

        key_time: str = f"{self._name}//{self._key_func()}/time"
        key_count: str = f"{self._name}//{self._key_func()}/count"

        existing_time: float = float(extensions.storage_service.get(key_time) or 0)
        request_count: int = int(extensions.storage_service.get(key_count) or 0)

        new_mean_time = ((existing_time * request_count) + processing_time) / (request_count + 1)

        extensions.storage_service.set(key_time, new_mean_time)
        extensions.storage_service.set(key_count, request_count + 1)

        g.processing_time = processing_time

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
        """
        Transfers the data from the fallback storage to Redis.

        This method iterates over the items in the fallback storage and transfers them to Redis.
        After the transfer is complete, the fallback storage is cleared.
        """
        for key, value in self._fallback_storage.items():
            if isinstance(value, dict):
                value = json.dumps(value)
            self._redis_service.set(key, self._serialize(value))
        self._fallback_storage.clear()

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
    """Cache only complete anonymous public GET representations."""

    def __init__(self, name: str = "CACHE_SERVICE"):
        GatewayService.__init__(self, name)
        Cache.__init__(self)

    def init_app(self, app: Flask):
        GatewayService.init_app(self, app)
        app.config.setdefault("CACHE_REDIS_URL", self.get_service_config("REDIS_URI"))
        app.config.setdefault(
            "CACHE_TYPE", self.get_service_config("CACHE_TYPE", "RedisCache")
        )
        Cache.init_app(self, app)

    @staticmethod
    def _generation_key(request_path: str) -> str:
        digest = hashlib.sha256(request_path.encode("utf-8")).hexdigest()
        return f"proxy-cache-generation/{digest}"

    def clear_cache(self, request_path: str) -> bool:
        """Invalidate all query and representation variants for one route."""
        if request_path == "*":
            self._logger.info("Clearing all proxy cache entries")
            return self.clear()
        key = self._generation_key(request_path)
        incremented = self.cache.inc(key)
        if incremented is None or incremented is False:
            if not self.cache.add(key, 1, timeout=0):
                incremented = self.cache.inc(key)
        self._logger.info("Invalidated proxy cache route generation")
        return incremented is not False

    @staticmethod
    def _cache_control_directives(value: str) -> dict:
        directives = {}
        for token in value.split(","):
            name, separator, directive_value = token.strip().partition("=")
            if name:
                directives[name.lower()] = (
                    directive_value.strip().strip('"') if separator else None
                )
        return directives

    @classmethod
    def _request_cache_constraints(cls):
        directives = cls._cache_control_directives(
            request.headers.get("Cache-Control", "")
        )
        if "no-cache" in directives or "no-store" in directives:
            return None
        if {
            token.strip().lower()
            for token in request.headers.get("Pragma", "").split(",")
        } & {"no-cache"}:
            return None
        if set(directives) - {"max-age", "min-fresh"}:
            return None
        constraints = {}
        for directive in ("max-age", "min-fresh"):
            if directive not in directives:
                continue
            try:
                value = int(directives[directive])
            except (TypeError, ValueError):
                return None
            if value < 0 or directive == "max-age" and value == 0:
                return None
            constraints[directive] = value
        return constraints

    @classmethod
    def _normalize_cache_request(cls, query_policy, representation_policy):
        constraints = cls._request_cache_constraints()
        if (
            constraints is None
            or request.method != "GET"
            or request.content_length not in {None, 0}
            or request.environ.get("wsgi.input_terminated", False)
            or any(
                request.headers.get(name)
                for name in (
                    "Authorization",
                    "Cookie",
                    "Proxy-Authorization",
                    "Range",
                    "If-Range",
                    "X-api-uid",
                    "X-Access-Modality",
                )
            )
        ):
            return None

        query_pairs = []
        if set(request.args) - set(query_policy):
            return None
        for name in sorted(request.args):
            values = request.args.getlist(name)
            if len(values) != 1 or values[0] not in query_policy[name]:
                return None
            query_pairs.append((name, values[0]))
        if request.query_string != urlencode(query_pairs).encode("ascii"):
            return None

        connection_tokens = {
            token.strip().lower()
            for token in request.headers.get("Connection", "").split(",")
            if token.strip()
        }
        if connection_tokens.intersection(representation_policy):
            return None

        header_values = []
        for name in sorted(representation_policy):
            values = request.headers.getlist(name)
            if len(values) > 1:
                return None
            value = values[0] if values else None
            if value is not None and value not in representation_policy[name]:
                return None
            header_values.append((name, value))
        return query_pairs, header_values, constraints

    @classmethod
    def _cache_response_eligible(
        cls, response: Response, representation_policy
    ) -> bool:
        cache_control = cls._cache_control_directives(
            response.headers.get("Cache-Control", "")
        )
        vary = {
            token.strip().lower()
            for token in response.headers.get("Vary", "").split(",")
            if token.strip()
        }
        return (
            not getattr(response, "_proxy_cache_forbidden", False)
            and response.status_code == 200
            and not response.is_streamed
            and "Set-Cookie" not in response.headers
            and "Content-Range" not in response.headers
            and "private" not in cache_control
            and "no-store" not in cache_control
            and "no-cache" not in cache_control
            and "*" not in vary
            and vary.issubset(set(representation_policy))
        )

    @classmethod
    def _cache_response_freshness(
        cls,
        response: Response,
        configured_timeout: int,
        now: float,
        response_delay: float = 0,
    ):
        directives = cls._cache_control_directives(
            response.headers.get("Cache-Control", "")
        )
        try:
            age_value = int(response.headers.get("Age", "0"))
        except (TypeError, ValueError):
            return None
        if age_value < 0:
            return None

        date_value = None
        if "Date" in response.headers:
            try:
                parsed_date = parsedate_to_datetime(response.headers["Date"])
            except (TypeError, ValueError, OverflowError):
                return None
            if parsed_date is None:
                return None
            if parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=timezone.utc)
            date_value = parsed_date.timestamp()
        apparent_age = max(0, now - date_value) if date_value is not None else 0
        corrected_age_value = float(age_value) + max(0, response_delay)
        initial_age = max(corrected_age_value, apparent_age)

        lifetimes = {}
        for directive in ("s-maxage", "max-age"):
            if directive not in directives:
                continue
            try:
                lifetimes[directive] = int(directives[directive])
            except (TypeError, ValueError):
                return None
            if lifetimes[directive] <= 0:
                return None
        origin_lifetime = lifetimes.get(
            "s-maxage", lifetimes.get("max-age")
        )
        if origin_lifetime is None and "Expires" in response.headers:
            try:
                expires_at = parsedate_to_datetime(response.headers["Expires"])
            except (TypeError, ValueError, OverflowError):
                return None
            if expires_at is None:
                return None
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if date_value is not None:
                origin_lifetime = expires_at.timestamp() - date_value
            else:
                origin_lifetime = initial_age + expires_at.timestamp() - now
        freshness_lifetime = float(configured_timeout)
        if origin_lifetime is not None:
            freshness_lifetime = min(
                freshness_lifetime, float(origin_lifetime)
            )
        remaining = freshness_lifetime - initial_age
        if remaining <= 0:
            return None
        return initial_age, freshness_lifetime, remaining

    @classmethod
    def _cache_response_timeout(
        cls, response: Response, configured_timeout: int, now: float = None
    ):
        freshness = cls._cache_response_freshness(
            response,
            configured_timeout,
            time.time() if now is None else now,
        )
        return None if freshness is None else max(1, math.ceil(freshness[2]))

    @staticmethod
    def _cached_response_is_fresh(
        initial_age, freshness_lifetime, stored_at, constraints, now
    ):
        current_age = initial_age + max(0, now - stored_at)
        if current_age >= freshness_lifetime:
            return None
        if (
            "max-age" in constraints
            and current_age > constraints["max-age"]
        ):
            return None
        if (
            "min-fresh" in constraints
            and current_age + constraints["min-fresh"] >= freshness_lifetime
        ):
            return None
        return current_age

    def cached(
        self,
        timeout: int,
        namespace: str,
        query_policy: dict,
        representation_policy: dict,
        max_object_bytes: int = 1024 * 1024,
    ) -> Callable:
        if type(timeout) is not int or not 1 <= timeout <= 300:
            raise RuntimeError("Proxy cache TTL must be between 1 and 300 seconds")
        if not isinstance(query_policy, dict) or not isinstance(
            representation_policy, dict
        ):
            raise RuntimeError("Proxy cache grammar is invalid")
        if type(max_object_bytes) is not int or max_object_bytes <= 0:
            raise RuntimeError("Proxy cache object limit must be a positive integer")

        def decorator(function):
            @wraps(function)
            def wrapped(*args, **kwargs):
                normalized = self._normalize_cache_request(
                    query_policy, representation_policy
                )
                if normalized is None:
                    return function(*args, **kwargs)
                query_pairs, header_values, constraints = normalized
                key = self._make_cache_key(
                    namespace, query_pairs, header_values
                )
                cached_response = self.get(key)
                now = time.time()
                if (
                    isinstance(cached_response, tuple)
                    and len(cached_response) == 7
                    and cached_response[0] == "proxy-cache-v2"
                ):
                    (
                        _,
                        body,
                        status,
                        headers,
                        stored_at,
                        initial_age,
                        freshness_lifetime,
                    ) = cached_response
                    current_age = self._cached_response_is_fresh(
                        initial_age,
                        freshness_lifetime,
                        stored_at,
                        constraints,
                        now,
                    )
                    if current_age is not None:
                        response = Response(body, status=status, headers=headers)
                        response.headers["Age"] = str(int(current_age))
                        return response
                    absolute_age = initial_age + max(0, now - stored_at)
                    if absolute_age >= freshness_lifetime:
                        self.delete(key)

                request_time = now
                g.proxy_cache_capture = max_object_bytes
                try:
                    response = current_app.make_response(function(*args, **kwargs))
                finally:
                    g.pop("proxy_cache_capture", None)
                if self._cache_response_eligible(
                    response, representation_policy
                ):
                    stored_at = time.time()
                    freshness = self._cache_response_freshness(
                        response,
                        timeout,
                        stored_at,
                        response_delay=stored_at - request_time,
                    )
                    body = response.get_data()
                    headers = list(response.headers.items())
                    object_bytes = len(body) + sum(
                        len(str(name).encode("utf-8"))
                        + len(str(value).encode("utf-8"))
                        for name, value in headers
                    )
                    if freshness is not None and object_bytes <= max_object_bytes:
                        initial_age, freshness_lifetime, remaining = freshness
                        self.set(
                            key,
                            (
                                "proxy-cache-v2",
                                body,
                                response.status_code,
                                headers,
                                stored_at,
                                initial_age,
                                freshness_lifetime,
                            ),
                            timeout=max(1, math.ceil(remaining)),
                        )
                return response

            return wrapped

        return decorator

    def _make_cache_key(
        self, namespace: str, query_pairs: list, header_values: list
    ) -> str:
        generation = self.get(self._generation_key(request.path)) or 0
        material = json.dumps(
            [
                "proxy-cache-v2",
                namespace,
                request.method,
                request.path,
                query_pairs,
                header_values,
                generation,
            ],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "proxy-view/" + hashlib.sha256(material).hexdigest()


class SecurityService(GatewayService, Security):
    """A service for managing user authentication and authorization.

    This service provides methods for creating and managing users and roles, changing passwords and email addresses,
    and generating and verifying email verification tokens.


    """

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

        self._token_serializer = URLSafeTimedSerializer(self.get_service_config("SECRET_KEY"))

    def create_user(self, email: str, password: str, **kwargs) -> User:
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

        email = self._mail_util.validate(email)
        pbad, password = self._password_util.validate(password, True)

        if pbad is not None:
            raise ValueError(", ".join(pbad))

        # Passwords are hashed in the setter of the model. No need to do it here.
        user = self.datastore.create_user(email=email, password=password, **kwargs)
        self.datastore.commit()

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

    def change_password(self, user: User, password: str) -> User:
        """
        Change the password for a given user.

        Args:
            user (User): The user object for which to change the password.
            password (str): The new password to set for the user.

        Raises:
            ValueError: If the new password is invalid.

        Returns:
            User: The updated user object.
        """
        pbad, password = self._password_util.validate(password, True)

        if pbad is not None:
            raise ValueError(", ".join(pbad))

        user = self.datastore.db.session.merge(user)
        user.password = password
        self.datastore.commit()

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
            self._mail_util.validate(email)
        except Exception:
            return False

        return True

    def change_email(self, user: User, email: str) -> User:
        """
        Change the email of a user.

        Args:
            user (User): The user object to update.
            email (str): The new email address for the user.

        Returns:
            User: The updated user object.
        """
        email = self._mail_util.validate(email)

        user = self.datastore.db.session.merge(user)
        user.email = email
        self.datastore.commit()

        return user

    def generate_email_token(self, user_id: str = None) -> str:
        """
        Generate an email verification token for the provided user.

        If no user id is provided, the current user is used.

        Returns:
            str: The email verification token.
        """
        if user_id is None:
            user_id = current_user.id

        return self.generate_token(user_id, salt=self.get_service_config("VERIFY_EMAIL_SALT"))

    def generate_password_token(self, user_id: str = None) -> str:
        """
        Generate a password reset token for the current user.

        Returns:
            str: The password reset token.
        """

        if user_id is None:
            user_id = current_user.id
        current_app.logger.info("Generating password token for user: {}".format(user_id))

        return self.generate_token(user_id, salt=self.get_service_config("VERIFY_PASSWORD_SALT"))

    def generate_token(self, content: str, salt: str):
        """
        Generate a token for the given content and salt.

        Returns:
            str: The generated token.
        """
        return self._token_serializer.dumps(content, salt=salt)

    def verify_password_token(self, token: str) -> User:
        """
        Verifies the password reset token and returns the associated user.

        Args:
            token (str): The password reset token to verify.

        Returns:
            User: The user associated with the token if it's valid, None otherwise.
        """
        salt = self.get_service_config("VERIFY_PASSWORD_SALT")
        return self.verify_token(token, salt)

    def verify_email_token(self, token: str) -> User:
        """
        Verifies the email confirmation token and returns the associated user.

        Args:
            token (str): The email confirmation token to verify.

        Returns:
            User: The user associated with the token if it's valid, None otherwise.
        """
        salt = self.get_service_config("VERIFY_EMAIL_SALT")
        return self.verify_token(token, salt)

    def verify_token(self, token: str, salt: str) -> User:
        """
        Verify email token and return the User object associated with the token.

        Args:
            token (str): The email verification token.

        Raises:
            ValueError: If the token is invalid or expired.
            NotFoundError: If no user is associated with the verification token.
            ValueError: If the user's email has already been validated.

        Returns:
            User: The user object associated with the verification token.
        """
        try:
            user_id = self._token_serializer.loads(token, max_age=86400, salt=salt)
        except Exception as ex:
            self._logger.warning(
                "{0} verification token not validated. Reason: {1}".format(token, ex)
            )
            raise ValueError("unknown verification token")
        current_app.logger.info("Verifying token for user: {}".format(user_id))
        user: User = User.query.filter_by(id=user_id).first()

        if user is None:
            raise NotFoundError("no user associated with that verification token")

        return user


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
