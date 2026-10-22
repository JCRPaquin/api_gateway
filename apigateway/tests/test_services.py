import hashlib
import hmac
import json
import time
from email.utils import formatdate
from unittest.mock import MagicMock

import pytest
import requests
from flask import Response, g, request
from werkzeug.routing import Rule

from apigateway.exceptions import ValidationError
from apigateway.models import OAuth2Client, OAuth2Token, User
from apigateway.services import GatewayService


class TestGatewayService:
    def test_init_app(self, app):
        # Arrange
        service = GatewayService("test_service")

        # Act
        service.init_app(app)

        # Assert
        assert hasattr(app, "extensions")
        assert "test_service" in app.extensions
        assert app.test_service == service

    def test_get_service_config(self, app):
        # Arrange
        app.config["test_service_test_key"] = "test_value"
        service = GatewayService("test_service", app)

        # Act
        value = service.get_service_config("test_key")

        # Assert
        assert value == "test_value"

    def test_get_service_config_default(self, app):
        # Arrange
        service = GatewayService("test_service", app)

        # Act
        value = service.get_service_config("test_key_empty", "default_value")

        # Assert
        assert value == "default_value"


class TestAuthService:
    def test_load_client(self, app, mock_anon_user):
        # Arrange
        token = OAuth2Token(user_id=mock_anon_user.get_id(), access_token="test_token")
        client = OAuth2Client(user_id=mock_anon_user.get_id(), client_id="test_client")

        app.db.session.add(token)
        app.db.session.add(client)
        app.db.session.commit()

        # Act
        client, token = app.auth_service.load_client("test_client")

        # Assert
        assert client.client_id == "test_client"
        assert token.user_id == mock_anon_user.get_id()

    def test_bootstrap_anon_user(self, app, mock_anon_user):
        # Act
        client, token = app.auth_service.bootstrap_user()

        # Assert
        assert client.user_id == mock_anon_user.get_id()
        assert token.user_id == mock_anon_user.get_id()
        assert token.expires_in == app.config.get("BOOTSTRAP_TOKEN_EXPIRES")

    def test_bootstrap_user(self, app, mock_regular_user):
        # Act
        client, token = app.auth_service.bootstrap_user()

        # Assert
        assert client.user_id == mock_regular_user.get_id()
        assert token.user_id == mock_regular_user.get_id()

    def test_bootstrap_user_no_capacity(self, app, mock_regular_user):
        with pytest.raises(ValidationError):
            _, _ = app.auth_service.bootstrap_user(ratelimit_multiplier=100)

    def test_bootstrap_invalid_scope(self, app, mock_regular_user):
        with pytest.raises(ValidationError):
            _, _ = app.auth_service.bootstrap_user(scope="invalid")

    def test_bootstrap_valid_scope(self, app, mock_regular_user):
        try:
            _, _ = app.auth_service.bootstrap_user(scope="test_scope")
        except ValidationError:
            pytest.fail("Unexpected ValidationError")

    def test_headers_set(self, app, mock_regular_user):
        _, token = app.auth_service.bootstrap_user()

        @app.route("/test_auth_headers_set")
        def test_route():
            pass

        with app.test_request_context(
            "/test_auth_headers_set",
            headers={
                "Authorization": "Bearer " + token.access_token,
            },
        ):
            # Manually call before_request functions
            for func in app.before_request_funcs[None]:
                func()

            assert "X-api-uid" in request.headers


    def test_headers_not_set(self, app):

        @app.route("/test_auth_headers_not_set")
        def test_auth_headers_not_set():
            pass

        with app.test_request_context("/test_auth_headers_not_set"):
            # Manually call before_request functions
            for func in app.before_request_funcs[None]:
                func()

            assert "X-api-uid" not in request.headers

    def test_modality_header_anon_bootstrap_session_not_ui(self, app, mock_anon_user):
        # An anonymous bootstrap session is authenticated but NOT a real user.
        mock_anon_user.is_authenticated = True

        @app.route("/test_modality_anon")
        def view_modality_anon():
            pass

        with app.test_request_context("/test_modality_anon"):
            for func in app.before_request_funcs[None]:
                func()

            assert "X-Access-Modality" not in request.headers
            # Existing behavior preserved: X-api-uid is still set for the anonymous session.
            assert "X-api-uid" in request.headers

    def test_modality_header_stripped_unauthenticated(self, app):
        @app.route("/test_modality_stripped")
        def view_modality_stripped():
            pass

        with app.test_request_context(
            "/test_modality_stripped",
            headers={"X-Access-Modality": "evil"},
        ):
            for func in app.before_request_funcs[None]:
                func()

            assert "X-Access-Modality" not in request.headers

    def test_modality_header_api_token_any_client(self, app, mock_regular_user, mock_client):
        mock_regular_user.is_authenticated = False
        mock_client.client_name = "ADS API client"
        mock_token = MagicMock(user=mock_regular_user, client=mock_client)

        with app.test_request_context("/test_modality_api"):
            g.pop("access_modality", None)  # no session verdict for token-only path
            app.auth_service._token_authenticated(sender=None, token=mock_token)

            assert request.headers["X-Access-Modality"] == "api"
            assert len(request.headers.getlist("X-Access-Modality")) == 1

    def test_modality_header_bb_client_is_ui(self, app, mock_regular_user, mock_client):
        mock_regular_user.is_authenticated = False
        mock_client.client_name = "BB client"
        mock_token = MagicMock(user=mock_regular_user, client=mock_client)

        with app.test_request_context("/test_modality_bb"):
            g.pop("access_modality", None)  # no session verdict for token-only path
            app.auth_service._token_authenticated(sender=None, token=mock_token)

            # "BB client" does not contain "API", so it maps to the UI modality.
            assert request.headers["X-Access-Modality"] == "ui"
            assert len(request.headers.getlist("X-Access-Modality")) == 1

    def test_modality_header_token_client_name_decides(self, app, mock_regular_user, mock_client):
        mock_client.client_name = "ADS API client"
        mock_token = MagicMock(user=mock_regular_user, client=mock_client)

        @app.route("/test_modality_token_decides")
        def view_modality_token_decides():
            pass

        with app.test_request_context("/test_modality_token_decides"):
            for func in app.before_request_funcs[None]:
                func()
            app.auth_service._token_authenticated(sender=None, token=mock_token)

            # Modality is decided purely by the token's client name, so an
            # "ADS API client" token yields "api" even after the session path ran.
            assert request.headers["X-Access-Modality"] == "api"
            assert len(request.headers.getlist("X-Access-Modality")) == 1

    def test_modality_header_spoof_cannot_override_token(self, app, mock_regular_user, mock_client):
        mock_regular_user.is_authenticated = False
        mock_client.client_name = "ADS API client"
        mock_token = MagicMock(user=mock_regular_user, client=mock_client)

        @app.route("/test_modality_spoof_token")
        def view_modality_spoof_token():
            pass

        with app.test_request_context(
            "/test_modality_spoof_token",
            headers={"X-Access-Modality": "ui"},
        ):
            g.pop("access_modality", None)  # token-only: no leaked session verdict
            for func in app.before_request_funcs[None]:
                func()
            app.auth_service._token_authenticated(sender=None, token=mock_token)

            assert request.headers["X-Access-Modality"] == "api"
            assert len(request.headers.getlist("X-Access-Modality")) == 1

    def test_modality_header_token_none_no_crash(self, app):
        with app.test_request_context("/test_modality_none"):
            app.auth_service._token_authenticated(sender=None, token=None)

            assert "X-Access-Modality" not in request.headers

    def test_modality_header_real_api_client(self, app, mock_regular_user):
        # Exercise the real relationship/metadata path (not a MagicMock): a token
        # whose OAuth2Client metadata names it an API client resolves to "api".
        mock_regular_user.is_authenticated = False

        client = OAuth2Client(user_id=mock_regular_user.get_id(), client_id="real_api_client")
        client.set_client_metadata({"client_name": "ADS API client"})
        token = OAuth2Token(
            user_id=mock_regular_user.get_id(),
            client_id=client.id,
            access_token="real_api_token",
        )
        token.client = client
        token.user = mock_regular_user

        with app.test_request_context("/test_modality_real_api"):
            g.pop("access_modality", None)
            app.auth_service._token_authenticated(sender=None, token=token)

            assert request.headers["X-Access-Modality"] == "api"
            assert len(request.headers.getlist("X-Access-Modality")) == 1


class TestProxyService:
    KEY = "discovery-test-key"

    @staticmethod
    def _service(**updates):
        service = {
            "base_url": "https://backend.example/base",
            "deploy_path": "/scan",
            "discovery_path": "/resources",
            "discovery_hmac_key": TestProxyService.KEY,
            "tls_ca_bundle": "/run/secrets/internal-ca.pem",
            "policy": {
                "default": {
                    "methods": ["GET"],
                    "authorization": True,
                    "scopes": ["api"],
                    "csrf_exempt": False,
                    "rate_limit": [300, 86400],
                    "cache": None,
                }
            },
        }
        service.update(updates)
        return service

    @staticmethod
    def _response(document, timestamp=None, key=None):
        raw = json.dumps(document, separators=(",", ":")).encode()
        timestamp = timestamp or str(int(time.time()))
        signature = hmac.new(
            (key or TestProxyService.KEY).encode(),
            timestamp.encode() + b"\n" + raw,
            hashlib.sha256,
        ).hexdigest()
        response = MagicMock()
        response.status_code = 200
        response.headers = {
            "X-Discovery-Timestamp": timestamp,
            "X-Discovery-Signature": "v1=" + signature,
            "Content-Length": str(len(raw)),
        }
        response.iter_content.return_value = [raw]
        return response

    def test_signed_discovery_registers_prefixed_local_route(
        self,
        app,
        mock_requests,
        mock_limiter_service,
        mock_auth_service,
        mock_add_url_rule,
        mock_proxy_view,
    ):
        app.config["PROXY_SERVICE_WEBSERVICES"] = {"scan": self._service()}
        response = self._response(
            {"version": 1, "routes": [{"path": "/status", "methods": ["GET"]}]}
        )
        mock_get = mock_requests("get")
        mock_get.return_value = response

        app.proxy_service.register_services()

        mock_get.assert_called_once_with(
            "https://backend.example/base/resources",
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            timeout=(3, 5),
            allow_redirects=False,
            stream=True,
            verify="/run/secrets/internal-ca.pem",
        )
        mock_proxy_view.assert_called_once_with(
            "proxy:scan:/status",
            "/scan",
            "https://backend.example/base",
            "/status",
            ["GET"],
            True,
            False,
            "/run/secrets/internal-ca.pem",
        )
        mock_add_url_rule.assert_called_once()
        assert mock_add_url_rule.call_args.args[0] == "/scan/status"
        mock_auth_service.require_oauth.assert_called_once_with(["api"])
        response.close.assert_called_once()

    @pytest.mark.parametrize(
        "path",
        [
            "//outside",
            "/../outside",
            "/a//b",
            r"/a\b",
            "/a%2fb",
            "/a%2eb",
            "/a?query",
            "/<path:value>",
            "/trailing/",
        ],
    )
    def test_discovery_rejects_ambiguous_or_escaping_paths(self, app, path):
        raw = json.dumps(
            {"version": 1, "routes": [{"path": path, "methods": ["GET"]}]}
        ).encode()
        with pytest.raises(RuntimeError):
            app.proxy_service._validate_document(raw)

    @pytest.mark.parametrize(
        "document",
        [
            {"version": 1, "routes": [], "authorization": False},
            {
                "version": 1,
                "routes": [
                    {
                        "path": "/status",
                        "methods": ["GET"],
                        "scopes": [],
                    }
                ],
            },
            {
                "version": 1,
                "routes": [
                    {"path": "/same", "methods": ["GET"]},
                    {"path": "/same", "methods": ["GET"]},
                ],
            },
            {
                "version": 1,
                "routes": [{"path": "/status", "methods": ["get"]}],
            },
        ],
    )
    def test_discovery_schema_rejects_policy_and_duplicates(self, app, document):
        with pytest.raises(RuntimeError):
            app.proxy_service._validate_document(json.dumps(document).encode())

    def test_discovery_rejects_duplicate_json_keys(self, app):
        with pytest.raises(RuntimeError):
            app.proxy_service._validate_document(
                b'{"version":1,"version":1,"routes":[]}'
            )

    def test_discovery_rejects_missing_bad_and_stale_signatures(self, app):
        raw = b'{"version":1,"routes":[]}'
        fresh = str(int(time.time()))
        with pytest.raises(RuntimeError):
            app.proxy_service._verify_discovery(raw, fresh, "", self.KEY)
        with pytest.raises(RuntimeError):
            app.proxy_service._verify_discovery(
                raw, fresh, "v1=" + ("0" * 64), self.KEY
            )
        stale = str(int(time.time()) - 301)
        signature = hmac.new(
            self.KEY.encode(), stale.encode() + b"\n" + raw, hashlib.sha256
        ).hexdigest()
        with pytest.raises(RuntimeError):
            app.proxy_service._verify_discovery(
                raw, stale, "v1=" + signature, self.KEY
            )

    def test_invalid_discovery_fails_closed_without_cache(
        self, app, mock_requests, mock_add_url_rule
    ):
        app.config["PROXY_SERVICE_WEBSERVICES"] = {"scan": self._service()}
        response = self._response({"version": 1, "routes": []}, key="wrong-key")
        mock_requests("get").return_value = response
        with pytest.raises(RuntimeError):
            app.proxy_service.register_services()
        mock_add_url_rule.assert_not_called()
    def test_discovery_redirect_is_rejected(
        self, app, mock_requests, mock_add_url_rule
    ):
        app.config["PROXY_SERVICE_WEBSERVICES"] = {"scan": self._service()}
        response = self._response({"version": 1, "routes": []})
        response.status_code = 302
        mock_requests("get").return_value = response
        with pytest.raises(RuntimeError):
            app.proxy_service.register_services()
        mock_add_url_rule.assert_not_called()


    def test_explicit_authenticated_fresh_discovery_cache_is_accepted(
        self, app, mock_requests, mock_storage_service
    ):
        document = {
            "version": 1,
            "routes": [{"path": "/status", "methods": ["GET"]}],
        }
        response = self._response(document)
        raw = next(iter(response.iter_content()))
        service = self._service(discovery_cache=True)
        mock_storage_service.get.return_value = {
            "body": raw.decode(),
            "timestamp": response.headers["X-Discovery-Timestamp"],
            "signature": response.headers["X-Discovery-Signature"],
        }
        mock_requests("get").side_effect = requests.exceptions.ConnectionError

        routes = app.proxy_service._fetch_resource_document(
            "scan", "https://backend.example/resources", service
        )

        assert routes == [{"path": "/status", "methods": ["GET"]}]

    def test_local_policy_cannot_cache_protected_route(self, app):
        with pytest.raises(RuntimeError):
            app.proxy_service._validate_local_policy(
                {
                    "methods": ["GET"],
                    "authorization": True,
                    "scopes": ["api"],
                    "csrf_exempt": False,
                    "rate_limit": [1, 1],
                    "cache": {
                        "ttl_seconds": 30,
                        "query_parameters": {},
                        "representation_headers": {
                            "Accept": ["*/*", "application/json"],
                            "Accept-Language": ["en"],
                            "Content-Type": [],
                        },
                    },
                },
                ["GET"],
            )

    def test_cache_policy_normalizes_finite_local_variant_grammar(self, app):
        policy = app.proxy_service._validate_cache_policy(
            {
                "ttl_seconds": 30,
                "query_parameters": {"format": ["json", "text"]},
                "representation_headers": {
                    "Accept": ["*/*", "APPLICATION/JSON"],
                    "Accept-Language": ["EN"],
                    "Content-Type": [],
                },
            },
            False,
            ["GET"],
        )

        assert policy["query_parameters"] == {
            "format": ["json", "text"]
        }
        assert policy["representation_headers"]["accept"] == [
            "*/*",
            "APPLICATION/JSON",
        ]

    def test_root_proxy_deployment_is_rejected_before_discovery(
        self, app, mock_requests
    ):
        mock_get = mock_requests("get")
        with pytest.raises(RuntimeError):
            app.proxy_service.register_service(
                "root", self._service(deploy_path="/")
            )
        mock_get.assert_not_called()

    def test_dynamic_route_collision_rejects_overlapping_prefix_and_method(
        self, app, mock_requests
    ):
        app.url_map.add(
            Rule(
                "/reserved/<path:item>",
                endpoint="dynamic_proxy_collision",
                methods=["GET"],
            )
        )
        service = self._service(deploy_path="/reserved")
        response = self._response(
            {"version": 1, "routes": [{"path": "/status", "methods": ["GET"]}]}
        )
        mock_requests("get").return_value = response

        with pytest.raises(RuntimeError):
            app.proxy_service.register_service("reserved", service)

    def test_discovered_get_rejects_existing_head_route(self, app):
        app.url_map.add(
            Rule(
                "/scan/status",
                endpoint="head_only_proxy_collision",
                methods=["HEAD"],
            )
        )

        assert app.proxy_service._route_collides(
            "/scan/status", ["GET"]
        )

    def test_bound_matcher_handles_embedded_and_constrained_converters(
        self, app
    ):
        app.url_map.add(
            Rule(
                "/res<path:item>",
                endpoint="embedded_dynamic_proxy_collision",
                methods=["GET"],
            )
        )
        app.url_map.add(
            Rule(
                "/<int:item_id>",
                endpoint="constrained_dynamic_noncollision",
                methods=["GET"],
            )
        )

        assert app.proxy_service._route_collides(
            "/reserved/status", ["GET"]
        )
        assert not app.proxy_service._route_collides("/scan", ["GET"])
        assert not app.proxy_service._route_collides(
            "/reserved/status", ["POST"]
        )

class TestLimiterService:
    def test_group_endpoint(self, app):
        # Arrange
        app.limiter_service._ratelimit_groups = {
            "group1": {
                "counts": 1,
                "per_second": 3600 * 10,
                "patterns": ["/example/.*"],
            }
        }
        app.limiter_service._symbolic_ratelimits = {}

        # Act
        app.limiter_service.group_endpoint("/example/test", 300, 86400)

        # Assert
        assert app.limiter_service._symbolic_ratelimits["group1"] == {
            "name": "group1",
            "counts": 1,
            "per_second": 3600 * 10,
        }

    def test_shared_limit_with_limit_value(self, app):
        # Arrange
        app.limiter_service.clear_limits("*", None)

        limit_value = "5/minute"
        decorator = app.limiter_service.shared_limit(limit_value=limit_value)
        counter = 0

        @decorator
        def increment_counter():
            nonlocal counter
            counter += 1

        app.add_url_rule(
            "/test1",
            endpoint="/test1",
            view_func=increment_counter,
            methods=["GET", "POST"],
        )

        # Act
        with app.test_request_context("/test1"):
            for _ in range(10):
                try:
                    increment_counter()
                except Exception:
                    break
        # Assert
        assert counter == 5

    def test_shared_limit_with_counts_and_per_second(self, app, mock_current_token):
        # Arrange

        counts, per_second = 3, 60
        decorator = app.limiter_service.shared_limit(counts=counts, per_second=per_second)
        counter2 = 0

        @decorator
        def increment_counter2():
            nonlocal counter2
            counter2 += 1

        app.add_url_rule(
            "/test2",
            endpoint="/test2",
            view_func=increment_counter2,
            methods=["GET", "POST"],
        )

        # Act
        with app.test_request_context("/test2"):
            for _ in range(10):
                try:
                    increment_counter2()
                except Exception:
                    break
        # Assert
        assert counter2 == 9  # 9 because of rate limit multiplier of 3 for current user


class TestCacheService:
    def test_cache_key_preserves_exact_forwarded_header_values(
        self, app, monkeypatch
    ):
        service = app.cache_service
        monkeypatch.setattr(service, "get", MagicMock(return_value=0))
        query_policy = {"a": ["1"], "b": ["2"]}
        representation_policy = {
            "accept": ["APPLICATION/JSON", "application/json"],
        }

        with app.test_request_context(
            "/public?a=1&b=2", headers={"Accept": "APPLICATION/JSON"}
        ):
            query, headers, _ = service._normalize_cache_request(
                query_policy, representation_policy
            )
            uppercase = service._make_cache_key(
                "scan:/public", query, headers
            )
        with app.test_request_context(
            "/public?a=1&b=2", headers={"Accept": "application/json"}
        ):
            query, headers, _ = service._normalize_cache_request(
                query_policy, representation_policy
            )
            lowercase = service._make_cache_key(
                "scan:/public", query, headers
            )

        assert uppercase != lowercase

    @pytest.mark.parametrize(
        "path, headers",
        [
            ("/public?b=2&a=1", {"Accept": "application/json"}),
            ("/public?a=%31&b=2", {"Accept": "application/json"}),
            ("/public?a=1&b=2", {"Accept": "APPLICATION/JSON"}),
            (
                "/public?a=1&b=2",
                {
                    "Accept": "application/json",
                    "Connection": "keep-alive, Accept",
                },
            ),
        ],
    )
    def test_ambiguous_forwarded_dimensions_bypass_cache(
        self, app, path, headers
    ):
        with app.test_request_context(path, headers=headers):
            normalized = app.cache_service._normalize_cache_request(
                {"a": ["1"], "b": ["2"]},
                {"accept": ["application/json"]},
            )

        assert normalized is None

    @pytest.mark.parametrize(
        "headers",
        [
            {"Authorization": "Bearer secret"},
            {"Cookie": "session=secret"},
            {"Range": "bytes=0-1"},
            {"X-api-uid": "123"},
            {"Cache-Control": "no-cache"},
            {"Cache-Control": "max-age=0"},
            {"Pragma": "no-cache"},
        ],
    )
    def test_credentials_identity_and_ranges_bypass_cache(
        self, app, monkeypatch, headers
    ):
        service = app.cache_service
        get = MagicMock()
        monkeypatch.setattr(service, "get", get)
        wrapped = service.cached(
            timeout=30,
            namespace="scan:/public",
            query_policy={},
            representation_policy={},
        )(MagicMock(return_value=Response(b"body")))
        with app.test_request_context("/public", headers=headers):
            wrapped()
        get.assert_not_called()

    @pytest.mark.parametrize(
        "headers",
        [
            {"Set-Cookie": "session=secret"},
            {"Cache-Control": "private"},
            {"Cache-Control": "no-store"},
            {"Vary": "*"},
            {"Vary": "X-Unkeyed"},
            {"Content-Range": "bytes 0-1/2"},
            {"Cache-Control": "no-cache"},
        ],
    )
    def test_sensitive_or_partial_responses_are_not_cacheable(self, headers):
        response = Response(b"body", headers=headers)
        assert not app_cache_eligible(response)

    def test_identical_anonymous_requests_reuse_complete_response(
        self, app, monkeypatch
    ):
        service = app.cache_service
        monkeypatch.setattr("apigateway.services.time.time", MagicMock(return_value=100))
        get = MagicMock(
            side_effect=[
                0,
                None,
                0,
                (
                    "proxy-cache-v2",
                    b"body",
                    200,
                    [("Content-Type", "text/plain")],
                    100,
                    0,
                    30,
                ),
            ]
        )
        set_cache = MagicMock(return_value=True)
        monkeypatch.setattr(service, "get", get)
        monkeypatch.setattr(service, "set", set_cache)
        backend = MagicMock(return_value=Response(b"body", content_type="text/plain"))
        wrapped = service.cached(
            timeout=30,
            namespace="scan:/public",
            query_policy={},
            representation_policy={"accept": ["text/plain"]},
        )(backend)

        with app.test_request_context("/public", headers={"Accept": "text/plain"}):
            first = wrapped()
        with app.test_request_context("/public", headers={"Accept": "text/plain"}):
            second = wrapped()

        assert first.get_data() == second.get_data() == b"body"
        backend.assert_called_once()
        set_cache.assert_called_once()

    def test_unknown_query_parameter_bypasses_cache(
        self, app, monkeypatch
    ):
        service = app.cache_service
        get = MagicMock()
        set_cache = MagicMock()
        backend = MagicMock(return_value=Response(b"body"))
        monkeypatch.setattr(service, "get", get)
        monkeypatch.setattr(service, "set", set_cache)
        wrapped = service.cached(
            timeout=30,
            namespace="scan:/public",
            query_policy={"q": ["known"]},
            representation_policy={},
        )(backend)

        with app.test_request_context("/public?nonce=unbounded"):
            response = wrapped()

        assert response.get_data() == b"body"
        backend.assert_called_once()
        get.assert_not_called()
        set_cache.assert_not_called()

    def test_oversized_complete_response_is_not_stored(
        self, app, monkeypatch
    ):
        service = app.cache_service
        monkeypatch.setattr(
            service, "get", MagicMock(side_effect=[0, None])
        )
        set_cache = MagicMock()
        monkeypatch.setattr(service, "set", set_cache)
        wrapped = service.cached(
            timeout=30,
            namespace="scan:/public",
            query_policy={},
            representation_policy={},
            max_object_bytes=4,
        )(MagicMock(return_value=Response(b"larger than four bytes")))

        with app.test_request_context("/public"):
            response = wrapped()

        assert response.get_data() == b"larger than four bytes"
        set_cache.assert_not_called()

    def test_origin_freshness_bounds_cache_timeout(self, app, monkeypatch):
        service = app.cache_service
        monkeypatch.setattr(
            service, "get", MagicMock(side_effect=[0, None])
        )
        set_cache = MagicMock()
        monkeypatch.setattr(service, "set", set_cache)
        wrapped = service.cached(
            timeout=30,
            namespace="scan:/public",
            query_policy={},
            representation_policy={},
        )(
            MagicMock(
                return_value=Response(
                    b"body",
                    headers={
                        "Cache-Control": "s-maxage=10, max-age=20",
                        "Age": "3",
                    },
                )
            )
        )

        with app.test_request_context("/public"):
            wrapped()

        assert set_cache.call_args.kwargs["timeout"] == 7

    @pytest.mark.parametrize(
        "path, headers",
        [
            ("/public?q=nonce", {}),
            ("/public?q=known&q=known", {}),
            ("/public?q=known", {"Accept": "text/html"}),
            ("/public?q=known", {"Accept-Language": "zz"}),
            ("/public?q=known", {"Content-Type": "text/plain"}),
        ],
    )
    def test_unbounded_query_and_header_variants_bypass_cache(
        self, app, path, headers
    ):
        with app.test_request_context(path, headers=headers):
            normalized = app.cache_service._normalize_cache_request(
                {"q": ["known"]},
                {
                    "accept": ["application/json"],
                    "accept-language": ["en"],
                    "content-type": ["application/json"],
                },
            )
        assert normalized is None

    def test_cached_age_includes_origin_delay_and_advances_on_hit(
        self, app, monkeypatch
    ):
        service = app.cache_service
        stored = {}

        def cache_get(key):
            if key.startswith("proxy-cache-generation/"):
                return 0
            return stored.get(key)

        def cache_set(key, value, timeout):
            stored[key] = value
            return True

        monkeypatch.setattr(service, "get", cache_get)
        monkeypatch.setattr(service, "set", cache_set)
        monkeypatch.setattr(service, "delete", MagicMock())
        monkeypatch.setattr(
            "apigateway.services.time.time",
            MagicMock(side_effect=[1000, 1004, 1009]),
        )
        backend = MagicMock(
            return_value=Response(
                b"body",
                headers={
                    "Cache-Control": "max-age=30",
                    "Age": "5",
                    "Date": formatdate(1004, usegmt=True),
                },
            )
        )
        wrapped = service.cached(
            timeout=30,
            namespace="scan:/public",
            query_policy={},
            representation_policy={},
        )(backend)

        with app.test_request_context("/public"):
            wrapped()
        cached_value = next(iter(stored.values()))
        assert cached_value[5] == 9
        with app.test_request_context("/public"):
            response = wrapped()

        assert response.headers["Age"] == "14"
        backend.assert_called_once()
        assert (
            service._cached_response_is_fresh(
                10, 30, 1000, {"max-age": 14}, 1005
            )
            is None
        )
        assert (
            service._cached_response_is_fresh(
                10, 30, 1000, {"min-fresh": 15}, 1005
            )
            is None
        )
        assert service._cached_response_is_fresh(
            10, 30, 1000, {"min-fresh": 14}, 1005
        ) == 15

    def test_cache_age_is_sampled_after_cache_retrieval(
        self, app, monkeypatch
    ):
        service = app.cache_service
        now = [100]
        cached = (
            "proxy-cache-v2",
            b"stale",
            200,
            [],
            100,
            0,
            30,
        )

        def cache_get(key):
            if key.startswith("proxy-cache-generation/"):
                return 0
            now[0] = 105
            return cached

        monkeypatch.setattr(service, "get", cache_get)
        monkeypatch.setattr(service, "set", MagicMock())
        monkeypatch.setattr(
            "apigateway.services.time.time", lambda: now[0]
        )
        backend = MagicMock(return_value=Response(b"fresh"))
        wrapped = service.cached(
            timeout=30,
            namespace="scan:/public",
            query_policy={},
            representation_policy={},
        )(backend)

        with app.test_request_context(
            "/public", headers={"Cache-Control": "max-age=4"}
        ):
            response = wrapped()

        assert response.get_data() == b"fresh"
        backend.assert_called_once()

    def test_expiry_and_zero_age_directives_reject_stale_storage(self, app):
        service = app.cache_service
        assert (
            service._cache_response_timeout(
                Response(b"body", headers={"Cache-Control": "max-age=0"}),
                30,
                now=1000,
            )
            is None
        )
        assert (
            service._cache_response_timeout(
                Response(
                    b"body",
                    headers={"Expires": formatdate(999, usegmt=True)},
                ),
                30,
                now=1000,
            )
            is None
        )
        assert service._cache_response_timeout(
            Response(
                b"body",
                headers={"Expires": formatdate(1012, usegmt=True)},
            ),
            30,
            now=1000,
        ) == 12

def app_cache_eligible(response):
    from apigateway.services import CacheService

    return CacheService._cache_response_eligible(response, {"accept": []})



class TestSecurityService:
    def test_create_user(self, app):
        email = "test@gmail.com"
        password = "test_password"
        user = app.security_service.create_user(email, password)
        assert user.email == email
        assert user.password is not None

    def test_create_role(self, app):
        name = "test_role"
        description = "This is a test role"
        role = app.security_service.create_role(name, description)
        assert role.name == name
        assert role.description == description

    def test_add_role_to_user(self, app):
        email = "test@gmail.com"
        password = "test_password"
        user = app.security_service.create_user(email, password)
        name = "test_role"
        description = "This is a test role"
        role = app.security_service.create_role(name, description)
        result = app.security_service.add_role_to_user(user, role)
        assert result is True
        assert role in user.roles

    def test_change_password(self, app):
        email = "test@gmail.com"
        password = "test_password"
        user = app.security_service.create_user(email, password)
        new_password = "new_test_password"
        updated_user = app.security_service.change_password(user, new_password)
        assert updated_user.password != new_password
        assert updated_user.validate_password(new_password)

    def test_validate_email(self, app):
        valid_email = "test@gmail.com"
        invalid_email = "test"
        assert app.security_service.validate_email(valid_email) is True
        assert app.security_service.validate_email(invalid_email) is False

    def test_change_email(self, app):
        email = "test@gmail.com"
        password = "test_password"
        user = app.security_service.create_user(email, password)
        new_email = "new_test@gmail.com"
        updated_user = app.security_service.change_email(user, new_email)
        assert updated_user.email == new_email

    def test_generate_email_token(self, app, mock_regular_user):
        token = app.security_service.generate_email_token()
        assert isinstance(token, str)

    def test_verify_email_token(self, app, mock_regular_user):
        user = app.security_service.create_user(
            mock_regular_user.email, "test_password", id=mock_regular_user.id
        )
        token = app.security_service.generate_email_token()
        user = app.security_service.verify_email_token(token)
        assert isinstance(user, User)
